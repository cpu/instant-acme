use std::collections::HashMap;
use std::error::Error as StdError;
use std::io::Read;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::sync::LazyLock;
use std::time::Duration;
use std::{env, fs, io, thread};

use bytes::{Buf, Bytes};
use http::header::CONTENT_TYPE;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, verify_server_name};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::ParsedCertificate;
use rustls::RootCertStore;
use rustls_pki_types::UnixTime;
use serde::Serialize;
use serde_json::json;
use tempfile::NamedTempFile;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    // Spawn a Pebble CA and a challenge response server.
    let pebble = PebbleEnvironment::new(DEFAULT_CONFIG.clone())?;

    // Create a test account with the Pebble CA.
    let client = Box::new(pebble.http_client());
    let (account, _) = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &pebble.directory_url(),
        None,
        client,
    )
    .await?;

    // Create an order.
    let identifier = Identifier::Dns("example.com".to_string());
    let order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await?;

    // Issue a certificate w/ HTTP-01 challenge and verify it.
    test_http1(&pebble, order).await?;

    Ok(())
}

async fn test_http1(env: &PebbleEnvironment, mut order: Order) -> Result<(), Box<dyn StdError>> {
    let authorizations = order.authorizations().await?;
    let mut challenges = Vec::with_capacity(authorizations.len());
    let mut names = Vec::with_capacity(authorizations.len());

    // Collect up the relevant challenges, provisioning the expected responses as we go.
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => unreachable!("unexpected authz state: {:?}", authz.status),
        }

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| "no http01 challenge found")?;

        let Identifier::Dns(identifier) = &authz.identifier;

        // Provision the HTTP-01 challenge response with the Pebble challenge test server.
        let key_auth = order.key_authorization(challenge);
        env.add_http01_response(&challenge.token, key_auth.as_str())
            .await?;

        challenges.push((identifier, &challenge.url));
        names.push(identifier.clone());
    }

    // Tell the CA we have provisioned the response for each challenge.
    for (_, url) in &challenges {
        order.set_challenge_ready(url).await?;
    }

    // Poll until the order is ready.
    poll_until_ready(&mut order).await?;

    // Issue a certificate for the names and test the chain validates to the issuer root.
    issue_certificate(&mut order, names, env.issuer_roots().await?).await
}

// Poll the given order until it is ready, waiting longer between each attempt up to
// a maximum.
//
// Returns an error when the maximum number of tries has been reached.
async fn poll_until_ready(order: &mut Order) -> Result<(), Box<dyn StdError>> {
    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => eprintln!(
                "after {tries} tries order is {:#?} not ready, waiting {delay:?}",
                state.status
            ),
            false => {
                eprintln!("after {tries} tries - order is not ready: {state:#?}");
                return Err("order is not ready".into());
            }
        }
    }

    let state = order.state();
    match state.status {
        OrderStatus::Ready => Ok(()),
        _ => Err(format!("unexpected order status: {:?}", state.status).into()),
    }
}

// Issue a certificate for the given order, and identifiers.
//
// The issued certificate chain is verified with the provider roots.
async fn issue_certificate(
    order: &mut Order,
    identifiers: Vec<String>,
    roots: RootCertStore,
) -> Result<(), Box<dyn StdError>> {
    // Create a CSR for the identifiers corresponding to the order.
    let mut params = CertificateParams::new(identifiers.clone())?;
    params.distinguished_name = DistinguishedName::new();
    let private_key = KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;

    // Finalize the order and fetch the issued certificate chain.
    order.finalize(csr.der()).await.unwrap();
    let cert_chain_pem = loop {
        match order.certificate().await.unwrap() {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    // Parse the PEM chain into a vec of DER certificates ordered ee -> intermediates.
    let pem_certs = CertificateDer::pem_slice_iter(cert_chain_pem.as_bytes())
        .map(|result| result.unwrap())
        .collect::<Vec<_>>();

    // Split off and parse the EE cert, save the intermediates that follow.
    let (ee_cert, intermediates) = pem_certs.split_first().unwrap();
    let ee_cert = ParsedCertificate::try_from(ee_cert).unwrap();

    // Use the default crypto provider to verify the certificate chain to the Pebble CA root.
    let crypto_provider = CryptoProvider::get_default().unwrap();
    verify_server_cert_signed_by_trust_anchor(
        &ee_cert,
        &roots,
        intermediates,
        UnixTime::now(),
        crypto_provider.signature_verification_algorithms.all,
    )
    .unwrap();

    // Verify the EE cert is valid for each of the identifiers.
    for ident in identifiers {
        verify_server_name(&ee_cert, &ServerName::try_from(ident.as_str())?)?;
    }

    Ok(())
}

// A test environment running Pebble and a challenge test server.
//
// Subprocesses are torn down cleanly on drop.
#[allow(dead_code)] // fields are held to postpone drop, not used otherwise
struct PebbleEnvironment {
    config: Config,
    config_file: NamedTempFile,
    pebble: Subprocess,
    challtestsrv: Subprocess,
}

impl PebbleEnvironment {
    // Create a test environment for the given configuration.
    //
    // Set the PEBBLE and CHALLTESTSRV to pebble and pebble-challtestsrv binaries
    // respectively. If unset "./pebble" and "./pebble-challtestsrv" are used.
    //
    // Returns only once the Pebble CA server interface is responding.
    fn new(config: Config) -> io::Result<Self> {
        let config_file = NamedTempFile::new()?;
        fs::write(&config_file, serde_json::to_string_pretty(&config)?)?;

        let pebble_path = env::var("PEBBLE")
            .ok()
            .unwrap_or("./pebble".to_string());
        let challtestsrv_path = env::var("CHALLTESTSRV")
            .ok()
            .unwrap_or("./pebble-challtestsrv".to_string());

        let pebble = Subprocess::new(
            Command::new(&pebble_path)
                .arg("-config")
                .arg(config_file.path())
                .arg("-dnsserver")
                .arg("127.0.0.1:8053"), // Matched to default -dns01 addr for pebble-challtestsrv.
        )?;

        let challtestsrv = Subprocess::new(
            Command::new(&challtestsrv_path)
                .arg("-doh-cert")
                .arg("tests/testdata/server.pem")
                .arg("-doh-cert-key")
                .arg("tests/testdata/server.key"),
        )?;

        wait_for_server(&config.pebble.listen_address);

        Ok(Self {
            config,
            config_file,
            pebble,
            challtestsrv,
        })
    }

    // Return an HTTP client configured to trust the Pebble management interface root CA.
    //
    // Note: this is distinct from the CA issuer.
    fn http_client(&self) -> HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>> {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(
            CertificateDer::pem_file_iter("tests/testdata/ca.pem")
                .unwrap()
                .map(|result| result.unwrap()),
        );

        HyperClient::builder(TokioExecutor::new()).build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth(),
                )
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build(),
        )
    }

    // Provision an HTTP-01 challenge response for the given token and key authorization.
    //
    // The Pebble challenge test server will be configured to respond to HTTP-01 challenge
    // requests for the provided token by returning the expected key auth.
    async fn add_http01_response(
        &self,
        token: &str,
        key_auth: &str,
    ) -> Result<(), Box<dyn StdError>> {
        let client = self.http_client();

        let body = json!({
            "token": token,
            "content": key_auth,
        })
        .to_string();

        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/add-http01", self.challenge_management_url()))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body.into()))?;

        client.request(req).await?;

        Ok(())
    }

    // Return a RootCertStore containing the issuer root for the Pebble CA.
    //
    // This is distinct from the management root CA, and is randomly generated each
    // time that Pebble starts up. This is the issuer that signs the randomly generated
    // intermediate certificate returned as part of ACME issued certificate chains.
    async fn issuer_roots(&self) -> Result<RootCertStore, Box<dyn StdError>> {
        let client = self.http_client();

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("{}/roots/0", self.pebble_management_url()))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::default())?;

        let resp = client.request(req).await?;
        if resp.status() != 200 {
            return Err(format!("unexpected /roots/0 response status: {}", resp.status()).into());
        }

        let body = resp.collect().await?.aggregate();
        let mut pem = String::new();
        body.reader().read_to_string(&mut pem)?;
        let root = CertificateDer::from_pem_slice(pem.as_bytes())?;

        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(vec![root]);
        assert_eq!(roots.len(), 1);
        Ok(roots)
    }

    fn challenge_management_url(&self) -> &str {
        "http://127.0.0.1:8055" // Default.
    }

    fn pebble_management_url(&self) -> String {
        format!("https://{}", &self.config.pebble.management_listen_address)
    }

    fn directory_url(&self) -> String {
        format!("https://{}/dir", &self.config.pebble.listen_address)
    }
}

#[derive(Clone, Serialize)]
struct Config {
    pebble: PebbleConfig,
}

#[derive(Clone, Serialize)]
struct PebbleConfig {
    #[serde(rename = "listenAddress")]
    listen_address: String,
    #[serde(rename = "managementListenAddress")]
    management_listen_address: String,
    certificate: String,
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "httpPort")]
    http_port: u16,
    #[serde(rename = "tlsPort")]
    tls_port: u16,
    #[serde(rename = "ocspResponderURL")]
    ocsp_responder_url: String,
    #[serde(rename = "externalAccountBindingRequired")]
    external_account_binding_required: bool,
    #[serde(rename = "domainBlocklist")]
    domain_blocklist: Vec<String>,
    retry_after: RetryConfig,
    profiles: HashMap<String, Profile>,
}

#[derive(Clone, Serialize)]
struct RetryConfig {
    authz: u32,
    order: u32,
}

#[derive(Clone, Serialize)]
struct Profile {
    description: String,
    #[serde(rename = "validityPeriod")]
    validity_period: u32,
}

struct Subprocess(Option<Child>);

impl Subprocess {
    fn new(cmd: &mut Command) -> io::Result<Self> {
        Ok(Self(Some(cmd.spawn()?)))
    }
}

impl Drop for Subprocess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            child.kill().expect("failed to kill subprocess");
            child.wait().expect("failed to wait for killed subprocess");
        }
    }
}

fn wait_for_server(addr: &str) {
    for i in 0..10 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(i * 100));
    }
    panic!("failed to connect to {:?} after 10 tries", addr);
}

static DEFAULT_CONFIG: LazyLock<Config> = LazyLock::new(|| Config {
    pebble: PebbleConfig {
        listen_address: "127.0.0.1:14000".to_string(),
        management_listen_address: "127.0.0.1:15000".to_string(),
        certificate: "tests/testdata/server.pem".to_string(),
        private_key: "tests/testdata/server.key".to_string(),
        http_port: 5002,
        tls_port: 5001,
        ocsp_responder_url: "".to_string(),
        external_account_binding_required: false,
        domain_blocklist: vec!["blocked-domain.example".to_string()],
        retry_after: RetryConfig { authz: 3, order: 5 },
        profiles: HashMap::from([(
            "default".to_string(),
            Profile {
                description: "Default profile".to_string(),
                validity_period: 30,
            },
        )]),
    },
});
