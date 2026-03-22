//! ACME challenges and challenge type specific handling

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::account::{AccountInner, Key};
use crate::nonce_from_response;
use crate::types::{AuthorizationState, AuthorizedIdentifier, Empty, Error, Identifier, Problem};

/// An ACME challenge as described in RFC 8555 (section 7.1.5)
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5>
#[derive(Debug, Deserialize)]
pub struct Challenge {
    /// Challenge identifier
    pub url: String,
    /// Challenge type specific state
    #[serde(flatten)]
    pub state: ChallengeState,
    /// Current status
    pub status: ChallengeStatus,
    /// Potential error state
    pub error: Option<Problem>,
}

/// Challenge type specific state
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ChallengeState {
    /// State for an RFC 8555 HTTP-01 challenge
    #[serde(rename = "http-01")]
    Http01(http01::Challenge),
    /// State for an RFC 8555 DNS-01 challenge
    #[serde(rename = "dns-01")]
    Dns01(dns01::Challenge),
    /// State for a draft-ietf-acme-dns-persist-00 challenge
    ///
    /// Note: dns-persist-01 support is experimental
    #[serde(rename = "dns-persist-01")]
    DnsPersist01(dns_persist01::Challenge),
    /// State for an RFC 8737 TLS-ALPN-01 challenge
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01(tls_alpn01::Challenge),
    /// State for a draft-acme-device-attest-08 challenge
    ///
    /// Note: Device attestation support is experimental
    #[serde(rename = "device-attest-01")]
    DeviceAttest01(device_attest01::Challenge),
    /// An unknown challenge type
    #[serde(other)]
    Unknown,
}

/// Status of an ACME [Challenge]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// A handle for interacting with a challenge of a specific type
///
/// The `T` type parameter is the challenge type specific state type (e.g.
/// [`http01::Challenge`]) and determines which operations are available.
/// Obtain a handle from the accessor for the challenge type on
/// [`AuthorizationHandle`][crate::AuthorizationHandle] (e.g.
/// [`AuthorizationHandle::http01()`][crate::AuthorizationHandle::http01()]).
pub struct ChallengeHandle<'a, T> {
    state: ChallengeHandleState<'a>,
    challenge: &'a T,
}

impl<'a, T> ChallengeHandle<'a, T> {
    pub(crate) fn new(
        authz: &'a AuthorizationState,
        nonce: &'a mut Option<String>,
        account: &'a AccountInner,
    ) -> Option<Self>
    where
        T: ChallengeVariant,
    {
        if !T::supports_identifier(authz.identifier().identifier) {
            return None;
        }

        let (challenge, data) = authz
            .challenges
            .iter()
            .find_map(|c| Some((c, T::from_state(&c.state)?)))?;
        Some(Self {
            state: ChallengeHandleState {
                identifier: authz.identifier(),
                challenge,
                nonce,
                account,
            },
            challenge: data,
        })
    }
}

impl<T> ChallengeHandle<'_, T> {
    /// The underlying ACME challenge
    pub fn challenge(&self) -> &Challenge {
        self.state.challenge
    }

    /// The identifier for this challenge's authorization
    pub fn identifier(&self) -> &AuthorizedIdentifier<'_> {
        &self.state.identifier
    }
}

/// Shared state common to all challenge handles
struct ChallengeHandleState<'a> {
    identifier: AuthorizedIdentifier<'a>,
    challenge: &'a Challenge,
    nonce: &'a mut Option<String>,
    account: &'a AccountInner,
}

impl ChallengeHandleState<'_> {
    /// Notify the server that the given challenge is ready to be completed
    ///
    /// Traditional token-based challenges are acknowledged with an empty object body.
    async fn set_ready(&mut self) -> Result<(), Error> {
        self.respond(&Empty {}).await.map(drop)
    }

    /// Respond to the challenge with a type-specific payload
    async fn respond(&mut self, payload: &impl Serialize) -> Result<ChallengeStatus, Error> {
        let rsp = self
            .account
            .post(Some(payload), self.nonce.take(), &self.challenge.url)
            .await?;

        *self.nonce = nonce_from_response(&rsp);
        let response = Problem::check::<Challenge>(rsp).await?;
        match response.error {
            Some(details) => Err(Error::Api(details)),
            None => Ok(response.status),
        }
    }
}

/// A challenge state type corresponding to one [`ChallengeState`] variant
///
/// Implemented by the challenge state types in the per-challenge type submodules
/// (e.g. [`http01::Challenge`]).
pub(crate) trait ChallengeVariant: Sized {
    /// Get a reference to this state type's data from `state`, if the type matches
    fn from_state(state: &ChallengeState) -> Option<&Self>;

    /// Whether this challenge type supports authorizations for `identifier`
    fn supports_identifier(identifier: &Identifier) -> bool;
}

#[derive(Debug)]
struct KeyAuthorization {
    // The token is stored as the key authorization's prefix; retaining its length lets
    // token() borrow that prefix without allocating a second String.
    token_len: usize,
    value: String,
    digest: [u8; 32],
}

impl KeyAuthorization {
    fn new(token: &str, key: &Key) -> Self {
        let value = format!("{token}.{}", key.thumbprint());
        Self {
            digest: key.provider.sha256.hash(value.as_bytes()),
            token_len: token.len(),
            value,
        }
    }

    fn token(&self) -> &str {
        &self.value[..self.token_len]
    }
}

pub mod http01 {
    //! Support for RFC 8555 http-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.3>

    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::types::{Error, Identifier};

    /// Challenge state for an http-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::Http01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8555/#section-9.7.8
            // https://www.rfc-editor.org/info/rfc8738/#section-8.2
            matches!(identifier, Identifier::Dns(_) | Identifier::Ip(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(&self.challenge.token, &self.state.account.key)
        }
    }

    /// Challenge response data for an http-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        key_authorization: KeyAuthorization,
    }

    impl Response {
        fn new(token: &str, key: &super::Key) -> Self {
            Self {
                key_authorization: KeyAuthorization::new(token, key),
            }
        }

        /// The challenge token for this challenge response.
        pub fn token(&self) -> &str {
            self.key_authorization.token()
        }

        /// The key authorization content that should be placed in the challenge response file.
        ///
        /// The file should be provisioned at `/.well-known/acme-challenge/<token>` in your
        /// webserver's web root.
        pub fn key_authorization(&self) -> &str {
            &self.key_authorization.value
        }
    }

    /// A handle for interacting with an http-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod dns01 {
    //! Support for RFC 8555 dns-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8555#section-8.4>

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::account::Key;
    use crate::types::{Error, Identifier};

    /// Challenge state for a dns-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::Dns01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8555/#section-9.7.8
            // https://www.rfc-editor.org/rfc/rfc8738#section-7
            matches!(identifier, Identifier::Dns(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(
                self.state.identifier.identifier,
                &self.challenge.token,
                &self.state.account.key,
            )
        }
    }

    /// Challenge response data for a dns-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        host: String,
        rdata: String,
    }

    impl Response {
        fn new(identifier: &Identifier, token: &str, key: &Key) -> Self {
            let Identifier::Dns(domain) = identifier else {
                unreachable!("DNS-01 only supports domain identifiers");
            };

            let key_authorization = KeyAuthorization::new(token, key);

            Self {
                host: format!("_acme-challenge.{domain}."),
                rdata: BASE64_URL_SAFE_NO_PAD.encode(key_authorization.digest),
            }
        }

        /// Fully qualified hostname for the challenge response TXT record to be provisioned
        ///
        /// Includes a trailing dot.
        pub fn host(&self) -> &str {
            &self.host
        }

        /// The TXT record RDATA to provision for [`Self::host()`]
        ///
        /// This is the base64-encoded SHA256 digest of the challenge key authorization.
        pub fn rdata(&self) -> &str {
            &self.rdata
        }
    }

    /// A handle for interacting with a dns-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod dns_persist01 {
    //! Support for draft-ietf-acme-dns-persist-00 dns-persist-01 challenges
    //!
    //! See <https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-00>
    //!
    //! Note: dns-persist-01 support is experimental.

    use std::fmt::Write;
    use std::slice::Iter;
    use std::str::{self, FromStr};

    use serde::de;
    use serde::{Deserialize, Deserializer};

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant};
    use crate::types::{Error, Identifier};

    /// Challenge state for a dns-persist-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    #[non_exhaustive]
    pub struct Challenge {
        /// The list of issuer domain names accepted by the CA
        pub issuer_domain_names: IssuerDomainNames,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::DnsPersist01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-00#name-acme-validation-methods-reg
            matches!(identifier, Identifier::Dns(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The issuer domain names accepted by the CA
        pub fn issuer_domain_names(&self) -> &IssuerDomainNames {
            &self.challenge.issuer_domain_names
        }

        /// Create a builder for the DNS TXT record response
        ///
        /// The issuer must be one of [`Self::issuer_domain_names()`]. The account URI
        /// and DNS name come from the current order, and wildcard policy is enabled
        /// automatically for a wildcard authorization.
        ///
        /// Returns an error if `issuer` was not offered by the ACME server or the
        /// account URI cannot be embedded in the response RDATA.
        pub fn response_txt_record<'a>(
            &'a self,
            issuer: &'a IssuerDomainName,
        ) -> Result<RecordBuilder<'a>, Error> {
            if !self.challenge.issuer_domain_names.as_ref().contains(issuer) {
                return Err(Error::InvalidIssuerDomains(format!(
                    "issuer '{}' is not in the challenge's issuer domain names",
                    issuer.as_ref()
                )));
            }

            let Identifier::Dns(dns_name) = self.state.identifier.identifier else {
                unreachable!("dns-persist-01 only supports DNS identifiers");
            };
            let builder = RecordBuilder::new(&self.state.account.id, dns_name, issuer)?;

            Ok(if self.state.identifier.wildcard {
                builder.wildcard()
            } else {
                builder
            })
        }
    }

    /// Builder for a dns-persist-01 TXT record response
    ///
    /// Create this directly with [`Self::new()`], or from a challenge handle with
    /// [`Handle::response_txt_record()`]. Direct construction allows a persistent
    /// validation record to be provisioned before creating an order, when the account
    /// URI, identifier, and issuer are already known.
    #[must_use = "call build() to obtain the DNS TXT record response"]
    #[derive(Debug)]
    pub struct RecordBuilder<'a> {
        account_uri: &'a str,
        dns_name: &'a str,
        issuer: &'a IssuerDomainName,
        persist_until: Option<u64>,
        wildcard: bool,
    }

    impl<'a> RecordBuilder<'a> {
        /// Create a builder for a dns-persist-01 TXT record response
        ///
        /// `account_uri` is the ACME account URL, `dns_name` is the identifier without
        /// a wildcard prefix, and `issuer` is the selected issuer domain name.
        ///
        /// Returns an error if `account_uri` is empty or contains characters that
        /// cannot be embedded in the response RDATA, or if `dns_name` is empty.
        pub fn new(
            account_uri: &'a str,
            dns_name: &'a str,
            issuer: &'a IssuerDomainName,
        ) -> Result<Self, Error> {
            if account_uri.is_empty() {
                return Err(Error::Str("account URI must not be empty"));
            }
            // RFC 8659 section 4 permits printable ASCII other than `;` in CAA parameter values.
            // https://www.rfc-editor.org/rfc/rfc8659#section-4
            if !account_uri
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b';')
            {
                return Err(Error::Str(
                    "account URI contains characters that cannot be embedded in CAA RDATA",
                ));
            }
            if dns_name.is_empty() {
                return Err(Error::Str("DNS name must not be empty"));
            }

            Ok(Self {
                account_uri,
                dns_name,
                issuer,
                persist_until: None,
                wildcard: false,
            })
        }

        /// Set the `persistUntil` UNIX timestamp
        ///
        /// See <https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-00#section-7.9>.
        pub fn persist_until(mut self, timestamp: u64) -> Self {
            self.persist_until = Some(timestamp);
            self
        }

        /// Enable the `policy=wildcard` parameter
        ///
        /// Builders created from a [`Handle`] for wildcard identifiers enable this
        /// automatically.
        pub fn wildcard(mut self) -> Self {
            self.wildcard = true;
            self
        }

        /// Build the DNS TXT record response
        pub fn build(self) -> Response {
            const ACCOUNT_URI_SEPARATOR: &str = "; accounturi=";
            const WILDCARD_POLICY: &str = "; policy=wildcard";
            const PERSIST_UNTIL_SEPARATOR: &str = "; persistUntil=";

            let mut capacity =
                self.issuer.as_ref().len() + ACCOUNT_URI_SEPARATOR.len() + self.account_uri.len();
            if self.wildcard {
                capacity += WILDCARD_POLICY.len();
            }
            if self.persist_until.is_some() {
                capacity += PERSIST_UNTIL_SEPARATOR.len() + 20;
            }

            let mut rdata = String::with_capacity(capacity);
            rdata.push_str(self.issuer.as_ref());
            rdata.push_str(ACCOUNT_URI_SEPARATOR);
            rdata.push_str(self.account_uri);
            if self.wildcard {
                rdata.push_str(WILDCARD_POLICY);
            }
            if let Some(timestamp) = self.persist_until {
                write!(&mut rdata, "{PERSIST_UNTIL_SEPARATOR}{timestamp}")
                    .expect("writing to a String cannot fail");
            }

            Response {
                hostname: format!("_validation-persist.{}", self.dns_name),
                rdata,
            }
        }
    }

    /// DNS TXT record response for dns-persist-01 validation
    ///
    /// The complete logical RDATA is stored once. Use [`Self::rdata_chunks()`] when
    /// an interface requires RFC 1035 character-strings.
    #[must_use = "the response must be provisioned before marking the challenge ready"]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response {
        hostname: String,
        rdata: String,
    }

    impl Response {
        const MAX_CHAR_STRING_LEN: usize = 255;

        /// Fully qualified hostname for the TXT record to provision
        pub fn hostname(&self) -> &str {
            &self.hostname
        }

        /// Complete logical TXT record RDATA
        ///
        /// Use this with DNS APIs that accept a complete logical TXT value and split it into
        /// RFC 1035 character-strings themselves. For APIs requiring pre-split
        /// character-strings, use [`Self::rdata_chunks()`].
        pub fn rdata(&self) -> &str {
            &self.rdata
        }

        /// RDATA split lazily into RFC 1035 character-strings of at most 255 octets
        pub fn rdata_chunks(&self) -> impl ExactSizeIterator<Item = &str> {
            self.rdata
                .as_bytes()
                .chunks(Self::MAX_CHAR_STRING_LEN)
                .map(|chunk| {
                    str::from_utf8(chunk).expect("dns-persist-01 RDATA is validated as ASCII")
                })
        }
    }

    /// Issuer names for a dns-persist-01 challenge
    ///
    /// Contains between one and ten normalized issuer domain names.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct IssuerDomainNames(Vec<IssuerDomainName>);

    impl IssuerDomainNames {
        /// Maximum issuer domain names a server may send
        pub const MAX_COUNT: usize = 10;

        /// Create a non-empty, bounded issuer domain name collection
        ///
        /// Returns an error if `names` is empty or contains more than
        /// [`Self::MAX_COUNT`] elements.
        pub fn new(names: Vec<IssuerDomainName>) -> Result<Self, Error> {
            if names.is_empty() {
                return Err(Error::InvalidIssuerDomains(
                    "no issuer domains provided".to_owned(),
                ));
            }
            if names.len() > Self::MAX_COUNT {
                return Err(Error::InvalidIssuerDomains(format!(
                    "too many issuer domains provided: {sent} > {max}",
                    sent = names.len(),
                    max = Self::MAX_COUNT
                )));
            }
            Ok(Self(names))
        }

        /// The first issuer domain name
        ///
        /// This collection is guaranteed to be non-empty.
        pub fn first(&self) -> &IssuerDomainName {
            &self.0[0]
        }

        /// The number of issuer domain names
        #[allow(clippy::len_without_is_empty)] // The type guarantees it is non-empty.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Iterate over the issuer domain names
        pub fn iter(&self) -> impl Iterator<Item = &IssuerDomainName> {
            self.0.iter()
        }
    }

    impl AsRef<[IssuerDomainName]> for IssuerDomainNames {
        fn as_ref(&self) -> &[IssuerDomainName] {
            &self.0
        }
    }

    impl<'a> IntoIterator for &'a IssuerDomainNames {
        type Item = &'a IssuerDomainName;
        type IntoIter = Iter<'a, IssuerDomainName>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.iter()
        }
    }

    impl<'de> Deserialize<'de> for IssuerDomainNames {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            // This temporarily allocates entries beyond MAX_COUNT before rejecting them. A
            // custom SeqAccess visitor could cap that allocation, but ACME servers are trusted
            // inputs and the extra generic machinery is not justified for this small limit.
            Self::new(Vec::<IssuerDomainName>::deserialize(deserializer)?)
                .map_err(de::Error::custom)
        }
    }

    /// A normalized issuer name for a dns-persist-01 challenge
    ///
    /// Issuer names use lowercase A-label form, are at most 253 octets, and do
    /// not have a trailing dot.
    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct IssuerDomainName(String);

    impl IssuerDomainName {
        /// Maximum length of an issuer domain name
        pub const MAX_LEN: usize = 253;

        /// Create a normalized issuer domain name
        ///
        /// Returns an error if `value` is not a lowercase A-label form domain name,
        /// exceeds [`Self::MAX_LEN`], or has a trailing dot.
        pub fn new(value: &str) -> Result<Self, Error> {
            Self::validate(value)?;
            Ok(Self(value.to_owned()))
        }

        fn from_string(value: String) -> Result<Self, Error> {
            Self::validate(&value)?;
            Ok(Self(value))
        }

        fn validate(value: &str) -> Result<(), Error> {
            if value.is_empty() {
                return Err(Error::InvalidIssuerDomains(
                    "issuer name was empty".to_owned(),
                ));
            }
            if value.len() > Self::MAX_LEN {
                return Err(Error::InvalidIssuerDomains(format!(
                    "issuer name was too long: {len} > {max}",
                    len = value.len(),
                    max = Self::MAX_LEN
                )));
            }
            if !value.is_ascii() {
                return Err(Error::InvalidIssuerDomains(
                    "issuer name was not in A-label form".to_owned(),
                ));
            }
            if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
                return Err(Error::InvalidIssuerDomains(
                    "issuer name was not all lowercase".to_owned(),
                ));
            }
            if value.ends_with('.') {
                return Err(Error::InvalidIssuerDomains(
                    "issuer name had a trailing dot".to_owned(),
                ));
            }

            for label in value.split('.') {
                if label.is_empty() {
                    return Err(Error::InvalidIssuerDomains(
                        "issuer name contained an empty label".to_owned(),
                    ));
                }
                if label.len() > 63 {
                    return Err(Error::InvalidIssuerDomains(
                        "issuer name contained a label longer than 63 octets".to_owned(),
                    ));
                }

                if !Self::is_valid_label(label) {
                    return Err(Error::InvalidIssuerDomains(
                        "issuer name contained an invalid label".to_owned(),
                    ));
                }
            }

            Ok(())
        }

        fn is_valid_label(label: &str) -> bool {
            fn is_letter_or_digit(byte: &u8) -> bool {
                byte.is_ascii_lowercase() || byte.is_ascii_digit()
            }

            let bytes = label.as_bytes();
            bytes.first().is_some_and(is_letter_or_digit)
                && bytes.last().is_some_and(is_letter_or_digit)
                && bytes
                    .iter()
                    .all(|byte| is_letter_or_digit(byte) || *byte == b'-')
        }
    }

    impl AsRef<str> for IssuerDomainName {
        fn as_ref(&self) -> &str {
            &self.0
        }
    }

    impl FromStr for IssuerDomainName {
        type Err = Error;

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            Self::new(value)
        }
    }

    impl TryFrom<String> for IssuerDomainName {
        type Error = Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            Self::from_string(value)
        }
    }

    impl<'de> Deserialize<'de> for IssuerDomainName {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Self::from_string(String::deserialize(deserializer)?).map_err(de::Error::custom)
        }
    }

    /// A handle for interacting with a dns-persist-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod tls_alpn01 {
    //! Support for RFC 8737 tls-alpn-01 challenges
    //!
    //! See <https://www.rfc-editor.org/rfc/rfc8737#section-3>

    use serde::Deserialize;

    use super::{ChallengeHandle, ChallengeState, ChallengeVariant, KeyAuthorization};
    use crate::types::{Error, Identifier};

    /// Challenge state for a tls-alpn-01 challenge
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {
        /// A token for constructing a key authorization to complete this challenge
        pub token: String,
    }

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::TlsAlpn01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://www.rfc-editor.org/info/rfc8737/#section-6.3
            // https://www.rfc-editor.org/info/rfc8738/#section-8.2
            matches!(identifier, Identifier::Dns(_) | Identifier::Ip(_))
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready to be completed
        pub async fn set_ready(&mut self) -> Result<(), Error> {
            self.state.set_ready().await
        }

        /// The token for this challenge
        pub fn token(&self) -> &str {
            &self.challenge.token
        }

        /// Create a [`Response`] for this challenge
        pub fn response(&self) -> Response {
            Response::new(&self.challenge.token, &self.state.account.key)
        }
    }

    /// Challenge response data for a tls-alpn-01 challenge
    #[must_use = "the response data must be provisioned before marking the challenge ready"]
    #[derive(Debug)]
    pub struct Response {
        key_authorization: KeyAuthorization,
    }

    impl Response {
        fn new(token: &str, key: &super::Key) -> Self {
            Self {
                key_authorization: KeyAuthorization::new(token, key),
            }
        }

        /// The unhashed key authorization string
        ///
        /// Typically, you would prefer using [`Self::extension_value`] to construct
        /// a DER encoded id-pe-acmeIdentifier extension.
        ///
        /// This API may be useful when using a higher-level TLS-ALPN-01 certificate generation
        /// API that expects the RFC-8555 §8.1 key authorization string as input.
        pub fn key_authorization(&self) -> &str {
            &self.key_authorization.value
        }

        /// The SHA-256 digest of the RFC-8555 §8.1 key authorization string
        ///
        /// This can be used to construct a DER encoded id-pe-acmeIdentifier extension
        /// for embedding in a provisioned TLS-ALPN-01 challenge response certificate.
        pub fn extension_value(&self) -> &[u8; 32] {
            &self.key_authorization.digest
        }
    }

    /// A handle for interacting with a tls-alpn-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

pub mod device_attest01 {
    //! Support for draft-ietf-acme-device-attest device-attest-01 challenges
    //!
    //! See <https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/>
    //!
    //! Note: device attestation support is experimental.

    use std::borrow::Cow;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    use super::{
        ChallengeHandle, ChallengeState, ChallengeStatus, ChallengeVariant, DeviceAttestation,
    };
    use crate::types::{Error, Identifier};

    /// Challenge state for a device-attest-01 challenge
    ///
    /// device-attest-01 challenges carry no additional type specific state.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
    #[non_exhaustive]
    pub struct Challenge {}

    impl ChallengeVariant for Challenge {
        fn from_state(state: &ChallengeState) -> Option<&Self> {
            match state {
                ChallengeState::DeviceAttest01(data) => Some(data),
                _ => None,
            }
        }

        fn supports_identifier(identifier: &Identifier) -> bool {
            // https://datatracker.ietf.org/doc/html/draft-acme-device-attest-08#section-7.2
            matches!(
                identifier,
                Identifier::PermanentIdentifier(_) | Identifier::HardwareModule(_)
            )
        }
    }

    impl ChallengeHandle<'_, Challenge> {
        /// Notify the server that the challenge is ready by sending a device attestation
        ///
        /// See <https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/> for details.
        ///
        /// `payload` is the device attestation object. Provide the attestation
        /// object as a raw blob; base64 encoding is done by this function.
        pub async fn send_attestation(
            &mut self,
            payload: &DeviceAttestation<'_>,
        ) -> Result<ChallengeStatus, Error> {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct DeviceAttestationBase64<'a> {
                att_obj: Cow<'a, str>,
            }

            let payload = DeviceAttestationBase64 {
                att_obj: Cow::Owned(BASE64_URL_SAFE_NO_PAD.encode(&payload.att_obj)),
            };

            self.state.respond(&payload).await
        }
    }

    /// A handle for interacting with a device-attest-01 challenge
    pub type Handle<'a> = ChallengeHandle<'a, Challenge>;
}

/// Attestation payload used for device-attest-01
///
/// See <https://datatracker.ietf.org/doc/draft-acme-device-attest/> for details.
pub struct DeviceAttestation<'a> {
    /// CBOR encoded attestation payload
    pub att_obj: Cow<'a, [u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.4
    #[test]
    fn challenge() {
        const CHALLENGE: &str = r#"{
          "type": "dns-01",
          "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
          "status": "pending",
          "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        }"#;

        let obj = serde_json::from_str::<Challenge>(CHALLENGE).unwrap();
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);

        let ChallengeState::Dns01(chall_state) = obj.state else {
            panic!("wrong challenge state type");
        };
        assert_eq!(
            chall_state.token,
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
        );
    }

    #[test]
    fn valid_issuer_domains() {
        let names =
            dns_persist01::IssuerDomainNames::new(vec!["authority.example".parse().unwrap()])
                .unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names.first().as_ref(), "authority.example");

        let names = dns_persist01::IssuerDomainNames::new(
            (0..dns_persist01::IssuerDomainNames::MAX_COUNT)
                .map(|i| format!("ca{i}.example").parse().unwrap())
                .collect(),
        )
        .unwrap();
        assert_eq!(names.len(), dns_persist01::IssuerDomainNames::MAX_COUNT);

        let max_length = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(max_length.len(), dns_persist01::IssuerDomainName::MAX_LEN);
        assert!(dns_persist01::IssuerDomainName::new(&max_length).is_ok());
    }

    #[test]
    fn invalid_issuer_domains() {
        let error = dns_persist01::IssuerDomainNames::new(vec![]).unwrap_err();
        assert!(error.to_string().contains("no issuer domains"));

        let error = dns_persist01::IssuerDomainNames::new(
            (0..=dns_persist01::IssuerDomainNames::MAX_COUNT)
                .map(|i| format!("ca{i}.example").parse().unwrap())
                .collect(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("too many"));

        for invalid in [
            "",
            "Authority.example",
            "authority.example.",
            "authority..example",
            "-authority.example",
            "authority-.example",
            "authority_example",
            "authority example",
            "authority\n.example",
            "ca.example; policy=wildcard",
            "café.example",
        ] {
            assert!(
                dns_persist01::IssuerDomainName::new(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }

        let long_label = format!("{}.example", "a".repeat(64));
        assert!(dns_persist01::IssuerDomainName::new(&long_label).is_err());

        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert_eq!(too_long.len(), dns_persist01::IssuerDomainName::MAX_LEN + 1);
        assert!(dns_persist01::IssuerDomainName::new(&too_long).is_err());
    }

    #[test]
    fn issuer_domain_deserialization_enforces_limit() {
        let eleven_names = format!(
            "[{}]",
            (0..=dns_persist01::IssuerDomainNames::MAX_COUNT)
                .map(|i| format!(r#""ca{i}.example""#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let error =
            serde_json::from_str::<dns_persist01::IssuerDomainNames>(&eleven_names).unwrap_err();
        assert!(error.to_string().contains("too many"));
    }

    #[test]
    fn dns_persist_record_builder() {
        let issuer = dns_persist01::IssuerDomainName::new("authority.example").unwrap();
        let response = dns_persist01::RecordBuilder::new(
            "https://ca.example/acme/acct/123",
            "www.example.com",
            &issuer,
        )
        .unwrap()
        .wildcard()
        .persist_until(1_234_567_890)
        .build();

        assert_eq!(response.hostname(), "_validation-persist.www.example.com");
        assert_eq!(
            response.rdata(),
            "authority.example; accounturi=https://ca.example/acme/acct/123; policy=wildcard; persistUntil=1234567890"
        );
    }

    #[test]
    fn dns_persist_record_builder_rejects_injection() {
        let issuer = dns_persist01::IssuerDomainName::new("authority.example").unwrap();
        for account_uri in [
            "",
            "https://ca.example/acct/1; policy=wildcard",
            "https://ca.example/acct/1 extra",
            "https://ca.example/acct/1\n",
            "https://café.example/acct/1",
        ] {
            assert!(
                dns_persist01::RecordBuilder::new(account_uri, "example.com", &issuer).is_err(),
                "{account_uri:?} should be rejected"
            );
        }

        assert!(
            dns_persist01::RecordBuilder::new("https://ca.example/acct/1", "", &issuer).is_err()
        );
    }

    fn response_with_rdata_length(length: usize) -> dns_persist01::Response {
        const ACCOUNT_PREFIX: &str = "https://ca.example/acct/";
        const ACCOUNT_SEPARATOR: &str = "; accounturi=";

        let issuer = dns_persist01::IssuerDomainName::new("authority.example").unwrap();
        let fixed_length = issuer.as_ref().len() + ACCOUNT_SEPARATOR.len() + ACCOUNT_PREFIX.len();
        let account_uri = format!("{ACCOUNT_PREFIX}{}", "a".repeat(length - fixed_length));

        dns_persist01::RecordBuilder::new(&account_uri, "example.com", &issuer)
            .unwrap()
            .build()
    }

    #[test]
    fn dns_persist_rdata_chunk_boundaries() {
        for (length, expected_chunks) in [(255, 1), (256, 2)] {
            let response = response_with_rdata_length(length);
            assert_eq!(response.rdata().len(), length);
            assert_eq!(response.rdata_chunks().len(), expected_chunks);
            assert!(response.rdata_chunks().all(|chunk| chunk.len() <= 255));
            assert_eq!(
                response.rdata_chunks().collect::<String>(),
                response.rdata()
            );
        }
    }

    #[test]
    fn dns_persist_challenge_valid_deserialization() {
        // <https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-00#section-3.1>
        const CHALLENGE: &str = r#"{
              "type": "dns-persist-01",
              "url": "https://ca.example/acme/authz/1234/0",
              "status": "pending",
              "issuer-domain-names": ["authority.example", "ca.example.net"]
            }"#;

        let obj = serde_json::from_str::<Challenge>(CHALLENGE).unwrap();
        assert_eq!(obj.status, ChallengeStatus::Pending);
        assert_eq!(obj.url, "https://ca.example/acme/authz/1234/0");

        let ChallengeState::DnsPersist01(challenge) = &obj.state else {
            panic!("unexpected challenge state");
        };

        assert_eq!(challenge.issuer_domain_names.len(), 2);
        assert_eq!(
            challenge.issuer_domain_names.first().as_ref(),
            "authority.example"
        );
        assert_eq!(
            challenge.issuer_domain_names.as_ref()[1].as_ref(),
            "ca.example.net"
        );
    }

    #[test]
    fn dns_persist_challenge_invalid_deserialization() {
        const CHALLENGE: &str = r#"{
              "type": "dns-persist-01",
              "url": "https://ca.example/acme/authz/1234/0",
              "status": "pending",
              "issuer-domain-names": ["a.ex","b.ex","c.ex","d.ex","e.ex","f.ex","g.ex","h.ex","i.ex","j.ex","k.ex"]
            }"#;

        let error = serde_json::from_str::<Challenge>(CHALLENGE).unwrap_err();
        assert!(error.to_string().contains("too many"));
    }
}
