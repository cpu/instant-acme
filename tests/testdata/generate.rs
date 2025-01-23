#!/usr/bin/env -S cargo -Z script
---cargo
[package]
edition = "2021"
[dependencies]
rcgen = { version = "0.13", features = ["pem"] }
---

use std::fs::OpenOptions;
use std::io::Write;
use std::env;

use rcgen::{DistinguishedName, KeyPair, DnType, IsCa, BasicConstraints};

fn main() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(
        DnType::CommonName,
        "Pebble CA".to_string(),
    );
    ca_params.distinguished_name = distinguished_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_cert_pem = ca_cert.pem();

    let ca_cert_file_path = env::current_dir().unwrap().join("tests/testdata/ca.pem");
    let mut ca_cert_file = OpenOptions::new().write(true).create(true).open(ca_cert_file_path).unwrap();
    ca_cert_file.write_all(ca_cert_pem.as_bytes()).unwrap();

    let ee_key = KeyPair::generate().unwrap();
    let mut ee_params = rcgen::CertificateParams::new(["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    ee_params.distinguished_name = DistinguishedName::new();

    let ee_cert = ee_params.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let ee_cert_pem = ee_cert.pem();

    let ee_cert_file_path = env::current_dir().unwrap().join("tests/testdata/server.pem");
    let mut ee_cert_file = OpenOptions::new().write(true).create(true).open(ee_cert_file_path).unwrap();
    ee_cert_file.write_all(ee_cert_pem.as_bytes()).unwrap();

    let ee_key_file_path = env::current_dir().unwrap().join("tests/testdata/server.key");
    let mut ee_key_file = OpenOptions::new().write(true).create(true).open(ee_key_file_path).unwrap();
    ee_key_file.write_all(ee_key.serialize_pem().as_bytes()).unwrap();
}