//! Runs the language-neutral conformance vectors in `spec/vectors/` as part of
//! `cargo test`, so the reference implementation can never drift from them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use std::path::PathBuf;

use interlingua::vectors::{self, Report};

fn file(name: &str) -> String {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "spec",
        "vectors",
        name,
    ]
    .iter()
    .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn assert_clean(name: &str, report: Report) {
    assert!(report.passed > 0, "{name}: no checks ran");
    assert!(
        report.is_ok(),
        "{name}: {} failure(s):\n{}",
        report.failures.len(),
        report.failures.join("\n")
    );
}

#[test]
fn cbor_vectors() {
    assert_clean("cbor.rsp", vectors::check_cbor(&file("cbor.rsp")).unwrap());
}

#[test]
fn label_vectors() {
    assert_clean(
        "label.rsp",
        vectors::check_label(&file("label.rsp")).unwrap(),
    );
}

#[test]
fn ccsds_vectors() {
    assert_clean(
        "ccsds.rsp",
        vectors::check_ccsds(&file("ccsds.rsp")).unwrap(),
    );
}

#[test]
fn envelope_vectors() {
    let report = vectors::check_envelope(
        &file("envelope.rsp"),
        &file("keyring.pub"),
        &file("test-secrets.txt"),
    )
    .unwrap();
    assert_clean("envelope.rsp", report);
}

#[test]
fn routing_vectors() {
    let report = vectors::check_routing(
        &file("routing.rsp"),
        &file("routing-policy.ndb"),
        &file("keyring.pub"),
    )
    .unwrap();
    assert_clean("routing.rsp", report);
}
