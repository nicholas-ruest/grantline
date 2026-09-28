use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

const ROOT: &str = r#"{
  "schema_version": 1,
  "id": "root",
  "principal": "acme",
  "delegate": "buyer",
  "actions": ["quote"],
  "resources": ["catalog/*"],
  "models": ["model-a"],
  "counterparties": ["supplier/*"],
  "budget": {"spend_cents": 5000, "tool_calls": 10, "tokens": 10000},
  "valid_from": 100,
  "expires_at": 500,
  "remaining_delegations": 1,
  "approval_above_cents": 2000
}"#;

#[test]
fn cli_allows_valid_action() {
    let directory = tempdir().expect("temp dir");
    let mandate = directory.path().join("mandate.json");
    let request = directory.path().join("request.json");
    fs::write(&mandate, ROOT).expect("mandate");
    fs::write(
        &request,
        r#"{
          "action":"quote", "resource":"catalog/laptop", "model":"model-a",
          "counterparty":"supplier/one", "spend_cents":1000, "tool_calls":2,
          "tokens":1000, "timestamp":200
        }"#,
    )
    .expect("request");

    Command::cargo_bin("grantline")
        .expect("binary")
        .args([
            "authorize",
            mandate.to_str().unwrap(),
            request.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOW action"));
}

#[test]
fn cli_denies_out_of_scope_action_with_exit_two() {
    let directory = tempdir().expect("temp dir");
    let mandate = directory.path().join("mandate.json");
    let request = directory.path().join("request.json");
    fs::write(&mandate, ROOT).expect("mandate");
    fs::write(
        &request,
        r#"{
          "action":"purchase", "resource":"secrets/key", "model":"model-z",
          "counterparty":"unknown", "spend_cents":9000, "tool_calls":20,
          "tokens":20000, "timestamp":600
        }"#,
    )
    .expect("request");

    Command::cargo_bin("grantline")
        .expect("binary")
        .args([
            "authorize",
            mandate.to_str().unwrap(),
            request.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"allowed\": false"))
        .stdout(predicate::str::contains("spend_exceeded"));
}
