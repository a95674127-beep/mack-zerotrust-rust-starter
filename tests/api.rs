//! End-to-end API tests: boot the real server on an ephemeral port and
//! speak raw HTTP to it — including the exact request from the README.

use std::io::{Read, Write};
use std::net::TcpStream;

use mack_zerotrust_rust_starter::build_app;

async fn spawn() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        axum::serve(listener, build_app()).await.expect("serve");
    });
    port
}

fn http(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    // Belt and braces: a wedged server must fail the test, never hang it.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set read timeout");
    stream.write_all(request.as_bytes()).expect("write");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read");
    buf
}

fn post_verify(port: u16, token: &str) -> String {
    let body = format!("{{\"token\": \"{token}\"}}");
    http(
        port,
        &format!(
            "POST /v1/verify HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ),
    )
}

// NOTE: multi_thread is required — the HTTP client below is a blocking
// std TcpStream; on a current-thread runtime it would starve the very
// server task it is talking to and deadlock the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_ok() {
    let port = spawn().await;
    let resp = http(
        port,
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.contains("200"), "response: {resp}");
    assert!(resp.contains("\"status\":\"ok\""), "response: {resp}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readme_sample_token_verifies() {
    let port = spawn().await;
    let resp = post_verify(port, "sample_local_token");
    assert!(resp.contains("\"verified\":true"), "response: {resp}");
    assert!(resp.contains("\"reason\":\"ok\""), "response: {resp}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_tokens_are_denied_by_default() {
    let port = spawn().await;
    let short = post_verify(port, "abc");
    assert!(short.contains("\"verified\":false"), "response: {short}");
    assert!(short.contains("token_too_short"), "response: {short}");
    let revoked = post_verify(port, "revoked_demo_token_0001");
    assert!(
        revoked.contains("\"verified\":false"),
        "response: {revoked}"
    );
    assert!(revoked.contains("token_revoked"), "response: {revoked}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_verification_extends_the_audit_chain() {
    let port = spawn().await;
    let first = post_verify(port, "sample_local_token");
    assert!(first.contains("\"audit_entries\":1"), "response: {first}");
    let second = post_verify(port, "another_sample_token");
    assert!(second.contains("\"audit_entries\":2"), "response: {second}");
}
