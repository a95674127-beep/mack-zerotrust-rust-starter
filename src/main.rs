//! MACK Zero-Trust Starter — local verification node.
//! Listens on http://127.0.0.1:8080 (local-first: loopback only).

use mack_zerotrust_rust_starter::build_app;

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind 127.0.0.1:8080");
    println!("MACK Zero-Trust Starter listening on http://127.0.0.1:8080");
    axum::serve(listener, build_app())
        .await
        .expect("server run");
}
