//! MACK Zero-Trust Rust Starter Kit — Community Edition core.
//!
//! A small, honest, local-first verification node:
//! - `POST /v1/verify` checks a token against a default-deny policy.
//! - Every verification is fingerprinted (SHA-256) — the raw token is
//!   never stored — and appended to a hash-chained audit log.
//! - `GET /health` reports liveness.
//!
//! Scope, stated plainly: this is a *starter*. The Community policy is a
//! structural/demo policy (shape, character set, and a sample revocation
//! list). It is not the full MACK vault; production policy engines,
//! persistence, and multi-tenant controls are Pro Kit territory.

pub mod audit;
pub mod policy;

use std::sync::{Arc, Mutex};

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use audit::AuditChain;
use policy::evaluate;

/// Lowercase hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone)]
pub struct AppState {
    pub chain: Arc<Mutex<AuditChain>>,
}

pub fn build_app() -> Router {
    let state = AppState {
        chain: Arc::new(Mutex::new(AuditChain::new())),
    };
    Router::new()
        .route("/health", get(health))
        .route("/v1/verify", post(verify))
        .with_state(state)
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub reason: String,
    pub fingerprint: String,
    pub audit_entries: u64,
    pub audit_tip: String,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "service": "mack-zerotrust-starter"}))
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    let fp = policy::fingerprint(&req.token);
    let verdict = evaluate(&req.token, &fp);
    let (count, tip) = {
        let mut chain = state.chain.lock().expect("audit chain lock poisoned");
        chain.append(&fp, verdict.allowed);
        (chain.len() as u64, chain.tip().to_string())
    };
    Json(VerifyResponse {
        verified: verdict.allowed,
        reason: verdict.reason.to_string(),
        fingerprint: fp,
        audit_entries: count,
        audit_tip: tip,
    })
}
