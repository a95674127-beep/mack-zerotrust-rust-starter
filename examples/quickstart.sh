#!/usr/bin/env bash
# Quickstart demo for the MACK Zero-Trust Rust Starter Kit.
#
#   1) In another terminal:  cargo run
#   2) In this one:          bash examples/quickstart.sh
#
# Shows one allowed verification and two denials (too short, revoked),
# and how the audit chain grows with every call.
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"

verify() {
  curl -s -X POST "$BASE/v1/verify" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$1\"}"
  echo
}

echo "== Health =="
curl -s "$BASE/health"
echo
echo

echo "== A good token (the README sample) =="
verify "sample_local_token"
echo

echo "== Too short — denied by default =="
verify "abc"
echo

echo "== On the sample revocation list — denied =="
verify "revoked_demo_token_0001"
