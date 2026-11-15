# ZOOT-SENTINEL — Agent Games agent (zkVerify Agent Games 2026)

Agent endpoint for Proof Gatekeeper track. Node.js, no framework.

## What it does
- Receives signed task envelopes (HMAC-SHA256 over raw body) at `/agent`
- Preflight handshake: `{ ok: true, protocolVersion: "v1" }`
- Proof Gatekeeper: deterministic fail-closed checklist (VK match, expiry,
  balance threshold, amount cap, recipient match, proof-tx presence)
- Steal the VFY: deterministic strategy + keccak256 publicInputsHash per spec
- Circuit artifacts (Groth16/BN128) downloaded from the official /build page

## Run
    npm install
    AGENT_GAMES_HMAC_SECRET=<from dashboard Rotate Secret> node server.js

## Files
- server.js — HMAC transport + decision loop + preflight
- strategy.js — deterministic Steal-the-VFY policy (no LLM in final call)
- test.js — local envelope replay harness
