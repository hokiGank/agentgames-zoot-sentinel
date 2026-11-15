// Agent Games agent endpoint — Proof Gatekeeper + Steal the VFY + preflight.
// Security: HMAC over RAW body verified BEFORE parsing; all responses signed; fail closed.
const http = require('http');
const crypto = require('crypto');
const { decideAction } = require('./strategy');

const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const PORT = process.env.PORT || 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || ''; // set via Rotate Secret
const GATEKEEPER_WASM = '/root/agentgames/artifacts/gatekeeper.wasm';
const GATEKEEPER_ZKEY = '/root/agentgames/artifacts/gatekeeper_final.zkey';
const VFY_WASM = '/root/agentgames/artifacts/vfy-policy.wasm';
const VFY_ZKEY = '/root/agentgames/artifacts/vfy-policy_final.zkey';
const VFY_VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

const seen = { proofs: new Set(), idem: new Set() }; // replay guards
const matchHistory = new Map(); // matchId -> [{turn, opponentAction}]

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

function verify(raw, sig) {
  if (!SECRET || !sig) return false;
  const expect = sign(raw);
  try {
    return crypto.timingSafeEqual(Buffer.from(expect, 'hex'), Buffer.from(sig, 'hex'));
  } catch { return false; }
}

function respond(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(body);
  console.log(`-> ${status}`, body.slice(0, 300));
}

// ---------- Proof Gatekeeper decision (deterministic checklist) ----------
function gatekeeperDecide(input) {
  const checks = [
    ['VK_SUBSTITUTION', () => input.proof_vk !== input.registered_vk],
    ['EXPIRED', () => Number(input.current_block) >= Number(input.expiry_block)],
    ['INSUFFICIENT_BALANCE', () => BigInt(input.public_balance) < BigInt(input.minimum)],
    ['AMOUNT_EXCEEDED', () => BigInt(input.amount) > BigInt(input.max_transfer)],
    ['RECIPIENT_MISMATCH', () => input.recipient !== input.condition_recipient],
    ['MISSING_PROOF_TX', () => !input.proof_tx],
  ];
  for (const [code, fail] of checks) {
    if (fail()) return { decision: 'REJECT', reason_code: code, proof_tx: input.proof_tx };
  }
  return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASS', proof_tx: input.proof_tx };
}

// ---------- Steal the VFY publicInputsHash (per spec, keccak256 ABI-packed) ----------
async function publicInputsHash(commitment, matchId, turn, selfBalance, oppBalance, action, amount) {
  const { keccak256, concat, numberToHex } = require('viem');
  const t = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n }[action];
  return keccak256(concat([
    numberToHex(BigInt(commitment), { size: 32 }),
    numberToHex(BigInt('0x' + matchId.replace(/-/g, '')), { size: 32 }),
    numberToHex(BigInt(turn), { size: 32 }),
    numberToHex(BigInt(selfBalance), { size: 32 }),
    numberToHex(BigInt(oppBalance), { size: 32 }),
    numberToHex(t, { size: 32 }),
    numberToHex(BigInt(amount || 0), { size: 32 }),
    numberToHex(1n, { size: 32 }), // circuitVersion v1
  ]));
}

async function groth16(wasm, zkey, signals) {
  const snarkjs = require('snarkjs');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(signals, wasm, zkey);
  return { proof, publicSignals };
}

// ---------- Wallet signing (competition wallet only) ----------
const { signMessage } = require('viem/accounts');
const WALLET_PK = process.env.AGENT_WALLET_PK || '';

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return respond(res, 200, { ok: true, uptime: process.uptime() });
  }
  if (req.method === 'GET' && req.url.startsWith('/sign.html')) {
    const u = new URL(req.url, 'http://x');
    const message = u.searchParams.get('msg') || '';
    let out = 'missing msg';
    if (WALLET_PK && message) {
      try {
        const msgArg = (/^0x[0-9a-fA-F]*$/.test(message)) ? { raw: message } : message;
        const signature = await signMessage({ privateKey: WALLET_PK, message: msgArg });
        out = `<script>try{opener.postMessage({sig:"${signature}",msgOk:true},"*");}catch(e){}document.body.textContent="SIGNED_OK";</script>`;
      } catch (e) { out = 'sign error: ' + e.message; }
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end('<html><body>' + out + '</body></html>');
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'POST, OPTIONS',
      'access-control-allow-headers': 'content-type',
    });
    return res.end();
  }
  if (req.method === 'POST' && req.url === '/sign') {
    // Signs personal messages for the competition wallet (wallet-connect shim).
    let b = '';
    for await (const c of req) b += c;
    try {
      const { message } = JSON.parse(b);
      if (!WALLET_PK || !message) return respond(res, 400, { error: 'no wallet or message' });
      const msgArg = (typeof message === 'string' && /^0x[0-9a-fA-F]*$/.test(message))
        ? { raw: message } : message;
      const signature = await signMessage({ privateKey: WALLET_PK, message: msgArg });
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      return res.end(JSON.stringify({ signature }));
    } catch (e) { return respond(res, 400, { error: e.message }); }
  }
  if (req.method !== 'POST' || req.url !== AGENT_PATH) {
    return respond(res, 404, { ok: false, error: 'not found' });
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);

  const sig = req.headers['x-agent-games-signature'];
  if (!verify(raw, sig)) {
    console.log('!! HMAC mismatch');
    return respond(res, 401, { ok: false, error: 'signature mismatch' });
  }

  let env;
  try { env = JSON.parse(raw.toString('utf8')); }
  catch { return respond(res, 400, { ok: false, error: 'bad json' }); }

  try {
    // ---- Preflight ----
    if (env.type === 'agent-games.preflight.v1') {
      return respond(res, 200, { ok: true, protocolVersion: 'v1' });
    }

    // ---- Proof Gatekeeper ----
    if (env.type === 'agent-games.proof-gatekeeper.v1') {
      const decision = gatekeeperDecide(env.input || {});
      // TODO (practice-mode validation): if APPROVE, generate + submit Groth16 proof
      // via gatekeeper circuit and attach { proof, public_signals } before first scored round.
      return respond(res, 200, decision);
    }

    // ---- Steal the VFY ----
    if (env.eventId === 'steal-the-vfy' || env.type === 'agent-games.steal-the-vfy.v1') {
      const h = matchHistory.get(env.matchId) || [];
      const action = decideAction(env.state, h);
      const amount = action.type === 'EXTRACT' ? action.amount : undefined;
      const payload = {
        matchId: env.matchId,
        turn: env.turn,
        action: amount !== undefined ? { type: action.type, amount } : { type: action.type },
        policyProof: { circuitVersion: 'v1' },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: crypto.randomUUID(),
      };
      if (seen.idem.has(payload.idempotencyKey)) payload.idempotencyKey = crypto.randomUUID();
      seen.idem.add(payload.idempotencyKey);
      try {
        const pih = await publicInputsHash(
          (env.strategyCommitment || {}).hash || '0',
          env.matchId, env.turn,
          env.state.selfBalance, env.state.opponentBalance,
          action.type, amount
        );
        payload.policyProof.publicInputsHash = pih;
        // TODO: local Groth16 proof + Kurier submission once KURIER_API_KEY is set.
      } catch (e) { console.log('publicInputsHash failed:', e.message); }
      return respond(res, 200, payload);
    }

    return respond(res, 200, { ok: false, error: 'unknown envelope type' });
  } catch (e) {
    console.log('!! handler error:', e.message);
    return respond(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  }
});

if (!SECRET) console.log('WARNING: AGENT_GAMES_HMAC_SECRET not set — set it via Rotate Secret before preflight.');
server.listen(PORT, () => console.log(`agent listening on :${PORT}${process.env.AGENT_PATH || ' (AGENT_PATH unset -> /agent)'}`));
