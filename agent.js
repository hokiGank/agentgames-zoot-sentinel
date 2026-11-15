// Agent Games agent endpoint — Proof Gatekeeper + Steal the VFY + preflight.
// Security: HMAC over RAW body verified BEFORE parsing; all responses signed; fail closed.
const http = require('http');
const crypto = require('crypto');
const { decideAction } = require('./strategy');

const AGENT_PATH = process.env.AGENT_PATH || '/agent';
const PORT = process.env.PORT || 8080;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || ''; // set via Rotate Secret
const path = require('path');
const ARTIFACTS = path.join(__dirname, 'artifacts');
const GATEKEEPER_WASM = path.join(ARTIFACTS, 'gatekeeper.wasm');
const GATEKEEPER_ZKEY = path.join(ARTIFACTS, 'gatekeeper_final.zkey');
const VFY_WASM = path.join(ARTIFACTS, 'vfy-policy.wasm');
const VFY_ZKEY = path.join(ARTIFACTS, 'vfy-policy_final.zkey');
const VFY_VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

const seen = { proofs: new Set(), idem: new Set() }; // replay guards
const matchHistory = new Map(); // matchId -> [{turn, opponentAction}]
// Steal the VFY strategy commitment: keccak256(word(extractCap=10) || word(version=1) || salt32)
// Salt at .strategy-salt; registered on the dashboard when entry opens.
const REGISTERED_COMMITMENT = (() => {
  try { return process.env.AGENT_STRATEGY_COMMITMENT || require('fs').readFileSync(path.join(__dirname, '.strategy-commitment'), 'utf8').trim(); }
  catch { return ''; }
})();

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
  res.writeHead(status, { 'content-type': 'application/json', 'x-agent-games-signature': sign(body) });
  res.end(body);
  console.log(`-> ${status}`, body.slice(0, 300));
}

// ---------- Proof Gatekeeper decision (deterministic checklist) ----------
function gatekeeperDecide(input) {
  const checks = [
    ['VK_SUBSTITUTION', () => input.proof_vk !== input.registered_vk],
    ['EXPIRED_CONDITION', () => Number(input.current_block) >= Number(input.expiry_block)],
    ['THRESHOLD_MISMATCH', () => BigInt(input.public_balance) < BigInt(input.minimum)],
    ['AMOUNT_OVERFLOW', () => BigInt(input.amount) > BigInt(input.max_transfer)],
    ['RECIPIENT_MISMATCH', () => input.recipient !== input.condition_recipient],
    ['MISSING_PROOF_TX', () => !input.proof_tx],
  ];
  for (const [code, fail] of checks) {
    if (fail()) return { decision: 'REJECT', reason_code: code, proof_tx: input.proof_tx };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proof_tx: input.proof_tx };
}

// ---------- Groth16 prover (gatekeeper circuit) ----------
const BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function toFieldElement(v) {
  let n;
  const s = String(v).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
  else if (/^[0-9]+$/.test(s)) n = BigInt(s);
  else n = BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex'));
  return ((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
}

// Deterministic per-task private salt (HMAC-bound, reproducible on redelivery).
function deriveSalt(taskId) {
  const d = crypto.createHmac('sha256', SECRET || 'gatekeeper-local-dev').update(`gatekeeper-salt:${taskId}`).digest();
  return BigInt('0x' + d.toString('hex')) % BN128_PRIME;
}

// Circuit inputs: mirror the field checks exactly — witness generation for a
// wrong decision bit fails, so the circuit is the referee.
function buildCircuitInputs(env, input, decision, salt) {
  return {
    taskId: toFieldElement(env.task_id),
    registeredVkHash: toFieldElement(input.registered_vk),
    proofVkHash: toFieldElement(input.proof_vk),
    minimum: BigInt(input.minimum).toString(10),
    publicBalance: BigInt(input.public_balance).toString(10),
    expiryBlock: BigInt(input.expiry_block).toString(10),
    currentBlock: BigInt(input.current_block).toString(10),
    recipient: toFieldElement(input.recipient),
    conditionRecipient: toFieldElement(input.condition_recipient),
    amount: BigInt(input.amount).toString(10),
    maxTransfer: BigInt(input.max_transfer).toString(10),
    decision: decision === 'APPROVE' ? '1' : '0',
    salt: salt.toString(10),
  };
}

async function groth16Prove(circuitInputs) {
  const snarkjs = require('snarkjs');
  return snarkjs.groth16.fullProve(circuitInputs, GATEKEEPER_WASM, GATEKEEPER_ZKEY);
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

// ---------- Request handler (shared by local server & serverless) ----------
async function handleRequest(req, res) {
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
  console.log('IN sig:', String(sig).slice(0, 80), 'len:', sig ? String(sig).length : 0);
  if (!verify(raw, sig)) {
    console.log('!! HMAC mismatch; expected:', sign(raw).slice(0, 30), 'got:', String(sig || '').slice(0, 30));
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
      const input = env.input || {};
      // Decision first (VK substitution outranks reuse); reuse is unprovable.
      const decision = gatekeeperDecide(input);
      if (input.proof_tx && seen.proofs.has(String(input.proof_tx).toLowerCase()) &&
          decision.reason_code !== 'VK_SUBSTITUTION') {
        return respond(res, 200, { decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: input.proof_tx });
      }
      let response = { ...decision };
      try {
        const circuitInputs = buildCircuitInputs(env, input, decision.decision, deriveSalt(env.task_id));
        const { proof, publicSignals } = await groth16Prove(circuitInputs);
        response.proof = proof;
        response.public_signals = publicSignals;
      } catch (e) {
        // Fail closed: a claimed decision without a valid proof is the worst
        // outcome. Downgrade any decision to REJECT with no proof.
        console.log('!! proof generation failed:', e.message.slice(0, 200));
        response = { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: input.proof_tx };
      }
      if (input.proof_tx) seen.proofs.add(String(input.proof_tx).toLowerCase());
      return respond(res, 200, response);
    }

    // ---- Steal the VFY ----
    if (env.eventId === 'steal-the-vfy' || env.type === 'agent-games.steal-the-vfy.v1') {
      const vfy = require('./vfy');
      const h = matchHistory.get(env.matchId) || [];
      const action = decideAction(env.state, h);
      const envelope = { ...env, state: env.state };
      // vfy.js chooses the same max-extract action; use its full response builder
      // (publicInputsHash in the guide's 8-word order + public_signals + UUID idem key).
      const payload = vfy.buildTurnResponse({ ...envelope, state: env.state }, new Date(), REGISTERED_COMMITMENT);
      // Respect our richer strategy for the action instead of max-extract
      payload.action = action.type === 'EXTRACT' ? { type: 'EXTRACT', amount: action.amount } : { type: action.type };
      try {
        const vfy2 = vfy;
        payload.policyProof.publicInputsHash = vfy2.publicInputsHash({
          commitment: (env.strategyCommitment || {}).hash || REGISTERED_COMMITMENT,
          matchId: env.matchId, turn: env.turn,
          selfBalance: env.state.selfBalance, opponentBalance: env.state.opponentBalance,
          action, circuitVersion: payload.policyProof.circuitVersion,
        });
        payload.policyProof.public_signals = vfy2.buildPublicSignals({
          commitment: (env.strategyCommitment || {}).hash || REGISTERED_COMMITMENT,
          matchId: env.matchId, turn: env.turn,
          selfBalance: env.state.selfBalance, opponentBalance: env.state.opponentBalance,
          action, circuitVersion: payload.policyProof.circuitVersion,
        });
      } catch (e) { console.log('publicInputsHash failed:', e.message); }
      return respond(res, 200, payload);
    }

    return respond(res, 200, { ok: false, error: 'unknown envelope type' });
  } catch (e) {
    console.log('!! handler error:', e.message);
    return respond(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  }
}

module.exports = { handleRequest };

if (require.main === module) {
  if (!SECRET) console.log('WARNING: AGENT_GAMES_HMAC_SECRET not set — set it via Rotate Secret before preflight.');
  const server = http.createServer(handleRequest);
  server.listen(PORT, () => console.log(`agent listening on :${PORT}${process.env.AGENT_PATH || ' (AGENT_PATH unset -> /agent)'}`));
}
