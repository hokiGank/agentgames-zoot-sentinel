// test-runner: starts nothing; run tests against a child agent server started with the secret from start.sh
import crypto from 'crypto';
import fs from 'fs';
import { spawn } from 'child_process';

const s = fs.readFileSync('/root/agentgames/start.sh', 'utf8');
const SECRET = /AGENT_GAMES_HMAC_SECRET="([^"]+)"/.exec(s)[1];
const PORT = 8083;

const server = spawn('node', ['/root/agentgames/agent.js'], {
  env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stdout.on('data', d => process.stdout.write('[srv] ' + d));
server.stderr.on('data', d => process.stdout.write('[err] ' + d));

const wait = ms => new Promise(r => setTimeout(r, ms));
await wait(2500);

async function post(obj) {
  const body = JSON.stringify(obj);
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  const r = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig },
    body,
  });
  return { status: r.status, body: await r.json() };
}

console.log('preflight:', JSON.stringify(await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: 'now', nonce: 'abc' })));

const env = { type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_a1b2c3d4-1234-4abc-8def-001122334455', mode: 'practice', issued_at: 'now', deadline_at: 'later',
  input: { registered_vk: '0x7d91', proof_vk: '0x7d91', minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000, recipient: '0xDe42...9f01', condition_recipient: '0xDe42...9f01', amount: '500', max_transfer: '1000', proof_tx: '0xa8...2c' } };
const t0 = Date.now();
const gk = await post(env);
console.log('gk clean:', gk.status, gk.body.decision, gk.body.reason_code, (Date.now() - t0) + 'ms');
console.log('public_signals[0] (taskId field):', gk.body.public_signals?.[0]);
const gk2 = await post({ ...env, input: { ...env.input, proof_vk: '0x13aa' } });
console.log('gk trap:', gk2.body.decision, gk2.body.reason_code);
const stv = await post({ protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition', matchId: '9f4e1b2a-0000-0000-0000-000000000000', turn: 3, issuedAt: 'now', deadlineAt: 'later', state: { selfBalance: '95', opponentBalance: '105' }, strategyCommitment: { hash: '0x7d91' }, resolverVersion: 'v1', nonce: '3c2f' });
console.log('stv:', JSON.stringify(stv.body).slice(0, 160));
server.kill();
process.exit(0);
