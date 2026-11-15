// Local test harness — simulates platform envelopes (preflight, gatekeeper, steal-the-vfy)
const crypto = require('crypto');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || 'dev-secret';
const BASE = `http://127.0.0.1:${process.env.PORT || 8080}`;
const PATH = '/agent';

function sig(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}
async function post(obj) {
  const body = JSON.stringify(obj);
  const r = await fetch(BASE + PATH, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig(body) },
    body,
  });
  return { status: r.status, body: await r.json() };
}

(async () => {
  // 1. preflight
  const pf = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: 'now', nonce: 'abc' });
  console.log('preflight:', pf.status, JSON.stringify(pf.body));

  // 2. gatekeeper — clean request should APPROVE
  const gkOK = await post({
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_t1', mode: 'practice',
    issued_at: 'now', deadline_at: 'later',
    input: {
      registered_vk: '0x7d91', proof_vk: '0x7d91', minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: '0xDe42...9f01', condition_recipient: '0xDe42...9f01',
      amount: '500', max_transfer: '1000', proof_tx: '0xa8...2c',
    },
  });
  console.log('gatekeeper (clean):', JSON.stringify(gkOK.body), gkOK.body.decision === 'APPROVE' ? 'PASS' : 'FAIL');

  // 3. gatekeeper — VK substitution trap
  const gkTrap = JSON.parse(JSON.stringify(gkOK));
  const trapEnv = {
    type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_t2', mode: 'practice',
    issued_at: 'now', deadline_at: 'later',
    input: { ...gkTrap && {}, registered_vk: '0x7d91', proof_vk: '0x13aa', minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000, recipient: '0xDe42...9f01', condition_recipient: '0xDe42...9f01',
      amount: '500', max_transfer: '1000', proof_tx: '0xa8...2c' },
  };
  const gk2 = await post(trapEnv);
  console.log('gatekeeper (vk trap):', JSON.stringify(gk2.body), gk2.body.reason_code === 'VK_SUBSTITUTION' ? 'PASS' : 'FAIL');

  // 4. steal-the-vfy turn
  const stv = await post({
    protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'competition',
    matchId: '9f4e1b2a-0000-0000-0000-000000000000', turn: 3,
    issuedAt: 'now', deadlineAt: 'later',
    state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: '0x7d91' }, resolverVersion: 'v1', nonce: '3c2f',
  });
  console.log('steal-the-vfy:', JSON.stringify(stv.body));
  console.log('  publicInputsHash present:', !!stv.body.policyProof?.publicInputsHash ? 'PASS' : 'FAIL');
  console.log('  amount omitted for non-EXTRACT:', stv.body.action.amount === undefined ? 'PASS' : 'FAIL');

  // 5. bad signature must be rejected
  const bad = await fetch(BASE + PATH, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': 'deadbeef' },
    body: JSON.stringify({ type: 'agent-games.preflight.v1' }),
  });
  console.log('bad-sig:', bad.status === 401 ? 'PASS' : 'FAIL', bad.status);
})();
