// Public preflight smoke test against the tunnel URL.
const crypto = require('crypto');
const SECRET = '1bea7e6e358e2d9851d208cf60977ef14969d03092d8fd7237d3629eb2e13520';
const URL = process.argv[2] || 'http://localhost:8080/agent';
(async () => {
  const body = JSON.stringify({ type: 'agent-games.preflight.v1', agent_id: 'agt_selftest', nonce: 'self-' + Date.now() });
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  const r = await fetch(URL, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig }, body });
  console.log('preflight:', r.status, await r.text());
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
