// Vercel serverless entry for the agent endpoint (/agent).
let handleRequest, loadError;
try {
  ({ handleRequest } = require('../agent'));
} catch (e) {
  loadError = e.stack || String(e);
}

module.exports = async (req, res) => {
  if (loadError) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    return res.end('MODULE LOAD ERROR:\n' + loadError);
  }
  try {
    return await handleRequest(req, res);
  } catch (e) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    return res.end('HANDLER ERROR:\n' + (e.stack || String(e)));
  }
};
