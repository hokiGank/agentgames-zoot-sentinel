#!/bin/bash
cd /root/agentgames
export AGENT_WALLET_PK="$(sed -n 's/^Private key: //p' /root/wallets/agentgames-evm.txt)"
export AGENT_GAMES_HMAC_SECRET="${AGENT_GAMES_HMAC_SECRET:-dev-secret}"
exec node server.js
