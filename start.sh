#!/bin/bash
cd /root/agentgames
export WALLET_PK="$(sed -n 's/^Private key: //p' /root/wallets/agentgames-evm.txt)"
export AGENT_WALLET_PK="$WALLET_PK"
export AGENT_GAMES_HMAC_SECRET="1bea7e6e358e2d9851d208cf60977ef14969d03092d8fd7237d3629eb2e13520"
exec node agent.js
