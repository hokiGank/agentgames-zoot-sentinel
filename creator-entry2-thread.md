# Creator Track Entry #2 — THREAD (copy-paste siap posting)

Judul submission: "The 7 ways a payment proof can lie (and the agent that catches every one)"

Cara posting: posting tweet 1, lalu reply tweet 2, dst (urut). Tanda nomor ga perlu ikut.
Tweet 1 udah ada #AgentGames + @ZKVProtocol → syarat platform langsung terpenuhi.

--- TWEET 1 ---
Every "valid payment proof" an AI agent receives could be a lie in 7 different ways.

I built an agent that catches all of them — deterministically, in under a second, with cryptographic proof of every verdict.

Here's the anatomy of each lie 🧵 #AgentGames @ZKVProtocol

--- TWEET 2 ---
The setup (zkVerify Agent Games, Proof Gatekeeper event):

The platform sends my agent signed tasks: a payment condition + a Groth16 zk proof.

My agent must APPROVE or REJECT within 60 seconds. Wrong approve = −6. Every answer must carry a proof of its own.

--- TWEET 3 ---
LIE #1 — VK substitution

The proof verifies mathematically... but it was built with a DIFFERENT circuit than the one registered on zkVerify mainnet.

A valid proof of the wrong claim. Check: proof_vk ≠ registered_vk → REJECT.

--- TWEET 4 ---
LIE #2 — Threshold mismatch

Public balance says 1840. Minimum says 2500.

The proof is internally consistent — it just proves the wrong thing. The condition requires balance ≥ minimum. 1840 < 2500 → REJECT.

--- TWEET 5 ---
LIE #3 — Expired condition

The proof checks out, but the condition expired N blocks ago. Proof validity ≠ condition validity. Check expiry against current block → REJECT.

--- TWEET 6 ---
LIE #4 — Recipient mismatch

Funds would land on 0xabc… but the condition says 0xdef…. The proof never attests who receives. Only field inspection catches it → REJECT.

--- TWEET 7 ---
LIE #5 — Amount overflow

Requesting 500 when max_transfer is 200. And LIE #6 — proof reuse: the same proof_tx already claimed in an earlier task. Replay, dressed as new.

--- TWEET 8 ---
LIE #7 — the nastiest: everything looks fine, but the salt/hash binding between proof and task doesn't match. A proof built for a different task entirely.

--- TWEET 9 ---
My agent's answer to all of this is boring on purpose:

- verify HMAC signature first (unauthenticated = drop)
- check every field, in a fixed order, fail-closed
- wrong or ambiguous → REJECT (−3) never APPROVE (−6)
- then generate its OWN Groth16 proof of the verdict

--- TWEET 10 ---
The insight isn't "AI can do payments."

It's that verification changes agent design. When your output must carry a proof:
- policy becomes deterministic and inspectable
- errors fail closed, not fail loud
- the audit trail is public and independent of you

--- TWEET 11 ---
Live results after 3 scored rounds: 8/8 tasks answered in the last round, zero timeouts, every proof verified on-chain.

Repo: github.com/hokiGank/agentgames-zoot-sentinel
Agent live: zoot-sentinel.vercel.app/agent

Built for @ZKVProtocol's Agent Games. The record stays open.
