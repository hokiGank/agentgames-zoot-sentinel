# ZOOT-SENTINEL — Creator Track thread draft (X, ~10 tweets)

**Hook / 1/10**

A wrong decision shouldn't just be a mistake your agent can hide.
In zkVerify's Agent Games, it's *mathematically impossible* to submit.

We built ZOOT-SENTINEL, a Proof Gatekeeper agent. Here's how a circuit becomes the referee 🧵

**2/10 — The game**

Every task = a signed payment request backed by a ZK proof. Your agent has 60 seconds to APPROVE or REJECT:
- Does the proof's VK match the registered one?
- Is the balance above the minimum?
- Is the condition expired?
- Does the recipient match? Is the amount under the cap?
- Has this proof been used before?

**3/10 — The trap**

Sounds easy — except the platform sends 7 varieties of traps: VK substitution, proof reuse, threshold mismatch, expired conditions, recipient swaps, amount overflow. Approve a trap: −6. Reject a valid request: −3. Wrong proof: −2.

**4/10 — The referee**

Here's the part we love: we can't just "decide". Every response must carry a Groth16 proof generated over the gatekeeper circuit. Inside the circuit, the decision bit must equal the AND of the five field checks.

If the fields describe a trap, witness generation for "APPROVE" *fails*. The math refuses to lie.

**5/10 — Fail-closed by design**

So our decision logic is ~40 lines of deterministic code — no LLM anywhere near the final call. And when proof generation fails, we don't ship a naked APPROVE (the worst outcome). We downgrade to REJECT. Fail closed, always.

**6/10 — Verification as public record**

The proof is verified against a registered verification key on zkVerify mainnet. Every decision becomes a permanent, public, on-chain audit trail. Agent reasoning is invisible; agent *proofs* are not.

**7/10 — The numbers**

Practice so far: 12/12 correct decisions, every proof VERIFIED on-chain, ~0.5–1.3s end-to-end (60s deadline). The proving itself is ~300ms with snarkjs — 647 witnesses, bn128.

**8/10 — The infra story (the unglamorous part)**

A public HTTPS endpoint that must never change mid-round. We went through three setups: a quick Cloudflare tunnel (URL changed on restart — dangerous), an is-a.dev subdomain (the registry rejects tunnel CNAMEs for first-timers), and finally Vercel serverless with the circuit artifacts shipped alongside the function.

**9/10 — What we learned**

The interesting insight isn't "AI agents can do finance". It's that *verification changes agent design*: when your output must carry a proof, you architect differently — deterministic policy, idempotency guards, replay sets, fail-closed error paths. Verification isn't a checkbox; it's the whole shape of the system.

**10/10 — Follow along**

Repo: github.com/hokiGank/agentgames-zoot-sentinel
Agent: ZOOT-SENTINEL, live at zoot-sentinel.vercel.app/agent
Rounds run daily through Nov 21. Scores and proofs land on-chain.

Built for @zkVerify's Agent Games. The record stays open.

---

## Alternatif hook (kalau mau lebih punchy):

"The circuit is the referee: if your agent's wrong, the math literally won't let you submit. Here's what building a zk-verified payment gatekeeper taught us about agent design 🧵"

## Catatan
- Post pakai akun X kamu; mention @zkVerify + tag #AgentGames kalau ada hashtag resmi
- Idealnya sertakan 1-2 screenshot: dashboard ACTIVE + practice result "PROOF VERIFIED" (sudah ada di browser)
- Bisa juga diubah jadi artikel dev.to/Mirror dengan konten sama
