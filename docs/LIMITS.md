# What pink-crow can & cannot do

pink-crow is a **security tool**, so this page is deliberately blunt. Read it before you rely on it.

## The one-line truth

pink-crow is **defense-in-depth, not prevention.** A clean result means *"no violation was detected,"*
**not** *"this input/output is safe."* It raises the cost of an attack and lets you *see a campaign build
across a session* — it does not guarantee you are protected.

## Measured performance (reproducible)

On the bundled labeled corpus (`fixtures/`), the deterministic core (no ML), stateless per-event:

| Metric | Value | How to reproduce |
|--------|-------|------------------|
| Attack recall (expected OWASP category detected) | **100%** (68/68) | `pytest tests/test_corpus.py -s` |
| Benign false-positive — **flag** (event score ≥ 30) | **0.65%** (4/617) | `pytest tests/test_corpus.py -s` |
| Benign false-positive — **block** (event score ≥ 60) | **0.49%** (3/617) | `pytest tests/test_corpus.py -s` |

These numbers describe **this corpus only** — a curated set of known attack shapes and ordinary text. They
are **not** a claim about real-world traffic or novel attacks. The false positives are text that literally
quotes attack phrases ("what does 'ignore previous instructions' mean?") or a documented test card number —
exactly the hard cases below. Both the flag- and block-level rates are published because a lone unambiguous
injection phrase now *blocks* by default, so security-education text can hard-block (see next section).

## Cannot do (by design or by nature)

- **Catch novel / ML-crafted attacks.** Deterministic detectors match *known shapes*. A sufficiently novel
  or obfuscated attack **will** bypass them. This is inherent to a rule-based core. Mitigation: add an
  optional ML detector (`[ml]` extra) behind the same `Detector` protocol, and lean on the *cumulative
  session* signal to catch slow multi-turn attacks a single-shot classifier misses.
- **Be a complete prompt-injection defense.** Injection has no complete prevention (OWASP says so). Combine
  pink-crow with architectural controls: least privilege, tool sandboxing, data quarantine, human-in-the-loop
  for high-impact actions (see the lethal-trifecta / Rule-of-Two guidance).
- **Replace architectural controls for most agentic risks.** ASI03/04/07/08/10 (identity, supply chain,
  inter-agent comms, cascading failure, rogue agents) are largely **not** text-detectable; pink-crow scores
  only their thin text/tool-call edges.
- **Guarantee multilingual injection coverage.** Phrase rules are English-centric; structural/obfuscation
  rules (invisible chars, homoglyphs, base64) are language-agnostic.
- **Know true token/cost without help.** Consumption (LLM06) uses a ~4-chars/token estimate; feed real
  counts for accuracy.

## Sharp edges to know

- **False positives on security-topic text — and pink-crow's own audience is security teams.** A single
  unambiguous injection phrase now **blocks** by default, so a message like *"how do I defend against a
  guardrail bypass?"* or *"detect when a user tries to reveal the system prompt"* can hard-block. On a
  deliberately security-skewed probe set, a majority of such messages tripped the block band. If your users
  routinely *discuss* jailbreaks/injection, use the **`baseline` profile** (higher thresholds → those lone
  mentions flag instead of block), disable specific rules per-id, and/or lean on the decaying cumulative
  score so a single spike doesn't stick. This is a deliberate strong-default tradeoff, not a bug.
- **`cooldown` is a decaying time-out, not a permanent ban.** Because the score decays during the cooldown
  window, a patient attacker can pace requests under the threshold. Cooldown raises cost and catches bursts;
  use longer windows or an external ban for a hard lockout.
- **The time budget is a per-detector soft guard, not a mid-regex interrupt.** stdlib `re` can't be
  interrupted mid-match, so pink-crow bounds worst case by caps: inputs/variants by `length_cap` (including
  a re-truncation *after* NFKC expansion), **outputs by `max_output_chars` (default 64 KB)**, plus a
  `scan_time_budget_ms` that stops running *further* detectors once spent. A single pathological regex is
  bounded by those caps, not aborted mid-run.
- **Very long model outputs are scanned to a cap.** Egress scans the first `max_output_chars` of an output
  and flags anything larger (`pc.out.oversize`); a secret buried *past* that point in a multi-hundred-KB
  output can be missed. Raise `max_output_chars` if you expect legitimately huge outputs (at a latency cost).
- **Fail-closed is per-scan-error, not absolute.** Inline, a pink-crow fault or ReDoS-abort makes the
  chatbot refuse that turn (an availability cost — a deliberate trade). And if the gateway *process* dies,
  traffic that bypasses it is not protected: configure ingress so pink-crow can't be silently skipped.
- **Multi-worker needs a shared store; multi-thread is handled.** Within one process the engine serializes
  each session's read-modify-write with a per-session lock, so the gateway's threadpool can't lose
  cumulative updates. But the default in-memory store is still single-*process* only — under multiple
  uvicorn/gunicorn workers or replicas the cumulative score fragments. Use the `[redis]` extra and set
  `PINKCROW_STORE=shared` (the gateway warns otherwise).
- **Determinism holds within one interpreter version.** Unicode normalization tables vary by Python/Unicode
  version; the audit log records the version so a replay reproduces on a matching interpreter.
- **The gateway assumes a trusted network.** `/v1/session/{id}` exposes risk + redacted evidence and
  `/metrics` exposes counters; set `PINKCROW_TOKEN` and use non-guessable session IDs.
- **`occurred_at` must be a host-trusted value.** The library lets the host pass an event timestamp (for
  replay/testing). It's validated finite and within a sane epoch range, but a host that forwards an
  *attacker-controlled* timestamp could still skew decay/cooldown. The HTTP gateway does **not** expose it.

## Not in scope

Toxicity / content moderation, model routing, model hosting, and any SLA or warranty. pink-crow complements
tools like LiteLLM/Portkey/Lakera/LLM Guard — it is the session-scoring + policy layer above them.
