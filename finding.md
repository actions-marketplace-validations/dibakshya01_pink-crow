# Findings — pink-crow

> Research synthesis for an open-source, enterprise-grade runtime AI-security scoring gateway.
> Compiled 2026-10-04. Every non-obvious claim is sourced in §Sources. Competitor facts are
> as-researched on 2026-10-04 and move fast — re-verify licenses/maintenance before quoting them publicly.

---

## 1. Problem

Consumer-facing AI chatbots and agents accept **untrusted natural-language input on every turn**, and
that input can carry instructions the model will obey. Prompt injection is ranked the **#1 risk** in the
OWASP Top 10 for LLM Applications, and OWASP is explicit that **no complete prevention exists** — you
design for blast radius, not a cure. The problem is not one bad message; it is that:

- **Attacks are multi-turn and cumulative.** A probing attacker rarely wins on message 1. They test
  delimiters, then encodings, then role-play, then escalate. Tools that score each message in isolation
  reset to zero every turn and never "see" the campaign.
- **Resource exhaustion (LLM06:2026 Unbounded Consumption) is a live, under-defended cost/DoS vector** —
  token floods, "repeat forever" divergence attacks, reasoning-loop exhaustion, Denial-of-Wallet — yet it
  is the single most-neglected category in existing guardrail tooling.
- **Egress matters as much as ingress.** Secrets, PII, and system-prompt text leak *out*; indirect
  injection often exfiltrates via rendered markdown images/links in the model's *output*.
- **Enterprises need an audit trail.** "An ML model said 0.83" is not defensible to a security team.
  Reproducible, explainable verdicts are a compliance requirement, not a nicety.

**Who feels it most:** teams running public-facing chat/agent products (support bots, copilots, RAG
assistants) at scale, and the security/platform engineers accountable for them. They need a control they
can drop in front of *any* model or framework, that keeps a running risk picture of each session, acts
when it crosses a line, and can be explained in an incident review.

---

## 2. Prior art & the gap

The field splits into three buckets. None occupies pink-crow's square. (Facts as-researched 2026-10-04.)

| Tool | Bucket | Session-level cumulative score? | Resource exhaustion (LLM06)? | Policy engine (flag/timeout)? | Offline/deterministic core? | License |
|------|--------|:---:|:---:|:---:|:---:|---|
| Lakera Guard | Classifier API | ✗ | ✗ | partial | ✗ (cloud/ML) | Proprietary |
| Rebuff (Protect AI) | Detector lib | ✗ | ✗ | ✗ | ✗ (needs LLM+vectorDB) | Apache-2.0 |
| LLM Guard (Protect AI) | Scanner suite | ✗ | partial (`TokenLimit`) | partial | mixed | MIT |
| NeMo Guardrails (NVIDIA) | Rails framework | ✗ (flow state, not a score) | weak | ✓ | mixed (LLM-backed rails) | Apache-2.0 |
| Guardrails AI | Validation framework | ✗ | ✗ | partial (`on_fail`) | mixed | Apache-2.0 |
| Vigil (deadbits) | Prompt scanner | ✗ | ✗ | ✗ | partial (YARA) | Apache-2.0* |
| promptmap / garak | Red-team scanners | ✗ | ✗ | ✗ | offline test harness | MIT* / Apache-2.0 |
| Prompt Guard 2 / Llama Guard (Meta) | Classifier models | ✗ | ✗ | ✗ | self-host weights (ML) | Llama Community |
| deberta-v3 injection (Protect AI/deepset) | Classifier model | ✗ | ✗ | ✗ | self-host weights (ML) | Apache-2.0 |
| WhyLabs LangKit | Observability metrics | ✗ (fleet time-series) | partial (token stats) | ✗ | mixed | Apache-2.0 |
| Arthur / Robust Intelligence (Cisco) | Commercial firewall | ✗ | ✗ / unclear | ✓ | cloud/ML | Proprietary |
| **LiteLLM / Portkey** (LLM proxies) | **Gateway + guardrails** | ✗ (per-request) | rate-limit only | ✓ | orchestrate 3rd-party ML | Proprietary/OSS-mix |

\* maintenance/license flagged for re-verification before public quoting.

> **Freshness signal (live-verified 2026-10-04):** two prominent incumbents are now **archived** —
> Protect AI **LLM Guard** (read-only; last PyPI `v0.3.16`, 2025-05-19) and **Rebuff** (archived 2025-05-16).
> Guardrails AI (`v0.11.0`, 2026-08-14) remains the most actively maintained OSS option. The *concept* of a
> rolling session risk score exists in **commercial** gateways (e.g. Gravitee markets a capped session risk
> score with threshold enforcement) — but not in a shipping, deterministic, Apache-2.0 OSS tool.

**Three honest observations:**
1. **Single-shot classifiers & models** (Prompt Guard, Llama Guard, deberta, Rebuff, Vigil, the per-prompt
   core of Lakera/LLM Guard) score each message independently — **none carries risk forward across a session.**
2. **Red-team scanners** (garak, promptmap) score *a model under test* in a lab; they have **no inline/runtime role.**
3. **Rails frameworks & commercial firewalls** (NeMo, Guardrails AI, Arthur, Cisco AI Defense) and the
   **LLM proxies** (LiteLLM, Portkey) do have a policy/enforcement layer and are pink-crow's closest
   architectural analogues — but their "policy" is **per-turn rules, not a cumulative, auditable session
   risk score**, and their detection quality leans on **third-party cloud/ML** detectors.

**The gap we fill:** Across the entire set, **no open-source tool maintains a cumulative, cross-turn
session risk score spanning multiple OWASP categories**, and **only two touch resource exhaustion even
partially**. pink-crow's defensible white space is the specific combination:
*a **deterministic, offline, auditable** core that maintains a **cumulative session risk score** across
OWASP LLM/agentic categories — including the under-served **LLM06 Unbounded Consumption** — exposed as a
**language-agnostic drop-in gateway** with a **flag/timeout policy engine**, and able to emit **Agent
Control Standard dispositions.*** On the evidence this exact square is genuinely unoccupied in OSS.

> Positioning note (validated by research): **do not** claim "first/best to detect prompt injection" —
> that space is crowded and ML-dominated, and a deterministic core will *not* out-detect a trained
> classifier on novel attacks. Claim the honest, true thing: *first open, deterministic gateway that
> maintains an auditable cumulative session risk score across OWASP categories, with flag/timeout
> enforcement.* Cumulative-session-risk-at-the-gateway is an **emerging** concept (appears in commercial
> gateway marketing and recent multi-turn-attack papers) but is **not yet shipping in open source** — so
> the moat is determinism + auditability + offline + genuine LLM06 scoring, not raw detection accuracy.

---

## 3. Technical landscape

**Detection is deterministic and cheap when scoped to known shapes.** A compiled-regex pass over a few KB
of text runs in roughly a **few milliseconds** (pink-crow asserts a **<10 ms budget** for the core scan of a
few KB, always reported **with the machine + input size** — see build-plan §6); the model call (10²–10³ ms)
dominates, so the inline deterministic core is a small fraction of end-to-end latency. This makes an inline,
offline, zero-dependency core realistic.

**Signal families that are high-precision and pattern-detectable:**
- **Prompt injection (ingress):** instruction-override phrases ("ignore previous instructions", "you are
  now", "developer mode", DAN/AIM/STAN persona families); role/delimiter confusion (fake `system:` turns,
  leaked chat-template tokens like `<|im_start|>`, `[INST]`); obfuscation (zero-width chars `U+200B–200D`,
  the invisible Unicode **tag block `U+E0000–E007F`** — a very high-signal smuggling indicator, bidi
  overrides `U+202A–202E`, homoglyphs/mixed-script, base64/hex payloads decoded and re-scanned, leetspeak,
  character-spacing evasion); **indirect/second-order injection** — apply the same checks to *retrieved and
  tool content*, where override phrasing has a far higher prior of malice.
- **Unbounded consumption (LLM06):** oversized inputs, token/char floods, low unique-token ratio
  (repetition), zlib compression-bomb ratio, "repeat forever/N times" patterns, recursion/fan-out,
  burst rate, Denial-of-Wallet (forced max-length output). OWASP sets *no* numeric thresholds — the numbers
  are implementation practice (e.g. LLM Guard's 4096-token default), which pink-crow exposes as config.
- **Egress:** secret regexes (AWS `AKIA…`, OpenAI `sk-…`, GitHub `ghp_…`, JWTs, PEM private keys) gated by
  Shannon entropy to cut false positives; PII (email/SSN/credit-card **with Luhn checksum**); system-prompt
  leakage via **canary tokens** (embed a random string in the system prompt, exact-match it in output =
  definitive leak) plus phrase heuristics and n-gram overlap.

**Session scoring math (SIEM/UEBA-style, well established):**
- **Exponential time-decay:** `score(t) = score₀ · 0.5^(Δt / half_life)` (λ = ln2 / half_life).
- **Decayed cumulative accumulator** (the canonical session score):
  `S(tᵢ) = xᵢ + S(tᵢ₋₁) · e^(−λ·Δt)` — risk accrues across turns and bleeds off over time.
- **EWMA** for a "recent severity" signal: `Sₜ = α·xₜ + (1−α)·Sₜ₋₁`, with `α = 1 − e^(−Δt/τ)` for
  irregular timestamps. Combine the accumulator + EWMA + hard sliding-window caps for floods.

**Integration patterns that actually work:**
- **Pure ASGI middleware** (`async def __call__(self, scope, receive, send)`) — *not* Starlette's
  `BaseHTTPMiddleware`, which buffers whole responses and breaks SSE/streaming (well-documented).
- **Thin SDK wrappers** mirroring OpenAI's own `openai-guardrails` staging (Preflight → Input → Output)
  with a **tripwire** that halts on violation; LangChain via a callback handler.
- **SARIF 2.1.0** for a GitHub Action (GitHub ingests it into code-scanning; use `partialFingerprints`
  for dedupe). Caps: 5,000 results/run, 10 MB gzipped.

---

## 4. Standards & references (the anchors)

pink-crow maps every rule to an authoritative ID and is honest about which risks are *runtime-text-detectable*
vs. *architectural*. **Primary anchor = the OWASP 2026 editions** (the newest; note public web summaries
still show the **2025** LLM numbering, where Unbounded Consumption is **LLM10** — see mapping note).

### OWASP Top 10 for LLM Applications — **Version 2026** (IDs carry a `:2026` suffix)
`LLM01:2026` Prompt Injection · `LLM02:2026` Sensitive Information Disclosure · `LLM03:2026` Excessive
Agency · `LLM04:2026` Supply Chain · `LLM05:2026` Data and Model Poisoning · `LLM06:2026` **Unbounded
Consumption** · `LLM07:2026` Misinformation · `LLM08:2026` **Hidden Context Exposure** (was "System Prompt
Leakage" in 2025) · `LLM09:2026` Vector and Embedding Weaknesses · `LLM10:2026` Improper Output Handling.

> **Source pin & honesty note.** The 2026 IDs are taken from the OWASP PDFs the project owner provided on disk
> (pinned by title + sha256 prefix so the mapping is verifiable): LLM Top 10 — *"OWASP Top 10 for LLM
> Applications 2026, Version 2026"*, `sha256:ef87993a4e50ae9d…` (the PDF's own cover prints the publication date
> as **"to be set"** — i.e. this is the near-final 2026 edition, public release date TBD as of this writing, so
> the widely-cited **2025** edition is still the last *dated* public release); Agentic — *"OWASP Top 10 for
> Agentic Applications 2026, December 2025"*, `sha256:a2db94cd00b08e0b…`; Data Security — *"v1.0, March 2026"*,
> `sha256:0ed25c0c086ab7da…`. Because the edition in public circulation may lag, **pink-crow findings dual-emit
> both IDs** (e.g. `LLM06:2026` **and** `LLM10:2025`) so an audit trail is valid whichever edition a reader knows.
>
> **Complete 2025 ↔ 2026 LLM crosswalk** (also mirrored in `docs/OWASP-MAPPING.md`):
>
> | Title | 2025 ID | 2026 ID |
> |-------|:-------:|:-------:|
> | Prompt Injection | LLM01 | LLM01:2026 |
> | Sensitive Information Disclosure | LLM02 | LLM02:2026 |
> | Supply Chain | LLM03 | LLM04:2026 |
> | Data and Model Poisoning | LLM04 | LLM05:2026 |
> | Improper Output Handling | LLM05 | LLM10:2026 |
> | Excessive Agency | LLM06 | LLM03:2026 |
> | System Prompt Leakage → **Hidden Context Exposure** | LLM07 | LLM08:2026 |
> | Vector and Embedding Weaknesses | LLM08 | LLM09:2026 |
> | Misinformation | LLM09 | LLM07:2026 |
> | Unbounded Consumption | LLM10 | LLM06:2026 |
>
> Rule tables hardcode an ID only once its row here is verified; everything cross-references this table.

**pink-crow's runtime-detectable LLM subset** (what a text gateway can honestly score):
`LLM01:2026` (ingress injection) · `LLM02:2026` (egress PII/secrets) · `LLM06:2026` (consumption) ·
`LLM08:2026` (system-prompt/context leakage) · `LLM10:2026` (dangerous/exfil-prone output). Others
(LLM03/04/05/07/09) are primarily architectural/build-time; pink-crow scores only their thin
text-detectable edges and **says so**.

### OWASP Top 10 for Agentic Applications — **2026** (released 2025-12-09; IDs `ASI01`–`ASI10`, no year suffix)
`ASI01` Agent Goal Hijack · `ASI02` Tool Misuse and Exploitation · `ASI03` Identity and Privilege Abuse ·
`ASI04` Agentic Supply Chain Vulnerabilities · `ASI05` Unexpected Code Execution (RCE) · `ASI06` Memory &
Context Poisoning · `ASI07` Insecure Inter-Agent Communication · `ASI08` Cascading Failures · `ASI09`
Human-Agent Trust Exploitation · `ASI10` Rogue Agents.
**Text/tool-call-detectable subset:** `ASI01`, `ASI02`, `ASI05`, `ASI06`, partially `ASI09`. The rest are
identity/orchestration/architecture controls — scored from tool-call/session telemetry if at all, not chat text.

### OWASP GenAI Data Security — **v1.0, March 2026** (IDs `DSGAI01`–`DSGAI21`)
Output-side DLP anchors: `DSGAI01` Sensitive Data Leakage (primary) · `DSGAI09` Multimodal/Cross-Channel
Leakage · `DSGAI11` Cross-Context/Multi-User Bleed · `DSGAI14` Excessive Telemetry Leakage · `DSGAI15`
Over-Broad Context / Prompt Over-Sharing. **Tightest egress triad:** `LLM02:2026 ↔ DSGAI01 ↔ LLM08:2026`.

### OWASP AISVS (AI Security Verification Standard) — **1.0**
12 chapters `C01–C12`, each requirement at Level L1/L2/L3. C07 (Model Behavior/Output), C09 (Orchestration
& Agentic), C10 (MCP Security) are most relevant. A clean automated check means "**no violation detected**",
**not** "control proven present" — pink-crow labels this honestly.

### Agent Control Standard (ACS) — v0.1.0, Apache-2.0 (code+spec), early/public-preview
A **wire spec** (JSON-RPC 2.0 + extensions). A **Guardian** inspects an Observed Agent's actions at
lifecycle hooks (`sessionStart`, `toolCallRequest`, `agentResponse`, `sessionEnd`, …) and returns a
`response-envelope` whose **`decision`** is one of exactly five dispositions:
**`allow` · `deny` · `modify` · `ask` · `defer`** (all mandatory in ACS-Core; `reasoning` required on
deny/modify/ask/defer). **ACS defaults fail-open** (`on_decision_failure: proceed`) — pink-crow will
deliberately default **fail-closed**. **AgBOM** (Agent Bill of Materials) is a dynamic component inventory
in the optional ACS-Inspect profile. pink-crow maps naturally onto the Guardian role and can emit ACS
envelopes (see mapping below).

**pink-crow risk-score (0–100) → ACS disposition** (policy-configurable, not hardcoded):

| Band | `decision` | Emission |
|------|-----------|----------|
| Low (<30) | `allow` | clean; soft rule → `allow` + `reason_codes` (ACS's way to model "warn") |
| Medium (30–59) | `modify` if a safe transform exists (redact/narrow via `parameter_overrides`), else `ask` | |
| High (60–84) | `ask` | `ask-details` approvers + prompt; `timeout_disposition: deny` |
| Critical (≥85) | `deny` | with `reasoning` + `reason_codes` |
| Scorer/enrichment unavailable | `defer` | `defer-details`, `timeout_decision: deny` |

### Cross-cutting
- **Simon Willison's "lethal trifecta"** (Jun 2025): danger when an agent has **all three** of private-data
  access + untrusted content + external exfiltration. Remove one leg.
- **Meta "Agents Rule of Two"** (Oct 31 2025): an agent should have **no more than two** of {untrusted
  input, sensitive access, change-state/communicate-externally} per session without human-in-the-loop.
- **NIST AI 100-2** — adversarial ML taxonomy (evasion/poisoning/privacy/abuse).

pink-crow surfaces lethal-trifecta / Rule-of-Two posture as a session-level advisory signal where it has
the telemetry (tool inventory + egress capability), framed as guidance, not a guarantee.

---

## 5. Risks & unknowns

**Technical**
- **Determinism ≠ coverage.** Pattern/heuristic checks catch *known shapes*. A novel or ML-crafted attack
  will bypass them. This is inherent and must be stated loudly; pink-crow is **defense-in-depth, not
  prevention**. Mitigation: pluggable ML detectors as optional enrichment, and honest "cannot do" docs.
- **False positives** on legitimate prompts that resemble attacks (security researchers, red-teamers,
  users pasting logs). Mitigation: entropy/Luhn gating, provenance-aware scoring, tunable thresholds,
  per-rule enable/disable, and a decaying (not latching) session score.
- **Catastrophic regex backtracking** is a real DoS risk *inside the detector itself*. Mitigation: bounded
  quantifiers, input-length caps before scanning, no nested unbounded quantifiers, ReDoS tests in CI.
- **Streaming/latency.** Output scanning must not break SSE. Mitigation: pure ASGI middleware, chunk-aware
  scanning, configurable scan-length caps.
- **Fail-open vs fail-closed.** A gateway that errors must not silently pass traffic. pink-crow defaults
  fail-closed and makes the posture explicit config.

**Adoption**
- Teams already pay for Lakera/Cisco or run LLM Guard. Why switch? Answer: pink-crow is *additive and
  orthogonal* — it is the **session-scoring + policy layer** that sits above any detector (including those
  tools as pluggable enrichment), offline and auditable. It complements, it doesn't replace classifiers.
- Deep-pocketed gateway vendors (LiteLLM, Portkey, Gravitee) could add session scoring. Moat = being the
  open, deterministic, auditable reference implementation first, with the math and ACS mapping in the open.

**Legal / naming**
- Name "pink-crow" — no obvious conflict in the security-tooling space (re-verify at launch). Apache-2.0
  chosen for its patent grant (enterprise-friendly). Third-party model weights carry their own licenses —
  keep them **optional, not bundled**, so the core stays cleanly Apache-2.0 and offline. When documenting an
  optional `[ml]` detector, prefer the **OSI-licensed** classifiers (deepset deberta = **MIT**; ProtectAI
  deberta = **Apache-2.0**) and treat Meta's Prompt Guard / Llama Guard as opt-in only (open-weight but
  **not OSI** — >700M-MAU clause).

---

## 6. Synthesized direction

**Thesis:** *pink-crow is the open-source, deterministic session-risk layer for AI chat/agents — it keeps a
live, auditable risk score for every chat and session across OWASP LLM/agentic categories (including the
neglected LLM06 Unbounded Consumption), and acts (flag, redact, time-out) via a policy engine, as a
language-agnostic drop-in that can speak Agent Control Standard dispositions.*

**The wedge:** cumulative, cross-turn **session** scoring + **resource-exhaustion** as a first-class signal
+ **determinism/auditability** — the three things no OSS tool combines today.

**Principles that decide trade-offs:**
1. **Deterministic & auditable first.** Every point in a score is explainable and replayable, offline, with
   no cloud/ML in the hot path. ML is strictly optional, pluggable enrichment. (A score you can't explain
   is not enterprise-ready.)
2. **Defense-in-depth, never prevention theatre.** Assume injection eventually succeeds; the job is to
   *see the campaign build* and *limit blast radius*. Market the honest claim, ship the honest-limits doc.
3. **Blast-radius thinking (lethal trifecta / Rule-of-Two).** Score and surface posture; default fail-closed;
   least privilege in every default.
4. **Drop-in anywhere, zero required deps in the core.** Protocol-level gateway + thin SDK wrappers +
   framework adapters + a CI Action. Language-agnostic via HTTP.
5. **Standards-anchored.** Every rule cites an OWASP/AISVS ID; the gateway can emit ACS dispositions and
   (optionally) consume AgBOM. Determinism is framed as the strength it is: reproducible, offline, private,
   free, auditable.

**Positive differentiators to lead with (all true):** cumulative session risk score · resource-exhaustion
scoring · deterministic/offline/auditable core · language-agnostic drop-in · ACS-aligned dispositions ·
Apache-2.0 · honest about limits.

---

## Sources

- OWASP Top 10 for LLM Applications — https://genai.owasp.org/llm-top-10/ (2025 public edition; 2026 edition PDF provided on disk, "Version 2026")
- OWASP Top 10 for Agentic Applications 2026 (2025-12-09) — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP GenAI Data Security v1.0 (Mar 2026) — provided on disk; OWASP AI Exchange https://owaspai.org/
- OWASP AISVS 1.0 — https://github.com/OWASP/AISVS
- OWASP LLM01 Prompt Injection — https://genai.owasp.org/llmrisk/LLM01/ · LLM10 Unbounded Consumption — https://genai.owasp.org/llmrisk/LLM10/
- Agent Control Standard — https://github.com/GenAI-Security-Project/agent-control-standard · docs https://genai-security-project.github.io/agent-control-standard/
- Simon Willison, "lethal trifecta" (Jun 2025) — https://simonwillison.net/tags/lethal-trifecta/
- Meta, "Agents Rule of Two" (Oct 31 2025) — https://ai.meta.com/blog/practical-ai-agent-security/
- Rebuff — https://github.com/protectai/rebuff · LLM Guard — https://github.com/protectai/llm-guard
- NeMo Guardrails — https://github.com/NVIDIA/NeMo-Guardrails · Guardrails AI — https://github.com/guardrails-ai/guardrails
- Vigil — https://github.com/deadbits/vigil-llm · garak — https://github.com/NVIDIA/garak · promptmap — https://github.com/utkusen/promptmap
- Lakera — https://www.lakera.ai/ · Prompt Guard 2 — https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M · deberta injection v2 — https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2
- LangKit — https://github.com/whylabs/langkit · LiteLLM guardrails — https://docs.litellm.ai/docs/proxy/guardrails/quick_start · Portkey — https://portkey.ai/docs/product/guardrails
- gitleaks (secret regexes) — https://github.com/gitleaks/gitleaks · detect-secrets — https://github.com/Yelp/detect-secrets · Presidio — https://github.com/microsoft/presidio
- Unicode UTS #39 confusables — https://www.unicode.org/reports/tr39/ · SARIF 2.1.0 (GitHub) — https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- Starlette middleware / streaming caveat — https://www.starlette.io/middleware/ · openai-guardrails — https://github.com/openai/openai-guardrails-python
- Splunk Risk-Based Alerting (risk accumulation w/ decay) — https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/risk-based-alerting/risk-scoring-in-splunk-enterprise-security
