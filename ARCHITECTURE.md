# Architecture

pink-crow is a small, deterministic, stdlib-only core with thin surfaces around it. Data flows one way:
**text → detectors → findings (OWASP-mapped) → decayed session score → policy → disposition**, with an
injectable clock and an append-only audit log making every verdict reproducible.

```
                   ┌──────────────────────── pink-crow ────────────────────────┐
  chat input  ───▶ │  Engine.scan_input ─┐                                      │
 (user / RAG /     │                     ├─▶ Detectors ─▶ Findings (OWASP IDs)  │
  tool content)    │  Engine.scan_output─┘        │                             │
                   │                               ▼        ▲ injectable Clock   │
  model output ──▶ │                      Scoring (decayed accumulator +EWMA)   │
                   │                               │  SessionStore (TTL)         │
                   │                               ▼        ├─▶ Audit log        │
                   │                      PolicyEngine ─▶ Disposition  (replay)  │
                   │                               │   (allow/flag/redact/       │
                   │                               ▼    block/cooldown)          │
                   │   risk header  ◀───  ScanResult ──▶ .to_acs()  ──▶ ACS env  │
                   └────────────────────────────────────────────────────────────┘
      surfaces:  CLI · FastAPI gateway · ASGI middleware · OpenAI/guard() SDK · GitHub Action (SARIF)
```

## Components

| Module | Responsibility |
|--------|----------------|
| `models.py` | `Finding`, `ScanResult`, `Disposition`, `Severity`, `Action`, `ACSDecision`, `RedactionSpan` |
| `signals/` | stdlib primitives: `normalize` (invisible/bidi/tag-block/homoglyph/leet/spacing variants), `entropy`, `luhn`, `tokens` (repetition/zlib), `codecs` (bounded base64/hex decode) |
| `detectors/` | `injection` (LLM01), `consumption` (LLM06), `egress` (LLM02/08/10/DSGAI01); `base` (Detector protocol + `ScanContext`), `rules_data` (pattern tables with OWASP IDs) |
| `scoring.py` | decay-on-read cumulative accumulator + EWMA + sliding window; `SessionState` |
| `session.py` | `SessionStore` protocol + single-process `InMemorySessionStore` (redis via the `[redis]` extra) |
| `clock.py` | injectable `Clock` (`SystemClock`, `FixedClock`) — makes scoring replayable |
| `policy.py` + `config.py` | `Policy`/`ScanConfig` + profiles; the canonical band → action → ACS mapping |
| `acs.py` | `ScanResult.to_acs()` → ACS v0.1.0 response-envelope |
| `riskheader.py` | the `X-PinkCrow-Risk` header |
| `audit.py` | audit log (no raw text) vs replay log (with text) + replay |
| `engine.py` | the `Engine` façade: ties it all together; `scan_input` / `scan_output` |
| `gateway/` | FastAPI app + pure-ASGI middleware (`[gateway]` extra) |
| `integrations/` | `guard()` context manager, `GuardedOpenAI` wrapper |
| `cli.py` + `sarif.py` + `catalog.py` | CLI, SARIF 2.1.0 emitter, rule catalog |

## Scoring (the moat)

The session score is a **decayed cumulative accumulator**: on each event it decays the stored (unclamped)
accumulator by `e^(−λ·Δt)` (λ = ln2 / half_life), adds the event's noisy-OR'd finding score, and bands the
result to 0–100. EWMA is an advisory recent-severity signal; sliding-window caps are a hard override for
floods. All time comes from the injectable clock, so a recorded event log **replays to a byte-identical
score trajectory** — which is what makes "why was this session blocked?" answerable.

## Trust boundaries

Untrusted input enters at `scan_input` (user text; retrieved/tool content is weighted higher via
provenance). Model output is untrusted for egress at `scan_output`. Detectors are ReDoS-bounded (length cap
+ time budget) and never `eval` input; matched secrets are redacted before they can reach logs. The gateway
terminates no TLS and assumes a trusted network (optional bearer token); deploy it behind your ingress.

## Design principles (constraints)

1. Deterministic & auditable first — no cloud/ML in the hot path; ML is optional, pluggable enrichment.
2. Defense-in-depth, never prevention theatre — see the campaign build, limit blast radius.
3. Blast-radius thinking — default fail-closed; least privilege in every default.
4. Drop-in anywhere — stdlib-only core; server/stores/ML are extras.
5. Standards-anchored — every rule cites an OWASP/AISVS ID; emit ACS dispositions.
