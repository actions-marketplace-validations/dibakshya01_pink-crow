# pink-crow v0.1.0

**The deterministic session-risk layer for AI chatbots & agents.** pink-crow keeps a live, auditable risk
score for every chat and every session — across OWASP LLM & agentic categories, including the widely-ignored
resource-exhaustion (LLM06) — and acts on it (flag · redact · block · session time-out) via a policy engine.
Offline, zero-dependency core, Apache-2.0.

## Highlights
- **Cumulative session scoring** — a time-decayed accumulator that sees an attack *campaign* build across
  turns, not just the last message. Deterministic and **replayable** (byte-identical trajectory from a
  recorded event log).
- **OWASP-mapped detectors** (dual-emit 2026 + 2025 IDs): prompt injection + obfuscation + second-order
  (LLM01), unbounded consumption (LLM06), secret/PII egress with redaction (LLM02/DSGAI01), system-prompt
  leakage (LLM08), dangerous/exfil-prone output (LLM10).
- **Policy engine** → allow / flag / redact / block / session cooldown, and **Agent Control Standard**
  dispositions (allow/deny/modify/ask/defer). Fail-closed by default.
- **Drop in anywhere:** Python SDK, `guard()` context manager, `GuardedOpenAI` wrapper, FastAPI gateway,
  pure-ASGI (streaming-safe) middleware, a CLI, and this GitHub Action (SARIF for code-scanning).
- **Honest by design:** measured on the bundled corpus — detection recall 100% (68/68), benign
  false-positive 0.65% flag / 0.49% block — with a candid `docs/LIMITS.md`. Defense-in-depth, not prevention.

## Use as a GitHub Action (CI red-team / guardrail gate)
```yaml
- uses: dibakshya01/pink-crow@v1
  with:
    path: prompts/        # files to scan
    fail-on: '60'         # fail the job at/above this score
    format: sarif         # emits SARIF for GitHub code-scanning
```

## Install (library / gateway)
```bash
pip install pink-crow               # zero-dependency core
pip install "pink-crow[gateway]"    # + FastAPI HTTP gateway
```

## Security & limits
pink-crow is defense-in-depth, not prevention — a clean result means "no violation detected", not "safe".
Deterministic detectors catch known shapes; see `docs/LIMITS.md` for the honest "what it can & cannot do"
(novel-attack bypass, security-topic false positives, English-centric phrase rules, multi-worker store, etc.).
Report vulnerabilities privately via GitHub security advisories (`SECURITY.md`).

**Pre-1.0:** the API may change before 1.0. Built in the open.
