# OWASP mapping

Every pink-crow rule maps to one or more authoritative OWASP IDs, **dual-emitting both the 2026
and 2025 edition IDs** where a crosswalk exists (see the table at the bottom). This file is generated
from the rule catalog (`pink-crow rules --format json`), so it stays in sync with the code.

## Rules (37)

| Rule | OWASP IDs | Category | What it detects |
|------|-----------|----------|-----------------|
| `pc.con.amplification` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | compression-bomb-like input (low zlib ratio) |
| `pc.con.charrun` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | single character repeated at length |
| `pc.con.oversize` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | oversized input vs char cap |
| `pc.con.repeat_abuse` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | 'repeat forever / N times' amplification request |
| `pc.con.repetition` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | low lexical diversity (repetition) |
| `pc.con.tokens` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | token-estimate flood vs token cap |
| `pc.inj.chat_template` | `LLM01:2026`, `LLM01:2025` | prompt-injection | leaked chat-template / role token |
| `pc.inj.encoded` | `LLM01:2026`, `ASI06`, `LLM01:2025` | prompt-injection | injection payload hidden in base64/hex (second-order) |
| `pc.inj.invisible` | `LLM01:2026`, `LLM01:2025` | prompt-injection | invisible / bidi / Unicode tag-block smuggling |
| `pc.inj.override` | `LLM01:2026`, `ASI01`, `LLM01:2025` | prompt-injection | instruction-override phrasing |
| `pc.inj.override_soft` | `LLM01:2026`, `LLM01:2025` | prompt-injection | disregard-preceding-context phrasing |
| `pc.inj.persona` | `LLM01:2026`, `LLM01:2025` | prompt-injection | known jailbreak persona / mode |
| `pc.inj.prompt_extraction` | `LLM01:2026`, `LLM08:2026`, `LLM01:2025`, `LLM07:2025` | prompt-injection | system-prompt extraction probe |
| `pc.inj.role_confusion` | `LLM01:2026`, `LLM01:2025` | prompt-injection | fake conversation-role turn |
| `pc.inj.role_reassign` | `LLM01:2026`, `LLM01:2025` | prompt-injection | role-reassignment phrasing |
| `pc.inj.safety_bypass` | `LLM01:2026`, `LLM01:2025` | prompt-injection | safety/guardrail-bypass phrasing |
| `pc.leak.canary` | `LLM08:2026`, `LLM07:2025` | context-exposure | system-prompt canary token leaked in output |
| `pc.leak.overlap` | `LLM08:2026`, `LLM07:2025` | context-exposure | output overlaps the known system prompt (n-gram) |
| `pc.leak.phrase` | `LLM08:2026`, `LLM07:2025` | context-exposure | system-prompt-leakage phrasing in output |
| `pc.out.ansi` | `LLM10:2026`, `LLM05:2025` | improper-output | ANSI/OSC terminal control characters in output |
| `pc.out.exfil_link` | `LLM10:2026`, `DSGAI01`, `LLM05:2025` | improper-output | markdown/autolink to a non-allowlisted host (exfil channel) |
| `pc.out.oversize` | `LLM06:2026`, `LLM10:2025` | unbounded-consumption | model output too large to fully scan (egress cap exceeded) |
| `pc.out.shell` | `LLM10:2026`, `ASI05`, `LLM05:2025` | improper-output | dangerous shell/exec construct in output |
| `pc.out.sql` | `LLM10:2026`, `LLM05:2025` | improper-output | SQL construct in output |
| `pc.out.xss` | `LLM10:2026`, `LLM05:2025` | improper-output | HTML/JS (XSS) construct in output |
| `pc.pii.card` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | pii-egress | Luhn-valid payment card in output |
| `pc.pii.email` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | pii-egress | email address in output |
| `pc.pii.ssn` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | pii-egress | US SSN pattern in output |
| `pc.sec.aws_key` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | AWS access key id |
| `pc.sec.generic` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | entropy-gated generic key=value credential |
| `pc.sec.github` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | GitHub token |
| `pc.sec.google` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | Google API key |
| `pc.sec.jwt` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | JSON Web Token |
| `pc.sec.openai` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | OpenAI-style API key |
| `pc.sec.pem` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | PEM private key block |
| `pc.sec.slack` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | Slack token |
| `pc.sec.stripe` | `LLM02:2026`, `DSGAI01`, `LLM02:2025` | secret-egress | Stripe secret key |

## OWASP LLM Top 10 — 2025 ↔ 2026 crosswalk

pink-crow anchors to the **2026** editions (the newest; the LLM edition's public release date was
TBD on the source PDF — see `finding.md`). Because the 2025 edition is still widely cited and the
numbering changed, findings carry both IDs.

| Title | 2025 | 2026 |
|-------|------|------|
| Prompt Injection | `LLM01` | `LLM01:2026` |
| Sensitive Information Disclosure | `LLM02` | `LLM02:2026` |
| Supply Chain | `LLM03` | `LLM04:2026` |
| Data and Model Poisoning | `LLM04` | `LLM05:2026` |
| Improper Output Handling | `LLM05` | `LLM10:2026` |
| Excessive Agency | `LLM06` | `LLM03:2026` |
| System Prompt Leakage -> Hidden Context Exposure | `LLM07` | `LLM08:2026` |
| Vector and Embedding Weaknesses | `LLM08` | `LLM09:2026` |
| Misinformation | `LLM09` | `LLM07:2026` |
| Unbounded Consumption | `LLM10` | `LLM06:2026` |

Agentic IDs use the `ASI01`–`ASI10` prefix (no year suffix in the source doc); data-security
egress IDs use `DSGAI01`–`DSGAI21` (primary egress anchor: `DSGAI01` Sensitive Data Leakage).

