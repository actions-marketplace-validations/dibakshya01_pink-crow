# The lethal-trifecta session signal (+ sharper exfil detection)

pink-crow scores the **session**, not just the message. This document covers the detectors that exist
*because* of that — the ones a per-prompt classifier structurally cannot provide.

## Why this exists

Prompt injection has no clean cure: at the token level an LLM has no boundary between "instructions" and
"data," so you cannot reliably prevent a hijack. What you *can* do is bound the damage. The most useful
runtime lever, well-established in the literature, is to refuse to let one trust context assemble the
**lethal trifecta** (Simon Willison) — equivalently, to enforce the **Rule of Two** (Meta):

1. **Untrusted input** — the session ingested attacker-controllable content (a retrieved doc, a tool
   result, a web page) or a prompt-injection pattern fired.
2. **Sensitive data** — secrets, PII, or hidden context appeared in the session.
3. **External channel** — the output contains an egress path (a link/image to a non-allowlisted host, a
   data-bearing URL, an IDN lookalike).

Any one leg alone is usually fine. **All three together is the exfiltration pattern.** The legs light up
on *different turns*, so a single-message scanner cannot see the trifecta — but a cumulative session
scorer can. pink-crow records which legs a session has lit (each with a last-seen timestamp so a leg
decays out of a quiet session after `policy.trifecta_window`) and emits a correlation finding:

| Legs active in the session | Finding | Severity |
|---|---|---|
| 2 of 3 | `pc.ses.trifecta` | `MEDIUM` (advisory — one leg away from an exfil path) |
| all 3 | `pc.ses.trifecta` | `CRITICAL` (the trifecta is assembled) |

It only runs for scans that pass a `session_id` (correlation needs cross-event memory); stateless scans
never correlate. Disable it with `policy.scan.rule_overrides["pc.ses.trifecta"] = False`; tune how long a
leg stays active with `policy.trifecta_window` (seconds; `0` = permanent for the session's life). The
`strict` profile remembers legs longer (1800s) so a slowly-assembled trifecta still trips.

```python
import pink_crow as pc
eng = pc.Engine()
# turn 1: a RAG/tool turn ingests untrusted content  -> leg 1
eng.scan_input("…retrieved document…", session_id="s1", provenance="retrieved")
# turn 2: the model surfaces a secret and an external link -> legs 2 + 3 => CRITICAL trifecta
r = eng.scan_output("key AKIA… see [more](https://evil.tld/x)", session_id="s1")
assert any(f.rule_id == "pc.ses.trifecta" for f in r.findings)
```

## Sharper egress detection (the "external channel" leg)

Two new output rules strengthen the egress leg against the exfil channels that survive in practice:

- **`pc.out.exfil_query` — data-in-URL exfil (the "zero-click" class).** A non-allowlisted URL whose
  query or fragment carries a long, high-entropy blob (e.g. `…/collect?d=<base64-secret>`). This is how a
  secret leaves even when the link looks ordinary: the recipient's own client (email, chat, a markdown
  previewer) auto-fetches the URL, carrying the data in the query string. Thresholds are deliberately
  conservative (token length ≥ 24 **and** Shannon entropy ≥ 3.6) so ordinary tracking/`utm_` params don't
  trip it. Allowlisted hosts are skipped (an operator-trusted signed URL is not exfil).
- **`pc.out.exfil_punycode` — IDN/punycode lookalike hosts.** An output link to an `xn--…` or non-ASCII
  host — the homoglyph trick an injected payload uses to send you somewhere that *renders* like a trusted
  domain. Skipped if the operator explicitly allowlisted the host.

Both reuse the existing ReDoS-free, host-capturing link parse, so they add coverage without new scan cost
and without touching the false-positive budget (measured flag-FP stayed at 0.65%).

## Honest scope

This does not *prevent* exfiltration — nothing at this layer can. `pc.ses.trifecta` is a high-signal
**alarm** that the dangerous combination now exists in a session, so a policy can flag, block, or time it
out before the third leg is used. Treat a clean result as "no trifecta *observed*," not "safe." The
durable fix is architectural: never give one agent context untrusted input, secret access, and an
external channel at once. pink-crow's job is to notice — loudly — when something did.

## Provenance of these ideas

These detectors were added from the conclusions of a focused prompt-injection research program (an
autonomous, self-adversarial design loop). Its honest verdict: injection's *integrity* consequences can
be contained by architecture (object-capability / reference-monitor designs such as CaMeL and Microsoft
FIDES), but its *confidentiality* consequences cannot be eliminated by design without destroying utility —
so the right posture is to **break the lethal trifecta and score the residual risk**, which is exactly
what a runtime monitor like pink-crow is for. The data-in-URL and lookalike-host rules target the single
most reliable real-world exfil channel surfaced by that review.
