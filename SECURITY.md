# Security Policy

pink-crow is a security tool, so we hold our own code to the bar we ask of others.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on the
[pink-crow repository](https://github.com/dibakshya01/pink-crow/security/advisories/new).
We aim to acknowledge within **72 hours** and to agree on a disclosure timeline with you.

In scope and especially welcome:
- **Detector bypasses** — an injection/exfiltration/consumption payload that should score but doesn't,
  or an obfuscation that evades normalization.
- **ReDoS / resource issues inside pink-crow itself** — an input that makes a detector pathologically slow
  despite the length cap + time budget.
- **Scoring/policy correctness** — a way to make the session score or a disposition wrong (e.g. make a
  `block`/`cooldown` fail to fire, or a benign session trip).
- **Gateway issues** — auth/exposure of `/v1/session/{id}` or `/metrics`, session-store consistency bugs.

## What pink-crow is (and is not) — read before filing

pink-crow is **defense-in-depth, not prevention.** Its deterministic detectors catch *known shapes*; a novel
or ML-crafted attack bypassing them is **expected** and documented in [`docs/LIMITS.md`](docs/LIMITS.md), not a
vulnerability in itself. A "clean" result means *no violation was detected*, **not** that input/output is safe.
A finding is in scope when pink-crow behaves **differently from its documented behavior** — e.g. a payload that
matches a shape we claim to detect but is scored as benign.

## Supported versions

Pre-1.0: the latest released minor version receives security fixes. We will document a longer support window
once 1.0 ships.
