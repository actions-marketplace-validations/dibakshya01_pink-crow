# Contributing to pink-crow

Thanks for helping build an honest, auditable AI-security tool. Contributions of all sizes are welcome —
new detectors, fixtures, docs, integrations, and especially **adversarial tests that break our claims.**

## Principles (please read — they decide PR acceptance)

1. **Deterministic & auditable first.** The core (`pink_crow/`, no `[ml]`) must stay **stdlib-only, offline,
   and reproducible.** No network calls, no model downloads, no non-stdlib imports in the core. ML belongs in
   the optional `[ml]` extra, behind the `Detector` protocol.
2. **No over-claiming.** This is a security tool. Every detector maps to an OWASP/AISVS ID and ships with
   fixtures. We describe what it *detects*, never that it makes a system "safe." If a change narrows what we
   can honestly claim, update [`docs/LIMITS.md`](docs/LIMITS.md) in the same PR.
3. **Every claim has a test.** A new detector needs positive **and** benign fixtures (so we can report its
   false-positive cost). A new scoring/policy behavior needs a deterministic test. Bug fixes land with a
   regression test that fails before and passes after.
4. **ReDoS-safe rules.** New regexes use bounded quantifiers (no nested unbounded quantifiers) and pass the
   complexity lint. Add a pathological-input timing test for anything non-trivial.

## Dev setup

```bash
git clone https://github.com/dibakshya01/pink-crow && cd pink-crow
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,gateway]"
pytest            # tests
ruff check .      # lint
mypy pink_crow    # types
pink-crow scan README.md --output   # self-scan (should report no critical findings)
```

## Workflow

- Open an issue first for anything non-trivial so we can agree on the shape.
- One logical change per PR. Keep the diff reviewable.
- Run `pytest`, `ruff`, and `mypy` locally before pushing — CI runs them across Python 3.9–3.12.
- Adding a detector? Put patterns in `pink_crow/detectors/rules_data.py` with their OWASP IDs (dual-emit 2026
  **and** 2025 per the crosswalk in `docs/OWASP-MAPPING.md`), add fixtures under `fixtures/`, and wire it via
  the `Detector` protocol.
- By contributing you agree your work is licensed under **Apache-2.0** (see [`LICENSE`](LICENSE)).

## Good first issues

New secret/PII patterns (with fixtures), additional obfuscation normalizations, a framework adapter
(LangChain/LlamaIndex), docs, or translating phrase rules to another language. Check the issue tracker's
`good first issue` label.
