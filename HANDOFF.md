# pink-crow — Handoff (the steps only you can do)

Everything that can be built, tested, documented, and committed locally is **done** and committed on
`main`. What remains are the outward-facing actions that need **your** GitHub/PyPI account, credentials, or
a human/legal decision. They're numbered in priority — **#1 (push) unlocks everything else.**

Current local state: 122 tests green · ruff + mypy clean · 5 adversarial hardening rounds · wheel+sdist
build and `twine check` pass · site verified in-browser. The repo has **no remote commits yet** (local only).

---

## 1. 🔴 Push to GitHub (unlocks 2–6)
`gh` isn't installed here and there's no stored git credential/SSH key, so I couldn't push. Pick one:
```bash
# Option A — GitHub CLI
brew install gh && gh auth login
cd "/Users/dibakshya/Documents/OpenSource Projects/pink-crow"
git push -u origin main

# Option B — SSH / PAT
cd "/Users/dibakshya/Documents/OpenSource Projects/pink-crow"
git push -u origin main   # authenticate when prompted
```
Then set the repo **description** and **topics** (Settings → General): topics like
`prompt-injection, llm-security, ai-security, owasp, guardrails, agentic-security, gateway`.

## 2. Enable GitHub Pages (the site)
Settings → **Pages** → Source: **Deploy from a branch** → **`main` / `/docs`** → Save.
Live at `https://dibakshya01.github.io/pink-crow/` in ~1 min. (Site lives in `docs/`, `.nojekyll` present.)

## 3. Upload the social-preview card
Settings → **General → Social preview** needs a **PNG/JPG**. The design is committed as
`docs/assets/social-card.svg` (also the README banner + `og:image`). I couldn't rasterize it locally (no
`cairo`/`librsvg`). To make the PNG:
```bash
brew install librsvg && rsvg-convert -w 1280 -h 640 docs/assets/social-card.svg -o social-card.png
```
…or open the SVG in a browser and export at 1280×640, then upload `social-card.png`.

## 4. Publish to PyPI (so `pip install pink-crow` works)
Build + `twine check` already pass locally. When ready (needs your PyPI token):
```bash
cd "/Users/dibakshya/Documents/OpenSource Projects/pink-crow"
rm -rf dist && python -m build && python -m twine upload dist/*
```
Consider a test run to TestPyPI first (`twine upload -r testpypi dist/*`).

## 5. Publish the GitHub Action to the Marketplace  ✅ eligible (it's an Action)
pink-crow ships a root `action.yml` (branding: shield/purple; inputs path/profile/fail-on/output/format),
so it qualifies as a **GitHub Action** on the Marketplace — a CI red-team / guardrail-regression gate.
Prereqs on your account: **2FA enabled** and a one-time acceptance of the **GitHub Marketplace Developer
Agreement** (both are yours to do; GitHub will prompt). Then:
1. Repo → **Releases → Draft a new release** → create tag **`v1.0.0`** (or `v0.1.0`), title it, paste the
   release notes drafted in **`RELEASE_NOTES.md`**.
2. Tick **“Publish this Action to the GitHub Marketplace.”**
3. Pick a **primary category** (Code quality / Security) + a secondary, confirm the shield/purple icon renders.
4. ✋ **Accept the Marketplace Developer Agreement** (legal — your click), enable **2FA** if prompted.
5. ✋ **Publish release**.
6. After it's live, add the Marketplace badge to the README (URL is on the listing page).

> I can drive this flow in your own Chrome (up to the three ✋ clicks, which stay yours) **once the repo is
> pushed and you're signed in to GitHub** — just ask. I didn't open a browser now because there's nothing to
> publish until #1.

## 6. Launch posts (optional)
Draft copy for HN / Reddit / X / LinkedIn is in **`LAUNCH.md`** (git-ignored — not published). Post from your
own accounts, in your voice.

---

## Notes / decisions for you
- **License:** Apache-2.0 (patent grant). Optional ML plugins carry their own licenses and are never bundled.
- **Name:** "pink-crow" — re-verify no trademark conflict before a big launch (quick USPTO/search).
- **Honest posture:** the README/site/LIMITS lead with "defense-in-depth, not prevention" and publish both
  flag- and block-level false-positive rates. Keep that framing in any launch copy.
- **Version:** package is `0.1.0`; tag the Marketplace release accordingly (or `v1.0.0` if you prefer a 1.0
  launch — then bump `pyproject.toml` + `__init__.__version__` to match first).
