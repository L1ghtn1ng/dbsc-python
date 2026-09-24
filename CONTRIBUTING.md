# Contributing

Thanks for helping. This is a security library, so changes are reviewed with that in mind. Please
read this page before opening a pull request.

**Found a vulnerability?** Don't open an issue or PR. Follow [SECURITY.md](SECURITY.md) instead.

## Development setup

You need [uv](https://docs.astral.sh/uv/). It installs Python 3.14 for you if needed.

```bash
git clone https://github.com/L1ghtn1ng/dbsc-python.git
cd dbsc-python
uv sync
```

## Checks

CI runs all of these on every pull request. Run them locally before pushing:

```bash
uv run ruff check            # lint
uv run ruff format --check   # formatting (`uv run ruff format` to fix)
uv run ty check              # type-check
uv run pytest                # tests
uv build                     # the package builds
```

The test suite generates real EC P-256 device keys, builds the JWTs exactly as Chrome does, and
drives the full register/refresh/enforce/revoke flow. It also covers the attack cases: wrong device
key, wrong/expired/mismatched challenge, stale cookie, `alg=none`, off-curve JWKs, and corrupt
stored state. Time comes from a fake clock (`tests/support.py`), so TTL tests never sleep. The
example server in `examples/` is exercised over a real socket, so keep it working too.

### End-to-end tests with a real browser

`tests/e2e/` drives the example server with a real headless Chromium through
[Playwright](https://playwright.dev/python/): Chrome's own keys and JWTs, its refresh scheduling,
request deferral and cookie handling. They run in CI on every pull request. Locally they're
skipped unless you point `DBSC_E2E_BROWSER` at a DBSC-capable Chromium:

```bash
export DBSC_E2E_BROWSER="$(uv run python scripts/fetch_e2e_browser.py)"  # ~185 MB, cached in .cache/
uv run playwright install-deps chromium   # system libraries, if your distro lacks them (Linux)
uv run pytest -m e2e
```

On Linux, Chromium only does DBSC with two feature switches (the tests pass them):
`DeviceBoundSessions` and `EnableBoundSessionCredentialsSoftwareKeysForManualTesting`, which swaps
the TPM for software keys. That second switch is a manual-testing aid and version-sensitive:
Chrome for Testing 149 and Chromium 150 honour it, while Chromium 153 (Playwright's bundled
build) silently ignores the registration header. That is why the suite uses a pinned Chrome for
Testing build (`CHROME_VERSION` in `scripts/fetch_e2e_browser.py`) rather than
`playwright install`. To move the pin, bump the version, run `pytest -m e2e` against it, and
only merge if it passes.

Things to keep in mind when writing e2e tests:

- **Refreshes are rate-limited.** Every refresh spends a device-key signature, and Chromium
  answers a burst with `Secure-Session-Skipped: quota_exceeded`, which stops refreshing and trips
  the gate. Force at most a couple of refreshes per test, and keep non-page requests out of scope
  (the fixtures exclude `/favicon.ico`).
- **The demo's login route signs anyone in.** Don't let a test follow a redirect to it when you
  mean "the user was logged out"; assert on the 302 instead (see
  `test_stolen_session_cookie_is_rejected`).
- **Don't assume request order.** With a short cookie lifetime, Chromium starts refreshing the
  moment registration completes, concurrently with whatever page load comes next. Assert what
  must hold whatever the interleaving, not a particular sequence (see
  `test_advertised_challenge_is_harmless`). Deterministic interleavings belong in the unit suite
  (`tests/test_concurrency.py`).
- **Poll, don't sleep.** Use `eventually()` for browser-side state, and only sleep to let a
  cookie expire.

## Guidelines

- **Tests for behaviour changes.** Every bug fix or feature needs a test that fails without it.
  Security fixes need a test for the attack they close.
- **Wire behaviour is load-bearing.** The "Wire-protocol notes" in the README come from testing
  against real Chrome. If you change headers, status codes or the session-instructions JSON, say
  what you tested against in the PR.
- **Keep the store format stable.** `Binding` / `PendingRegistration` JSON is shared with
  dbsc-php. New fields must be optional with safe defaults, like the existing overlap fields.
- **Standard library first.** `cryptography` is the only runtime dependency. Discuss any new one in
  an issue before sending code.
- **Security invariants are tested.** SECURITY.md maps each OWASP Top 10:2025 category to its
  controls. A change that weakens one needs a matching test change and an explicit
  justification in the PR. Pin any new GitHub Action to a full commit SHA.
- **Public API is documented.** Ruff enforces docstrings on public library code. Update the README
  and `CHANGELOG.md` (under `Unreleased`) for anything user-visible.

## Releasing

Releases are published by `.github/workflows/release.yml` when a `v*` tag is pushed, through PyPI
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/). No PyPI API token exists
anywhere, and each file gets a PEP 740 attestation linking it to the workflow run. Never publish
from a laptop.

One-time setup, for maintainers:

1. On PyPI, add a trusted publisher for project `dbsc`: owner `L1ghtn1ng`, repository
   `dbsc-python`, workflow `release.yml`, environment `pypi`.
2. On GitHub, create the `pypi` environment (Settings → Environments), add required reviewers,
   and restrict it to `v*` tags.
3. Enable private vulnerability reporting, Dependabot alerts and code scanning (Settings →
   Code security), and protect `main` and `v*` tags with rulesets.

Each release:

1. Move the `Unreleased` entries in `CHANGELOG.md` under a new version heading with today's date,
   and update the comparison links at the bottom.
2. Bump `version` in `pyproject.toml` (`uv version --bump minor`, or `patch` / `major`).
3. Run the full set of checks above, plus `uv audit --locked --preview-features audit-command`.
4. Commit, then tag and push: `git tag v0.1.0 && git push origin v0.1.0`. The workflow checks
   that the tag matches the package version, re-runs the checks, builds, and waits for an
   environment reviewer before publishing.
5. Create a GitHub release for the tag, using the changelog entry as its notes.
