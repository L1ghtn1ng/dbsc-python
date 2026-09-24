# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until `1.0.0`, minor
versions may contain breaking changes; they will always be called out here.

## [Unreleased]

## [0.1.0] - Unreleased

First release: a Python port of [report-uri/dbsc-php](https://github.com/report-uri/dbsc-php)
with the same wire behaviour.

### Added

- `DbscServer` with the full DBSC lifecycle: registration offer, single-phase registration,
  two-phase refresh, revocation, and enforcement-gate primitives.
- Optional single-phase first refresh via `advertise_refresh_challenge()`, with single-depth
  challenge overlap to cover a racing reactive 403.
- Bound-cookie rotation overlap: the immediately-previous cookie value is accepted until its own
  expiry.
- `RetryableRefreshError` family (`MissingChallengeError`, `ChallengeExpiredError`,
  `ChallengeMismatchError`) separating benign refresh races from terminal failures.
- `scope_specification` (`ScopeRule`) and `allowed_refresh_initiators` support, configurable
  statically on `Config` or per request on `RequestContext`.
- Async `Store` and `AuditLogger` protocols, a bundled `InMemoryStore`, and `AuditEvent`.
- Concurrency-safe state updates. `Store.commit_registration()` consumes a registration offer
  and creates the binding atomically, and only on a successful registration. `Store.replace_binding()`
  makes binding updates compare-and-set. Concurrent requests on one session therefore can't undo
  each other: a refresh racing a page load, a reactive 403 or a logout; two refreshes proving the
  same challenge; two registrations on one offer; or a logout or re-login mid-registration.
  Failed registration attempts no longer consume the offer, so junk attempts can't keep a session
  on plain cookie auth. `Store` subclasses inherit single-process defaults for both; `InMemoryStore`
  implements them atomically. dbsc-php has these races; the stored JSON format is unchanged.
- Security hardening mapped to the OWASP Top 10:2025 (see SECURITY.md):
  - Session-fixation defence: a binding recorded for one user is refused for another, on the
    gate, on refresh and on registration.
  - Strict validation of `Config`, `ScopeRule` and `RequestContext`: `__Host-` cookie names,
    same-origin paths, bounded lifetimes, known `SameSite` values, host-pattern initiators, and
    https origins.
  - Stored identifiers and cookie values are format-checked on decode, and JSON with duplicate
    member names is refused (tokens and stored records).
  - JWTs with a `crit` header, or over 8 KiB, are refused.
  - Malformed JWTs are audited, not just rejected.
  - Every response carrying session state sends `Cache-Control: no-store`.
- Supply-chain hardening: SHA-pinned CI actions without persisted credentials, `uv audit` on
  every PR and weekly, CodeQL for the code and the workflows, and a release workflow using PyPI
  Trusted Publishing with attestations.
- Fail-closed handling of corrupt stored state (`CorruptStateError`).
- ES256-only JWT verification (`JwtVerifier`) with algorithm pinning and P-256 point validation.
- Stored-record JSON and device PEM that are interchangeable with dbsc-php.
- Injectable clock on `DbscServer` and `InMemoryStore`.
- Reference asyncio demo server in `examples/demo_server.py`.
- End-to-end tests against a real headless Chromium (pinned Chrome for Testing) via Playwright,
  run in CI alongside the unit suite.

[Unreleased]: https://github.com/L1ghtn1ng/dbsc-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/L1ghtn1ng/dbsc-python/releases/tag/v0.1.0
