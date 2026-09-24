# Security Policy

`dbsc-python` is a security library: it verifies the device-bound
signatures that protect authenticated sessions against cookie theft. A flaw
here can silently downgrade every consumer's session protection, so reports are
taken seriously and triaged quickly.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a suspected
vulnerability.** Public disclosure before a fix is available puts every
downstream application at risk.

Instead, use **GitHub Private Vulnerability Reporting**:

> Repository → **Security** tab → **Report a vulnerability**

This opens a private advisory visible only to the maintainers. Please include:

- the affected version(s) / commit,
- a description of the issue and its security impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

We aim to acknowledge a report within **3 working days** and to provide a
remediation timeline after initial triage. Please allow a reasonable
coordinated-disclosure window before any public write-up; we are happy to
credit reporters in the advisory and release notes.

## Scope

In scope:

- Signature / JWT verification (`src/dbsc/jwt.py`).
- The registration / refresh / enforcement state machine (`src/dbsc/server.py`).
- The storage contract (`src/dbsc/store.py`) and input validation
  (`src/dbsc/_validate.py`).
- The release pipeline (`.github/workflows/`).
- Anything that could let a stolen session cookie be replayed, a binding be
  forged or bypassed, the challenge nonce be replayed, or the enforcement gate
  be silently disabled.

Out of scope:

- Misuse in a consuming application (e.g. storing DBSC state in a
  read-modify-written shared session blob — see `README.md` → *Storage*).
- The bundled `examples/` and `tests/` reference code, which is illustrative and
  not intended for production use.

## Security design (OWASP Top 10:2025)

How the library addresses each [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
category that applies to it. Integrators still own their side; see the checklist
below.

| Category | Controls |
|---|---|
| **A01 Broken Access Control** | A binding is keyed by session id and records its user. A binding recorded for one user is refused for another on the gate, on refresh and on registration. `refresh_path` / `register_path` must be same-origin paths, so a `//host` value can't point the browser at another server. |
| **A02 Security Misconfiguration** | `Config`, `ScopeRule` and `RequestContext` refuse unsafe values at construction: the `__Host-` cookie prefix is required, lifetimes are bounded (bound cookie ≤ 1 h, challenge ≤ 24 h, grace ≤ 60 s), `SameSite` must be a known value, and the origin must be `https` (loopback `http` excepted). Every response carrying session state sends `Cache-Control: no-store`. |
| **A03 Software Supply Chain Failures** | One runtime dependency (`cryptography`). All dependencies are locked with hashes (`uv.lock`) and installed with `--locked`. `uv audit` checks them against OSV on every PR and weekly. CI actions are pinned to commit SHAs and don't persist credentials. CodeQL scans the Python code and the workflows. Releases go out only through PyPI Trusted Publishing, with PEP 740 attestations and no stored API token. |
| **A04 Cryptographic Failures** | ES256 only, verified by `cryptography` (OpenSSL): `alg` is pinned, JWK points are validated on-curve, and signatures must be raw 64-byte `r‖s`. Tokens with a `crit` header are refused. Nonces, challenges, session ids and cookie values are 256-bit `secrets` values. Every secret comparison is constant-time. |
| **A05 Injection** | Values that reach response headers or cookies are validated: config paths and names at startup, stored identifiers and cookie values when a record is decoded. Everything else goes into the session instructions through `json.dumps`. The library builds no SQL, shell or HTML. |
| **A06 Insecure Design** | Every state change is a conditional write (`commit_registration`, `replace_binding`), so concurrent requests can't undo each other: a refresh racing a page load, a 403 or a logout, or two registrations racing on one offer. Registration offers are consumed only by a successful registration, so junk attempts can't burn the offer and keep a session on cookie auth. |
| **A07 Authentication Failures** | The replay defence is a single-use challenge inside a device-signed JWT. A spent challenge is dropped on success, and the challenge overlap is single-depth and TTL-bounded. There's a session-fixation defence (see A01), and the reference server rotates its session id at login. |
| **A08 Software or Data Integrity Failures** | Stored records are strictly typed and format-checked on decode. JSON with duplicate member names is refused, in tokens and in stored records. Unreadable state raises `CorruptStateError` and fails closed; it never degrades to cookie auth. |
| **A09 Security Logging and Alerting Failures** | Every transition, including malformed tokens, is reported to the `AuditLogger`. Benign races log `dbscRefreshRetryable`, so `dbscRefreshFailed` and `dbscEnforcementTerminated` stay clean alerting signals. |
| **A10 Mishandling of Exceptional Conditions** | Oversized tokens are refused before decoding. Malformed input raises typed `DbscError`s rather than stray exceptions. Retries after a lost write race are bounded, and exhausting them is a benign, retryable outcome. |

## Integrator checklist

The library can't enforce these; your application must:

- **Issue a new session id at login** and pass `user_id` into every `RequestContext`
  once it's known. Without both, the session-fixation defence can't work.
- **Set `origin_host_url` from configuration**, never from the request's `Host`
  header.
- **Back `Store` with a dedicated, shared key space** (not the session blob), and
  implement `commit_registration` and `replace_binding` atomically in your backend.
  The inherited defaults are single-process only.
- **Run the enforcement gate** on document loads and on subresources past the
  registration grace. **On a terminal refresh failure, revoke and end the session
  server-side.**
- **Exclude everything that needs no session from the DBSC scope**
  (`scope_specification`), so refreshes don't exhaust the browser's signing quota.
- **Rate-limit `/dbsc/register` and `/dbsc/refresh`** like any other authentication
  endpoint.
- **Alert on `dbscRefreshFailed` and `dbscEnforcementTerminated`.** Store audit
  events where an attacker who holds a session can't tamper with them.
- **Serve over HTTPS** with HSTS.

## Supported versions

Until a `1.0.0` release, only the latest tagged release on the default branch
receives security fixes.
