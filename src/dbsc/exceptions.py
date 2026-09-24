"""The DBSC exception hierarchy.

``refresh()`` failures split into two families, and callers must tell them apart::

    try:
        response = await dbsc.refresh(jwt, ctx)
    except RetryableRefreshError:
        response = await dbsc.issue_refresh_challenge(ctx)  # benign: 403, browser retries
    except DbscError:
        response = await dbsc.revoke(ctx, enforcement_terminated=True)  # terminal

The ``except RetryableRefreshError`` clause MUST come first: every retryable error is also a
:class:`DbscError`, so a lone ``except DbscError`` would force-log users out over benign races.
"""


class DbscError(Exception):
    """Base type for every recoverable DBSC protocol failure.

    Catch this in the refresh handler to treat any verification failure as "terminate the
    session" (see README, refresh flow).
    """


class RetryableRefreshError(DbscError):
    """Marker for benign ``refresh()`` failures: issue a fresh challenge and 403, don't terminate.

    Subclassed by :class:`MissingChallengeError`, :class:`ChallengeExpiredError`, and
    :class:`ChallengeMismatchError`; catch this instead of enumerating all three.
    """


class JwtInvalidError(DbscError):
    """The presented JWT is structurally invalid, uses an unsupported algorithm, or its signature
    does not verify against the device key.

    On refresh this is the stolen-cookie-from-another-device signal: terminate the session.
    Deliberately NOT a :class:`RetryableRefreshError`.
    """


class ChallengeExpiredError(RetryableRefreshError):
    """The server challenge the browser signed has exceeded its TTL.

    Benign on refresh: issue a fresh challenge and 403 so the browser retries (see README,
    refresh flow).
    """


class ChallengeMismatchError(RetryableRefreshError):
    """The refresh JWT's signature verified against the device key, but its ``jti`` matched
    neither the current nor the previous challenge.

    A validly-signed JWT proves the device-bound private key was used, so this can only be a
    benign race (idle session, concurrent refresh, lost 403). Unlike :class:`JwtInvalidError`, it
    is NOT a stolen-cookie signal. Benign on refresh: issue a fresh challenge and 403 so the
    browser retries.

    Also raised, with the message "Binding changed concurrently", when the refresh kept losing
    the conditional write to other requests updating the same binding. That is the same kind of
    benign race.
    """


class MissingChallengeError(RetryableRefreshError):
    """No pending challenge exists for this session.

    None was issued, it was already consumed, or the store lost it.

    Benign on refresh: issue a fresh challenge and 403 so the browser retries.
    """


class SessionNotFoundError(DbscError):
    """No binding exists for this session, or the presented ``Sec-Secure-Session-Id`` does not
    match the stored one.

    On refresh: terminate the session.
    """


class CorruptStateError(DbscError):
    """A stored DBSC record exists but cannot be parsed.

    Causes include a serializer mismatch, a truncated value, or schema skew between versions.
    Clients can't trigger this: the write path always produces valid, well-typed JSON.

    Treat it as fail-closed: a present-but-unreadable binding must terminate the session, never
    silently degrade a hard-DBSC session to plain cookie auth (that is exactly the fail-open DBSC
    exists to prevent). Absence of a record is distinct: the store returns ``None`` for that and
    never raises this exception.
    """
