"""Internal helpers shared by the stored-record and JWT decoders."""

import hmac
import json


def dumps(value: object) -> str:
    """Compact JSON, matching the byte shape the browser and existing stores already see."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def loads_object(raw: str | bytes) -> dict[str, object] | None:
    """Decode a JSON object, or ``None`` if the input isn't valid JSON or isn't an object.

    Duplicate member names anywhere in the document count as invalid. JSON parsers disagree on
    which duplicate wins, so accepting them lets two components read the same bytes differently.
    """
    try:
        data = json.loads(raw, object_pairs_hook=_unique_members)
    except ValueError, RecursionError:
        return None
    return data if isinstance(data, dict) else None


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members = dict(pairs)
    if len(members) != len(pairs):
        raise ValueError("duplicate member name")
    return members


def as_str(value: object) -> str | None:
    """``value`` if it is a JSON string, else ``None``."""
    return value if isinstance(value, str) else None


def as_int(value: object) -> int | None:
    """``value`` if it is a JSON integer, else ``None``.

    Excludes ``bool``, which Python treats as a subclass of ``int``.
    """
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def constant_time_equals(known: str, presented: str) -> bool:
    """Constant-time string comparison.

    Both sides are encoded first: :func:`hmac.compare_digest` raises ``TypeError`` for non-ASCII
    ``str`` arguments, and the presented value is attacker-controlled.
    """
    return hmac.compare_digest(known.encode(), presented.encode())
