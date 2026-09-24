"""The short-lived registration challenge."""

from dataclasses import dataclass
from typing import Self

from dbsc._json import as_int, as_str, dumps, loads_object
from dbsc._validate import is_sf_string_safe, require
from dbsc.exceptions import CorruptStateError


@dataclass(frozen=True, slots=True)
class PendingRegistration:
    """The short-lived registration challenge.

    Written when the ``Secure-Session-Registration`` header is emitted at login, before the
    browser has proven DBSC support. Kept in its own store key (separate from
    :class:`~dbsc.binding.Binding`) so that "a binding exists" is true only after a successful
    registration, never merely because DBSC was offered. Never consulted by the enforcement gate.
    """

    user_id: str
    reg_challenge: str
    reg_challenge_time: int

    def __post_init__(self) -> None:
        require(
            is_sf_string_safe(self.reg_challenge), "PendingRegistration.reg_challenge is unsafe."
        )

    def to_json(self) -> str:
        """Serialise for storage (camelCase keys, interchangeable with the PHP library)."""
        return dumps(
            {
                "userId": self.user_id,
                "regChallenge": self.reg_challenge,
                "regChallengeTime": self.reg_challenge_time,
            }
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> Self:
        """Parse a stored pending registration.

        Raises on a present-but-unreadable value rather than returning ``None``, so a corrupt
        record fails closed rather than registering on garbage. Absence is represented by the
        store returning ``None`` without ever calling this method.

        Raises:
            CorruptStateError: the record is not a JSON object or a field is missing or has the
                wrong type.
        """
        data = loads_object(raw)
        if data is None:
            raise CorruptStateError("Pending registration record is not a JSON object")
        user_id = as_str(data.get("userId"))
        reg_challenge = as_str(data.get("regChallenge"))
        reg_challenge_time = as_int(data.get("regChallengeTime"))
        if user_id is None or reg_challenge is None or reg_challenge_time is None:
            raise CorruptStateError("Pending registration record has missing or wrong-typed fields")
        try:
            return cls(user_id, reg_challenge, reg_challenge_time)
        except ValueError as e:
            raise CorruptStateError(
                f"Pending registration record has an unsafe value: {e}"
            ) from None
