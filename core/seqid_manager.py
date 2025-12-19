# core/seqid_manager.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


@dataclass(frozen=True)
class SeqBinding:
    """
    Server-issued sequential identity bound to a specific UID for a limited time window.
    """
    uid: str
    seq_id: int
    issued_at: datetime
    expires_at: datetime
    used: bool = False  # set True once XRF is accepted (one-time use)


class SeqIdManager:
    """
    Issues monotonic SeqIDs and binds them to UID + time window.
    Properties:
      - monotonic counter (server-controlled)
      - time-limited validity
      - UID-bound
      - one-time usable (used flag)
    """

    def __init__(self, start_counter: int = 1, validity_minutes: int = 20) -> None:
        if start_counter < 1:
            raise ValueError("start_counter must be >= 1")
        if validity_minutes < 1:
            raise ValueError("validity_minutes must be >= 1")

        self._counter: int = start_counter
        self._validity: timedelta = timedelta(minutes=validity_minutes)

        # Active bindings indexed by uid and by seq_id for fast checks
        self._by_uid: Dict[str, SeqBinding] = {}
        self._by_seq: Dict[int, SeqBinding] = {}

    @staticmethod
    def now_utc() -> datetime:
        return datetime.now(timezone.utc)

    def issue(self, uid: str, issued_at: Optional[datetime] = None) -> SeqBinding:
        """
        Issue a new SeqID for a UID.
        If an active (unexpired, unused) binding exists for this UID, return it
        to prevent multiple SeqIDs being issued concurrently for same UID.
        """
        if not uid or not uid.strip():
            raise ValueError("uid must be non-empty")

        t0 = issued_at or self.now_utc()
        existing = self._by_uid.get(uid)

        if existing and (not self.is_expired(existing, t0)) and (not existing.used):
            return existing

        seq = self._counter
        self._counter += 1

        binding = SeqBinding(
            uid=uid,
            seq_id=seq,
            issued_at=t0,
            expires_at=t0 + self._validity,
            used=False,
        )

        self._by_uid[uid] = binding
        self._by_seq[seq] = binding
        return binding

    def get_by_uid(self, uid: str) -> Optional[SeqBinding]:
        return self._by_uid.get(uid)

    def get_by_seq(self, seq_id: int) -> Optional[SeqBinding]:
        return self._by_seq.get(seq_id)

    def is_expired(self, binding: SeqBinding, now: Optional[datetime] = None) -> bool:
        t = now or self.now_utc()
        return t > binding.expires_at

    def validate(self, uid: str, seq_id: int, now: Optional[datetime] = None) -> str:
        """
        Validates a presented (uid, seq_id).
        Returns a machine-friendly reason string:
          - OK
          - NO_BINDING_FOR_UID
          - SEQ_MISMATCH
          - EXPIRED
          - ALREADY_USED
        """
        t = now or self.now_utc()
        b = self._by_uid.get(uid)
        if not b:
            return "NO_BINDING_FOR_UID"
        if b.seq_id != seq_id:
            return "SEQ_MISMATCH"
        if self.is_expired(b, t):
            return "EXPIRED"
        if b.used:
            return "ALREADY_USED"
        return "OK"

    def mark_used(self, uid: str, seq_id: int) -> str:
        """
        Marks a binding as used (one-time).
        Returns:
          - OK
          - NOT_FOUND
          - SEQ_MISMATCH
        """
        b = self._by_uid.get(uid)
        if not b:
            return "NOT_FOUND"
        if b.seq_id != seq_id:
            return "SEQ_MISMATCH"

        # dataclass is frozen; create a new object with used=True
        used_binding = SeqBinding(
            uid=b.uid,
            seq_id=b.seq_id,
            issued_at=b.issued_at,
            expires_at=b.expires_at,
            used=True,
        )
        self._by_uid[uid] = used_binding
        self._by_seq[seq_id] = used_binding
        return "OK"
