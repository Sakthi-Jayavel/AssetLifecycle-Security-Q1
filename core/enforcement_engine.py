# core/enforcement_engine.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from core.state_machine import AssetLifecycleFSM, AssetState, EventType, TransitionResult
from core.seqid_manager import SeqIdManager


class Decision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    ALERT = "ALERT"   # accepted for logging/monitoring but security-relevant


@dataclass(frozen=True)
class EnforcementDecision:
    decision: Decision
    reason: str
    asset_id: str                 # internal key (we use UID as asset_id for now)
    prev_state: AssetState
    next_state: AssetState
    event: EventType
    timestamp_utc: str
    details: Dict[str, Any]


class AssetLifecycleEnforcementEngine:
    """
    ALEE: Combines
      - Phase 1: AssetLifecycleFSM (state-gated operations)
      - Phase 2: SeqIdManager (time-bound identity)
    and returns ACCEPT/REJECT/ALERT decisions with reason codes.
    """

    def __init__(self, seq_manager: SeqIdManager) -> None:
        self.seq = seq_manager
        # One FSM per asset (keyed by UID for now)
        self._fsms: Dict[str, AssetLifecycleFSM] = {}

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _get_fsm(self, uid: str) -> AssetLifecycleFSM:
        if uid not in self._fsms:
            self._fsms[uid] = AssetLifecycleFSM()
        return self._fsms[uid]

    # -------------------------------
    # Event Handlers (Core Workflow)
    # -------------------------------

    def handle_rfid_read(self, uid: str, gateway_id: str, ts_utc: Optional[str] = None) -> EnforcementDecision:
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        tr = fsm.apply(EventType.RFID_READ)
        if not tr.accepted:
            return self._reject(uid, tr, reason=tr.reason, details={"gateway_id": gateway_id})

        return self._accept(uid, tr, details={"gateway_id": gateway_id})

    def handle_seq_request(self, uid: str, ts_utc: Optional[str] = None) -> EnforcementDecision:
        """
        Server issues SeqID only if the asset is in RFID_VERIFIED state.
        """
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        if fsm.state != AssetState.RFID_VERIFIED:
            return self._reject_simple(uid, fsm.state, EventType.SEQ_ASSIGNED, "STATE_NOT_RFID_VERIFIED", {"ts": t})

        binding = self.seq.issue(uid)

        tr = fsm.apply(EventType.SEQ_ASSIGNED)
        if not tr.accepted:
            return self._reject(uid, tr, reason=tr.reason, details={"seq_id": binding.seq_id, "expires_at": binding.expires_at.isoformat()})

        return EnforcementDecision(
            decision=Decision.ACCEPT,
            reason="SEQ_ISSUED",
            asset_id=uid,
            prev_state=tr.prev_state,
            next_state=tr.next_state,
            event=EventType.SEQ_ASSIGNED,
            timestamp_utc=t,
            details={
                "seq_id": binding.seq_id,
                "issued_at": binding.issued_at.isoformat(),
                "expires_at": binding.expires_at.isoformat(),
            },
        )

    def handle_xrf_report(
        self,
        uid: str,
        seq_id: int,
        purity: float,
        scan_duration_s: int,
        contact_ok: bool,
        pc_id: str,
        ts_utc: Optional[str] = None,
        thresholds: Optional[Dict[str, Any]] = None,
    ) -> EnforcementDecision:
        """
        Accepts XRF report only if:
          - FSM state is SEQ_BOUND
          - SeqID validates OK (uid-bound, unexpired, unused)
          - sanity thresholds pass (purity, scan duration, contact flag)
        """
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        if fsm.state != AssetState.SEQ_BOUND:
            return self._reject_simple(uid, fsm.state, EventType.XRF_REPORT_ACCEPTED, "STATE_NOT_SEQ_BOUND", {"pc_id": pc_id})

        # 1) Validate SeqID
        seq_status = self.seq.validate(uid, seq_id)
        if seq_status != "OK":
            return self._reject_simple(uid, fsm.state, EventType.XRF_REPORT_ACCEPTED, f"SEQ_INVALID:{seq_status}", {"pc_id": pc_id, "seq_id": seq_id})

        # 2) Sanity checks (vendor-layer validation)
        th = thresholds or {}
        purity_min = float(th.get("purity_min_percent", 99.0))
        scan_min = int(th.get("scan_duration_min_seconds", 8))
        contact_required = bool(th.get("contact_required", True))

        if purity < purity_min:
            return self._reject_simple(uid, fsm.state, EventType.XRF_REPORT_ACCEPTED, "SANITY_FAIL:PURITY_TOO_LOW",
                                       {"purity": purity, "purity_min": purity_min, "pc_id": pc_id})

        if scan_duration_s < scan_min:
            return self._reject_simple(uid, fsm.state, EventType.XRF_REPORT_ACCEPTED, "SANITY_FAIL:SCAN_TOO_SHORT",
                                       {"scan_duration_s": scan_duration_s, "scan_min": scan_min, "pc_id": pc_id})

        if contact_required and (not contact_ok):
            return self._reject_simple(uid, fsm.state, EventType.XRF_REPORT_ACCEPTED, "SANITY_FAIL:CONTACT_NOT_OK",
                                       {"contact_ok": contact_ok, "pc_id": pc_id})

        # 3) Advance state
        tr = fsm.apply(EventType.XRF_REPORT_ACCEPTED)
        if not tr.accepted:
            return self._reject(uid, tr, reason=tr.reason, details={"pc_id": pc_id})

        # 4) Mark SeqID used (one-time)
        self.seq.mark_used(uid, seq_id)

        return self._accept(uid, tr, details={
            "pc_id": pc_id,
            "seq_id": seq_id,
            "purity": purity,
            "scan_duration_s": scan_duration_s,
            "contact_ok": contact_ok,
        })

    def handle_slot_assigned(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> EnforcementDecision:
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        if fsm.state != AssetState.XRF_VERIFIED:
            return self._reject_simple(uid, fsm.state, EventType.SLOT_ASSIGNED, "STATE_NOT_XRF_VERIFIED", {"slot_id": slot_id})

        tr = fsm.apply(EventType.SLOT_ASSIGNED)
        if not tr.accepted:
            return self._reject(uid, tr, reason=tr.reason, details={"slot_id": slot_id})

        return self._accept(uid, tr, details={"slot_id": slot_id})

    def handle_storage_confirmed(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> EnforcementDecision:
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        if fsm.state != AssetState.SLOT_BOUND:
            return self._reject_simple(uid, fsm.state, EventType.STORAGE_CONFIRMED, "STATE_NOT_SLOT_BOUND", {"slot_id": slot_id})

        tr = fsm.apply(EventType.STORAGE_CONFIRMED)
        if not tr.accepted:
            return self._reject(uid, tr, reason=tr.reason, details={"slot_id": slot_id})

        return self._accept(uid, tr, details={"slot_id": slot_id})

    def handle_slot_motion(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> EnforcementDecision:
        """
        Motion is a security alert. It should not advance state.
        Accept as ALERT for audit and evaluation.
        """
        fsm = self._get_fsm(uid)
        t = ts_utc or self._now_iso()

        tr = fsm.apply(EventType.SLOT_MOTION)
        # tr.accepted should be True (non-transition event), but we don't rely on it
        return EnforcementDecision(
            decision=Decision.ALERT,
            reason="SLOT_MOTION_DETECTED",
            asset_id=uid,
            prev_state=tr.prev_state,
            next_state=tr.next_state,
            event=EventType.SLOT_MOTION,
            timestamp_utc=t,
            details={"slot_id": slot_id},
        )

    # -------------------------------
    # Helpers
    # -------------------------------

    def _accept(self, uid: str, tr: TransitionResult, details: Dict[str, Any]) -> EnforcementDecision:
        return EnforcementDecision(
            decision=Decision.ACCEPT,
            reason=tr.reason,
            asset_id=uid,
            prev_state=tr.prev_state,
            next_state=tr.next_state,
            event=tr.event,
            timestamp_utc=self._now_iso(),
            details=details,
        )

    def _reject(self, uid: str, tr: TransitionResult, reason: str, details: Dict[str, Any]) -> EnforcementDecision:
        return EnforcementDecision(
            decision=Decision.REJECT,
            reason=reason,
            asset_id=uid,
            prev_state=tr.prev_state,
            next_state=tr.next_state,
            event=tr.event,
            timestamp_utc=self._now_iso(),
            details=details,
        )

    def _reject_simple(self, uid: str, prev_state: AssetState, event: EventType, reason: str, details: Dict[str, Any]) -> EnforcementDecision:
        return EnforcementDecision(
            decision=Decision.REJECT,
            reason=reason,
            asset_id=uid,
            prev_state=prev_state,
            next_state=prev_state,
            event=event,
            timestamp_utc=self._now_iso(),
            details=details,
        )
