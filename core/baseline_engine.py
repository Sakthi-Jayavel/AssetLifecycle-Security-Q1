# core/baseline_engine.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class Decision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    ALERT = "ALERT"


@dataclass(frozen=True)
class BaselineDecision:
    decision: Decision
    reason: str
    asset_id: str
    stage: str
    event: str
    timestamp_utc: str
    details: Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaselineEngine:
    """
    Baseline system (intentionally weaker):
    - No SeqID time-binding
    - Minimal ordering (accepts XRF without requiring Seq-bound freshness)
    - Accepts most workflow events if fields look present
    This is used ONLY for comparison in experiments.
    """

    def __init__(self) -> None:
        self._stage: Dict[str, str] = {}  # uid -> stage string

    def _get_stage(self, uid: str) -> str:
        return self._stage.get(uid, "UNREGISTERED")

    def _set_stage(self, uid: str, stage: str) -> None:
        self._stage[uid] = stage

    def rfid_read(self, uid: str, gateway_id: str, ts_utc: Optional[str] = None) -> BaselineDecision:
        t = ts_utc or _now_iso()
        self._set_stage(uid, "RFID_VERIFIED")
        return BaselineDecision(Decision.ACCEPT, "RFID_OK", uid, self._get_stage(uid), "RFID_READ", t, {"gateway_id": gateway_id})

    def xrf_report(self, uid: str, purity: float, scan_duration_s: int, contact_ok: bool, pc_id: str, ts_utc: Optional[str] = None) -> BaselineDecision:
        # Baseline accepts XRF as long as values exist; weak checks
        t = ts_utc or _now_iso()
        if not uid:
            return BaselineDecision(Decision.REJECT, "NO_UID", uid, self._get_stage(uid), "XRF_REPORT", t, {"pc_id": pc_id})
        self._set_stage(uid, "XRF_VERIFIED")
        return BaselineDecision(Decision.ACCEPT, "XRF_OK_BASELINE", uid, self._get_stage(uid), "XRF_REPORT", t,
                               {"pc_id": pc_id, "purity": purity, "scan_duration_s": scan_duration_s, "contact_ok": contact_ok})

    def slot_assigned(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> BaselineDecision:
        t = ts_utc or _now_iso()
        self._set_stage(uid, "SLOT_BOUND")
        return BaselineDecision(Decision.ACCEPT, "SLOT_OK_BASELINE", uid, self._get_stage(uid), "SLOT_ASSIGNED", t, {"slot_id": slot_id})

    def storage_confirmed(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> BaselineDecision:
        t = ts_utc or _now_iso()
        self._set_stage(uid, "STORED")
        return BaselineDecision(Decision.ACCEPT, "STORED_OK_BASELINE", uid, self._get_stage(uid), "STORAGE_CONFIRMED", t, {"slot_id": slot_id})

    def slot_motion(self, uid: str, slot_id: str, ts_utc: Optional[str] = None) -> BaselineDecision:
        t = ts_utc or _now_iso()
        # baseline treats motion as info only (still ALERT)
        return BaselineDecision(Decision.ALERT, "SLOT_MOTION_BASELINE", uid, self._get_stage(uid), "SLOT_MOTION", t, {"slot_id": slot_id})
