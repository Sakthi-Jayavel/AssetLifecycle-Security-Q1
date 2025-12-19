# core/state_machine.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Set, Tuple, Optional


class AssetState(str, Enum):
    UNREGISTERED = "UNREGISTERED"
    RFID_VERIFIED = "RFID_VERIFIED"
    SEQ_BOUND = "SEQ_BOUND"          # time-limited SeqID bound to UID
    XRF_VERIFIED = "XRF_VERIFIED"    # purity/sanity checks passed
    SLOT_BOUND = "SLOT_BOUND"        # physical slot assigned & bound
    STORED = "STORED"                # stored/locked state (monitoring active)


class EventType(str, Enum):
    RFID_READ = "RFID_READ"
    SEQ_ASSIGNED = "SEQ_ASSIGNED"
    XRF_REPORT_ACCEPTED = "XRF_REPORT_ACCEPTED"
    SLOT_ASSIGNED = "SLOT_ASSIGNED"
    STORAGE_CONFIRMED = "STORAGE_CONFIRMED"

    # anomaly-related events (do not advance state)
    SLOT_MOTION = "SLOT_MOTION"
    TAMPER = "TAMPER"


# Allowed transitions: (current_state, event) -> next_state
_ALLOWED: Dict[Tuple[AssetState, EventType], AssetState] = {
    (AssetState.UNREGISTERED, EventType.RFID_READ): AssetState.RFID_VERIFIED,
    (AssetState.RFID_VERIFIED, EventType.SEQ_ASSIGNED): AssetState.SEQ_BOUND,
    (AssetState.SEQ_BOUND, EventType.XRF_REPORT_ACCEPTED): AssetState.XRF_VERIFIED,
    (AssetState.XRF_VERIFIED, EventType.SLOT_ASSIGNED): AssetState.SLOT_BOUND,
    (AssetState.SLOT_BOUND, EventType.STORAGE_CONFIRMED): AssetState.STORED,
}

# Events that are valid to receive in any state but should NOT advance state
_NON_TRANSITION_EVENTS: Set[EventType] = {
    EventType.SLOT_MOTION,
    EventType.TAMPER,
}


@dataclass(frozen=True)
class TransitionResult:
    accepted: bool
    prev_state: AssetState
    event: EventType
    next_state: AssetState
    reason: str  # human-readable reason (useful for logs/paper)


class AssetLifecycleFSM:
    """
    Strict finite state machine for asset lifecycle enforcement.

    Key properties:
    - Only explicitly allowed transitions are permitted.
    - Non-transition events (e.g., SLOT_MOTION) are accepted but do not change state.
    - Everything else is rejected with a reason string (audit-friendly).
    """

    def __init__(self, initial: AssetState = AssetState.UNREGISTERED) -> None:
        self._state: AssetState = initial

    @property
    def state(self) -> AssetState:
        return self._state

    def can_apply(self, event: EventType) -> bool:
        if event in _NON_TRANSITION_EVENTS:
            return True
        return (self._state, event) in _ALLOWED

    def apply(self, event: EventType) -> TransitionResult:
        prev = self._state

        if event in _NON_TRANSITION_EVENTS:
            # Accept but do not advance.
            return TransitionResult(
                accepted=True,
                prev_state=prev,
                event=event,
                next_state=prev,
                reason="NON_TRANSITION_EVENT_ACCEPTED",
            )

        key = (prev, event)
        if key not in _ALLOWED:
            return TransitionResult(
                accepted=False,
                prev_state=prev,
                event=event,
                next_state=prev,
                reason=f"ILLEGAL_TRANSITION:{prev.value}->{event.value}",
            )

        nxt = _ALLOWED[key]
        self._state = nxt
        return TransitionResult(
            accepted=True,
            prev_state=prev,
            event=event,
            next_state=nxt,
            reason="STATE_ADVANCED",
        )

    @staticmethod
    def allowed_transitions() -> Dict[Tuple[AssetState, EventType], AssetState]:
        # returns a copy for safe external use (docs/figures/tests)
        return dict(_ALLOWED)
