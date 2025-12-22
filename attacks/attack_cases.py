# attacks/attack_cases.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Callable, List


@dataclass(frozen=True)
class AttackCase:
    name: str
    description: str
    apply: Callable[[Dict[str, Any]], Dict[str, Any]]  # transforms an event payload


def replay_event() -> AttackCase:
    return AttackCase(
        name="REPLAY",
        description="Replay a previously valid event payload without change.",
        apply=lambda e: dict(e),
    )


def delay_seconds(seconds: int) -> AttackCase:
    # we simulate delay by forcing the engine to validate using the same payload but later timestamp
    return AttackCase(
        name=f"DELAY_{seconds}s",
        description="Delay event timestamp to simulate stale delivery (expiry / delay attack).",
        apply=lambda e: {**e, "delay_seconds": seconds},
    )


def uid_mismatch(new_uid: str) -> AttackCase:
    return AttackCase(
        name="UID_MISMATCH",
        description="Change UID inside event to create UID/Seq mismatch scenario.",
        apply=lambda e: {**e, "uid": new_uid},
    )


def purity_manipulation(new_purity: float) -> AttackCase:
    return AttackCase(
        name="PURITY_MANIPULATION",
        description="Manipulate purity value below threshold to trigger sanity failure.",
        apply=lambda e: {**e, "purity": new_purity},
    )


def scan_too_short(new_scan_s: int) -> AttackCase:
    return AttackCase(
        name="SCAN_TOO_SHORT",
        description="Reduce scan duration to below sanity threshold.",
        apply=lambda e: {**e, "scan_duration_s": new_scan_s},
    )


def contact_fail() -> AttackCase:
    return AttackCase(
        name="CONTACT_FAIL",
        description="Set contact_ok False to simulate improper XRF contact.",
        apply=lambda e: {**e, "contact_ok": False},
    )
