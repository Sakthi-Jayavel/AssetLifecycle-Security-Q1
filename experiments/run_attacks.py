# experiments/run_attacks.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from server.config_loader import load_system_config
from server.audit_logger import AuditLogger
from core.seqid_manager import SeqIdManager
from core.enforcement_engine import AssetLifecycleEnforcementEngine
from core.baseline_engine import BaselineEngine
from attacks.attack_cases import (
    replay_event, delay_seconds, uid_mismatch,
    purity_manipulation, scan_too_short, contact_fail
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def add_delay(ts_iso: str, sec: int) -> str:
    t = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    return (t + timedelta(seconds=sec)).isoformat()

cfg = load_system_config("config/system_config.yaml")

# Proposed engine + logger
seq = SeqIdManager(start_counter=cfg.seq_start_counter, validity_minutes=cfg.seq_validity_minutes)
proposed = AssetLifecycleEnforcementEngine(seq)
logger_prop = AuditLogger(
    db_path="logs/audit_proposed.sqlite",
    event_log_path="logs/events_proposed.log",
    decision_log_path="logs/decisions_proposed.log"
)

# Baseline engine + logger
baseline = BaselineEngine()
logger_base = AuditLogger(
    db_path="logs/audit_baseline.sqlite",
    event_log_path="logs/events_baseline.log",
    decision_log_path="logs/decisions_baseline.log"
)

TH = {
    "purity_min_percent": cfg.purity_min_percent,
    "scan_duration_min_seconds": cfg.scan_duration_min_seconds,
    "contact_required": cfg.contact_required,
}

# ---- Build a clean normal workflow to capture "valid" event payloads ----
uid = "UID123"
gateway_id = "GW01"
pc_id = "PC01"
slot_id = "S-07"

ts0 = now_iso()

# Proposed normal (get seq_id)
logger_prop.log_event({"type": "RFID_READ", "uid": uid})
d1 = proposed.handle_rfid_read(uid=uid, gateway_id=gateway_id, ts_utc=ts0)
logger_prop.log_decision(d1)

d2 = proposed.handle_seq_request(uid=uid, ts_utc=ts0)
logger_prop.log_decision(d2)
seq_id = d2.details["seq_id"]

# Prepare a "valid XRF payload" (event payload used for attacks)
valid_xrf = {
    "uid": uid,
    "seq_id": seq_id,
    "purity": 99.6,
    "scan_duration_s": 10,
    "contact_ok": True,
    "pc_id": pc_id,
    "ts_utc": ts0
}

# ---- Define attack cases (we apply to XRF payload for now) ----
attacks = [
    replay_event(),
    delay_seconds(60 * 60),               # 1 hour delay
    uid_mismatch("UID999"),
    purity_manipulation(cfg.purity_min_percent - 0.5),
    scan_too_short(max(1, cfg.scan_duration_min_seconds - 3)),
    contact_fail(),
]

# ---- Execute attacks against Proposed + Baseline ----
for a in attacks:
    attacked = a.apply(valid_xrf)

    # apply delay if present
    ts_attack = attacked.get("ts_utc", ts0)
    if "delay_seconds" in attacked:
        ts_attack = add_delay(ts_attack, int(attacked["delay_seconds"]))

    # PROPOSED
    logger_prop.log_event({"type": "ATTACK", "attack": a.name, "payload": attacked})
    d = proposed.handle_xrf_report(
        uid=attacked["uid"],
        seq_id=int(attacked.get("seq_id", 0)),
        purity=float(attacked["purity"]),
        scan_duration_s=int(attacked["scan_duration_s"]),
        contact_ok=bool(attacked["contact_ok"]),
        pc_id=attacked["pc_id"],
        ts_utc=ts_attack,
        thresholds=TH
    )
    logger_prop.log_decision(d)

    # BASELINE (no seq_id used)
    logger_base.log_event({"type": "ATTACK", "attack": a.name, "payload": attacked})
    bd = baseline.xrf_report(
        uid=attacked["uid"],
        purity=float(attacked["purity"]),
        scan_duration_s=int(attacked["scan_duration_s"]),
        contact_ok=bool(attacked["contact_ok"]),
        pc_id=attacked["pc_id"],
        ts_utc=ts_attack
    )
    # Adapt baseline decision into EnforcementDecision-like JSON by logging dict
    # We'll just log it as details_json in sqlite using decision_log_path (file)
    # For sqlite, easiest: write baseline decisions as event logs only for now.
    with open("logs/decisions_baseline.log", "a", encoding="utf-8") as f:
        import json
        f.write(json.dumps({
            "decision": bd.decision.value,
            "reason": bd.reason,
            "asset_id": bd.asset_id,
            "prev_state": bd.stage,
            "next_state": bd.stage,
            "event": bd.event,
            "timestamp_utc": bd.timestamp_utc,
            "details": bd.details,
        }) + "\n")

print("DONE: attacks executed.")
print("Proposed logs: logs/decisions_proposed.log + logs/audit_proposed.sqlite")
print("Baseline logs: logs/decisions_baseline.log + logs/audit_baseline.sqlite (events) ")
