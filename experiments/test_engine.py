# experiments/test_engine.py
from core.seqid_manager import SeqIdManager
from core.enforcement_engine import AssetLifecycleEnforcementEngine

# thresholds (same meaning as config/system_config.yaml)
THRESHOLDS = {
    "purity_min_percent": 99.0,
    "scan_duration_min_seconds": 8,
    "contact_required": True,
}

seq = SeqIdManager(start_counter=1, validity_minutes=20)
engine = AssetLifecycleEnforcementEngine(seq)

uid = "UID123"

print("1) RFID:", engine.handle_rfid_read(uid=uid, gateway_id="GW01"))
print("2) SEQ:", engine.handle_seq_request(uid=uid))

# valid XRF
print("3) XRF OK:", engine.handle_xrf_report(
    uid=uid,
    seq_id=1,
    purity=99.6,
    scan_duration_s=10,
    contact_ok=True,
    pc_id="PC01",
    thresholds=THRESHOLDS
))

print("4) SLOT:", engine.handle_slot_assigned(uid=uid, slot_id="S-07"))
print("5) STORED:", engine.handle_storage_confirmed(uid=uid, slot_id="S-07"))

# post-storage motion -> ALERT
print("6) MOTION:", engine.handle_slot_motion(uid=uid, slot_id="S-07"))

# illegal example: try XRF without proper state for a new UID
uid2 = "UID999"
print("Illegal XRF:", engine.handle_xrf_report(
    uid=uid2, seq_id=1, purity=99.9, scan_duration_s=12, contact_ok=True, pc_id="PC01", thresholds=THRESHOLDS
))
