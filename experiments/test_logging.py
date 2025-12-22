from core.seqid_manager import SeqIdManager
from core.enforcement_engine import AssetLifecycleEnforcementEngine
from server.config_loader import load_system_config
from server.audit_logger import AuditLogger

cfg = load_system_config("config/system_config.yaml")

seq = SeqIdManager(start_counter=cfg.seq_start_counter, validity_minutes=cfg.seq_validity_minutes)
engine = AssetLifecycleEnforcementEngine(seq)

logger = AuditLogger(db_path=cfg.db_path, event_log_path=cfg.event_log_path, decision_log_path=cfg.decision_log_path)

uid = "UID123"
gateway_id = "GW01"
pc_id = "PC01"
slot_id = "S-07"

# event + decision logging
logger.log_event({"type": "RFID_READ", "uid": uid, "gateway_id": gateway_id})
d1 = engine.handle_rfid_read(uid=uid, gateway_id=gateway_id)
logger.log_decision(d1)

logger.log_event({"type": "SEQ_REQUEST", "uid": uid})
d2 = engine.handle_seq_request(uid=uid)
logger.log_decision(d2)

seq_id = d2.details["seq_id"]

logger.log_event({"type": "XRF_REPORT", "uid": uid, "seq_id": seq_id, "pc_id": pc_id})
d3 = engine.handle_xrf_report(
    uid=uid,
    seq_id=seq_id,
    purity=99.6,
    scan_duration_s=10,
    contact_ok=True,
    pc_id=pc_id,
    thresholds={
        "purity_min_percent": cfg.purity_min_percent,
        "scan_duration_min_seconds": cfg.scan_duration_min_seconds,
        "contact_required": cfg.contact_required,
    }
)
logger.log_decision(d3)

logger.log_event({"type": "SLOT_ASSIGNED", "uid": uid, "slot_id": slot_id})
d4 = engine.handle_slot_assigned(uid=uid, slot_id=slot_id)
logger.log_decision(d4)

logger.log_event({"type": "STORAGE_CONFIRMED", "uid": uid, "slot_id": slot_id})
d5 = engine.handle_storage_confirmed(uid=uid, slot_id=slot_id)
logger.log_decision(d5)

logger.log_event({"type": "SLOT_MOTION", "uid": uid, "slot_id": slot_id})
d6 = engine.handle_slot_motion(uid=uid, slot_id=slot_id)
logger.log_decision(d6)

print("DONE. Check logs/ and audit sqlite:", cfg.db_path)
