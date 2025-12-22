from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import yaml


@dataclass(frozen=True)
class SystemConfig:
    seq_validity_minutes: int
    seq_start_counter: int

    purity_min_percent: float
    scan_duration_min_seconds: int
    contact_required: bool

    db_path: str
    event_log_path: str
    decision_log_path: str


def load_system_config(path: str = "config/system_config.yaml") -> SystemConfig:
    with open(path, "r", encoding="utf-8") as f:
        cfg: Dict[str, Any] = yaml.safe_load(f)

    seq = cfg.get("seqid", {})
    sanity = cfg.get("sanity_checks", {})
    logging = cfg.get("logging", {})

    return SystemConfig(
        seq_validity_minutes=int(seq.get("validity_minutes", 20)),
        seq_start_counter=int(seq.get("start_counter", 1)),

        purity_min_percent=float(sanity.get("purity_min_percent", 99.0)),
        scan_duration_min_seconds=int(sanity.get("scan_duration_min_seconds", 8)),
        contact_required=bool(sanity.get("contact_required", True)),

        db_path=str(logging.get("db_path", "logs/audit.sqlite")),
        event_log_path=str(logging.get("event_log_path", "logs/events.log")),
        decision_log_path=str(logging.get("decision_log_path", "logs/decisions.log")),
    )
