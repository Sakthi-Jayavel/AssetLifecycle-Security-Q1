from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.enforcement_engine import EnforcementDecision


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    """
    Logs:
      1) raw events (append-only file)
      2) decisions (append-only file)
      3) structured decisions in SQLite (queryable for results tables)
    """

    def __init__(self, db_path: str, event_log_path: str, decision_log_path: str) -> None:
        self.db_path = db_path
        self.event_log_path = event_log_path
        self.decision_log_path = decision_log_path

        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs(os.path.dirname(event_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(decision_log_path), exist_ok=True)

        self._init_db()

    def _init_db(self) -> None:
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            event TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            prev_state TEXT NOT NULL,
            next_state TEXT NOT NULL,
            details_json TEXT NOT NULL
        )
        """)
        con.commit()
        con.close()

    def log_event(self, event: Dict[str, Any]) -> None:
        record = {"timestamp_utc": _now_iso(), **event}
        with open(self.event_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def log_decision(self, d: EnforcementDecision) -> None:
        # file log
        record = asdict(d)
        with open(self.decision_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        # sqlite log
        con = sqlite3.connect(self.db_path)
        cur = con.cursor()
        cur.execute(
            """
            INSERT INTO decisions (timestamp_utc, asset_id, event, decision, reason, prev_state, next_state, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d.timestamp_utc,
                d.asset_id,
                d.event.value,
                d.decision.value,
                d.reason,
                d.prev_state.value,
                d.next_state.value,
                json.dumps(d.details),
            ),
        )
        con.commit()
        con.close()
