from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from typing import Dict, List, Tuple

import pandas as pd
import matplotlib.pyplot as plt


PROPOSED_DB = "logs/audit_proposed.sqlite"
PROPOSED_DECISIONS_LOG = "logs/decisions_proposed.log"
BASELINE_DECISIONS_LOG = "logs/decisions_baseline.log"

OUT_TABLE_DIR = "results/tables"
OUT_GRAPH_DIR = "results/graphs"


def read_jsonl(path: str) -> List[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def read_proposed_decisions_sqlite(db_path: str) -> pd.DataFrame:
    con = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM decisions", con)
    con.close()
    return df


def main() -> None:
    os.makedirs(OUT_TABLE_DIR, exist_ok=True)
    os.makedirs(OUT_GRAPH_DIR, exist_ok=True)

    # 1) Load proposed sqlite decisions (authoritative structured store)
    df_prop = read_proposed_decisions_sqlite(PROPOSED_DB)

    # 2) Load proposed "attack events" from events_proposed.log (to know attack labels)
    attack_events = read_jsonl("logs/events_proposed.log")
    # Extract only attack entries
    attack_payloads = []
    for e in attack_events:
        if e.get("type") == "ATTACK":
            attack_payloads.append(e)

    # Map (timestamp, uid, pc_id maybe) -> attack name
    # We use order-based alignment: each ATTACK event is followed by one XRF decision in decisions log.
    prop_decisions_log = read_jsonl(PROPOSED_DECISIONS_LOG)
    xrf_decisions = [d for d in prop_decisions_log if d.get("event") == "XRF_REPORT_ACCEPTED"]

    # Align attacks to xrf decisions by index (safe because run_attacks logs in same loop)
    n = min(len(attack_payloads), len(xrf_decisions))
    aligned = []
    for i in range(n):
        aligned.append({
            "attack": attack_payloads[i]["attack"],
            "proposed_decision": xrf_decisions[i]["decision"],
            "proposed_reason": xrf_decisions[i]["reason"],
        })

    df_align = pd.DataFrame(aligned)

    # 3) Baseline decisions log (we wrote XRF decisions directly there)
    base_log = read_jsonl(BASELINE_DECISIONS_LOG)
    base_xrf = [d for d in base_log if d.get("event") == "XRF_REPORT"]
    # Align by index too (same attack loop order)
    m = min(len(df_align), len(base_xrf))
    df_align = df_align.iloc[:m].copy()
    df_align["baseline_decision"] = [base_xrf[i]["decision"] for i in range(m)]
    df_align["baseline_reason"] = [base_xrf[i]["reason"] for i in range(m)]

    # 4) Detection = Proposed rejected OR alerted for malicious case
    # Here: attacks should be rejected (except REPLAY may be rejected due to used seq, etc.)
    df_align["proposed_detected"] = df_align["proposed_decision"].isin(["REJECT", "ALERT"])
    df_align["baseline_detected"] = df_align["baseline_decision"].isin(["REJECT", "ALERT"])

    # 5) Aggregate: detection rate per attack
    agg = df_align.groupby("attack").agg(
        attacks=("attack", "count"),
        proposed_detected=("proposed_detected", "sum"),
        baseline_detected=("baseline_detected", "sum"),
    ).reset_index()

    agg["proposed_detection_rate"] = (agg["proposed_detected"] / agg["attacks"]) * 100.0
    agg["baseline_detection_rate"] = (agg["baseline_detected"] / agg["attacks"]) * 100.0

    # Save table
    out_csv = os.path.join(OUT_TABLE_DIR, "attack_detection.csv")
    agg.to_csv(out_csv, index=False)

    # 6) Reason distribution for proposed (why rejected)
    reason_counts = df_align.groupby(["attack", "proposed_reason"]).size().reset_index(name="count")
    out_reason_csv = os.path.join(OUT_TABLE_DIR, "proposed_reason_distribution.csv")
    reason_counts.to_csv(out_reason_csv, index=False)

    # 7) Plot: detection rate bar chart (proposed vs baseline)
    # Keep it simple and readable
    attacks = agg["attack"].tolist()
    x = range(len(attacks))

    plt.figure()
    plt.bar([i - 0.2 for i in x], agg["baseline_detection_rate"], width=0.4, label="Baseline")
    plt.bar([i + 0.2 for i in x], agg["proposed_detection_rate"], width=0.4, label="Proposed")

    plt.xticks(list(x), attacks, rotation=30, ha="right")
    plt.ylabel("Detection rate (%)")
    plt.title("Attack detection rate: Proposed vs Baseline")
    plt.legend()
    plt.tight_layout()

    out_png = os.path.join(OUT_GRAPH_DIR, "detection_rate.png")
    plt.savefig(out_png, dpi=300)
    plt.close()

    print("RESULTS GENERATED:")
    print(" -", out_csv)
    print(" -", out_reason_csv)
    print(" -", out_png)


if __name__ == "__main__":
    main()
