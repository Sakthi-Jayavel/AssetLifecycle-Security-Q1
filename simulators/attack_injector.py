import random
from typing import List
from simulators.rfid_stream_sim import RFIDEvent

def inject_replay(events: List[RFIDEvent], rate=0.1):
    replayed = []
    for e in events:
        replayed.append(e)
        if random.random() < rate:
            replayed.append(e)  # exact replay
    return replayed

def inject_delay(events: List[RFIDEvent], max_delay=5):
    delayed = []
    for e in events:
        delay = random.uniform(0, max_delay)
        delayed.append(
            RFIDEvent(
                ts_event=e.ts_event,
                ts_arrival=e.ts_arrival + delay,
                reader_id=e.reader_id,
                uid=e.uid,
                window_id=e.window_id,
            )
        )
    return delayed

def inject_uid_mismatch(events: List[RFIDEvent], rate=0.05):
    tampered = []
    for e in events:
        if random.random() < rate:
            tampered.append(
                RFIDEvent(
                    ts_event=e.ts_event,
                    ts_arrival=e.ts_arrival,
                    reader_id=e.reader_id,
                    uid="FAKE_UID",
                    window_id=e.window_id,
                )
            )
        else:
            tampered.append(e)
    return tampered
