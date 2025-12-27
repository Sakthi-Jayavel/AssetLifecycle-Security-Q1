import random
import time
from dataclasses import dataclass
from typing import List

@dataclass
class RFIDEvent:
    ts_event: float
    ts_arrival: float
    reader_id: str
    uid: str
    window_id: int

class RFIDStreamSimulator:
    def __init__(
        self,
        n_tags=200,
        readers=("R1", "R2"),
        window_ms=200,
        p_read=0.9,
        p_dup=0.3,
        collision_threshold=50,
    ):
        self.n_tags = n_tags
        self.readers = readers
        self.window_ms = window_ms
        self.p_read = p_read
        self.p_dup = p_dup
        self.collision_threshold = collision_threshold
        self.tags = [f"UID{i}" for i in range(n_tags)]

    def simulate_window(self, window_id: int) -> List[RFIDEvent]:
        events = []
        now = time.time()

        for reader in self.readers:
            # tags currently in range
            in_range = random.sample(
                self.tags, k=random.randint(10, min(len(self.tags), 100))
            )

            # collision effect
            effective_p_read = self.p_read
            if len(in_range) > self.collision_threshold:
                effective_p_read *= 0.6  # collision loss

            for uid in in_range:
                if random.random() < effective_p_read:
                    # primary read
                    arrival_delay = random.uniform(0, 0.05)
                    events.append(
                        RFIDEvent(
                            ts_event=now,
                            ts_arrival=now + arrival_delay,
                            reader_id=reader,
                            uid=uid,
                            window_id=window_id,
                        )
                    )

                    # duplicate read
                    if random.random() < self.p_dup:
                        dup_delay = arrival_delay + random.uniform(0.01, 0.1)
                        events.append(
                            RFIDEvent(
                                ts_event=now,
                                ts_arrival=now + dup_delay,
                                reader_id=reader,
                                uid=uid,
                                window_id=window_id,
                            )
                        )

        random.shuffle(events)
        return events
