# experiments/run_experiment.py

from simulators.rfid_stream_sim import RFIDStreamSimulator
from simulators.attack_injector import (
    inject_replay,
    inject_delay,
    inject_uid_mismatch,
)
from core.state_machine import RFIDStateMachine
from core.enforcement_engine import EnforcementEngine


def run_experiment(tag_count, label):
    sim = RFIDStreamSimulator(n_tags=tag_count)
    fsm = RFIDStateMachine()
    engine = EnforcementEngine(fsm)

    total_events = 0

    for window in range(50):
        events = sim.simulate_window(window)

        # attacks
        events = inject_replay(events, rate=0.15)
        events = inject_delay(events)
        events = inject_uid_mismatch(events)

        for event in events:
            total_events += 1
            engine.enforce(event)

    print(f"\nScenario: {label}")
    print(f"Total events : {total_events}")
    print(f"Allowed      : {engine.allowed}")
    print(f"Blocked      : {engine.blocked}")
    print(f"Block rate   : {engine.blocked / total_events:.2%}")


if __name__ == "__main__":
    run_experiment(50, "Low density")
    run_experiment(300, "Medium density")
    run_experiment(1000, "High density")
