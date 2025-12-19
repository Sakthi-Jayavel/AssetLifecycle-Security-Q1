# experiments/test_fsm.py
from core.state_machine import AssetLifecycleFSM, AssetState, EventType

fsm = AssetLifecycleFSM()

print("Initial:", fsm.state)
print(fsm.apply(EventType.RFID_READ))
print(fsm.apply(EventType.SEQ_ASSIGNED))
print(fsm.apply(EventType.XRF_REPORT_ACCEPTED))
print(fsm.apply(EventType.SLOT_ASSIGNED))
print(fsm.apply(EventType.STORAGE_CONFIRMED))
print("Final:", fsm.state)

# illegal example
fsm2 = AssetLifecycleFSM()
print(fsm2.apply(EventType.XRF_REPORT_ACCEPTED))  # should reject
