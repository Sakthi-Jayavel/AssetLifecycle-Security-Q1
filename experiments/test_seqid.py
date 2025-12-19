# experiments/test_seqid.py
from datetime import timedelta
from core.seqid_manager import SeqIdManager

m = SeqIdManager(start_counter=1, validity_minutes=20)

uid = "UID123"
b = m.issue(uid)
print("Issued:", b)

print("Validate OK:", m.validate(uid, b.seq_id))

# mark used
print("Mark used:", m.mark_used(uid, b.seq_id))
print("Validate after used:", m.validate(uid, b.seq_id))

# new issue after used should give new seq
b2 = m.issue(uid)
print("Issued new:", b2)
print("Validate new:", m.validate(uid, b2.seq_id))

# expiry simulation
fake_now = b2.expires_at + timedelta(seconds=1)
print("Validate expired:", m.validate(uid, b2.seq_id, now=fake_now))
