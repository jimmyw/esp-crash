"""Session-ticket tests: signing, expiry, and single use.

These carry the whole "who is connecting" story for the debug WebSocket, and
every failure mode below is one an attacker would try, so they are asserted
individually rather than through a happy-path round trip.
"""
import pytest

import gdb_tickets


@pytest.fixture
def signer():
    return gdb_tickets.TicketSigner("test-secret")


def test_round_trip(signer):
    gh_user, crash_id, jti = signer.verify(signer.issue("alice", 42))
    assert (gh_user, crash_id) == ("alice", 42)
    assert jti


def test_a_secret_is_mandatory():
    # An empty secret would sign everything with a predictable key, so this is
    # a startup failure rather than a default.
    with pytest.raises(ValueError):
        gdb_tickets.TicketSigner("")


def test_each_ticket_is_unique_even_for_the_same_user_and_crash(signer):
    a = signer.verify(signer.issue("alice", 42))[2]
    b = signer.verify(signer.issue("alice", 42))[2]
    assert a != b, "tickets must not be interchangeable, or one can be replayed"


@pytest.mark.parametrize("mutate", [
    lambda t: t[:-4] + "AAAA",          # tampered signature
    lambda t: t[5:],                    # truncated
    lambda t: "",                       # absent
    lambda t: "not-a-ticket",
])
def test_malformed_tickets_are_rejected(signer, mutate):
    with pytest.raises(gdb_tickets.InvalidTicket):
        signer.verify(mutate(signer.issue("alice", 42)))


def test_a_ticket_signed_with_another_key_is_rejected(signer):
    forged = gdb_tickets.TicketSigner("different-secret").issue("alice", 42)
    with pytest.raises(gdb_tickets.InvalidTicket):
        signer.verify(forged)


def test_an_expired_ticket_is_rejected(signer):
    token = signer.issue("alice", 42)
    with pytest.raises(gdb_tickets.InvalidTicket):
        gdb_tickets.TicketSigner("test-secret", ttl_seconds=-1).verify(token)


def test_the_user_cannot_be_swapped_without_resigning(signer):
    """The payload is signed, not encrypted - it is readable, which is fine
    (a username and a crash id are not secrets) but it must not be malleable."""
    token = signer.issue("alice", 42)
    import base64
    import json
    payload = token.split(".")[0]
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    assert decoded["u"] == "alice"          # readable, as expected
    decoded["u"] = "attacker"
    swapped = base64.urlsafe_b64encode(
        json.dumps(decoded).encode()).rstrip(b"=").decode()
    with pytest.raises(gdb_tickets.InvalidTicket):
        signer.verify(token.replace(payload, swapped))


# ------------------------------------------------------------- replay guard

def test_a_ticket_can_only_be_redeemed_once():
    guard = gdb_tickets.ReplayGuard()
    guard.consume("jti-1")
    with pytest.raises(gdb_tickets.InvalidTicket):
        guard.consume("jti-1")


def test_distinct_tickets_are_independent():
    guard = gdb_tickets.ReplayGuard()
    guard.consume("jti-1")
    guard.consume("jti-2")      # must not raise


def test_the_guard_is_bounded():
    # A flood of connection attempts must not grow this without limit.
    guard = gdb_tickets.ReplayGuard(maxsize=4)
    for i in range(100):
        guard.consume(f"jti-{i}")
    assert len(guard._seen) == 4


def test_the_guard_evicts_oldest_first():
    guard = gdb_tickets.ReplayGuard(maxsize=2)
    guard.consume("old")
    guard.consume("mid")
    guard.consume("new")            # evicts "old"
    guard.consume("old")            # so this is accepted again
    with pytest.raises(gdb_tickets.InvalidTicket):
        guard.consume("new")        # but the recent ones are still remembered
