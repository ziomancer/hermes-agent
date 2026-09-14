"""Generic safe-only native event construction, with actual gateway types."""

import uuid

import pytest

from hermes_cli.private_boundary import PrivateBoundaryError
from hermes_cli.private_conversation import AcceptedTurn, ConversationBinding
from plugins.platforms.whatsapp.adapter import WhatsAppAdapter


def turn(count=1, kind="command"):
    return AcceptedTurn(ConversationBinding(*(uuid.uuid4().hex for _ in range(3))),
                        tuple(uuid.uuid4().hex for _ in range(count)), kind)


@pytest.mark.parametrize("kind", ["command", "context", "control"])
def test_accepted_event_contains_only_safe_handles_and_preserves_all_members(kind):
    admitted = turn(12, kind)
    session, principal = uuid.uuid4().hex, uuid.uuid4().hex
    event = WhatsAppAdapter._build_accepted_event(admitted, session_ref=session,
                                                principal_ref=principal, chat_type="group")
    assert event.private_turn is admitted and len(event.private_turn.input_refs) == 12
    assert event.text == "[private input]" and event.raw_message is None
    assert not event.media_urls and not event.media_types
    assert event.source.chat_id == session and event.source.user_id == principal
    assert event.source.chat_name is None and event.source.user_name is None
    assert event.source.chat_id_alt is None and event.source.user_id_alt is None
    assert event.source.role_authorized is False
    assert event.source.delivered_via_upstream_relay is False


@pytest.mark.parametrize("change", [
    {"session_ref": "15550000001@s.whatsapp.net"},
    {"principal_ref": "raw sender"}, {"chat_type": []}, {"chat_type": "channel"},
    {"session_ref": None},
])
def test_safe_event_builder_rejects_raw_or_malformed_routing(change):
    arguments = {"session_ref": uuid.uuid4().hex, "principal_ref": uuid.uuid4().hex, "chat_type": "dm"}
    with pytest.raises(PrivateBoundaryError):
        WhatsAppAdapter._build_accepted_event(turn(), **(arguments | change))


def test_safe_event_builder_rejects_oversized_execution_group():
    with pytest.raises(PrivateBoundaryError):
        WhatsAppAdapter._build_accepted_event(turn(13), session_ref=uuid.uuid4().hex,
                                            principal_ref=uuid.uuid4().hex, chat_type="dm")
