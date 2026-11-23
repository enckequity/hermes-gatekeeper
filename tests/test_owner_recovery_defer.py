"""Owner-identity commands, automatic storage recovery, engine-neutral wording,
the keyword list and deferred approvals."""
import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_service import service, seed, payload
from test_inbound import source

ROOT = Path(__file__).resolve().parents[1]
OWNER = "relay:owner-1"


def owned(service, *ids):
    service.settings = replace(service.settings, owner_ids=tuple(ids or (OWNER,)))
    return service


def suppressed(service):
    with service.ledger.transaction() as db:
        return db.execute("select count(*) from suppressions").fetchone()[0]


# 1. Owner identity from an authenticated messaging session

@pytest.mark.parametrize("src", [
    {"platform": "relay", "chat_id": "c", "chat_type": "dm", "user_id": "owner-1"},
    SimpleNamespace(platform=SimpleNamespace(value="relay"), chat_id="c", chat_type="dm", user_id="owner-1"),
])
def test_configured_owner_manages_consent_and_optout_from_a_direct_chat(service, src):
    owned(service)
    assert "consent recorded" in service.command("consent +1-555-0100 sms portal 2026-01-01 UTC", platform="relay", source=src)
    assert service.before("send_message", payload()) is None
    assert "suppressed" in service.command("optout +1-555-0100", platform="relay", source=src)
    assert service.before("send_message", payload())["action"] == "block"
    assert "ready" in service.command("", platform="relay", source=src)


@pytest.mark.parametrize("platform,src", [
    ("relay", {"platform": "relay", "chat_type": "dm", "user_id": "someone-else"}),
    ("relay", {"platform": "relay", "chat_type": "group", "user_id": "owner-1"}),  # read out to a group
    ("relay", {"platform": "telegram", "chat_type": "dm", "user_id": "owner-1"}),  # platform disagrees
    ("telegram", {"platform": "telegram", "chat_type": "dm", "user_id": "owner-1"}),  # same id, other platform
    ("relay", {"platform": "relay", "chat_type": "dm"}),
    ("relay", {"platform": "relay", "chat_type": "dm", "user_id": ""}),
    ("relay", None),
    ("", {"platform": "", "chat_type": "dm", "user_id": "owner-1"}),
])
def test_anyone_but_the_configured_owner_is_refused(service, platform, src):
    owned(service)
    assert "Only the owner can" in service.command("optout +1-555-0100", platform=platform, source=src)
    assert suppressed(service) == 0


def test_no_owner_ids_keeps_messaging_sessions_refused(service):
    src = {"platform": "relay", "chat_type": "dm", "user_id": "owner-1"}
    assert "Only the owner can" in service.command("optout +1-555-0100", platform="relay", source=src)
    assert suppressed(service) == 0


@pytest.mark.parametrize("ids", ["relay:owner-1", ["relay"], ["relay:"], ["Relay:x"], ["relay: x"], [1]])
def test_owner_ids_setting_is_validated(ids):
    from gatekeeper.config import Settings
    with pytest.raises(ValueError):
        Settings.parse({"owner_ids": ids})
    assert Settings.parse({"owner_ids": ["relay:owner-1", "matrix:@a:b.org"]}).owner_ids == ("relay:owner-1", "matrix:@a:b.org")


# 2. Inbound/observation failures alert and recover by themselves

def broken(service):
    connect = service.ledger.connect
    service.ledger.connect = lambda: (_ for _ in ()).throw(OSError("synthetic failure"))
    return connect


def later(service, seconds):
    at = service.now() + timedelta(seconds=seconds)
    service.now = lambda: at


def test_missed_stop_alerts_holds_sends_then_recovers_and_saves_the_stop(service, caplog):
    seed(service)
    connect = broken(service)
    with caplog.at_level(logging.ERROR, logger="hermes-gatekeeper"):
        assert service.inbound(platform="sms", source=source(), message_id="1", text="STOP") == {"action": "handled"}
    assert any("ALERT" in r.message and "opt-out could not be saved" in r.message for r in caplog.records)
    service.ledger.connect = connect
    assert "gate_unavailable" in service.before("send_message", payload())["message"]  # inside the backoff
    later(service, 5)
    result = service.before("send_message", payload())
    assert result["action"] == "block" and "suppressed" in result["message"]  # recovered, and the STOP was kept
    assert not service.unhealthy.is_set()


def test_missed_reply_recovers_without_owner(service):
    seed(service)
    connect = broken(service)
    assert service.inbound(platform="sms", source=source(), message_id="1", text="synthetic reply") is None
    service.ledger.connect = connect
    later(service, 5)
    assert service.before("send_message", payload()) is None


def test_failed_send_observation_recovers(service):
    seed(service)
    service.before("send_message", payload(), tool_call_id="one")
    connect = broken(service)
    service.after("send_message", payload(), result='{"success":true}', status="ok", tool_call_id="one")
    assert service.unhealthy.is_set()
    service.ledger.connect = connect
    later(service, 5)
    # Recovered; the unconfirmed send still counts as pending, so a second text asks.
    assert service.before("send_message", payload())["action"] == "approve"


def test_backoff_doubles_and_is_bounded_while_storage_stays_down(service):
    seed(service)
    broken(service)
    service.inbound(platform="sms", source=source(), message_id="1", text="synthetic reply")
    delays = []
    for _ in range(10):
        later(service, service._retry_delay)
        assert service.before("send_message", payload())["action"] == "block"
        delays.append(service._retry_delay)
    assert delays[:4] == [10, 20, 40, 80] and max(delays) == 300 == delays[-1]


def test_stop_without_a_sender_waits_for_the_owner_resume(service):
    seed(service)
    assert service.inbound(platform="sms", source={}, message_id="1", text="STOP") == {"action": "handled"}
    later(service, 3600)
    assert service.before("send_message", payload())["action"] == "block"
    assert "tied to a sender" in service.command("", platform="cli")
    assert "sends resume" in service.command("resume", platform="cli")
    assert service.before("send_message", payload()) is None
    assert "nothing to resume" in service.command("resume", platform="cli")


def test_resume_with_storage_still_down_keeps_blocking(service):
    seed(service)
    broken(service)
    service.inbound(platform="sms", source=source(), message_id="1", text="STOP")
    assert "Sends stay blocked" in service.command("resume", platform="cli")
    assert service.unhealthy.is_set()


# 3. No user-visible text names the engine

def test_messages_never_name_the_engine(service):
    seed(service, zone="")
    asked = service.before("send_message", payload(message="unapproved synthetic"))
    assert asked["action"] == "approve" and asked["message"].endswith("Owner approval required.")
    refused = service.command("log", platform="telegram", source=None)
    for text in (asked["message"], refused, service.command("", platform="cli"), service.command("bogus", platform="cli"),
                 service.before("connectors__gmail__send_email", {"to": "x"})["message"]):
        assert "hermes" not in text.lower()


def test_runtime_string_literals_never_name_the_engine():
    # Docstrings and the lowercase program names the classifier matches are not shown to anyone.
    for path in [ROOT / "__init__.py", *(ROOT / "gatekeeper").glob("*.py")]:
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and n.body
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                assert "Hermes" not in node.value, (path.name, node.value)


# 4. Keyword list

@pytest.mark.parametrize("text", ["REVOKE", "optout", "Opt out", "opt-out", "OPT_OUT", "Stop.", "stop!", "Stop All", "unsubscribe "])
def test_revocation_keywords_and_common_spellings(text):
    from gatekeeper.suppression import is_stop
    assert is_stop(text)


@pytest.mark.parametrize("text", ["stop it", "don't stop", "cancel my appointment", "the end?", "opt in", ""])
def test_ordinary_messages_are_not_opt_outs(text):
    from gatekeeper.suppression import is_stop
    assert not is_stop(text)


def test_default_keywords_match_the_manifest_and_custom_keywords_normalize():
    import yaml
    from gatekeeper.config import Settings
    from gatekeeper.suppression import KEYWORDS
    manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
    assert tuple(manifest["config_schema"]["stop_keywords"]["default"]) == KEYWORDS
    assert {"CANCEL", "REVOKE", "OPTOUT", "STOP", "STOPALL", "UNSUBSCRIBE", "END", "QUIT"} == set(KEYWORDS)
    assert Settings.parse({"stop_keywords": ["opt-out"]}).stop_keywords == ("OPTOUT",)


# Coexistence: defer_approvals never asks a second time

@pytest.fixture
def deferring(service):
    service.settings = replace(service.settings, defer_approvals=True)
    return service


def test_deferred_wording_and_unknown_zone_are_logged_not_asked(deferring):
    seed(deferring, zone="")
    assert deferring.before("send_message", payload(message="unapproved synthetic")) is None
    with deferring.ledger.transaction() as db:
        row = db.execute("select rule, outcome from decisions order by id desc").fetchone()
        assert (row["rule"], row["outcome"]) == ("deferred:unknown_timezone", "pass")


def test_deferred_mode_blocks_double_texts_instead_of_asking(deferring):
    seed(deferring)
    assert deferring.before("send_message", payload(), tool_call_id="one") is None
    deferring.after("send_message", payload(), result=json.dumps({"success": True}), status="ok", tool_call_id="one")
    result = deferring.before("send_message", payload(), tool_call_id="two")
    assert result["action"] == "block" and "unanswered" in result["message"]
    deferring.inbound(platform="sms", source=source(), message_id="r1", text="synthetic reply")
    assert deferring.before("send_message", payload(), tool_call_id="three") is None


def test_deferred_mode_keeps_hard_blocks(deferring):
    seed(deferring, zone="Pacific/Honolulu")  # 06:00 recipient-local
    assert "quiet_hours" in deferring.before("send_message", payload(message="unapproved synthetic"))["message"]
    assert deferring.before("send_message", payload("+1-555-0199"))["action"] == "block"  # no consent
    deferring.inbound(platform="sms", source=source(), message_id="s", text="revoke")
    assert "suppressed" in deferring.before("send_message", payload())["message"]


def test_settings_accept_defer_flag_only_as_bool():
    from gatekeeper.config import Settings
    assert Settings.parse({"defer_approvals": True}).defer_approvals is True
    with pytest.raises(ValueError):
        Settings.parse({"defer_approvals": "yes"})
