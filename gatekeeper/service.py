"""Public hook policy orchestration. The host, never this plugin, sends."""
from datetime import datetime, timezone
import json
import logging
from threading import Event, Lock

from . import consent, double_text, escalate, history, quiet_hours, suppression, wording
from .classify import classify, Uninspectable
from .storage import body_hash

logger = logging.getLogger("hermes-gatekeeper")
RANK = {"pass": 0, "approve": 1, "block": 2}
RETRY_FIRST, RETRY_MAX = 5, 300  # seconds between automatic storage recovery attempts
HOLDS = {"unanswered", "minimum_gap"}  # double-text rules; block instead of asking when approvals are deferred


def call_key(tool_name, args, context):
    return body_hash(json.dumps([tool_name, args, context.get("session_id", ""),
                                context.get("task_id", ""), context.get("tool_call_id", "")],
                               sort_keys=True, ensure_ascii=True, separators=(",", ":")))


def directive(outcome, rules, key=""):
    if outcome == "pass":
        return None
    result = {"action": outcome, "message": "Gatekeeper: " + ", ".join(sorted(set(rules))) +
              (". Send blocked." if outcome == "block" else ". Owner approval required.")}
    if outcome == "approve":
        result["rule_key"] = "gatekeeper:" + key
    return result


class Gatekeeper:
    def __init__(self, settings, ledger, *, now=None, config_error=False):
        self.settings, self.ledger = settings, ledger
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.config_error = config_error
        self.unhealthy = Event()
        self.health_reason = ""
        self._health = Lock()
        self._held_stops = []    # (platform, targets, text) opt-outs to save once storage answers again
        self._latched = False    # an opt-out that names no sender: only the owner's resume clears it
        self._retry_at, self._retry_delay = 0.0, RETRY_FIRST

    def mark_unhealthy(self, reason, *, stop=None, latch=False):
        """Block every recognized send and alert; recovery is retried with bounded backoff."""
        with self._health:
            if stop:
                self._held_stops.append(stop)
            self._latched = self._latched or latch
            if not self.unhealthy.is_set():
                self._retry_delay = RETRY_FIRST
                self._retry_at = self.now().timestamp() + RETRY_FIRST
            self.health_reason = reason
            self.unhealthy.set()
            retry = "after the owner runs /gatekeeper resume" if self._latched else f"automatically in {self._retry_delay}s"
        logger.error("ALERT Gatekeeper: %s. Outbound texts are blocked; recovery is retried %s.", reason, retry)

    def recover(self, *, owner=False):
        """True when healthy. Retries storage (saving held opt-outs first) once the backoff has
        passed; an unattributed opt-out waits for the owner. Fails closed on any error."""
        if not self.unhealthy.is_set():
            return True
        with self._health:
            if not self.unhealthy.is_set():
                return True
            now = self.now().timestamp()
            if not owner and (self._latched or now < self._retry_at):
                return False
            try:
                with self.ledger.transaction() as db:
                    for platform, targets, text in self._held_stops:
                        for target in targets:
                            self.ledger.optout(db, target)
                            self.ledger.log(db, platform, target, "", text, "inbound_stop", "block", now)
            except Exception:
                self._retry_delay = min(self._retry_delay * 2, RETRY_MAX)
                self._retry_at = now + self._retry_delay
                logger.error("ALERT Gatekeeper: storage is still unavailable (%s). Outbound texts stay blocked; "
                             "next retry in %ss.", self.health_reason, self._retry_delay)
                return False
            self._held_stops.clear()
            self._latched, self.health_reason = False, ""
            self._retry_at, self._retry_delay = 0.0, RETRY_FIRST
            self.unhealthy.clear()
        logger.warning("Gatekeeper recovered: storage answers again and held opt-outs were saved. Sends are evaluated again.")
        return True

    def defer(self, rule):
        """With defer_approvals, Gatekeeper itself never asks: double-text holds block and the
        remaining ask-level rules are logged and left to the host's own approval prompt."""
        if not self.settings.defer_approvals or rule[0] != "approve":
            return rule
        return ("block", rule[1]) if rule[1] in HOLDS else ("pass", "deferred:" + rule[1])

    def evaluate(self, db, send, now):
        hard = (suppression.check(db, send.recipient) or
                consent.check(db, send.recipient, send.channel, self.settings.require_consent))
        if hard:
            return [hard]
        contact = consent.contact(db, send.recipient, send.channel)
        rules = [quiet_hours.check(contact, now, self.settings.start, self.settings.end, self.settings.region_windows),
                 double_text.check(db, send.recipient, send.channel, send.thread, now=now.timestamp(),
                                   min_gap=self.settings.min_gap_seconds),
                 wording.check(send.message, self.settings.templates, json.loads(contact.get("variables", "{}")))]
        return [self.defer(r) for r in rules if r] or [("pass", "routine")]

    def error(self, rule, tool_name, args):
        # Never serialize exception messages: they can include args, paths or bodies.
        try:
            with self.ledger.transaction() as db:
                self.ledger.log(db, "unresolved", "unresolved", "", json.dumps([tool_name, args], sort_keys=True),
                                rule, "block", self.now().timestamp())
        except Exception:
            logger.warning("Gatekeeper could not persist a blocked decision; send remains blocked.")
        return directive("block", [rule])

    def escalation(self, tool_name, args, kwargs):
        """Owner approval for a send-looking tool Gatekeeper cannot parse (never a pass)."""
        try:
            label = escalate.unrecognized_send(tool_name, args, self.settings)
        except Exception:
            label = "send-looking name"  # a broken matcher asks rather than waves the call through
        if label is None:
            return None
        try:
            name = escalate.safe_name(tool_name)
            with self.ledger.transaction() as db:
                # Tool name (when well-formed) in the channel column; arguments only as a hash.
                self.ledger.log(db, name if name == tool_name else "unrecognized_tool", "unresolved", "",
                                json.dumps([tool_name, args], sort_keys=True, default=str),
                                "unrecognized_send_tool", "approve", self.now().timestamp())
        except Exception:
            logger.warning("Gatekeeper could not persist an escalation; the approval request still stands.")
        try:
            key = call_key(tool_name, args, kwargs)
        except Exception:
            key = ""
        return {"action": "approve", "message": escalate.reason(tool_name, label), "rule_key": "gatekeeper:" + key}

    def before(self, tool_name="", args=None, **kwargs):
        try:
            sends = classify(tool_name, args)
        except Uninspectable:
            return self.error("uninspectable", tool_name, args)
        except Exception:
            return self.error("gate_error", tool_name, args)
        if not sends:
            return self.escalation(tool_name, args, kwargs)
        try:
            if self.config_error or not self.recover():
                return self.error("gate_unavailable", tool_name, args)
            now, key = self.now(), call_key(tool_name, args, kwargs)
            with self.ledger.transaction() as db:
                evaluations = [self.evaluate(db, send, now) for send in sends]
                outcome = max((r[0] for rules in evaluations for r in rules), key=RANK.get)
                for send, rules in zip(sends, evaluations):
                    rule = max(rules, key=lambda r: RANK[r[0]])[1]
                    decision = self.ledger.log(db, send.channel, send.recipient, send.thread, send.message,
                                               rule, outcome, now.timestamp())
                    # Deferred batches are checked again at each leaf; don't reserve twice.
                    if outcome != "block" and tool_name.rsplit(".", 1)[-1] in {"send_message", "terminal"}:
                        history.reserve(db, send.recipient, send.channel, send.thread, at=now.timestamp(),
                                        call_key=key, decision=decision)
            return directive(outcome, [r[1] for rules in evaluations for r in rules if r[0] != "pass"], key)
        except Exception:
            return self.error("gate_error", tool_name, args)

    def inbound(self, **kwargs):
        from .inbound import observe
        return observe(self, **kwargs)

    def command(self, raw="", **kwargs):
        from .commands import command
        return command(self, raw, **kwargs)

    def after(self, tool_name="", args=None, result="", status="", **kwargs):
        try:
            sends = classify(tool_name, args)
            if not sends or tool_name.rsplit(".", 1)[-1] not in {"send_message", "terminal"}:
                return None
            state = "failed" if status in {"blocked", "cancelled"} else None
            data = json.loads(result) if isinstance(result, str) else result
            if status == "ok" and isinstance(data, dict):
                if tool_name.rsplit(".", 1)[-1] == "send_message":
                    if data.get("success") is True and not data.get("skipped"):
                        state = "sent"
                elif type(data.get("exit_code")) is int and data["exit_code"] == 0:
                    state = "sent"
            if state and isinstance(kwargs.get("tool_call_id"), str) and kwargs["tool_call_id"]:
                with self.ledger.transaction() as db:
                    history.finish(db, call_key(tool_name, args, kwargs), state, at=self.now().timestamp())
        except Uninspectable:
            if status != "blocked":
                self.mark_unhealthy("a send outcome could not be inspected")
        except Exception:
            self.mark_unhealthy("a send outcome could not be recorded")
        return None
