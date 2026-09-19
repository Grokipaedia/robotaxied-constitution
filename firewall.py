"""
firewall.py -- the Remote Assistance Firewall + Robotaxi Constitution engine.

Every consequential action -- whether proposed by the vehicle's own driving
stack or commanded by a remote human operator -- passes through
ConstitutionFirewall.evaluate() before it is allowed to happen. The decision
is always one of ALLOW / DENY / ESCALATE, and it always comes with a reason
that names the specific rule involved. Nothing here is a trained model or a
confidence score: it's a deterministic rulebook, on purpose, because the
whole point of an IBA-style governance layer is that a denial has to be
traceable to a specific, auditable line of policy -- not a vibe.

This is deliberately small and dependency-free so it's easy to audit end to
end in one sitting.
"""

import json
from dataclasses import dataclass, field
from typing import Optional


ALLOW = "ALLOW"
DENY = "DENY"
ESCALATE = "ESCALATE"


@dataclass
class IntentEnvelope:
    """What the passenger actually asked for, made explicit and checkable."""
    destination: str
    allow_normal_roads_only: bool = True
    forbid_restricted_areas: bool = True
    allow_unscheduled_stops_for_safety_only: bool = True
    require_justification_to_terminate: bool = True


@dataclass
class Action:
    """A single proposed action, from either the vehicle or a remote operator."""
    actor: str  # "vehicle" or "remote_operator"
    action_type: str
    reason_category: Optional[str] = None  # e.g. "obstacle_avoidance", "emergency", "safety"
    detail: str = ""


@dataclass
class Decision:
    action: Action
    result: str  # ALLOW / DENY / ESCALATE
    policy_ref: str
    explanation: str

    def as_receipt_line(self):
        return {
            "actor": self.action.actor,
            "action": self.action.action_type,
            "reason": self.action.reason_category,
            "result": self.result,
            "policy_ref": self.policy_ref,
            "explanation": self.explanation,
        }


class ConstitutionFirewall:
    def __init__(self, constitution_path: str, envelope: IntentEnvelope):
        with open(constitution_path, "r") as f:
            self.constitution = json.load(f)
        self.envelope = envelope
        self.log = []

    def evaluate(self, action: Action) -> Decision:
        c = self.constitution

        # 1. Immutable constraints apply to everyone, vehicle or remote operator,
        #    and cannot be waived by any actor -- checked first, before any
        #    actor-specific permission list.
        if action.action_type == "override_immutable_constraint":
            decision = Decision(
                action, DENY, "immutable_constraints",
                "No actor -- vehicle or remote operator -- may override an immutable constraint."
            )
        elif action.action_type in c["escalation_triggers"]:
            decision = Decision(
                action, ESCALATE, "escalation_triggers",
                f"'{action.action_type}' is not resolvable within policy alone; routed to human review."
            )
        elif action.actor == "remote_operator":
            decision = self._evaluate_remote_operator(action)
        elif action.actor == "vehicle":
            decision = self._evaluate_vehicle(action)
        else:
            decision = Decision(action, DENY, "unknown_actor", f"Unrecognized actor '{action.actor}'.")

        self.log.append(decision)
        return decision

    def _evaluate_remote_operator(self, action: Action) -> Decision:
        c = self.constitution
        if action.action_type in c["remote_operator_may_not"]:
            return Decision(
                action, DENY, "remote_operator_may_not",
                f"Remote operator command '{action.action_type}' is outside delegated authority. "
                "A remote operator's instructions are checked the same as the vehicle's own actions -- "
                "being human does not grant unlimited authority."
            )
        if action.action_type in c["remote_operator_may"]:
            return Decision(
                action, ALLOW, "remote_operator_may",
                f"Remote operator command '{action.action_type}' is within delegated authority."
            )
        return Decision(
            action, DENY, "default_deny",
            f"'{action.action_type}' is not an explicitly delegated remote-operator authority; denied by default."
        )

    def _evaluate_vehicle(self, action: Action) -> Decision:
        c = self.constitution
        env = self.envelope

        if action.action_type in c["vehicle_may_not"]:
            return Decision(
                action, DENY, "vehicle_may_not",
                f"'{action.action_type}' is on the vehicle's explicit may-not list."
            )

        if action.action_type == "silently_change_destination":
            return Decision(
                action, DENY, "vehicle_may_not",
                "Destination changes require passenger authorization; the vehicle may not do this silently."
            )

        if action.action_type == "stop_for_safety":
            if action.reason_category in c["unscheduled_stop_exceptions"]:
                return Decision(
                    action, ALLOW, "unscheduled_stop_exceptions",
                    f"Unscheduled stop justified by '{action.reason_category}', "
                    "an explicit exception in the passenger's intent envelope."
                )
            elif env.allow_unscheduled_stops_for_safety_only:
                return Decision(
                    action, DENY, "intent_envelope.allow_unscheduled_stops_for_safety_only",
                    f"Unscheduled stop with reason '{action.reason_category}' does not match "
                    "an approved exception (safety/emergency) -- this is an intent violation, not just a policy one."
                )

        if action.action_type in c["vehicle_may"]:
            return Decision(
                action, ALLOW, "vehicle_may",
                f"'{action.action_type}' is within the vehicle's explicit authority"
                + (f" (justified by: {action.reason_category})." if action.reason_category else ".")
            )

        return Decision(
            action, DENY, "default_deny",
            f"'{action.action_type}' is not an explicitly granted vehicle authority; denied by default."
        )

    def journey_receipt(self, trip_label: str) -> dict:
        """Summarize the whole log into the passenger-facing 'Journey Receipt'
        described in the design doc -- consequential decisions only, not a
        play-by-play of every millisecond."""
        destination_changed = any(
            d.action.action_type == "silently_change_destination" and d.result == ALLOW
            for d in self.log
        )
        unscheduled_stops = [d for d in self.log if d.action.action_type == "stop_for_safety" and d.result == ALLOW]
        route_deviations = [d for d in self.log if d.action.action_type == "choose_route" and d.action.reason_category]
        remote_requests = [d for d in self.log if d.action.actor == "remote_operator"]
        blocked_remote = [d for d in remote_requests if d.result == DENY]
        safety_violations = [d for d in self.log if d.result == DENY and d.policy_ref in ("vehicle_may_not", "immutable_constraints")]
        intent_violations = [d for d in self.log if d.result == DENY and "intent_envelope" in d.policy_ref]

        return {
            "trip": trip_label,
            "destination_changed": destination_changed,
            "unscheduled_stops": [
                {"reason": d.action.reason_category} for d in unscheduled_stops
            ],
            "route_deviations": [
                {"reason": d.action.reason_category} for d in route_deviations
            ],
            "remote_assistance_requests": len(remote_requests),
            "remote_assistance_blocked": [
                {"command": d.action.action_type, "reason": d.explanation} for d in blocked_remote
            ],
            "safety_policy_violations": len(safety_violations),
            "intent_violations": len(intent_violations),
            "completed_within_authorized_envelope": (len(safety_violations) == 0 and len(intent_violations) == 0),
        }
