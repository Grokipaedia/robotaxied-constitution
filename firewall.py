"""
firewall.py -- the Remote Assistance Firewall + Robotaxied Constitution engine.

v2 adds a third actor (emergency authority) and the harder question that
creates: not just "is this one action authorized?" but "when two
independently-legitimate actors give conflicting instructions, whose wins?"
The answer is never hard-coded -- it's read from constitution.json's
authority_hierarchy, and a tie is never silently broken; it escalates.

Every consequential action -- from the vehicle's own driving stack, a remote
human operator, or an emergency responder acting under defined protocol --
passes through ConstitutionFirewall.evaluate() before it happens. The
decision is always ALLOW / DENY / ESCALATE, always with a reason naming the
specific rule involved. Nothing here is a trained model or a confidence
score: it's a deterministic rulebook, on purpose, because a denial (or an
arbitration outcome) has to be traceable to a specific, auditable line of
policy -- not a vibe.

This is deliberately small and dependency-free so it's easy to audit end to
end in one sitting.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional


ALLOW = "ALLOW"
DENY = "DENY"
ESCALATE = "ESCALATE"

ACTOR_TIERS = {
    "vehicle": "vehicle_operational_authority",
    "remote_operator": "remote_operator_authority",
    "emergency_authority": "emergency_authority",
}


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
    """A single proposed action, from the vehicle, a remote operator, or an
    emergency authority. `decision_point` is optional and only matters for
    conflict resolution: two actions that share a decision_point are
    competing proposals for the same real-world moment (e.g. both are
    answering "what does the vehicle do right now?")."""
    actor: str  # "vehicle", "remote_operator", or "emergency_authority"
    action_type: str
    reason_category: Optional[str] = None  # e.g. "obstacle_avoidance", "emergency", "safety"
    detail: str = ""
    decision_point: Optional[str] = None


@dataclass
class Decision:
    action: Action
    result: str  # ALLOW / DENY / ESCALATE
    policy_ref: str
    explanation: str

    def as_dict(self):
        return {
            "actor": self.action.actor,
            "action": self.action.action_type,
            "reason": self.action.reason_category,
            "decision_point": self.action.decision_point,
            "result": self.result,
            "policy_ref": self.policy_ref,
            "explanation": self.explanation,
        }


@dataclass
class ConflictResolution:
    decision_point: str
    decisions: List[Decision]
    conflict: bool
    applied: Optional[Decision]
    overridden: List[Decision] = field(default_factory=list)
    escalated: bool = False
    explanation: str = ""

    def as_dict(self):
        return {
            "decision_point": self.decision_point,
            "conflict": self.conflict,
            "escalated": self.escalated,
            "applied": self.applied.as_dict() if self.applied else None,
            "overridden": [d.as_dict() for d in self.overridden],
            "explanation": self.explanation,
        }


class ConstitutionFirewall:
    def __init__(self, constitution_path: str, envelope: IntentEnvelope):
        with open(constitution_path, "r") as f:
            self.constitution = json.load(f)
        self.envelope = envelope
        self.log: List[Decision] = []
        self.conflicts: List[ConflictResolution] = []

    # ------------------------------------------------------------------
    # Single-action evaluation
    # ------------------------------------------------------------------

    def evaluate(self, action: Action) -> Decision:
        c = self.constitution

        # Immutable constraints apply to every actor and cannot be waived by
        # anyone -- checked first, before any actor-specific permission list.
        if action.action_type == "override_immutable_constraint":
            decision = Decision(
                action, DENY, "immutable_constraints",
                "No actor -- vehicle, remote operator, or emergency authority -- may override an immutable constraint."
            )
        elif action.action_type in c["escalation_triggers"]:
            decision = Decision(
                action, ESCALATE, "escalation_triggers",
                f"'{action.action_type}' is not resolvable within policy alone; routed to human review."
            )
        elif action.actor == "remote_operator":
            decision = self._evaluate_remote_operator(action)
        elif action.actor == "emergency_authority":
            decision = self._evaluate_emergency_authority(action)
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

    def _evaluate_emergency_authority(self, action: Action) -> Decision:
        c = self.constitution
        if action.action_type in c["emergency_authority_may_not"]:
            return Decision(
                action, DENY, "emergency_authority_may_not",
                f"Emergency-authority command '{action.action_type}' is outside its delegated scope. "
                "Emergency authority outranks the vehicle and remote operator, but it is not unlimited either."
            )
        if action.action_type in c["emergency_authority_may"]:
            return Decision(
                action, ALLOW, "emergency_authority_may",
                f"Emergency-authority command '{action.action_type}' is within its delegated scope."
            )
        return Decision(
            action, DENY, "default_deny",
            f"'{action.action_type}' is not an explicitly delegated emergency authority; denied by default."
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

    # ------------------------------------------------------------------
    # Authority arbitration
    # ------------------------------------------------------------------

    def _rank(self, actor: str) -> int:
        """Lower number = higher priority. An actor not present in the
        configured hierarchy ranks below everyone who is -- fails closed,
        not open."""
        order = self.constitution["authority_hierarchy"]
        tier = ACTOR_TIERS.get(actor, actor)
        return order.index(tier) if tier in order else len(order)

    def resolve_conflict(self, decision_point: str, actions: List[Action]) -> ConflictResolution:
        """Two or more actors have each proposed an action for the same
        real-world decision point. Each proposal is first checked through
        the normal rulebook (an out-of-scope command loses on its own merits,
        before rank ever matters). Only if more than one proposal survives
        that check independently does rank get consulted -- and a tie in
        rank is never silently broken; it escalates instead."""
        for a in actions:
            a.decision_point = decision_point
        decisions = [self.evaluate(a) for a in actions]
        authorized = [d for d in decisions if d.result == ALLOW]

        if len(authorized) <= 1:
            result = ConflictResolution(
                decision_point=decision_point,
                decisions=decisions,
                conflict=False,
                applied=authorized[0] if authorized else None,
                explanation=(
                    "Only one proposal was independently authorized; no arbitration needed."
                    if authorized else
                    "No proposal for this decision point was independently authorized."
                ),
            )
            self.conflicts.append(result)
            return result

        ranked = sorted(authorized, key=lambda d: self._rank(d.action.actor))
        top_rank = self._rank(ranked[0].action.actor)
        tied = [d for d in ranked if self._rank(d.action.actor) == top_rank]

        if len(tied) > 1:
            actors = ", ".join(d.action.actor for d in tied)
            result = ConflictResolution(
                decision_point=decision_point,
                decisions=decisions,
                conflict=True,
                applied=None,
                overridden=[],
                escalated=True,
                explanation=(
                    f"{len(tied)} independently-authorized proposals ({actors}) rank equally in the "
                    "configured authority hierarchy. A tie is not silently broken -- this escalates to human review."
                ),
            )
        else:
            applied = ranked[0]
            overridden = [d for d in authorized if d is not applied]
            result = ConflictResolution(
                decision_point=decision_point,
                decisions=decisions,
                conflict=True,
                applied=applied,
                overridden=overridden,
                escalated=False,
                explanation=(
                    f"'{applied.action.actor}' outranks {', '.join(d.action.actor for d in overridden)} "
                    f"under the configured authority_hierarchy; its proposal ('{applied.action.action_type}') is applied."
                ),
            )

        self.conflicts.append(result)
        return result

    # ------------------------------------------------------------------
    # Journey Receipt
    # ------------------------------------------------------------------

    def journey_receipt(self, trip_id: str, trip_label: str) -> dict:
        """Summarize the whole log into the passenger-facing 'Journey
        Receipt' -- consequential decisions only, not a play-by-play of
        every millisecond -- plus a hash over the full record, so the
        vehicle can hand over a machine-verifiable statement of what it was
        authorized to do and what actually happened, not just a claim."""
        destination_changed = any(
            d.action.action_type == "silently_change_destination" and d.result == ALLOW
            for d in self.log
        )
        unscheduled_stops = [d for d in self.log if d.action.action_type == "stop_for_safety" and d.result == ALLOW]
        route_deviations = [d for d in self.log if d.action.action_type == "choose_route" and d.action.reason_category]
        remote_requests = [d for d in self.log if d.action.actor == "remote_operator"]
        blocked_remote = [d for d in remote_requests if d.result == DENY]
        emergency_actions = [d for d in self.log if d.action.actor == "emergency_authority" and d.result == ALLOW]
        emergency_blocked = [d for d in self.log if d.action.actor == "emergency_authority" and d.result == DENY]
        # Only the vehicle's OWN prohibited actions (or an immutable-constraint
        # breach by anyone) count as a safety-policy violation here. A blocked
        # remote-operator or emergency-authority command is the firewall
        # working as intended -- it's already reflected in
        # remote_assistance_blocked / emergency_actions_blocked, and must not
        # also flip completed_within_authorized_envelope to false.
        safety_violations = [d for d in self.log if d.result == DENY and d.policy_ref in
                              ("vehicle_may_not", "immutable_constraints")]
        intent_violations = [d for d in self.log if d.result == DENY and "intent_envelope" in d.policy_ref]
        escalated_conflicts = [c for c in self.conflicts if c.escalated]
        resolved_conflicts = [c for c in self.conflicts if c.conflict and not c.escalated]

        record = {
            "trip_id": trip_id,
            "trip": trip_label,
            "constitution_version": self.constitution.get("constitution_version", "unknown"),
            "authority_hierarchy": self.constitution.get("authority_hierarchy", []),
            "destination_changed": destination_changed,
            "unscheduled_stops": [{"reason": d.action.reason_category} for d in unscheduled_stops],
            "route_deviations": [{"reason": d.action.reason_category} for d in route_deviations],
            "remote_assistance_requests": len(remote_requests),
            "remote_assistance_blocked": [
                {"command": d.action.action_type, "reason": d.explanation} for d in blocked_remote
            ],
            "emergency_actions": [
                {"command": d.action.action_type} for d in emergency_actions
            ],
            "emergency_actions_blocked": [
                {"command": d.action.action_type, "reason": d.explanation} for d in emergency_blocked
            ],
            "authority_conflicts_resolved": [c.as_dict() for c in resolved_conflicts],
            "authority_conflicts_escalated": [c.as_dict() for c in escalated_conflicts],
            "safety_policy_violations": len(safety_violations),
            "intent_violations": len(intent_violations),
            "completed_within_authorized_envelope": (
                len(safety_violations) == 0 and len(intent_violations) == 0 and len(escalated_conflicts) == 0
            ),
            "full_decision_log": [d.as_dict() for d in self.log],
        }

        # Hash over the canonical (sorted-key) JSON of everything above --
        # deterministic for identical input, so two parties holding the same
        # record can independently confirm it hasn't been altered.
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["receipt_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return record
