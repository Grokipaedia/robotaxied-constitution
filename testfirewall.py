import os
import unittest

from firewall import ConstitutionFirewall, IntentEnvelope, Action, ALLOW, DENY, ESCALATE

HERE = os.path.dirname(os.path.abspath(__file__))
CONSTITUTION_PATH = os.path.join(HERE, "constitution.json")


def new_firewall():
    return ConstitutionFirewall(CONSTITUTION_PATH, IntentEnvelope(destination="Airport"))


class TestVehicleActions(unittest.TestCase):
    def test_normal_route_choice_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="choose_route"))
        self.assertEqual(d.result, ALLOW)

    def test_obstacle_avoidance_reroute_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="choose_route", reason_category="obstacle_avoidance"))
        self.assertEqual(d.result, ALLOW)

    def test_emergency_unscheduled_stop_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety", reason_category="emergency"))
        self.assertEqual(d.result, ALLOW)

    def test_unjustified_unscheduled_stop_denied(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety", reason_category="driver_wanted_coffee"))
        self.assertEqual(d.result, DENY)
        self.assertIn("intent_envelope", d.policy_ref)

    def test_silent_destination_change_denied(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="silently_change_destination"))
        self.assertEqual(d.result, DENY)

    def test_exceeding_operating_envelope_denied(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="exceed_operating_envelope"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "vehicle_may_not")

    def test_unlisted_vehicle_action_denied_by_default(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="do_something_never_specified"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "default_deny")


class TestRemoteOperatorActions(unittest.TestCase):
    def test_status_request_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="remote_operator", action_type="request_status"))
        self.assertEqual(d.result, ALLOW)

    def test_authorized_detour_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="remote_operator", action_type="authorize_detour"))
        self.assertEqual(d.result, ALLOW)

    def test_ignore_restriction_command_denied(self):
        """The original scenario: remote operator says 'ignore the
        restriction and continue' -- must be blocked even though a human issued it."""
        fw = new_firewall()
        d = fw.evaluate(Action(actor="remote_operator", action_type="instruct_ignore_restriction"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "remote_operator_may_not")

    def test_remote_operator_cannot_change_destination_without_consent(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="remote_operator", action_type="change_destination_without_passenger_consent"))
        self.assertEqual(d.result, DENY)

    def test_unlisted_remote_action_denied_by_default(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="remote_operator", action_type="do_something_never_specified"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "default_deny")


class TestEmergencyAuthorityActions(unittest.TestCase):
    def test_command_stop_allowed(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="emergency_authority", action_type="command_stop"))
        self.assertEqual(d.result, ALLOW)

    def test_disable_safety_systems_denied(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="emergency_authority", action_type="disable_vehicle_safety_systems"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "emergency_authority_may_not")

    def test_emergency_authority_cannot_override_immutable_constraint(self):
        """Outranking the vehicle and remote operator is not the same as
        having unlimited authority -- nobody overrides an immutable constraint."""
        fw = new_firewall()
        d = fw.evaluate(Action(actor="emergency_authority", action_type="override_immutable_constraint"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "immutable_constraints")

    def test_unlisted_emergency_action_denied_by_default(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="emergency_authority", action_type="do_something_never_specified"))
        self.assertEqual(d.result, DENY)
        self.assertEqual(d.policy_ref, "default_deny")


class TestImmutableConstraintsAndEscalation(unittest.TestCase):
    def test_immutable_override_denied_regardless_of_actor(self):
        fw = new_firewall()
        d1 = fw.evaluate(Action(actor="vehicle", action_type="override_immutable_constraint"))
        d2 = fw.evaluate(Action(actor="remote_operator", action_type="override_immutable_constraint"))
        self.assertEqual(d1.result, DENY)
        self.assertEqual(d2.result, DENY)
        self.assertEqual(d1.policy_ref, "immutable_constraints")
        self.assertEqual(d2.policy_ref, "immutable_constraints")

    def test_escalation_trigger_routes_to_escalate_not_allow_or_deny(self):
        fw = new_firewall()
        d = fw.evaluate(Action(actor="vehicle", action_type="ambiguous_safety_tradeoff"))
        self.assertEqual(d.result, ESCALATE)


class TestAuthorityArbitration(unittest.TestCase):
    def test_emergency_authority_outranks_remote_operator(self):
        """The doc's own scenario: remote operator says continue, emergency
        authority says stop. Emergency authority must win."""
        fw = new_firewall()
        result = fw.resolve_conflict(
            "intersection",
            [
                Action(actor="remote_operator", action_type="authorize_continue"),
                Action(actor="emergency_authority", action_type="command_stop"),
            ],
        )
        self.assertTrue(result.conflict)
        self.assertFalse(result.escalated)
        self.assertEqual(result.applied.action.actor, "emergency_authority")
        self.assertEqual(len(result.overridden), 1)
        self.assertEqual(result.overridden[0].action.actor, "remote_operator")

    def test_tied_authority_escalates_rather_than_silently_resolving(self):
        fw = new_firewall()
        result = fw.resolve_conflict(
            "disagreement",
            [
                Action(actor="remote_operator", action_type="authorize_continue"),
                Action(actor="remote_operator", action_type="authorize_detour"),
            ],
        )
        self.assertTrue(result.conflict)
        self.assertTrue(result.escalated)
        self.assertIsNone(result.applied)

    def test_out_of_scope_proposal_loses_on_its_own_merits_before_rank_matters(self):
        """A remote operator instructing something outside its authority
        should just be denied outright -- not treated as a rank contest."""
        fw = new_firewall()
        result = fw.resolve_conflict(
            "intersection",
            [
                Action(actor="remote_operator", action_type="instruct_ignore_restriction"),
                Action(actor="vehicle", action_type="stop_for_safety", reason_category="emergency"),
            ],
        )
        self.assertFalse(result.conflict)  # only one proposal was independently authorized
        self.assertEqual(result.applied.action.actor, "vehicle")

    def test_no_authorized_proposals_at_all(self):
        fw = new_firewall()
        result = fw.resolve_conflict(
            "intersection",
            [
                Action(actor="remote_operator", action_type="instruct_ignore_restriction"),
                Action(actor="emergency_authority", action_type="disable_vehicle_safety_systems"),
            ],
        )
        self.assertFalse(result.conflict)
        self.assertIsNone(result.applied)

    def test_unknown_actor_ranks_below_everyone_in_hierarchy(self):
        fw = new_firewall()
        self.assertLess(fw._rank("emergency_authority"), fw._rank("remote_operator"))
        self.assertLess(fw._rank("vehicle"), fw._rank("remote_operator"))
        self.assertGreater(fw._rank("some_unlisted_actor"), fw._rank("remote_operator"))


class TestJourneyReceipt(unittest.TestCase):
    def test_receipt_matches_original_scenario(self):
        fw = new_firewall()
        fw.evaluate(Action(actor="vehicle", action_type="choose_route"))
        fw.evaluate(Action(actor="vehicle", action_type="choose_route", reason_category="obstacle_avoidance"))
        fw.evaluate(Action(actor="remote_operator", action_type="instruct_ignore_restriction"))
        fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety", reason_category="emergency"))

        receipt = fw.journey_receipt(trip_id="T1", trip_label="Home -> Airport")
        self.assertFalse(receipt["destination_changed"])
        self.assertEqual(len(receipt["unscheduled_stops"]), 1)
        self.assertEqual(receipt["unscheduled_stops"][0]["reason"], "emergency")
        self.assertEqual(len(receipt["route_deviations"]), 1)
        self.assertEqual(receipt["remote_assistance_requests"], 1)
        self.assertEqual(len(receipt["remote_assistance_blocked"]), 1)
        self.assertEqual(receipt["safety_policy_violations"], 0)
        self.assertEqual(receipt["intent_violations"], 0)
        self.assertTrue(receipt["completed_within_authorized_envelope"])
        self.assertIn("receipt_hash", receipt)
        self.assertTrue(receipt["receipt_hash"].startswith("sha256:"))

    def test_receipt_flags_violation_when_present(self):
        fw = new_firewall()
        fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety", reason_category="driver_wanted_coffee"))
        receipt = fw.journey_receipt(trip_id="T2", trip_label="Home -> Airport")
        self.assertEqual(receipt["intent_violations"], 1)
        self.assertFalse(receipt["completed_within_authorized_envelope"])

    def test_receipt_flags_escalated_conflict_as_not_completed_cleanly(self):
        fw = new_firewall()
        fw.resolve_conflict(
            "disagreement",
            [
                Action(actor="remote_operator", action_type="authorize_continue"),
                Action(actor="remote_operator", action_type="authorize_detour"),
            ],
        )
        receipt = fw.journey_receipt(trip_id="T3", trip_label="Home -> Airport")
        self.assertEqual(len(receipt["authority_conflicts_escalated"]), 1)
        self.assertFalse(receipt["completed_within_authorized_envelope"])

    def test_receipt_records_resolved_conflict(self):
        fw = new_firewall()
        fw.resolve_conflict(
            "intersection",
            [
                Action(actor="remote_operator", action_type="authorize_continue"),
                Action(actor="emergency_authority", action_type="command_stop"),
            ],
        )
        receipt = fw.journey_receipt(trip_id="T4", trip_label="Home -> Airport")
        self.assertEqual(len(receipt["authority_conflicts_resolved"]), 1)
        self.assertEqual(receipt["authority_conflicts_resolved"][0]["applied"]["actor"], "emergency_authority")

    def test_hash_is_deterministic_for_identical_journeys(self):
        fw1 = new_firewall()
        fw1.evaluate(Action(actor="vehicle", action_type="choose_route"))
        r1 = fw1.journey_receipt(trip_id="SAME", trip_label="A -> B")

        fw2 = new_firewall()
        fw2.evaluate(Action(actor="vehicle", action_type="choose_route"))
        r2 = fw2.journey_receipt(trip_id="SAME", trip_label="A -> B")

        self.assertEqual(r1["receipt_hash"], r2["receipt_hash"])

    def test_hash_differs_when_journey_differs(self):
        fw1 = new_firewall()
        fw1.evaluate(Action(actor="vehicle", action_type="choose_route"))
        r1 = fw1.journey_receipt(trip_id="SAME", trip_label="A -> B")

        fw2 = new_firewall()
        fw2.evaluate(Action(actor="vehicle", action_type="choose_route", reason_category="obstacle_avoidance"))
        r2 = fw2.journey_receipt(trip_id="SAME", trip_label="A -> B")

        self.assertNotEqual(r1["receipt_hash"], r2["receipt_hash"])


if __name__ == "__main__":
    unittest.main()
