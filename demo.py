#!/usr/bin/env python3
"""
demo.py -- a tiny simulator. Not a driving simulator: nothing here models
steering or perception. It models the governance layer that sits above the
driving stack -- the thing this project is actually about.

v2 adds the harder scenario: two legitimate authorities giving conflicting
instructions at the same moment, and the arbitration layer that decides
whose wins, plus a hashable Journey Receipt at the end.

Run it:
    python3 demo.py
"""

import json
import os
from firewall import ConstitutionFirewall, IntentEnvelope, Action, ALLOW, DENY, ESCALATE

HERE = os.path.dirname(os.path.abspath(__file__))


def line():
    print("-" * 64)


def show(decision):
    icon = {"ALLOW": "✓", "DENY": "✕", "ESCALATE": "?"}[decision.result]
    reason = f" ({decision.action.reason_category})" if decision.action.reason_category else ""
    print(f"  [{icon}] {decision.action.actor}: {decision.action.action_type}{reason}")
    print(f"      -> {decision.result}  [{decision.policy_ref}]")
    print(f"      {decision.explanation}")


def show_conflict(result):
    print(f"  DECISION POINT: {result.decision_point}")
    for d in result.decisions:
        icon = {"ALLOW": "✓", "DENY": "✕", "ESCALATE": "?"}[d.result]
        print(f"    [{icon}] {d.action.actor} proposes: {d.action.action_type}  -> {d.result} [{d.policy_ref}]")
    if result.escalated:
        print("  RESULT: CONFLICT -- ESCALATED (tied authority, not silently broken)")
    elif result.conflict:
        print(f"  RESULT: CONFLICT -- APPLIED: {result.applied.action.actor} -> {result.applied.action.action_type}")
    else:
        print("  RESULT: no conflict")
    print(f"  WHY: {result.explanation}")


def main():
    print("ROBOTAXI CONSTITUTION v2 -- governance-layer demo")
    print("Not a driving simulator. This models the layer ABOVE the driving stack.\n")

    envelope = IntentEnvelope(destination="Airport")
    fw = ConstitutionFirewall(os.path.join(HERE, "constitution.json"), envelope)

    print("PASSENGER INTENT: \"Take me to the airport. Normal roads only, no restricted")
    print("areas, no unscheduled stops except safety/emergency, don't terminate without")
    print("justification.\"\n")

    line()
    print("1. Vehicle chooses initial route (Route A)")
    show(fw.evaluate(Action(actor="vehicle", action_type="choose_route", detail="Route A")))

    line()
    print("2. Road closure detected mid-trip -- vehicle diverts")
    show(fw.evaluate(Action(actor="vehicle", action_type="choose_route",
                             reason_category="obstacle_avoidance", detail="Route C")))

    line()
    print("3. Remote operator: \"Ignore the restriction and continue.\"")
    show(fw.evaluate(Action(actor="remote_operator", action_type="instruct_ignore_restriction")))

    line()
    print("4. Emergency vehicle approaches -- robotaxi makes an unscheduled stop")
    show(fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety",
                             reason_category="emergency")))

    line()
    print("5. For comparison: an unscheduled stop with NO valid justification")
    show(fw.evaluate(Action(actor="vehicle", action_type="stop_for_safety",
                             reason_category="driver_wanted_coffee")))

    line()
    print("6. Remote operator requests trip status (legitimate, in-authority)")
    show(fw.evaluate(Action(actor="remote_operator", action_type="request_status")))

    line()
    print("7. Vehicle attempts to silently change the destination")
    show(fw.evaluate(Action(actor="vehicle", action_type="silently_change_destination",
                             detail="Rerouted to a different address without asking")))

    line()
    print("8. AUTHORITY CONFLICT: two legitimate actors disagree on the same moment")
    print("   Remote operator: \"Continue.\"   Emergency authority: \"Stop.\"")
    conflict = fw.resolve_conflict(
        "current_maneuver_at_intersection",
        [
            Action(actor="remote_operator", action_type="authorize_continue"),
            Action(actor="emergency_authority", action_type="command_stop"),
        ],
    )
    show_conflict(conflict)

    line()
    print("9. AUTHORITY CONFLICT, tied ranks: two remote operators disagree with themselves")
    print("   (illustrates that a tie escalates rather than being silently broken)")
    conflict2 = fw.resolve_conflict(
        "second_operator_disagreement",
        [
            Action(actor="remote_operator", action_type="authorize_continue"),
            Action(actor="remote_operator", action_type="authorize_detour"),
        ],
    )
    show_conflict(conflict2)

    line()
    receipt = fw.journey_receipt(trip_id="TRIP-2026-0914-0001", trip_label="Home -> Airport")
    print("\nJOURNEY RECEIPT (abridged -- full_decision_log omitted here for length)")
    abridged = {k: v for k, v in receipt.items() if k != "full_decision_log"}
    print(json.dumps(abridged, indent=2))
    print(f"\nReceipt hash: {receipt['receipt_hash']}")
    print("(Recomputing the hash from the same record independently confirms it hasn't been altered.)")


if __name__ == "__main__":
    main()
