#!/usr/bin/env python3
"""
demo.py -- a tiny simulator. Not a driving simulator: nothing here models
steering or perception. It models the governance layer that sits above the
driving stack -- the thing this project is actually about.

v2.1 gives the passenger an actual voice mid-trip, not just a one-time
intent at trip start, and demonstrates the real question this project
exists to answer: when the vehicle, a remote operator, AND the passenger
all want different things at the same moment, who wins? (Answer: the
passenger outranks the vehicle and the remote operator, because they're
the one who granted the trip's authority in the first place -- but even
they don't outrank an emergency authority or an immutable constraint.)

Run it:
    python3 demo.py
"""

import json
import os
from firewall import ConstitutionFirewall, IntentEnvelope, Action, ALLOW, DENY, ESCALATE

HERE = os.path.dirname(os.path.abspath(__file__))


def line():
    print("-" * 72)


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


def print_five_column_table(receipt):
    """Lay the decision log out the way the design conversation for this
    project framed it: what was asked for, what was proposed, who asked,
    what rule decided it, and what actually happened. This is the same
    data as full_decision_log -- just shaped for a human to read at a
    glance rather than for a machine to hash."""
    rows = []
    for d in receipt["full_decision_log"]:
        rows.append([
            receipt["trip"],
            d["action"] + (f" ({d['reason']})" if d["reason"] else ""),
            d["actor"],
            d["policy_ref"],
            d["result"],
        ])

    headers = ["Passenger Intent", "Proposed Action", "Requested By", "Rule Applied", "Outcome"]
    widths = [max(len(str(row[i])) for row in ([headers] + rows)) for i in range(5)]

    def fmt_row(row):
        return "  " + " | ".join(str(v).ljust(widths[i]) for i, v in enumerate(row))

    print(fmt_row(headers))
    print("  " + "-+-".join("-" * w for w in widths))
    for row in rows:
        print(fmt_row(row))


def main():
    print("ROBOTAXIED CONSTITUTION v2.1 -- governance-layer demo")
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
    print("8. Compare: the PASSENGER asks for a destination change -- their own")
    print("   intent to change, which needs no one else's permission")
    show(fw.evaluate(Action(actor="passenger", action_type="request_new_destination",
                             detail="Downtown Hotel")))
    print(f"   (Intent envelope destination is now: {envelope.destination!r})")

    line()
    print("9. AUTHORITY CONFLICT: two legitimate actors disagree on the same moment")
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
    print("10. TIED CONFLICT: two remote operators disagree with each other")
    print("    (illustrates that a tie escalates rather than being silently broken)")
    conflict2 = fw.resolve_conflict(
        "second_operator_disagreement",
        [
            Action(actor="remote_operator", action_type="authorize_continue"),
            Action(actor="remote_operator", action_type="authorize_detour"),
        ],
    )
    show_conflict(conflict2)

    line()
    print("11. THE THREE-WAY CONFLICT this project exists to demonstrate:")
    print("    Vehicle wants to continue. Remote operator agrees. But the")
    print("    PASSENGER -- who granted this trip's authority in the first")
    print("    place -- asks the vehicle to stop right now.")
    conflict3 = fw.resolve_conflict(
        "mid_trip_stop_decision",
        [
            Action(actor="vehicle", action_type="continue_to_destination"),
            Action(actor="remote_operator", action_type="authorize_continue"),
            Action(actor="passenger", action_type="request_immediate_stop"),
        ],
    )
    show_conflict(conflict3)
    print("\n    The vehicle had 'enormous operational freedom' to get to the airport --")
    print("    but that freedom was always subordinate to the passenger who granted it.")

    line()
    receipt = fw.journey_receipt(trip_id="TRIP-2026-0914-0001", trip_label="Home -> Airport")

    print("\nFIVE-COLUMN DECISION TABLE (Intent / Proposed Action / Requested By / Rule / Outcome)")
    print_five_column_table(receipt)

    print("\nJOURNEY RECEIPT (abridged -- full_decision_log omitted here, shown above as a table)")
    abridged = {k: v for k, v in receipt.items() if k != "full_decision_log"}
    print(json.dumps(abridged, indent=2))
    print(f"\nReceipt hash: {receipt['receipt_hash']}")
    print("(Recomputing the hash from the same record independently confirms it hasn't been altered.)")


if __name__ == "__main__":
    main()
