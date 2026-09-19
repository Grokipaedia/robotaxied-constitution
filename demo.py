#!/usr/bin/env python3
"""
demo.py -- a tiny simulator. Not a driving simulator: nothing here models
steering or perception. It models the governance layer that sits above the
driving stack -- the thing this project is actually about.

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


def main():
    print("ROBOTAXI CONSTITUTION -- governance-layer demo")
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
    receipt = fw.journey_receipt("Home -> Airport")
    print("\nJOURNEY RECEIPT")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
