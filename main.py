import json
from datetime import datetime, timezone

from rule_engine import evaluate_findings
from approval_manager import is_approved


AUDIT_FILE = "audit_log.json"


def save_evaluation_audit(results):
    summary = {
        "compliant": 0,
        "safe": 0,
        "exception": 0,
        "review": 0,
        "manual": 0,
        "approved": 0,
        "blocked": 0
    }

    decisions = []
    findings = []

    for result in results:
        decision = result["decision"].lower()

        if decision in summary:
            summary[decision] += 1

        final_action = "NO_ACTION"

        if decision == "safe":
            rule = result["resource"]

            if is_approved(rule):
                final_action = "APPROVED_FOR_REMEDIATION"
                summary["approved"] += 1
            else:
                final_action = "BLOCKED_PENDING_APPROVAL"
                summary["blocked"] += 1

        elif decision == "review":
            final_action = "WAIT_FOR_REVIEW"

        elif decision == "manual":
            final_action = "MANUAL_REMEDIATION"

        elif decision == "exception":
            final_action = "PRESERVE_CONFIGURATION"

        decisions.append({
            "rule": result["resource"],
            "decision": result["decision"],
            "final_action": final_action
        })

        findings.append({
            "resource": result["resource"],
            "status": result["status"],
            "reason": result["reason"],
            "decision": result["decision"]
        })

    timestamp = datetime.now(timezone.utc).isoformat()

    audit_entry = {
        "timestamp": timestamp,
        "vm": "vm-p078-demo",
        "assignment": "AzureLinuxBaseline",
        "type": "policy_evaluation",
        "summary": summary,
        "findings": findings,
        "decisions": decisions
    }

    try:
        with open(AUDIT_FILE, "r") as file:
            audit_log = json.load(file)

        if not isinstance(audit_log, dict):
            audit_log = {}

    except (FileNotFoundError, json.JSONDecodeError):
        audit_log = {}

    # Update the latest dashboard state
    audit_log["timestamp"] = timestamp
    audit_log["vm"] = "vm-p078-demo"
    audit_log["assignment"] = "AzureLinuxBaseline"
    audit_log["summary"] = summary
    audit_log["findings"] = findings

    # Preserve evaluation history
    if "evaluation_history" not in audit_log:
        audit_log["evaluation_history"] = []

    audit_log["evaluation_history"].append(audit_entry)

    with open(AUDIT_FILE, "w") as file:
        json.dump(audit_log, file, indent=2)

    return summary, decisions


def main():
    print("\n==========================================")
    print("       P078 VM ENFORCEMENT ENGINE")
    print("==========================================\n")

    print("STEP 1: Collecting Guest Configuration...")
    print()

    results = evaluate_findings()

    print("\nSTEP 2: Policy Evaluation")
    print("------------------------------------------")

    for result in results:
        if result["decision"] == "COMPLIANT":
            continue

        rule = result["resource"]
        decision = result["decision"]

        print(f"\nRule     : {rule}")
        print(f"Decision : {decision}")

        if decision == "SAFE":
            if is_approved(rule):
                print("Approval : APPROVED")
                print("Action   : ELIGIBLE FOR REMEDIATION")
            else:
                print("Approval : NOT APPROVED")
                print("Action   : BLOCKED")

        elif decision == "REVIEW":
            print("Action   : WAIT FOR REVIEW")

        elif decision == "MANUAL":
            print("Action   : MANUAL REMEDIATION REQUIRED")

        elif decision == "EXCEPTION":
            print("Action   : PRESERVE CUSTOM CONFIGURATION")

        print("-" * 70)

    summary, decisions = save_evaluation_audit(results)

    print("\n==========================================")
    print("             P078 SUMMARY")
    print("==========================================")

    print(f"Compliant : {summary['compliant']}")
    print(f"Safe      : {summary['safe']}")
    print(f"Exception : {summary['exception']}")
    print(f"Review    : {summary['review']}")
    print(f"Manual    : {summary['manual']}")
    print(f"Approved  : {summary['approved']}")
    print(f"Blocked   : {summary['blocked']}")

    print("\nAudit updated : audit_log.json")

    print("\n==========================================")
    print("        NO VM CHANGES PERFORMED")
    print("==========================================\n")


if __name__ == "__main__":
    main()
