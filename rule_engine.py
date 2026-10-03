import json

from collector import collect_baseline_findings
from exception_manager import evaluate_exception


SAFE_RULES = {
    "Ensure file permissions on /etc/gshadow are configured",
    "Ensure file permissions on /etc/gshadow- are configured",
    "Ensure file permissions on /etc/shadow are configured",
    "Ensure file permissions on /etc/shadow- are configured",
    "Ensure logger configuration files are restricted",
    "Ensure permissions on /etc/cron.d are configured",
    "Ensure permissions on /etc/cron.daily are configured",
    "Ensure permissions on /etc/ssh/sshd_config are configured"
}


def get_base_rule(resource):
    if " (CIS:" in resource:
        return resource.split(" (CIS:")[0].strip()

    return resource.strip()


def classify_finding(finding):

    resource = finding["resource"]
    status = str(finding["status"]).lower()

    # Already compliant
    if status == "true":
        return "COMPLIANT"

    # ---------------------------------------
    # STEP 1: Exception Manager
    # ---------------------------------------

    exception = evaluate_exception(resource)

    if exception["matched"]:

        if exception["action"] == "PRESERVE":
            return "EXCEPTION"

        if exception["action"] == "REVIEW":
            return "REVIEW"

    # ---------------------------------------
    # STEP 2: Safe remediation allowlist
    # ---------------------------------------

    base_rule = get_base_rule(resource)

    if base_rule in SAFE_RULES:
        return "SAFE"

    # ---------------------------------------
    # STEP 3: Everything else = manual
    # ---------------------------------------

    return "MANUAL"


def evaluate_findings():

    findings = collect_baseline_findings()

    results = []

    for finding in findings:

        decision = classify_finding(finding)

        result = {
            "resource": finding["resource"],
            "status": finding["status"],
            "reason": finding["reason"],
            "decision": decision
        }

        results.append(result)

    return results


if __name__ == "__main__":

    print("\n=== P078 POLICY-AWARE RULE ENGINE ===\n")

    results = evaluate_findings()

    counts = {
        "COMPLIANT": 0,
        "SAFE": 0,
        "EXCEPTION": 0,
        "REVIEW": 0,
        "MANUAL": 0
    }

    for result in results:

        decision = result["decision"]

        counts[decision] += 1

        if decision != "COMPLIANT":

            print(f"Rule     : {result['resource']}")
            print(f"Status   : {result['status']}")
            print(f"Decision : {decision}")
            print(f"Reason   : {result['reason']}")
            print("-" * 70)

    print("\n=== P078 DECISION SUMMARY ===")

    print(f"Compliant : {counts['COMPLIANT']}")
    print(f"Safe      : {counts['SAFE']}")
    print(f"Exception : {counts['EXCEPTION']}")
    print(f"Review    : {counts['REVIEW']}")
    print(f"Manual    : {counts['MANUAL']}")
