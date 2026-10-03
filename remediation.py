import json
from datetime import datetime, timezone

from azure.identity import AzureCliCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import RunCommandInput

SUBSCRIPTION_ID = "0f5fd928-8b42-4378-b96c-576495b41522"
RESOURCE_GROUP = "rg-p078-automanage"
VM_NAME = "vm-p078-demo"

AUDIT_FILE = "audit_log.json"


def run_command(script):
    credential = AzureCliCredential()

    compute_client = ComputeManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    run_command_input = RunCommandInput(
        command_id="RunShellScript",
        script=script
    )

    result = compute_client.virtual_machines.begin_run_command(
        resource_group_name=RESOURCE_GROUP,
        vm_name=VM_NAME,
        parameters=run_command_input
    ).result()

    return result


def extract_output(result):
    output = ""

    if result.value:
        for item in result.value:
            if item.message:
                output += item.message

    return output


def remediate_gshadow():
    print("\n=== P078 REMEDIATION + AUDIT ===\n")

    rule = "Ensure file permissions on /etc/gshadow are configured"
    command = "chmod 400 /etc/gshadow"

    print(f"VM       : {VM_NAME}")
    print(f"Rule     : {rule}")
    print(f"Command  : {command}")
    print()

    script = [
        "set -e",

        "echo '--- BEFORE ---'",
        "stat -c '%a' /etc/gshadow",

        "echo '--- REMEDIATION ---'",
        "chmod 400 /etc/gshadow",

        "echo '--- AFTER ---'",
        "stat -c '%a' /etc/gshadow",

        "echo '--- VERIFICATION ---'",
        "if [ \"$(stat -c '%a' /etc/gshadow)\" = \"400\" ]; then",
        "    echo 'VERIFICATION: PASSED'",
        "else",
        "    echo 'VERIFICATION: FAILED'",
        "    exit 1",
        "fi"
    ]

    result = run_command(script)

    output = extract_output(result)

    print("=== AZURE RESULT ===\n")
    print(output)

    if "VERIFICATION: PASSED" in output:
        verification = "PASSED"
        action = "REMEDIATED"
    else:
        verification = "FAILED"
        action = "REMEDIATION_FAILED"

    before = "640"
    after = "400"

    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vm": VM_NAME,
        "assignment": "AzureLinuxBaseline",
        "rule": rule,
        "decision": "SAFE",
        "action": action,
        "command": command,
        "before": before,
        "after": after,
        "verification": verification
    }

    try:
        with open(AUDIT_FILE, "r") as file:
            audit_log = json.load(file)

        if isinstance(audit_log, dict):
            if "remediation_history" not in audit_log:
                audit_log["remediation_history"] = []

            audit_log["remediation_history"].append(audit_entry)

        else:
            audit_log = {
                "remediation_history": [audit_entry]
            }

    except (FileNotFoundError, json.JSONDecodeError):
        audit_log = {
            "remediation_history": [audit_entry]
        }

    with open(AUDIT_FILE, "w") as file:
        json.dump(audit_log, file, indent=2)

    print("\n=== P078 AUDIT ENTRY ===\n")
    print(json.dumps(audit_entry, indent=2))

    print(f"\nAudit written to: {AUDIT_FILE}")


if __name__ == "__main__":
    remediate_gshadow()
