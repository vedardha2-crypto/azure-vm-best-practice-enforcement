import json
from datetime import datetime, timezone

from azure.identity import AzureCliCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import RunCommandInput


SUBSCRIPTION_ID = "0f5fd928-8b42-4378-b96c-576495b41522"
RESOURCE_GROUP = "rg-p078-automanage"
VM_NAME = "vm-p078-demo"

AUDIT_FILE = "audit_log.json"

RULE = "Ensure file permissions on /etc/gshadow- are configured"
COMMAND = "chmod 400 /etc/gshadow-"


def update_audit_log(before, after, verification):
    timestamp = datetime.now(timezone.utc).isoformat()

    entry = {
        "timestamp": timestamp,
        "vm": VM_NAME,
        "assignment": "AzureLinuxBaseline",
        "rule": RULE,
        "decision": "SAFE",
        "action": "REMEDIATED",
        "command": COMMAND,
        "before": before,
        "after": after,
        "verification": verification
    }

    try:
        with open(AUDIT_FILE, "r") as file:
            audit_log = json.load(file)

        if not isinstance(audit_log, dict):
            audit_log = {}

    except (FileNotFoundError, json.JSONDecodeError):
        audit_log = {}

    if "remediation_history" not in audit_log:
        audit_log["remediation_history"] = []

    audit_log["remediation_history"].append(entry)

    with open(AUDIT_FILE, "w") as file:
        json.dump(audit_log, file, indent=2)

    return entry


def main():
    credential = AzureCliCredential()
    client = ComputeManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    script = [
        "set -e",
        "BEFORE=$(stat -c %a /etc/gshadow-)",
        "echo \"--- BEFORE ---\"",
        "echo \"$BEFORE\"",

        "if [ \"$BEFORE\" != \"400\" ]; then",
        "    echo '--- REMEDIATION ---'",
        "    chmod 400 /etc/gshadow-",
        "else",
        "    echo '--- REMEDIATION ---'",
        "    echo 'Already compliant - no change required'",
        "fi",

        "AFTER=$(stat -c %a /etc/gshadow-)",
        "echo '--- AFTER ---'",
        "echo \"$AFTER\"",

        "echo '--- VERIFICATION ---'",
        "if [ \"$AFTER\" = \"400\" ]; then",
        "    echo 'VERIFICATION: PASSED'",
        "else",
        "    echo 'VERIFICATION: FAILED'",
        "    exit 1",
        "fi"
    ]

    command = RunCommandInput(
        command_id="RunShellScript",
        script=script
    )

    result = client.virtual_machines.begin_run_command(
        resource_group_name=RESOURCE_GROUP,
        vm_name=VM_NAME,
        parameters=command
    ).result()

    print("\n=== P078 CONTROLLED REMEDIATION ===\n")

    output = ""

    for item in result.value:
        if item.message:
            output += item.message

    print(output)

    before = None
    after = None
    verification = "FAILED"

    lines = output.splitlines()

    for index, line in enumerate(lines):
        line = line.strip()

        if line == "--- BEFORE ---" and index + 1 < len(lines):
            before = lines[index + 1].strip()

        if line == "--- AFTER ---" and index + 1 < len(lines):
            after = lines[index + 1].strip()

        if "VERIFICATION: PASSED" in line:
            verification = "PASSED"

    if verification == "PASSED":
        update_audit_log(
            before=before,
            after=after,
            verification=verification
        )

        print("\nAudit updated : audit_log.json")
        print("Remediation history recorded : YES")

    else:
        print("\nAudit updated : NO")
        print("Remediation failed.")


if __name__ == "__main__":
    main()
