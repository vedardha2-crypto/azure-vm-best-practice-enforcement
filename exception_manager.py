import json

EXCEPTIONS_FILE = "exceptions.json"


def load_exceptions():
    with open(EXCEPTIONS_FILE, "r") as file:
        data = json.load(file)

    return data.get("exceptions", [])


def normalize_rule(rule):
    return rule.strip().lower()


def find_exception(resource):
    resource_normalized = normalize_rule(resource)

    for exception in load_exceptions():
        exception_rule = normalize_rule(exception["rule"])

        if resource_normalized.startswith(exception_rule):
            return exception

    return None


def evaluate_exception(resource):
    exception = find_exception(resource)

    if exception is None:
        return {
            "matched": False,
            "action": None,
            "reason": None
        }

    return {
        "matched": True,
        "action": exception["action"],
        "reason": exception["reason"]
    }


if __name__ == "__main__":

    print("\n=== P078 EXCEPTION MANAGER ===\n")

    test_rules = [
        "Ensure that appropriate ciphers are used for SSH (CIS: L1 - Server - 5.2.13)",
        "Ensure that only approved MAC algorithms are used (CIS: L1 - Server - 5.2.14)",
        "Ensure that the SSH PermitRootLogin is configured (CIS: L1 - Server - 5.2.10)",
        "Ensure the default umask for all users is configured"
    ]

    for rule in test_rules:

        result = evaluate_exception(rule)

        print(f"Rule   : {rule}")

        if result["matched"]:
            print("Matched: YES")
            print(f"Action : {result['action']}")
            print(f"Reason : {result['reason']}")
        else:
            print("Matched: NO")

        print("-" * 70)
