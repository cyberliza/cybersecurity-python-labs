import sys
import os



sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER


users = {
    "risk_manager": {
        "role": "risk_analyst", 
        "clearance": 4, 
        "department": "Risk Management",
          "active": True
          },
    "business_analyst": {
        "role": "business_analyst",
        "clearance": 2,
        "department": "Business", 
        "active": True
        },
    "legal_counsel": {
        "role": "legal", 
        "clearance": 3,
        "department": "Legal",
        "active": True
    },
    "contractor_dev": {
        "role": "contractor",
        "clearance": 2,
        "department": "Contract",
        "active": True
    },
    "obsolete_system": {
        "role": "legacy_system",
        "clearance": 1,
        "department": "Legacy",
        "active": False
    }
}
resources = [("risk_registers", 4), ("business_requirements", 2),
("legal_documents", 3), ("contract_code", 2), ("governance_framework", 4),
("meeting_minutes", 1), ("regulatory_reports", 3), ("executive_dashboards", 4),
("project_specs", 2), ("public_statements", 1)]
security_levels = ("Public", "Internal Use", "Restricted", "Highly Restricted")
blocked_users = {"obsolete_system", "contract_expired", "legal_hold"}

def check(username: str, resource_level: int) -> tuple[bool, str]: # 
    if username not in users:
        return False, "User not found"

    if username in blocked_users:
        return False, "User is blocked"

    user_data = users[username]

    if not user_data.get("active", False):
        return False, "Account is inactive"

    user_clearance = user_data.get("clearance", 0)

    if user_clearance >= resource_level:
        return True, "ALLOW"

    return False, "Insufficient clearance"


def main():
    print(
        f"\nСтудент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} \n"
    )

    for res_name, lvl in resources:

        print(f"Ресурс: {res_name:} | Рівень: {security_levels[lvl - 1]} ({lvl})")


    test_users = list(users.keys()) + ["unknown_user"]

    print(
        f"{'\nКористувач'} | {'Ресурс'} | {'Статус'} | {'Причина\n'}"
    )

    for user in test_users:
        for res_name, lvl in resources:
            allowed, reason = check(user, lvl)
            status = "ALLOW" if allowed else "DENY"
            print(f"{user} | {res_name} | {status} | {reason}")


if __name__ == "__main__":
    main()