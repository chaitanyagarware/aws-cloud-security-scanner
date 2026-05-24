from __future__ import annotations

# MITRE ATT&CK Enterprise/Cloud mappings used for portfolio/demo triage.
RULE_TO_ATTACK: dict[str, list[str]] = {
    "IAM-001": ["TA0003 Persistence", "TA0004 Privilege Escalation"],
    "IAM-002": ["TA0004 Privilege Escalation"],
    "IAM-003": ["TA0001 Initial Access", "TA0008 Lateral Movement"],
    "CT-001": ["TA0006 Credential Access"],
    "CT-002": ["TA0001 Initial Access", "TA0006 Credential Access"],
    "CT-003": ["TA0003 Persistence", "TA0005 Defense Evasion", "TA0004 Privilege Escalation"],
    "CT-004": ["TA0007 Discovery"],
    "CT-005": ["TA0002 Execution", "TA0007 Discovery"],
    "CT-006": ["TA0007 Discovery"],
    "GD-UnauthorizedAccess": ["TA0001 Initial Access", "TA0006 Credential Access"],
    "GD-Stealth": ["TA0005 Defense Evasion"],
    "GD-CredentialAccess": ["TA0006 Credential Access"],
    "GD-Discovery": ["TA0007 Discovery"],
    "AA-EXTERNAL_ACCESS": ["TA0001 Initial Access"],
    "CORR-001": ["TA0004 Privilege Escalation", "TA0008 Lateral Movement"],
}

def attack_for(rule_id: str, title: str = "") -> list[str]:
    if rule_id in RULE_TO_ATTACK:
        return RULE_TO_ATTACK[rule_id]
    if rule_id.startswith("GD-"):
        low = title.lower()
        if "unauthorized" in low or "iamuser" in low:
            return RULE_TO_ATTACK["GD-UnauthorizedAccess"]
        if "stealth" in low or "cloudtrail" in low:
            return RULE_TO_ATTACK["GD-Stealth"]
        if "credential" in low:
            return RULE_TO_ATTACK["GD-CredentialAccess"]
        if "discovery" in low or "recon" in low:
            return RULE_TO_ATTACK["GD-Discovery"]
    low = title.lower()
    if "credential" in low:
        return ["TA0006 Credential Access"]
    if "privilege" in low or "admin" in low:
        return ["TA0004 Privilege Escalation"]
    if "mfa" in low or "login" in low:
        return ["TA0001 Initial Access"]
    return []
