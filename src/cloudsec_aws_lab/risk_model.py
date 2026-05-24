from __future__ import annotations

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def normalize_severity(value: str | float | int | None) -> str:
    if value is None:
        return "INFO"
    if isinstance(value, (int, float)):
        if value >= 8.9:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MEDIUM"
        if value > 0:
            return "LOW"
        return "INFO"
    value = str(value).upper()
    aliases = {"SEVERE": "CRITICAL", "WARN": "MEDIUM", "WARNING": "MEDIUM"}
    return aliases.get(value, value if value in SEVERITY_ORDER else "INFO")


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
