from typing import Any, Dict, List, Tuple


IMPACT_MAP = {
    "none": 1,
    "logs": 2,
    "internal": 2,
    "public": 3,
    "backups": 4,
    "pii": 5,
    "credentials": 5,
    "secrets": 5,
    "unknown": 3,
}

PRIVILEGE_MAP = {
    "read": 2,
    "write": 3,
    "admin": 5,
    "network": 3,
    "unknown": 3,
}

BLAST_MAP = {
    "single": 2,
    "multi": 3,
    "account": 5,
    "unknown": 3,
}

EXPOSURE_MAP = {
    "none": 1,
    "internal": 2,
    "partial": 3,
    "public": 5,
    "unknown": 3,
}

EASE_MAP = {
    "hard": 1,
    "moderate": 3,
    "easy": 5,
}

ATTACK_MAP = {
    "low": 2,
    "medium": 3,
    "high": 5,
}


def _avg(values: List[int]) -> int:
    if not values:
        return 1
    return max(1, round(sum(values) / len(values)))


def calculate_impact(impact_factors: Dict[str, str]) -> int:
    values = [
        IMPACT_MAP.get(impact_factors.get("data_sensitivity", "unknown"), 3),
        PRIVILEGE_MAP.get(impact_factors.get("privilege", "unknown"), 3),
        BLAST_MAP.get(impact_factors.get("blast_radius", "unknown"), 3),
    ]
    return _avg(values)


def calculate_likelihood(likelihood_factors: Dict[str, str]) -> int:
    values = [
        EXPOSURE_MAP.get(likelihood_factors.get("internet_exposure", "unknown"), 3),
        EASE_MAP.get(likelihood_factors.get("ease_of_exploit", "moderate"), 3),
        ATTACK_MAP.get(likelihood_factors.get("common_attack_pattern", "medium"), 3),
    ]
    return _avg(values)


def categorize(score: int) -> str:
    if score >= 20:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 6:
        return "Medium"
    return "Low"


def score_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for finding in findings:
        impact = calculate_impact(finding.get("impact_factors", {}))
        likelihood = calculate_likelihood(finding.get("likelihood_factors", {}))
        risk_score = impact * likelihood
        finding["impact_score"] = impact
        finding["likelihood_score"] = likelihood
        finding["risk_score"] = risk_score
        finding["risk_category"] = categorize(risk_score)
    return findings


def prioritize(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scored = score_findings(findings)
    scored.sort(key=lambda f: (f.get("risk_score", 0), f.get("impact_score", 0)), reverse=True)
    for idx, finding in enumerate(scored, start=1):
        finding["fix_priority"] = idx
    return scored


def overall_posture(findings: List[Dict[str, Any]]) -> Tuple[str, int]:
    if not findings:
        return "Low", 0
    top = max(findings, key=lambda f: f.get("risk_score", 0))
    return top.get("risk_category", "Low"), top.get("risk_score", 0)
