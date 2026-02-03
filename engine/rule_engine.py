import os
from typing import Any, Dict, List

from rules.iam_rules import run_iam_rules
from rules.network_rules import run_network_rules
from rules.storage_rules import run_storage_rules


def run_all_rules(parsed_inputs: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    iam_policies = parsed_inputs.get("iam_policies", [])
    s3_configs = parsed_inputs.get("s3_configs", [])
    security_groups = parsed_inputs.get("security_groups", [])

    print("RULE ENGINE: iam_policies=", len(iam_policies), "s3_configs=", len(s3_configs), "security_groups=", len(security_groups))

    iam_findings = run_iam_rules(iam_policies)
    print("IAM RULES EXECUTED: produced", len(iam_findings))
    findings.extend(iam_findings)

    s3_findings = run_storage_rules(s3_configs)
    print("S3 RULES EXECUTED: produced", len(s3_findings))
    findings.extend(s3_findings)

    net_findings = run_network_rules(security_groups)
    print("NETWORK RULES EXECUTED: produced", len(net_findings))
    findings.extend(net_findings)

    # Optional test forcing via environment variable for UI rendering validation
    if os.environ.get("FORCE_TEST_FINDING") == "1":
        print("RULE ENGINE: FORCE_TEST_FINDING active — adding synthetic test finding")
        findings.append({
            "id": "TEST_PIPELINE",
            "title": "Pipeline test",
            "description": "Synthetic finding to validate end-to-end pipeline and UI rendering.",
            "remediation": "No-op; test only",
            "resource_type": "iam_policy",
            "resource_id": "test",
            "fix_priority": "P0",
            "risk_category": "Critical",
            "risk_score": 25,
            "impact_score": 5,
            "likelihood_score": 5,
            "impact_factors": {"data_sensitivity": "pii", "privilege": "admin", "blast_radius": "account"},
            "likelihood_factors": {"internet_exposure": "public", "ease_of_exploit": "easy", "common_attack_pattern": "high"},
        })

    # Normalize findings to include risk metadata expected by templates and scoring logic
    for f in findings:
        f.setdefault("impact_factors", {})
        f.setdefault("likelihood_factors", {})
        # placeholder scores; will be computed in risk engine if not present
        f.setdefault("impact_score", 0)
        f.setdefault("likelihood_score", 0)
        f.setdefault("risk_score", 0)
        f.setdefault("risk_category", "Low")
        f.setdefault("fix_priority", None)
        f.setdefault("description", f.get("description") or "No description provided.")

    print("RULE ENGINE: total findings=", len(findings))

    return findings
