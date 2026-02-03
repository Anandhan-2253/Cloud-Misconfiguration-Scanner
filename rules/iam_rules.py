from typing import Any, Dict, List


def _normalize_actions(action: Any) -> List[str]:
    if action is None:
        return []
    if isinstance(action, str):
        return [action]
    if isinstance(action, list):
        return [a for a in action if isinstance(a, str)]
    return []


def run_iam_rules(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("IAM RULES: received", len(policies), "policies")
    findings: List[Dict[str, Any]] = []

    for policy in policies:
        # Support both raw upload shape and parser-normalized shape
        policy_name = policy.get("policy_name") or policy.get("PolicyName") or "UnknownPolicy"
        statements = policy.get("statements")
        if statements is None:
            statements = policy.get("PolicyDocument", {}).get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            # Support both normalized keys (lowercase) and raw keys
            effect = (stmt.get("effect") or stmt.get("Effect") or "").lower()
            if effect != "allow":
                continue

            actions = _normalize_actions(stmt.get("actions") or stmt.get("Action"))
            # normalize actions to lowercase strings for comparison
            actions_norm = [a.lower() for a in actions]

            resources = stmt.get("resources") or stmt.get("Resource") or []
            if isinstance(resources, str):
                resources = [resources]

            resources_norm = [r for r in resources]

            action_wild = ("*" in actions_norm) or any(a.endswith(":*") for a in actions_norm)
            resource_wild = ("*" in resources_norm)

            if action_wild and resource_wild:
                findings.append({
                    "id": "IAM_WILDCARD_ADMIN",
                    "title": "Over-permissive IAM policy",
                    "service": "IAM",
                    "severity": "Critical",
                    "issue": "Wildcard IAM permissions",
                    "resource_type": "iam_policy",
                    "resource_id": policy_name,
                    "resource": policy_name,
                    "description": "IAM policy allows all actions on all resources (wildcard '*').",
                    "explanation": "IAM policy allows all actions on all resources, enabling full account compromise.",
                    "remediation": "Restrict actions and resources explicitly and follow least-privilege principles.",
                })

    print("IAM RULES EXECUTED: produced", len(findings))
    return findings
