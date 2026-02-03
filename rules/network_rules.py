from typing import Any, Dict, List


def run_network_rules(security_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("NETWORK RULES: received", len(security_groups), "security groups")
    findings: List[Dict[str, Any]] = []

    for sg in security_groups:
        sg_name = sg.get("group_name") or sg.get("GroupName") or "UnknownSG"
        environment = sg.get("environment") or sg.get("Environment") or "unknown"

        # Accept multiple inbound shapes: parsed 'rules' (with direction) or raw 'InboundRules'
        inbound_rules = sg.get("InboundRules") or sg.get("Inbound") or sg.get("rules") or []

        for rule in inbound_rules:
            # If parser uses 'rules' with direction key, skip non-ingress entries
            if isinstance(rule, dict) and rule.get("direction") and rule.get("direction") != "ingress":
                continue

            cidr = rule.get("CidrIp") or rule.get("cidr") or rule.get("Cidr")
            # Some inputs might provide a list or dict of cidr blocks - normalize to string if possible
            if isinstance(cidr, list):
                cidr_list = cidr
            elif isinstance(cidr, str):
                cidr_list = [cidr]
            else:
                cidr_list = []

            # normalize port field
            port = rule.get("FromPort") or rule.get("from_port") or rule.get("port") or rule.get("From")
            try:
                port = int(port) if port is not None else None
            except Exception:
                port = None

            # check for public cidr
            if "0.0.0.0/0" not in cidr_list:
                continue

            if port == 3389:
                findings.append({
                    "id": "NET_PUBLIC_RDP",
                    "title": "RDP exposed to the internet",
                    "service": "Network",
                    "severity": "Critical",
                    "issue": "Public RDP access",
                    "resource_type": "security_group",
                    "resource_id": sg_name,
                    "resource": sg_name,
                    "description": "RDP (TCP/3389) is open to 0.0.0.0/0.",
                    "explanation": f"RDP is publicly accessible in {environment} environment.",
                    "remediation": "Remove public RDP and use VPN or SSM Session Manager."
                })

            if port == 22:
                findings.append({
                    "id": "NET_PUBLIC_SSH",
                    "title": "SSH exposed to the internet",
                    "service": "Network",
                    "severity": "High",
                    "issue": "Public SSH access",
                    "resource_type": "security_group",
                    "resource_id": sg_name,
                    "resource": sg_name,
                    "description": "SSH (TCP/22) is open to 0.0.0.0/0.",
                    "explanation": f"SSH is publicly accessible in {environment} environment.",
                    "remediation": "Restrict SSH to trusted IPs or use bastion hosts."
                })

    print("NETWORK RULES EXECUTED: produced", len(findings))
    return findings
# IAM rule helpers were duplicated here previously and have been removed to avoid confusion.
# Use the canonical implementation in rules/iam_rules.py

