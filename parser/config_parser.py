import json
from typing import Any, Dict, List, Tuple


def _safe_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_json_file(path: str) -> Tuple[Any, List[str]]:
    errors: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), errors
    except FileNotFoundError:
        errors.append(f"File not found: {path}")
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {path}: {exc}")
    except Exception as exc:
        errors.append(f"Unexpected error reading {path}: {exc}")
    return None, errors


def parse_iam_policies(raw: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    policies: List[Dict[str, Any]] = []

    if raw is None:
        return policies, errors

    # Accept common top-level wrappers using different casing (e.g., 'policies' or 'Policies')
    if isinstance(raw, dict) and ("policies" in raw or "Policies" in raw):
        raw_policies = raw.get("policies") or raw.get("Policies", [])
    else:
        raw_policies = raw

    if isinstance(raw_policies, dict):
        raw_policies = [raw_policies]

    if not isinstance(raw_policies, list):
        errors.append("IAM policies must be a list or a dict with 'policies'")
        return policies, errors

    for policy in raw_policies:
        if not isinstance(policy, dict):
            errors.append("IAM policy entry is not an object")
            continue

        policy_name = policy.get("policy_name") or policy.get("PolicyName") or "UnnamedPolicy"
        policy_id = policy.get("policy_id") or policy.get("PolicyId") or policy_name
        document = policy.get("document") or policy.get("PolicyDocument") or {}
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        normalized_statements = []
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            actions = _safe_list(stmt.get("Action") or stmt.get("Actions"))
            resources = _safe_list(stmt.get("Resource") or stmt.get("Resources"))
            normalized_statements.append({
                "sid": stmt.get("Sid") or "Statement",
                "effect": (stmt.get("Effect") or "Allow").lower(),
                "actions": actions,
                "resources": resources,
                "conditions": stmt.get("Condition") or {},
            })

        policies.append({
            "policy_id": policy_id,
            "policy_name": policy_name,
            "statements": normalized_statements,
            "tags": policy.get("tags") or policy.get("Tags") or {},
        })

    return policies, errors


def parse_s3_configs(raw: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    buckets: List[Dict[str, Any]] = []

    if raw is None:
        return buckets, errors

    # Accept common wrappers for S3 config files (e.g., 'buckets' or 'Buckets')
    if isinstance(raw, dict) and ("buckets" in raw or "Buckets" in raw):
        raw_buckets = raw.get("buckets") or raw.get("Buckets", [])
    else:
        raw_buckets = raw

    if isinstance(raw_buckets, dict):
        raw_buckets = [raw_buckets]

    if not isinstance(raw_buckets, list):
        errors.append("S3 configs must be a list or a dict with 'buckets'")
        return buckets, errors

    for bucket in raw_buckets:
        if not isinstance(bucket, dict):
            errors.append("S3 bucket entry is not an object")
            continue

        # Accept both boolean flags and structured dicts
        public_access = bucket.get("public_access") or bucket.get("PublicAccess") or {}
        encryption = bucket.get("encryption") or bucket.get("EncryptionAtRest") or {}
        logging = bucket.get("logging") or bucket.get("AccessLogging") or {}

        # If PublicAccess is a boolean, convert to read/write flags
        if isinstance(public_access, bool):
            public_access = {"read": public_access, "write": public_access}

        # If EncryptionAtRest is a boolean, convert to dict
        if isinstance(encryption, bool):
            encryption = {"enabled": encryption}

        buckets.append({
            "bucket_name": bucket.get("bucket_name") or bucket.get("BucketName") or bucket.get("name") or "unnamed-bucket",
            "environment": bucket.get("environment") or bucket.get("Environment") or "unknown",
            "public_access": {
                "read": bool(public_access.get("read")),
                "write": bool(public_access.get("write")),
            },
            "encryption": {
                "enabled": bool(encryption.get("enabled")),
                "algorithm": encryption.get("algorithm") or "none",
            },
            "logging": {
                "enabled": bool(logging.get("enabled")) if isinstance(logging, dict) else bool(logging),
                "target": logging.get("target") if isinstance(logging, dict) else None,
            },
            "data_classification": bucket.get("data_classification") or bucket.get("DataSensitivity") or "unknown",
            "tags": bucket.get("tags") or bucket.get("Tags") or {},
        })

    return buckets, errors


def parse_security_groups(raw: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    groups: List[Dict[str, Any]] = []

    if raw is None:
        return groups, errors

    # Accept common wrappers for security groups (e.g., 'security_groups' or 'SecurityGroups')
    if isinstance(raw, dict) and ("security_groups" in raw or "SecurityGroups" in raw):
        raw_groups = raw.get("security_groups") or raw.get("SecurityGroups", [])
    else:
        raw_groups = raw

    if isinstance(raw_groups, dict):
        raw_groups = [raw_groups]

    if not isinstance(raw_groups, list):
        errors.append("Security groups must be a list or a dict with 'security_groups'")
        return groups, errors

    for sg in raw_groups:
        if not isinstance(sg, dict):
            errors.append("Security group entry is not an object")
            continue

        # Support various inbound rule field names (e.g., 'rules', 'InboundRules', 'inbound_rules')
        rules = sg.get("rules") or sg.get("InboundRules") or sg.get("inbound_rules") or []
        if isinstance(rules, dict):
            rules = [rules]

        normalized_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            # Normalize CIDR that may be in several fields or list forms
            cidr_raw = rule.get("cidr") or rule.get("cidr_blocks") or rule.get("cidr_ip") or rule.get("CidrIp") or rule.get("CidrIpRanges") or None
            if isinstance(cidr_raw, (list, tuple)):
                cidr = cidr_raw[0] if cidr_raw else "0.0.0.0/0"
            else:
                cidr = cidr_raw or "0.0.0.0/0"

            # Normalize ports and direction/protocol from various schemas
            direction = rule.get("direction") or rule.get("Direction") or "ingress"
            protocol = rule.get("protocol") or rule.get("IpProtocol") or "tcp"
            from_port = rule.get("from_port") or rule.get("FromPort") or rule.get("port")
            to_port = rule.get("to_port") or rule.get("ToPort") or rule.get("port")

            normalized_rules.append({
                "direction": direction.lower(),
                "protocol": protocol.lower(),
                "from_port": from_port,
                "to_port": to_port,
                "cidr": cidr,
                "description": rule.get("description") or rule.get("Description") or "",
            })

        groups.append({
            "group_id": sg.get("group_id") or sg.get("id") or "sg-unknown",
            "group_name": sg.get("group_name") or sg.get("name") or "unnamed-sg",
            "vpc_id": sg.get("vpc_id") or "unknown",
            "environment": sg.get("environment") or "unknown",
            "rules": normalized_rules,
            "tags": sg.get("tags") or {},
        })

    return groups, errors
