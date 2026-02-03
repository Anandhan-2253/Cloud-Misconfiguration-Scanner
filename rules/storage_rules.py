from typing import Any, Dict, List


def run_storage_rules(buckets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("S3 RULES: received", len(buckets), "buckets")
    findings: List[Dict[str, Any]] = []

    for bucket in buckets:
        # Support both parser-normalized keys and raw uploaded variants
        name = bucket.get("bucket_name") or bucket.get("BucketName") or bucket.get("name") or "unnamed-bucket"

        # Normalize public access (parser -> public_access dict, uploads -> PublicAccess boolean)
        public_access = False
        pa = bucket.get("public_access") or bucket.get("PublicAccess")
        if isinstance(pa, dict):
            public_access = bool(pa.get("read") or pa.get("write"))
        else:
            public_access = bool(pa)

        # Normalize encryption
        enc = bucket.get("encryption") or bucket.get("EncryptionAtRest")
        if isinstance(enc, dict):
            encrypted = bool(enc.get("enabled"))
        else:
            encrypted = bool(enc)

        # Normalize sensitivity/classification
        classification = bucket.get("data_classification") or bucket.get("DataSensitivity") or bucket.get("data_sensitivity") or "unknown"

        if public_access:
            findings.append({
                "id": "S3_PUBLIC_BUCKET",
                "title": "Public S3 bucket",
                "service": "Storage",
                "severity": "Critical" if str(classification).lower() in {"pii","credentials","secrets"} else "Medium",
                "issue": "Publicly accessible S3 bucket",
                "resource_type": "s3_bucket",
                "resource_id": name,
                "resource": name,
                "description": "Public access increases the likelihood of data exposure or tampering, especially for sensitive data.",
                "explanation": f"S3 bucket is public and stores {classification} data.",
                "evidence": {"public_access": public_access},
                "remediation": "Block public access and review bucket policies."
            })

        if not encrypted:
            findings.append({
                "id": "S3_NO_ENCRYPTION",
                "title": "Unencrypted S3 bucket",
                "service": "Storage",
                "severity": "Medium",
                "issue": "S3 bucket encryption disabled",
                "resource_type": "s3_bucket",
                "resource_id": name,
                "resource": name,
                "description": "Unencrypted buckets increase exposure if data is exfiltrated or copied.",
                "explanation": "S3 bucket does not have encryption at rest enabled.",
                "evidence": {"encryption": enc},
                "remediation": "Enable SSE-S3 or SSE-KMS encryption."
            })

    print("S3 RULES EXECUTED: produced", len(findings))
    return findings
