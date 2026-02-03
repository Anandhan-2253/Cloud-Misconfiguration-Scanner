MITRE_MAPPING = {
    "IAM_WILDCARD_ACTION": ["T1078.004 - Valid Accounts: Cloud Accounts"],
    "IAM_WILDCARD_RESOURCE": ["T1098 - Account Manipulation"],
    "IAM_MISSING_CONDITIONS": ["T1078.004 - Valid Accounts: Cloud Accounts"],
    "IAM_PRIV_ESCALATION": ["T1098 - Account Manipulation"],
    "S3_PUBLIC_ACCESS": ["T1530 - Data from Cloud Storage"],
    "S3_NO_ENCRYPTION": ["T1530 - Data from Cloud Storage"],
    "S3_LOGGING_DISABLED": ["T1562 - Impair Defenses"],
    "S3_SENSITIVE_PUBLIC": ["T1530 - Data from Cloud Storage"],
    "NET_PUBLIC_SSH": ["T1133 - External Remote Services"],
    "NET_PUBLIC_RDP": ["T1133 - External Remote Services"],
    "NET_EXCESSIVE_PORTS": ["T1046 - Network Service Discovery"],
    "NET_PROD_NO_SEGMENT": ["T1021 - Remote Services"],
}
