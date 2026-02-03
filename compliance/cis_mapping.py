CIS_MAPPING = {
    "IAM_WILDCARD_ACTION": ["CIS AWS Foundations Benchmark 1.16 - Ensure IAM policies follow least privilege"],
    "IAM_WILDCARD_RESOURCE": ["CIS AWS Foundations Benchmark 1.16 - Ensure IAM policies follow least privilege"],
    "IAM_MISSING_CONDITIONS": ["CIS AWS Foundations Benchmark 1.14 - Ensure IAM conditions are used for privileged actions"],
    "IAM_PRIV_ESCALATION": ["CIS AWS Foundations Benchmark 1.18 - Ensure privileged actions are restricted"],
    "S3_PUBLIC_ACCESS": ["CIS AWS Foundations Benchmark 2.1 - Ensure S3 buckets are not publicly accessible"],
    "S3_NO_ENCRYPTION": ["CIS AWS Foundations Benchmark 2.2 - Ensure S3 buckets are encrypted"],
    "S3_LOGGING_DISABLED": ["CIS AWS Foundations Benchmark 2.6 - Ensure S3 bucket access logging is enabled"],
    "S3_SENSITIVE_PUBLIC": ["CIS AWS Foundations Benchmark 2.1 - Ensure S3 buckets are not publicly accessible"],
    "NET_PUBLIC_SSH": ["CIS AWS Foundations Benchmark 4.1 - Ensure no security groups allow 0.0.0.0/0 to port 22"],
    "NET_PUBLIC_RDP": ["CIS AWS Foundations Benchmark 4.2 - Ensure no security groups allow 0.0.0.0/0 to port 3389"],
    "NET_EXCESSIVE_PORTS": ["CIS AWS Foundations Benchmark 4.3 - Restrict wide ingress ranges"],
    "NET_PROD_NO_SEGMENT": ["CIS AWS Foundations Benchmark 4.4 - Enforce security group segmentation for production"],
}
