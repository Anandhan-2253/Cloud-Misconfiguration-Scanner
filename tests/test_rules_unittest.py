import json
import unittest
from parser.config_parser import parse_iam_policies, parse_s3_configs, parse_security_groups
from rules.iam_rules import run_iam_rules
from rules.storage_rules import run_storage_rules
from rules.network_rules import run_network_rules


def load_json(path):
    with open(path) as f:
        return json.load(f)


class RuleTests(unittest.TestCase):
    def test_iam_rules_detects_wildcard(self):
        data = load_json('input/iam_policies/iam_policies_test.json')
        policies, _ = parse_iam_policies(data)
        findings = run_iam_rules(policies)
        ids = {f['id'] for f in findings}
        self.assertIn('IAM_WILDCARD_ADMIN', ids)

    def test_s3_rules_detect_public_and_unencrypted(self):
        data = load_json('input/sample/s3_configs/s3_configs_test.json')
        buckets, _ = parse_s3_configs(data)
        findings = run_storage_rules(buckets)
        ids = [f['id'] for f in findings]
        self.assertIn('S3_PUBLIC_BUCKET', ids)
        self.assertIn('S3_NO_ENCRYPTION', ids)

    def test_network_rules_detects_ssh_and_rdp(self):
        data = load_json('input/sample/security_groups/security_groups_test.json')
        sgs, _ = parse_security_groups(data)
        findings = run_network_rules(sgs)
        ids = {f['id'] for f in findings}
        self.assertIn('NET_PUBLIC_SSH', ids)
        self.assertIn('NET_PUBLIC_RDP', ids)


if __name__ == '__main__':
    unittest.main()
