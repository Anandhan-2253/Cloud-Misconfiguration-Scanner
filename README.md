# Cloud Misconfiguration Scanner (Risk-Based Prototype)

## Overview
This project is a risk-based cloud misconfiguration audit tool designed to mirror real-world cloud security assessments. It analyzes IAM policies, storage configurations, and network rules, then prioritizes findings based on impact ? likelihood. The goal is to provide a defensible remediation order, not just a list of issues.

This is an on-demand audit tool and does **not** perform real-time monitoring or continuous posture management.

## Architecture
- `parser/`: Normalizes IAM, S3, and Security Group JSON into structured objects
- `rules/`: Explainable, explicit misconfiguration checks
- `engine/`: Risk scoring and prioritization logic
- `compliance/`: CIS, OWASP Cloud Top 10, and MITRE ATT&CK mappings
- `reports/`: HTML report generator
- `dashboard/`: Lightweight Flask UI for running scans

## Risk Scoring Methodology
Each finding is scored with:
- **Impact**: data sensitivity, privilege level, and blast radius
- **Likelihood**: internet exposure, ease of exploitation, and common attack patterns

Risk Score = `Impact ? Likelihood`

Categories:
- Critical: 20?25
- High: 12?19
- Medium: 6?11
- Low: 1?5

Findings are sorted by risk score and assigned a remediation priority order.

## Example Findings
- Public S3 bucket with PII ? Critical
- Public S3 bucket with logs ? Medium
- IAM admin policy without conditions ? Privilege escalation risk
- SSH open to the world on production ? Immediate remediation

## Running the Prototype
1. Install dependencies:
   - `pip install flask`
2. Start the dashboard:
   - `python dashboard/app.py`
3. Upload JSON configurations or use the sample data.
4. Download the generated HTML report.

## Scaling to a Real CSPM
This prototype can evolve into a CSPM by:
- Pulling live configurations via cloud APIs
- Running continuous scans on a schedule
- Integrating ticketing and alerting pipelines
- Adding asset inventory and drift detection

## Notes
- Runs locally with no cloud credentials required.
- Focuses on risk prioritization and explainability.
