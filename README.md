# ☁️ Cloud Misconfiguration Scanner

<p align="center">
  <img src="https://raw.githubusercontent.com/Anandhan-2253/Cloud-Misconfiguration-Scanner/main/assets/cover.png" alt="Cloud Misconfiguration Scanner" />
</p>

> [!NOTE]
> **Risk-Based Cloud Security Audit Tool**

**Cloud Misconfiguration Scanner** is a security audit prototype designed to detect, prioritize, and report **cloud misconfigurations** across IAM policies, storage services, and network security groups.

The tool simulates how **cloud security engineers, SOC analysts, and DevSecOps teams** identify configuration weaknesses that commonly lead to data breaches, privilege escalation, and unauthorized access.

It focuses on **risk-based analysis**, **schema-safe rule execution**, and **professional reporting**, rather than raw scanning.

---

<p align="center">
  🔗 <strong>Repository:</strong>
  <a href="https://github.com/Anandhan-2253/Cloud-Misconfiguration-Scanner">
    Cloud Misconfiguration Scanner
  </a>
</p>

<p align="center">
  <a href="https://github.com/Anandhan-2253/Cloud-Misconfiguration-Scanner">
    <img src="https://img.shields.io/static/v1?label=Python&message=Security%20Tool&color=0A1A2F&labelColor=1E293B&style=for-the-badge&logo=python&logoColor=white" />
  </a>
  <a href="https://github.com/Anandhan-2253/Cloud-Misconfiguration-Scanner/issues">
    <img src="https://img.shields.io/github/issues/Anandhan-2253/Cloud-Misconfiguration-Scanner?style=for-the-badge&color=8B0000&logo=github" />
  </a>
  <a href="https://github.com/Anandhan-2253/Cloud-Misconfiguration-Scanner/stargazers">
    <img src="https://img.shields.io/github/stars/Anandhan-2253/Cloud-Misconfiguration-Scanner?style=for-the-badge&color=FFD700&logo=github" />
  </a>
</p>

---

## 🔍 What This Tool Does

Cloud Misconfiguration Scanner performs **offline cloud configuration audits** by analyzing JSON-based cloud configuration files.

It detects:
- Over-permissive IAM policies
- Publicly exposed storage
- Insecure network access rules
- Missing encryption and access controls

Findings are **prioritized by risk** and mapped to **security best practices**, producing a professional security assessment report.

---

## 🛡️ Supported Security Domains

The scanner currently analyzes:

### 🔐 Identity & Access Management (IAM)
- Wildcard permissions (`*`)
- Over-privileged roles
- Missing conditional access controls

### 🗄️ Storage Security
- Public storage buckets
- Sensitive data exposure (PII, logs)
- Missing encryption at rest

### 🌐 Network Security
- Public SSH / RDP exposure
- Overly permissive security groups
- Insecure inbound access rules

---

## 🧠 Why This Project Matters

Cloud misconfigurations are among the **top causes of cloud breaches**.

This project demonstrates:
- How security teams **prevent silent false negatives**
- Why schema normalization matters in security tools
- How rule-based engines outperform naive scanners
- The importance of **strict finding schemas** for reporting

This is **not a live CSPM**, but a **realistic audit prototype** designed for learning and evaluation.

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    A[User / Analyst] --> B[Flask Dashboard]
    B --> C[Configuration Parser]
    C --> D[IAM Rule Engine]
    C --> E[Storage Rule Engine]
    C --> F[Network Rule Engine]
    D --> G[Risk Prioritization]
    E --> G
    F --> G
    G --> H[Compliance Mapping]
    H --> I[HTML Security Report]
    H --> J[Dashboard Results]
📁 Project Structure
cloud_mis_scan/
├── dashboard/
│   └── app.py
├── engine/
│   └── rule_engine.py
├── rules/
│   ├── iam_rules.py
│   ├── storage_rules.py
│   └── network_rules.py
├── reports/
│   └── report_generator.py
├── sample_data/
│   ├── iam_policies_test.json
│   ├── s3_configs_test.json
│   └── security_groups_test.json
└── README.md
🚀 Getting Started
1️⃣ Clone the repository
git clone https://github.com/Anandhan-2253/Cloud-Misconfiguration-Scanner.git
cd Cloud-Misconfiguration-Scanner
2️⃣ Run the application
cd dashboard
python app.py
3️⃣ Access the dashboard
http://127.0.0.1:5000
Upload sample JSON files or use bundled test data to run a scan.

📄 Output
Risk-prioritized findings

Interactive dashboard results

Downloadable HTML security assessment report

⚠️ Limitations
No live cloud provider integration

No continuous monitoring

No automatic remediation

These are intentional to keep the focus on security logic and correctness.

🔮 Future Enhancements
AWS / Azure / GCP API integration

Continuous configuration monitoring

Auto-remediation playbooks

CI/CD security checks

Role-based access control

👤 Author
Anandhanarayan K
Cloud Security & Cybersecurity Enthusiast
India 🇮🇳

📜 License
This project is released for educational and non-commercial use.

Unauthorized commercial usage is prohibited.

⭐ Star History


---

## 🧠 Why this README works for jobs

Recruiters immediately see:
- Clear **security problem**
- Real **engineering challenges**
- Proper **architecture**
- Honest **limitations**
- Professional **presentation**

This README alone signals **“industry-ready mindset”**.

---

## 🚀 Next (optional but powerful)
I can:
- Create a **cover image** (`assets/cover.png`)
- Optimize README for **ATS keywords**
- Write **resume bullets mapped to this repo**
- Draft a **LinkedIn project post**

Just tell me what you want next 👌
