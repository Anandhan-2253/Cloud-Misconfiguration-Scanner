import datetime
import json
import os
import sys
from typing import Any, Dict, List, Tuple

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from flask import Flask, redirect, render_template, request, send_from_directory, url_for

from compliance.cis_mapping import CIS_MAPPING
from compliance.mitre_mapping import MITRE_MAPPING
from compliance.owasp_cloud import OWASP_CLOUD_MAPPING
from engine.rule_engine import run_all_rules
from engine.risk_engine import overall_posture, prioritize
from parser.config_parser import parse_iam_policies, parse_s3_configs, parse_security_groups
from reports.report_generator import generate_report


app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)

REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SAMPLE_PATH = os.path.join(BASE_DIR, "sample_data", "realistic_examples.json")
INDEX_PATH = os.path.join(REPORTS_DIR, "scan_index.json")

LAST_SCAN: Dict[str, Any] = {}


def _load_json_from_upload(file_storage):
    if not file_storage:
        return None, ["No file uploaded"]
    try:
        return json.loads(file_storage.read().decode("utf-8")), []
    except Exception as exc:
        return None, [f"Invalid JSON: {exc}"]


def _load_sample():
    with open(SAMPLE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_index() -> List[Dict[str, Any]]:
    if not os.path.exists(INDEX_PATH):
        return []
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_index(index_entries: List[Dict[str, Any]]) -> None:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(index_entries, f, indent=2)


def _service_label(resource_type: str) -> str:
    mapping = {
        "iam_policy": "IAM",
        "s3_bucket": "Storage",
        "security_group": "Network",
    }
    return mapping.get(resource_type, "Unknown")


def _count_by_category(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.get("risk_category", "Low")] += 1
    return counts


def _level(score: int) -> Tuple[str, int]:
    if score >= 4:
        return "High", 3
    if score >= 3:
        return "Medium", 2
    return "Low", 1


def _heatmap(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    grid = {}
    labels = ["Low", "Medium", "High"]
    for impact in labels:
        for likelihood in labels:
            key = f"{impact}:{likelihood}"
            grid[key] = {
                "impact": impact,
                "likelihood": likelihood,
                "count": 0,
                "example": "No findings",
                "risk": "Low",
            }

    for f in findings:
        impact_label, impact_val = _level(f.get("impact_score", 1))
        likelihood_label, likelihood_val = _level(f.get("likelihood_score", 1))
        score = impact_val * likelihood_val
        if score >= 8:
            risk = "Critical"
        elif score >= 5:
            risk = "High"
        elif score >= 3:
            risk = "Medium"
        else:
            risk = "Low"
        key = f"{impact_label}:{likelihood_label}"
        cell = grid[key]
        cell["count"] += 1
        if cell["example"] == "No findings":
            cell["example"] = f.get("title", "Finding")
        cell["risk"] = risk

    return {
        "labels": labels,
        "cells": [grid[f"{impact}:{likelihood}"] for impact in labels for likelihood in labels],
    }


def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = _count_by_category(findings)
    by_service = {"IAM": 0, "Storage": 0, "Network": 0}
    for f in findings:
        by_service[_service_label(f.get("resource_type", ""))] = (
            by_service.get(_service_label(f.get("resource_type", "")), 0) + 1
        )
    return {"counts": counts, "by_service": by_service}


@app.route("/", methods=["GET"])
def index():
    last_scan = LAST_SCAN.get("timestamp")
    return render_template("scan.html", active_page="scan", last_scan=last_scan)


@app.route("/scan", methods=["POST"])
def scan():
    errors = []
    if request.form.get("use_sample"):
        data = _load_sample()
        iam_raw = data.get("iam_policies")
        s3_raw = data.get("s3_configs")
        sg_raw = data.get("security_groups")
    else:
        iam_raw, iam_errors = _load_json_from_upload(request.files.get("iam_file"))
        s3_raw, s3_errors = _load_json_from_upload(request.files.get("s3_file"))
        sg_raw, sg_errors = _load_json_from_upload(request.files.get("sg_file"))
        errors.extend(iam_errors + s3_errors + sg_errors)

    # Debug: raw upload checks
    print("IAM RAW:", isinstance(iam_raw, (dict, list)), iam_raw if isinstance(iam_raw, (dict, list)) else str(iam_raw))
    print("S3 RAW:", isinstance(s3_raw, (dict, list)), s3_raw if isinstance(s3_raw, (dict, list)) else str(s3_raw))
    print("SG RAW:", isinstance(sg_raw, (dict, list)), sg_raw if isinstance(sg_raw, (dict, list)) else str(sg_raw))

    iam_policies, iam_parse_errors = parse_iam_policies(iam_raw)
    s3_configs, s3_parse_errors = parse_s3_configs(s3_raw)
    security_groups, sg_parse_errors = parse_security_groups(sg_raw)
    errors.extend(iam_parse_errors + s3_parse_errors + sg_parse_errors)

    # Debug: parser output counts
    print("IAM PARSED COUNT:", len(iam_policies))
    print("S3 PARSED COUNT:", len(s3_configs))
    print("SG PARSED COUNT:", len(security_groups))
    print("PARSER ERRORS:", iam_parse_errors + s3_parse_errors + sg_parse_errors)

    findings = run_all_rules({
        "iam_policies": iam_policies,
        "s3_configs": s3_configs,
        "security_groups": security_groups,
    })

    prioritized = prioritize(findings)
    posture = overall_posture(prioritized)
    report_html = generate_report(prioritized, posture)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_name = f"report-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.html"
    report_path = os.path.join(REPORTS_DIR, report_name)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    summary = f"{posture[0]} (Score {posture[1]})"
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    index_entries = _load_index()
    index_entries.insert(
        0,
        {
            "report_name": report_name,
            "created_at": timestamp,
            "summary": summary,
            "counts": _count_by_category(prioritized),
        },
    )
    _save_index(index_entries[:50])

    LAST_SCAN.update(
        {
            "timestamp": timestamp,
            "summary": summary,
            "posture": posture,
            "report_name": report_name,
            "errors": errors,
            "findings": prioritized,
        }
    )

    return redirect(url_for("results"))


@app.route("/results", methods=["GET"])
def results():
    if not LAST_SCAN:
        return render_template("results.html", active_page="results", empty_state=True)

    findings = LAST_SCAN.get("findings", [])
    for finding in findings:
        finding["service"] = _service_label(finding.get("resource_type", ""))
        finding["cis"] = CIS_MAPPING.get(finding.get("id"), [])
        finding["owasp"] = OWASP_CLOUD_MAPPING.get(finding.get("id"), [])
        finding["mitre"] = MITRE_MAPPING.get(finding.get("id"), [])
    summary = _summarize(findings)
    heatmap = _heatmap(findings)
    return render_template(
        "results.html",
        active_page="results",
        empty_state=False,
        findings=findings,
        summary=summary,
        heatmap=heatmap,
        report_name=LAST_SCAN.get("report_name"),
        posture=LAST_SCAN.get("posture"),
        timestamp=LAST_SCAN.get("timestamp"),
        errors=LAST_SCAN.get("errors", []),
    )


@app.route("/reports", methods=["GET"])
def reports():
    entries = _load_index()
    return render_template("reports.html", active_page="reports", reports=entries, last_scan=LAST_SCAN.get("timestamp"))


@app.route("/report/<path:filename>", methods=["GET"])
def report(filename):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
