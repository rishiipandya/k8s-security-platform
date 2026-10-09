import os
import json
import sqlite3
import hashlib
import time
from datetime import datetime, timezone
from functools import wraps

import yaml
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)
DB_PATH = os.environ.get("SECURITY_DB", "security.db")
METRICS = {
    "scans_total": 0,
    "findings_total": 0,
    "drift_checks_total": 0,
    "drift_detected_total": 0,
    "scan_duration_seconds": 0.0,
}

SAMPLE = open("sample.yaml", encoding="utf-8").read() if os.path.exists("sample.yaml") else ""

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kubernetes Security Platform</title>
<style>
body{font:16px system-ui;background:#f3f5f9;color:#192337;max-width:1100px;margin:30px auto;padding:0 16px}
header{background:#172b4d;color:white;padding:24px;border-radius:12px}
.card{background:white;padding:20px;margin:16px 0;border-radius:12px;box-shadow:0 2px 8px #0001}
textarea{box-sizing:border-box;width:100%;min-height:300px;font:14px monospace}
button{padding:10px 14px;margin:5px 5px 5px 0;cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd;vertical-align:top}
.CRITICAL,.HIGH{color:#bd2525;font-weight:bold}.MEDIUM{color:#965b00;font-weight:bold}.LOW{color:#555}
small{color:#667085}.pill{display:inline-block;background:#e8edf5;padding:5px 9px;border-radius:20px}
</style>
</head>
<body>
<header>
<h1>Kubernetes Runtime Security</h1>
<p>Policy-as-Code · RBAC Analysis · Configuration Drift</p>
<small>Local academic prototype — no live cluster connected</small>
</header>
<div class="card">
<h2>Security overview</h2>
<p>Scans recorded: <b>{{metrics.scans_total}}</b> |
Findings: <b>{{metrics.findings_total}}</b> |
Drift events: <b>{{metrics.drift_detected_total}}</b></p>
<p><a href="/metrics">Prometheus metrics</a> · <a href="/health">Health check</a></p>
</div>
<div class="card">
<h2>1. Scan Kubernetes manifests</h2>
<form method="post" action="/scan">
<textarea name="manifest" required>{{manifest}}</textarea><br>
<button type="submit">Run security scan</button>
</form>
</div>
{% if error %}<div class="card"><b>Input error:</b> {{error}}</div>{% endif %}
{% if findings is not none %}
<div class="card">
<h2>2. Policy findings ({{findings|length}})</h2>
{% if findings %}
<table><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Details</th></tr>
{% for f in findings %}
<tr><td class="{{f.severity}}">{{f.severity}}</td><td>{{f.rule}}</td><td>{{f.resource}}</td><td>{{f.detail}}</td></tr>
{% endfor %}</table>
{% else %}<p>No findings for this scan.</p>{% endif %}
</div>
{% endif %}
<div class="card">
<h2>3. Baseline and drift experiment</h2>
<form method="post" action="/baseline">
<textarea name="manifest" required>{{manifest}}</textarea><br>
<button>Save baseline</button>
</form>
<form method="post" action="/drift">
<textarea name="manifest" required>{{manifest}}</textarea><br>
<button>Check drift</button>
</form>
{% if drift %}<p><span class="pill">{{drift}}</span></p>{% endif %}
</div>
<div class="card">
<h2>4. Exception workflow</h2>
<form method="post" action="/exceptions">
<input name="finding" placeholder="Finding rule, e.g. PRIVILEGED_CONTAINER" required>
<input name="reason" placeholder="Reason for exception" required>
<button>Request exception</button>
</form>
<table><tr><th>ID</th><th>Finding</th><th>Reason</th><th>Status</th><th>Action</th></tr>
{% for e in exceptions %}
<tr><td>{{e.id}}</td><td>{{e.finding}}</td><td>{{e.reason}}</td><td>{{e.status}}</td><td>
{% if e.status == 'Pending' %}
<form method="post" action="/exceptions/{{e.id}}/review">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="reject">Reject</button>
</form>
{% endif %}</td></tr>
{% endfor %}</table>
<small>Demo workflow only. Reviewer authentication is not implemented.</small>
</div>
<div class="card"><h2>5. Recent audit trail</h2>
{% for e in events %}<p><small>{{e.time}}</small> <b>{{e.action}}</b> — {{e.details}}</p>{% endfor %}
</div>
</body></html>
"""


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS audits(
            id INTEGER PRIMARY KEY, time TEXT, action TEXT, details TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS baselines(
            id INTEGER PRIMARY KEY, digest TEXT, content TEXT, time TEXT)""")
        con.execute("""CREATE TABLE IF NOT EXISTS exceptions(
            id INTEGER PRIMARY KEY, finding TEXT, reason TEXT, status TEXT,
            created TEXT)""")


def audit(action, details):
    with connect() as con:
        con.execute(
            "INSERT INTO audits(time,action,details) VALUES(?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             action, str(details)[:500])
        )


def scan_manifest(content):
    findings = []
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        return [{"severity": "HIGH", "rule": "INVALID_YAML",
                 "resource": "Input", "detail": str(exc)}]

    for doc in documents:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "Unknown")
        metadata = doc.get("metadata") or {}
        name = metadata.get("name", "unnamed")
        spec = doc.get("spec") or {}
        resource = f"{kind}/{name}"

        def add(severity, rule, detail):
            findings.append({"severity": severity, "rule": rule,
                             "resource": resource, "detail": detail})

        # Inspect Pod containers, including Deployment/Job-style templates.
        pod_spec = spec
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
            pod_spec = ((spec.get("template") or {}).get("spec") or {})
        elif kind == "CronJob":
            job_spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
            pod_spec = (((job_spec.get("template") or {}).get("spec")) or {})

        if kind == "Pod" or kind in {
            "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"
        }:
            for container in (pod_spec.get("containers") or []):
                sc = container.get("securityContext") or {}
                cname = container.get("name", "container")
                if sc.get("privileged") is True:
                    add("CRITICAL", "PRIVILEGED_CONTAINER",
                        f"{cname} enables privileged mode")
                if sc.get("runAsUser") == 0:
                    add("HIGH", "ROOT_EXECUTION",
                        f"{cname} explicitly runs as root")
                if sc.get("allowPrivilegeEscalation") is not False:
                    add("MEDIUM", "PRIVILEGE_ESCALATION",
                        f"{cname} does not explicitly disable privilege escalation")
                if sc.get("readOnlyRootFilesystem") is not True:
                    add("LOW", "WRITABLE_ROOT_FILESYSTEM",
                        f"{cname} does not enable a read-only root filesystem")

        if kind == "Service" and spec.get("type") in {"NodePort", "LoadBalancer"}:
            add("MEDIUM", "EXPOSED_SERVICE",
                f"Service type is {spec['type']}")

        if kind in {"Role", "ClusterRole"}:
            for rule in (doc.get("rules") or spec.get("rules") or []):
                if "*" in (rule.get("verbs") or []):
                    add("HIGH", "RBAC_WILDCARD_VERBS",
                        "RBAC rule grants wildcard verbs")
                if "*" in (rule.get("resources") or []):
                    add("HIGH", "RBAC_WILDCARD_RESOURCES",
                        "RBAC rule grants wildcard resources")
                if "*" in (rule.get("apiGroups") or []):
                    add("MEDIUM", "RBAC_WILDCARD_APIGROUPS",
                        "RBAC rule grants wildcard API groups")

    return findings


def digest(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def page(manifest=None, findings=None, error=None, drift=None):
    with connect() as con:
        events = con.execute(
            "SELECT * FROM audits ORDER BY id DESC LIMIT 15"
        ).fetchall()
        exceptions = con.execute(
            "SELECT * FROM exceptions ORDER BY id DESC"
        ).fetchall()
    return render_template_string(
        PAGE, manifest=SAMPLE if manifest is None else manifest,
        findings=findings, error=error, drift=drift,
        events=events, exceptions=exceptions, metrics=METRICS
    )


@app.get("/")
def home():
    return page()


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "k8s-security-platform"})


@app.get("/api/health")
def api_health():
    return health()


@app.post("/scan")
def scan_route():
    content = request.form.get("manifest", "")
    started = time.perf_counter()
    findings = scan_manifest(content)
    duration = time.perf_counter() - started
    METRICS["scans_total"] += 1
    METRICS["findings_total"] += len(findings)
    METRICS["scan_duration_seconds"] += duration
    audit("SCAN", f"{len(findings)} findings; duration={duration:.6f}s")
    return page(content, findings)


@app.post("/api/scan")
def api_scan():
    data = request.get_json(silent=True) or {}
    content = data.get("manifest", "")
    if not isinstance(content, str) or not content.strip():
        return jsonify({"error": "manifest must be a non-empty string"}), 400
    started = time.perf_counter()
    findings = scan_manifest(content)
    duration = time.perf_counter() - started
    METRICS["scans_total"] += 1
    METRICS["findings_total"] += len(findings)
    METRICS["scan_duration_seconds"] += duration
    audit("API_SCAN", f"{len(findings)} findings")
    return jsonify({"findings": findings, "count": len(findings),
                    "duration_seconds": duration})


@app.post("/baseline")
def baseline():
    content = request.form.get("manifest", "")
    with connect() as con:
        con.execute("DELETE FROM baselines")
        con.execute(
            "INSERT INTO baselines(digest,content,time) VALUES(?,?,?)",
            (digest(content), content, datetime.now(timezone.utc).isoformat())
        )
    audit("BASELINE_SAVED", f"SHA256={digest(content)}")
    return page(content, drift="Baseline saved")


@app.post("/drift")
def drift():
    content = request.form.get("manifest", "")
    METRICS["drift_checks_total"] += 1
    with connect() as con:
        baseline_row = con.execute(
            "SELECT digest FROM baselines ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if baseline_row is None:
        result = "NO_BASELINE"
    elif digest(content) != baseline_row["digest"]:
        result = "DRIFT_DETECTED"
        METRICS["drift_detected_total"] += 1
    else:
        result = "NO_DRIFT"
    audit("DRIFT_CHECK", result)
    return page(content, drift=result)


@app.post("/exceptions")
def request_exception():
    finding = request.form.get("finding", "").strip()[:200]
    reason = request.form.get("reason", "").strip()[:500]
    if not finding or not reason:
        return page(error="Finding and reason are required"), 400
    with connect() as con:
        con.execute(
            "INSERT INTO exceptions(finding,reason,status,created) VALUES(?,?,?,?)",
            (finding, reason, "Pending",
             datetime.now(timezone.utc).isoformat())
        )
    audit("EXCEPTION_REQUESTED", finding)
    return page()


@app.post("/exceptions/<int:exception_id>/review")
def review_exception(exception_id):
    decision = request.form.get("decision")
    if decision not in {"approve", "reject"}:
        return page(error="Decision must be approve or reject"), 400
    status = "Approved" if decision == "approve" else "Rejected"
    with connect() as con:
        cur = con.execute(
            "UPDATE exceptions SET status=? WHERE id=? AND status='Pending'",
            (status, exception_id)
        )
    if cur.rowcount == 0:
        return page(error="Exception not found or already reviewed"), 404
    audit("EXCEPTION_REVIEWED", f"id={exception_id}; status={status}")
    return page()


@app.get("/metrics")
def metrics():
    lines = [
        "# HELP k8s_scans_total Total manifest scans",
        "# TYPE k8s_scans_total counter",
        f"k8s_scans_total {METRICS['scans_total']}",
        "# HELP k8s_findings_total Findings returned by scans",
        "# TYPE k8s_findings_total counter",
        f"k8s_findings_total {METRICS['findings_total']}",
        "# HELP k8s_drift_checks_total Drift comparisons",
        "# TYPE k8s_drift_checks_total counter",
        f"k8s_drift_checks_total {METRICS['drift_checks_total']}",
        "# HELP k8s_drift_detected_total Detected configuration drift",
        "# TYPE k8s_drift_detected_total counter",
        f"k8s_drift_detected_total {METRICS['drift_detected_total']}",
        "# HELP k8s_scan_duration_seconds_sum Total scan duration",
        "# TYPE k8s_scan_duration_seconds_sum counter",
        f"k8s_scan_duration_seconds_sum {METRICS['scan_duration_seconds']}",
    ]
    body = "\n".join(lines) + "\n"
    return app.response_class(body, mimetype="text/plain; version=0.0.4")


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
