"""
app.py
SysOps Toolkit — Main Flask Dashboard

Unified web dashboard demonstrating CompTIA A+, Network+, and Security+
knowledge through live hardware diagnostics, network analysis, and
threat detection. Portfolio project for IT certification showcase.
"""

from flask import Flask, render_template, jsonify, request
import json
import os

app = Flask(__name__)

# ─── A+ Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/hardware")
def hardware():
    return render_template("hardware.html")


@app.route("/api/hardware/diagnostics")
def api_hardware():
    from hardware.diagnostics import run_diagnostics
    data = run_diagnostics()
    return jsonify(data)


@app.route("/api/hardware/report")
def api_hardware_report():
    from hardware.diagnostics import run_diagnostics
    from hardware.report import generate_html_report
    data = run_diagnostics()
    html = generate_html_report(data)
    return html, 200, {"Content-Type": "text/html"}


# ─── Net+ Routes ──────────────────────────────────────────────────────────────

@app.route("/network")
def network():
    return render_template("network.html")


@app.route("/api/network/scan")
def api_network_scan():
    subnet = request.args.get("subnet", "192.168.1.0/24")
    try:
        from network.scanner import scan_network
        results = scan_network(subnet)
        return jsonify(results)
    except Exception as e:
            return jsonify({"error": str(e), "subnet": subnet}), 500


@app.route("/api/network/subnet")
def api_subnet():
    cidr = request.args.get("cidr", "192.168.1.0/24")
    from network.subnet_calc import calculate_subnet
    result = calculate_subnet(cidr)
    return jsonify(result)


@app.route("/api/network/split")
def api_subnet_split():
    cidr = request.args.get("cidr", "192.168.1.0/24")
    prefix = int(request.args.get("prefix", 26))
    from network.subnet_calc import split_subnet
    result = split_subnet(cidr, prefix)
    return jsonify(result)


# ─── Sec+ Routes ──────────────────────────────────────────────────────────────

@app.route("/security")
def security():
    return render_template("security.html")

import os

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

@app.route("/api/security/analyze")
def api_security():
    log_path = request.args.get("log", "sample_logs/windows_events.json")
    if not os.path.isabs(log_path):
        log_path = os.path.join(PROJECT_ROOT, log_path)
    from security.ingest import ingest
    from security.detections import run_all_detections

    try:
        events = ingest(log_path)
        alerts = run_all_detections(events)

        # Remove raw event data to keep response lean
        for a in alerts:
            a.pop("events", None)

        return jsonify({
            "total_events": len(events),
            "total_alerts": len(alerts),
            "alerts": alerts,
            "event_summary": _summarize_events(events)
        })
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404


def _summarize_events(events: list) -> dict:
    """Quick summary stats for the dashboard."""
    severity_counts = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    categories = {}
    for e in events:
        sev = e.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        cat = e.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
    return {"by_severity": severity_counts, "by_category": categories}


if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  SysOps Toolkit — CompTIA A+ / Net+ / Sec+ Portfolio")
    print("=" * 55)
    print("  Dashboard: http://localhost:5000")
    print("  A+ Module: http://localhost:5000/hardware")
    print("  Net+ Module: http://localhost:5000/network")
    print("  Sec+ Module: http://localhost:5000/security")
    print("=" * 55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
