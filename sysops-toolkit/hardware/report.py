"""
hardware/report.py
CompTIA A+ Module — Diagnostic Report Generator

Generates a printable HTML technician report from diagnostic data.
Demonstrates: Documentation, troubleshooting output, professional reporting.
"""

import datetime
from hardware.diagnostics import run_diagnostics


STATUS_COLORS = {
    "OK": "#16a34a",
    "HEALTHY": "#16a34a",
    "WARNING": "#d97706",
    "CRITICAL": "#dc2626"
}


def generate_html_report(data: dict) -> str:
    """Build a full HTML diagnostic report from scan results."""
    health = data["overall_health"]
    color = STATUS_COLORS.get(health, "#6b7280")
    sys = data["system"]
    cpu = data["cpu"]
    ram = data["ram"]

    disk_rows = ""
    for d in data["disks"]:
        dc = STATUS_COLORS.get(d["status"], "#6b7280")
        disk_rows += f"""
        <tr>
          <td>{d['device']}</td>
          <td>{d['mountpoint']}</td>
          <td>{d['fstype']}</td>
          <td>{d['total_gb']} GB</td>
          <td>{d['used_gb']} GB ({d['usage_percent']}%)</td>
          <td style="color:{dc}; font-weight:600">{d['status']}</td>
        </tr>"""

    temp_section = ""
    if data["temperature"].get("available") and "sensors" in data["temperature"]:
        temp_section = "<h2>Temperature Sensors</h2><ul>"
        for sensor_name, entries in data["temperature"]["sensors"].items():
            for e in entries:
                ec = STATUS_COLORS.get(e["status"], "#6b7280")
                temp_section += f"<li><strong>{sensor_name} / {e['label']}</strong>: {e['current_c']}°C — <span style='color:{ec}'>{e['status']}</span></li>"
        temp_section += "</ul>"
    else:
        note = data["temperature"].get("note", "Not available")
        temp_section = f"<h2>Temperature Sensors</h2><p style='color:#6b7280'>{note}</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hardware Diagnostic Report — {data['timestamp']}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; color: #1f2937; }}
  h1 {{ font-size: 1.5rem; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; color: #374151; }}
  .badge {{ display: inline-block; padding: 4px 14px; border-radius: 999px; color: white;
            background: {color}; font-weight: 600; font-size: 0.9rem; }}
  .meta {{ color: #6b7280; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: #f3f4f6; text-align: left; padding: 8px 12px; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
  .stat {{ background: #f9fafb; padding: 12px 16px; border-radius: 8px; border: 1px solid #e5e7eb; }}
  .stat-label {{ font-size: 0.75rem; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-value {{ font-size: 1.2rem; font-weight: 600; margin-top: 4px; }}
  @media print {{ body {{ margin: 20px; }} }}
</style>
</head>
<body>
  <h1>Hardware Diagnostic Report &nbsp; <span class="badge">{health}</span></h1>
  <p class="meta">Generated: {data['timestamp']} &nbsp;|&nbsp; Host: {sys['hostname']} &nbsp;|&nbsp; OS: {sys['os']} {sys['architecture']}</p>
  <p class="meta">Uptime: {sys['uptime_hours']} hours &nbsp;|&nbsp; Boot time: {sys['boot_time']}</p>

  <h2>CPU</h2>
  <div class="grid">
    <div class="stat"><div class="stat-label">Usage</div><div class="stat-value">{cpu['usage_percent']}%</div></div>
    <div class="stat"><div class="stat-label">Cores (Physical / Logical)</div><div class="stat-value">{cpu['core_count_physical']} / {cpu['core_count_logical']}</div></div>
    <div class="stat"><div class="stat-label">Current Frequency</div><div class="stat-value">{cpu['freq_current_mhz']} MHz</div></div>
    <div class="stat"><div class="stat-label">Max Frequency</div><div class="stat-value">{cpu['freq_max_mhz']} MHz</div></div>
  </div>

  <h2>Memory (RAM)</h2>
  <div class="grid">
    <div class="stat"><div class="stat-label">Total</div><div class="stat-value">{ram['total_gb']} GB</div></div>
    <div class="stat"><div class="stat-label">Used</div><div class="stat-value">{ram['used_gb']} GB ({ram['usage_percent']}%)</div></div>
    <div class="stat"><div class="stat-label">Available</div><div class="stat-value">{ram['available_gb']} GB</div></div>
    <div class="stat"><div class="stat-label">Status</div><div class="stat-value" style="color:{STATUS_COLORS.get(ram['status'])}">{ram['status']}</div></div>
  </div>

  <h2>Disk Health</h2>
  <table>
    <tr><th>Device</th><th>Mount</th><th>FS Type</th><th>Total</th><th>Used</th><th>Status</th></tr>
    {disk_rows}
  </table>

  {temp_section}

  <hr style="margin-top: 3rem; border-color: #e5e7eb">
  <p style="font-size:0.8rem; color:#9ca3af">SysOps Toolkit — A+ Diagnostics Module &nbsp;|&nbsp; CompTIA A+ Portfolio Project</p>
</body>
</html>"""
    return html


if __name__ == "__main__":
    data = run_diagnostics()
    html = generate_html_report(data)
    filename = f"diagnostic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w") as f:
        f.write(html)
    print(f"[A+ Report] Saved to {filename}")
