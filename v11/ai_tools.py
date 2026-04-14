"""CYESCO AI insights and reporting add-ons.

"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from flask import abort, jsonify, render_template, request, send_file

import toolkit

app = toolkit.app
LOG_DIR = Path(toolkit.LOG_DIR)
REPORT_DIR = LOG_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_INDEX = REPORT_DIR / "report_index.jsonl"

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None  # type: ignore
    PSUTIL_AVAILABLE = False


TEXT_SUFFIXES = {".txt", ".log", ".csv", ".md", ".json", ".jsonl"}


def _safe_report_path(filename: str) -> Path | None:
    try:
        candidate = (REPORT_DIR / filename).resolve()
        if REPORT_DIR.resolve() not in candidate.parents and candidate != REPORT_DIR.resolve():
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        return candidate
    except Exception:
        return None


def _read_recent_text_files(limit: int = 12) -> List[Tuple[str, str]]:
    files: List[Tuple[str, str]] = []
    if not LOG_DIR.exists():
        return files

    roots = [LOG_DIR, REPORT_DIR]
    for base in roots:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(path.relative_to(LOG_DIR)) if LOG_DIR in path.parents else path.name
            files.append((rel, text))
            if len(files) >= limit:
                return files
    return files


def _recent_reports(limit: int = 8) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    if not REPORT_DIR.exists():
        return reports

    for path in sorted(REPORT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".md", ".log", ".json"}:
            continue
        stat = path.stat()
        item: Dict[str, Any] = {
            "name": path.name,
            "suffix": path.suffix.lower(),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
        if path.suffix.lower() == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
                item["risk_level"] = payload.get("score", {}).get("risk_level")
                item["risk_score"] = payload.get("score", {}).get("risk_score")
            except Exception:
                pass
        reports.append(item)
        if len(reports) >= limit:
            break
    return reports


def _score_snapshot(snapshot: Dict[str, Any], logs: Dict[str, Any], reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    cpu = float(snapshot.get("cpu_percent") or 0)
    mem = float(snapshot.get("memory_percent") or 0)
    disk = float(snapshot.get("disk_percent") or 0)
    honeypot = snapshot.get("honeypot", {})
    honeypot_running = bool(honeypot.get("running"))
    connection_count = int(honeypot.get("connection_count") or 0)

    risk = 0
    if cpu >= 85:
        risk += 2
    elif cpu >= 65:
        risk += 1
    if mem >= 85:
        risk += 2
    elif mem >= 70:
        risk += 1
    if disk >= 90:
        risk += 2
    elif disk >= 75:
        risk += 1
    if honeypot_running:
        risk += 1
    if connection_count >= 10:
        risk += 1
    if logs["counts"]["alerts"] >= 3:
        risk += 2
    elif logs["counts"]["alerts"] >= 1:
        risk += 1
    if logs["counts"]["errors"] >= 3:
        risk += 2
    elif logs["counts"]["errors"] >= 1:
        risk += 1

    if reports:
        latest = reports[0]
        if latest.get("risk_level") == "CRITICAL":
            risk += 1
        elif latest.get("risk_level") == "HIGH":
            risk += 1

    if risk >= 6:
        level = "CRITICAL"
    elif risk >= 4:
        level = "HIGH"
    elif risk >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    suggestions: List[str] = []
    if cpu >= 65:
        suggestions.append("Review heavy scans and active endpoints to reduce CPU pressure.")
    if mem >= 70:
        suggestions.append("Inspect packet capture buffers and browser tabs; memory is elevated.")
    if disk >= 75:
        suggestions.append("Rotate logs and clean old report files before disk pressure increases.")
    if honeypot_running:
        suggestions.append("Honeypot is active. Use the recent connections panel for live investigation.")
    if logs["counts"]["alerts"] > 0:
        suggestions.append("Open the latest alert lines from the log preview and prioritise those first.")
    if not suggestions:
        suggestions.append("System health looks stable. Keep the dashboard open for live monitoring.")

    return {
        "risk_score": risk,
        "risk_level": level,
        "suggestions": suggestions,
        "summary": {
            "cpu": cpu,
            "memory": mem,
            "disk": disk,
            "honeypot_running": honeypot_running,
            "honeypot_connections": connection_count,
        },
    }


def _extract_log_insights() -> Dict[str, Any]:
    recent = _read_recent_text_files()
    keywords = {
        "open_ports": 0,
        "warnings": 0,
        "alerts": 0,
        "connections": 0,
        "errors": 0,
        "reports": 0,
    }
    snippets: List[str] = []
    files_scanned: List[str] = []

    for name, text in recent:
        files_scanned.append(name)
        low = text.lower()
        keywords["alerts"] += low.count("alert")
        keywords["warnings"] += low.count("warning")
        keywords["errors"] += low.count("error")
        keywords["connections"] += low.count("connection")
        keywords["open_ports"] += low.count("open port") + low.count("open ports")
        keywords["reports"] += low.count("report")
        for line in text.splitlines():
            if any(token in line.lower() for token in ("alert", "error", "warning", "open port", "attack", "suspicious", "honeypot", "report")):
                snippets.append(line.strip())
            if len(snippets) >= 12:
                break
        if len(snippets) >= 12:
            break

    return {"counts": keywords, "snippets": snippets[:12], "files_scanned": files_scanned}


def _trend_from_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    risk_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    levels = [risk_map.get(r.get("risk_level", "LOW"), 1) for r in reports if r.get("risk_level")]
    if len(levels) >= 2:
        delta = levels[0] - levels[1]
    else:
        delta = 0
    if delta > 0:
        trend = "rising"
    elif delta < 0:
        trend = "improving"
    else:
        trend = "stable"

    return {
        "trend": trend,
        "latest_risk": reports[0].get("risk_level") if reports else None,
        "report_count": len(reports),
        "delta": delta,
    }


def _build_ai_payload() -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot_status": toolkit.honeypot_status_for_web(),
        "honeypot": {
            "running": bool(toolkit.HONEYPOT_WEB_THREADS),
            "ports": [p for p, _ in toolkit.HONEYPOT_WEB_THREADS],
        },
    }

    if PSUTIL_AVAILABLE:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(str(Path.home().anchor or "/"))
        net = psutil.net_io_counters()
        snapshot.update(
            {
                "cpu_percent": round(psutil.cpu_percent(interval=0.08), 1),
                "memory_percent": round(vm.percent, 1),
                "disk_percent": round(disk.percent, 1),
                "net_sent_mb": round(net.bytes_sent / (1024 ** 2), 2),
                "net_recv_mb": round(net.bytes_recv / (1024 ** 2), 2),
            }
        )
    else:
        snapshot.update({"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0})

    reports = _recent_reports()
    logs = _extract_log_insights()
    score = _score_snapshot(snapshot, logs, reports)
    trend = _trend_from_reports(reports)

    actions = list(score["suggestions"])
    if logs["counts"]["alerts"] > 0:
        actions.append("Inspect alert-heavy log files and the honeypot pane before deeper scans.")
    if logs["counts"]["errors"] > 0:
        actions.append("Investigate repeated errors in the module that generated them.")
    if trend["trend"] == "rising":
        actions.append("The latest report trend is rising; prioritise containment and log review.")
    if not logs["snippets"]:
        actions.append("Generate a sample scan or start the honeypot to create fresh evidence.")

    return {
        "snapshot": snapshot,
        "score": score,
        "logs": logs,
        "reports": reports,
        "trend": trend,
        "actions": actions,
    }


def _markdown_report(payload: Dict[str, Any]) -> str:
    snap = payload["snapshot"]
    score = payload["score"]
    logs = payload["logs"]
    trend = payload["trend"]
    reports = payload["reports"]

    lines = [
        "# CYESCO Security Report",
        "",
        f"Generated: {snap['timestamp']}",
        "",
        "## Executive Summary",
        f"- Risk Level: **{score['risk_level']}**",
        f"- Risk Score: **{score['risk_score']}**",
        f"- Trend: **{trend['trend']}**",
        f"- CPU: {snap.get('cpu_percent', 0)}%",
        f"- Memory: {snap.get('memory_percent', 0)}%",
        f"- Disk: {snap.get('disk_percent', 0)}%",
        f"- Honeypot Running: **{'Yes' if score['summary']['honeypot_running'] else 'No'}**",
        "",
        "## Recommended Actions",
    ]
    for item in payload["actions"]:
        lines.append(f"- {item}")

    lines.extend(["", "## Recent Evidence"])
    if logs["snippets"]:
        for line in logs["snippets"]:
            lines.append(f"- {line}")
    else:
        lines.append("- No recent warning or alert lines were found in the logs folder.")

    lines.extend(["", "## Recent Reports"])
    if reports:
        for rpt in reports[:6]:
            lines.append(
                f"- {rpt['name']} | {rpt.get('risk_level', 'n/a')} | {rpt['modified']}"
            )
    else:
        lines.append("- No prior reports found.")

    lines.extend(
        [
            "",
            "## Files Scanned",
        ]
    )
    for name in logs["files_scanned"][:8]:
        lines.append(f"- {name}")

    lines.extend(
        [
            "",
            "## Notes",
            "- Created by Team DM",
            "- Save location: logs/reports/",
            "- This report is meant for authorized use only.",
        ]
    )
    return "\n".join(lines)


def _plain_log_report(payload: Dict[str, Any]) -> str:
    snap = payload["snapshot"]
    score = payload["score"]
    trend = payload["trend"]
    logs = payload["logs"]
    return "\n".join(
        [
            f"Generated: {snap['timestamp']}",
            f"Risk Level: {score['risk_level']}",
            f"Risk Score: {score['risk_score']}",
            f"Trend: {trend['trend']}",
            f"CPU: {snap.get('cpu_percent', 0)}%",
            f"Memory: {snap.get('memory_percent', 0)}%",
            f"Disk: {snap.get('disk_percent', 0)}%",
            f"Honeypot Running: {'Yes' if score['summary']['honeypot_running'] else 'No'}",
            "",
            "Recommended Actions:",
            *[f"- {item}" for item in payload["actions"]],
            "",
            "Evidence Snippets:",
            *[f"- {line}" for line in logs["snippets"]],
        ]
    )


def _write_report(payload: Dict[str, Any]) -> Dict[str, str]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"cyesco_report_{ts}"
    md_path = REPORT_DIR / f"{base_name}.md"
    log_path = REPORT_DIR / f"{base_name}.log"
    json_path = REPORT_DIR / f"{base_name}.json"

    md_path.write_text(_markdown_report(payload), encoding="utf-8")
    log_path.write_text(_plain_log_report(payload), encoding="utf-8")
    json_payload = {
        "created_at": payload["snapshot"]["timestamp"],
        "score": payload["score"],
        "trend": payload["trend"],
        "actions": payload["actions"],
        "logs": payload["logs"],
        "reports": payload["reports"][:8],
        "snapshot": payload["snapshot"],
    }
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    index_entry = {
        "created_at": payload["snapshot"]["timestamp"],
        "base_name": base_name,
        "md": md_path.name,
        "log": log_path.name,
        "json": json_path.name,
        "risk_level": payload["score"]["risk_level"],
        "risk_score": payload["score"]["risk_score"],
        "trend": payload["trend"]["trend"],
    }
    with REPORT_INDEX.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(index_entry) + "\n")

    return {"md": str(md_path), "log": str(log_path), "json": str(json_path)}


@app.route("/ai-insights", methods=["GET", "POST"])
def ai_insights_page():
    payload = _build_ai_payload()
    generated = None

    if request.method == "POST":
        generated = _write_report(payload)
        payload["generated_report"] = generated

    return render_template(
        "ai_insights.html",
        payload=payload,
        generated_report=generated,
        reports=_recent_reports(),
    )


@app.route("/api/ai-insights")
def api_ai_insights():
    return jsonify(_build_ai_payload())


@app.route("/api/ai-insights/deep")
def api_ai_insights_deep():
    payload = _build_ai_payload()
    payload["generated_report_files"] = _recent_reports()
    return jsonify(payload)


@app.route("/api/ai-insights/report", methods=["POST"])
def api_ai_insights_report():
    payload = _build_ai_payload()
    generated = _write_report(payload)
    return jsonify({"status": "ok", "generated_report": generated, "payload": payload})


@app.route("/reports")
def reports_page():
    return render_template("reports.html", reports=_recent_reports())


@app.route("/api/reports")
def api_reports():
    return jsonify({"reports": _recent_reports()})


@app.route("/reports/<path:filename>/view")
def view_report(filename: str):
    file_path = _safe_report_path(filename)
    if not file_path:
        abort(404)
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    return render_template(
        "report_view.html",
        filename=file_path.name,
        content=content,
        suffix=file_path.suffix.lower(),
    )


@app.route("/reports/<path:filename>/download")
def download_report(filename: str):
    file_path = _safe_report_path(filename)
    if not file_path:
        abort(404)
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.route("/api/reports/<path:filename>")
def api_report_file(filename: str):
    file_path = _safe_report_path(filename)
    if not file_path:
        return jsonify({"error": "Report not found"}), 404
    if file_path.suffix.lower() == ".json":
        try:
            content = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            content = {"content": file_path.read_text(encoding="utf-8", errors="ignore")}
        return jsonify({"name": file_path.name, "content": content})
    return jsonify({"name": file_path.name, "content": file_path.read_text(encoding="utf-8", errors="ignore")})


@app.route("/api/report-latest")
def api_report_latest():
    reports = _recent_reports()
    if not reports:
        return jsonify({"latest": None})
    latest = reports[0]
    file_path = _safe_report_path(latest["name"])
    body = file_path.read_text(encoding="utf-8", errors="ignore") if file_path else ""
    return jsonify({"latest": latest, "content": body})
