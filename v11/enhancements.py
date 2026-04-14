"""CYESCO add-on routes and live summaries.

This module imports the original toolkit, then layers new tools on top of the
same Flask app without removing any of the original capabilities.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from flask import jsonify, render_template, request

import toolkit

app = toolkit.app
LOG_DIR = Path(toolkit.LOG_DIR)
REPORT_DIR = LOG_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None  # type: ignore
    PSUTIL_AVAILABLE = False

try:
    import dns.resolver  # type: ignore
    DNS_AVAILABLE = True
except Exception:
    dns = None  # type: ignore
    DNS_AVAILABLE = False


def _recent_log_files(limit: int = 10) -> List[Dict[str, Any]]:
    if not LOG_DIR.exists():
        return []
    files: List[Dict[str, Any]] = []
    for base in (LOG_DIR, REPORT_DIR):
        if not base.exists():
            continue
        for path in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".txt", ".log", ".csv", ".md", ".json", ".jsonl"}:
                continue
            stat = path.stat()
            files.append(
                {
                    "name": str(path.relative_to(LOG_DIR)) if path.is_relative_to(LOG_DIR) else path.name,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            if len(files) >= limit:
                return files
    return files


def _report_file_stats(limit: int = 8) -> List[Dict[str, Any]]:
    if not REPORT_DIR.exists():
        return []
    reports: List[Dict[str, Any]] = []
    for path in sorted(REPORT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".md", ".log", ".json"}:
            continue
        stat = path.stat()
        reports.append(
            {
                "name": path.name,
                "suffix": path.suffix.lower(),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        if len(reports) >= limit:
            break
    return reports


def _dns_query(domain: str, record: str) -> List[str]:
    if not DNS_AVAILABLE:
        return []
    try:
        answers = dns.resolver.resolve(domain, record)  # type: ignore[attr-defined]
        return [str(a).strip() for a in answers]
    except Exception:
        return []


def _collect_dns_info(domain: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "domain": domain,
        "a": _dns_query(domain, "A"),
        "aaaa": _dns_query(domain, "AAAA"),
        "mx": _dns_query(domain, "MX"),
        "ns": _dns_query(domain, "NS"),
        "txt": _dns_query(domain, "TXT"),
        "cname": _dns_query(domain, "CNAME"),
    }

    if not info["a"] and not info["aaaa"]:
        try:
            resolved = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
            info["a"] = [ip for ip in resolved if ":" not in ip]
            info["aaaa"] = [ip for ip in resolved if ":" in ip]
        except Exception:
            pass

    return info


def _collect_tls_info(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"available": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
        if cert:
            not_after = cert.get("notAfter")
            expiry_days = None
            if not_after:
                try:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry_days = (expiry_dt - datetime.utcnow()).days
                except Exception:
                    expiry_days = None

            result.update(
                {
                    "available": True,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {},
                    "not_before": cert.get("notBefore"),
                    "not_after": not_after,
                    "expiry_days": expiry_days,
                    "san": [x[1] for x in cert.get("subjectAltName", [])],
                }
            )
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _honeypot_snapshot() -> Dict[str, Any]:
    with toolkit.HONEYPOT_WEB_LOCK:
        running = bool(toolkit.HONEYPOT_WEB_THREADS)
        start_time = toolkit.HONEYPOT_WEB_STATS.get("start_time")
        connections = list(toolkit.HONEYPOT_WEB_STATS.get("connections", []))
        ports = [p for p, _ in toolkit.HONEYPOT_WEB_THREADS]

    return {
        "running": running,
        "ports": ports,
        "start_time": start_time,
        "connections": connections,
        "connection_count": len(connections),
        "status_text": toolkit.honeypot_status_for_web(),
    }


def _system_snapshot() -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot": _honeypot_snapshot(),
        "logs": _recent_log_files(),
        "reports": _report_file_stats(),
        "tool_status": {
            "wifi_ready": True,
            "sniffer_ready": toolkit.SCAPY_AVAILABLE,
            "endpoint_ready": PSUTIL_AVAILABLE,
            "dns_ready": DNS_AVAILABLE,
        },
    }

    if PSUTIL_AVAILABLE:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(str(Path.home().anchor or "/"))
        net = psutil.net_io_counters()
        snapshot.update(
            {
                "cpu_percent": round(psutil.cpu_percent(interval=0.1), 1),
                "memory_percent": round(vm.percent, 1),
                "memory_used_gb": round(vm.used / (1024**3), 2),
                "memory_total_gb": round(vm.total / (1024**3), 2),
                "disk_percent": round(disk.percent, 1),
                "disk_used_gb": round(disk.used / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "net_bytes_sent_mb": round(net.bytes_sent / (1024**2), 2),
                "net_bytes_recv_mb": round(net.bytes_recv / (1024**2), 2),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
    else:
        snapshot.update({"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0})
    return snapshot


def _honeypot_self_test(timeout: float = 1.0) -> Dict[str, Any]:
    snap = _honeypot_snapshot()
    results: List[Dict[str, Any]] = []

    for port in snap["ports"] or list(toolkit.HONEYPOT_WEB_PORTS):
        item: Dict[str, Any] = {"port": port, "working": False, "banner": None, "error": None}
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as conn:
                try:
                    conn.settimeout(timeout)
                    banner = conn.recv(256).decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = ""
                item["working"] = True
                item["banner"] = banner or "Connected successfully"
        except Exception as exc:
            item["error"] = str(exc)
        results.append(item)

    return {
        "honeypot": snap,
        "tests": results,
        "all_working": all(r["working"] for r in results) if results else False,
        "how_to_verify": [
            "Start the honeypot from the control panel.",
            "Connect from another device on the same authorized network to one of the listening ports.",
            "Confirm new entries appear in the recent connections panel and in logs/honeypot_log.txt.",
        ],
    }


@app.route("/dns-audit", methods=["GET", "POST"])
def dns_audit_page():
    target = ""
    error = None
    result = None
    if request.method == "POST":
        target = request.form.get("target", "").strip().lower()
        if not target:
            error = "Please enter a domain name."
        else:
            result = {
                "dns": _collect_dns_info(target),
                "tls": _collect_tls_info(target),
            }
    return render_template("dns_audit.html", target=target, result=result, error=error)


@app.route("/health")
def health_page():
    return render_template("health.html", snapshot=_system_snapshot())


@app.route("/honeypot-control", methods=["GET", "POST"])
def honeypot_control_page():
    message = None
    self_test = None

    if request.method == "POST":
        action = request.form.get("action")
        if action == "start":
            message = toolkit.start_honeypot_web()
        elif action == "stop":
            message = toolkit.stop_honeypot_web()
        elif action == "test":
            self_test = _honeypot_self_test()

    return render_template(
        "honeypot_control.html",
        message=message,
        status=_honeypot_snapshot(),
        self_test=self_test,
    )


@app.route("/api/summary")
def api_summary():
    return jsonify(_system_snapshot())


@app.route("/api/recent-logs")
def api_recent_logs():
    return jsonify({"logs": _recent_log_files(), "reports": _report_file_stats()})


@app.route("/api/honeypot/status")
def api_honeypot_status():
    return jsonify(_honeypot_snapshot())


@app.route("/api/honeypot/start", methods=["POST"])
def api_honeypot_start():
    return jsonify(
        {
            "message": toolkit.start_honeypot_web(),
            "honeypot": _honeypot_snapshot(),
        }
    )


@app.route("/api/honeypot/stop", methods=["POST"])
def api_honeypot_stop():
    return jsonify(
        {
            "message": toolkit.stop_honeypot_web(),
            "honeypot": _honeypot_snapshot(),
        }
    )


@app.route("/api/honeypot/self-test")
def api_honeypot_self_test():
    return jsonify(_honeypot_self_test())


# ---------- Exposure scan suite ----------

import http.client as http_client
from urllib.parse import urlparse

COMMON_SCAN_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080]
SCAN_INDEX = REPORT_DIR / "scan_index.jsonl"

def _normalize_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        return ""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target

def _resolve_target(target: str) -> List[str]:
    try:
        host = _normalize_target(target)
        if not host:
            return []
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except Exception:
        return []

def _probe_port(host: str, port: int, timeout: float = 0.45) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass

def _http_head(host: str, scheme: str = "https") -> Dict[str, Any]:
    result: Dict[str, Any] = {"available": False, "scheme": scheme, "status": None, "reason": None, "headers": {}}
    try:
        context = ssl._create_unverified_context()
        if scheme == "https":
            conn = http_client.HTTPSConnection(host, 443, timeout=4, context=context)
        else:
            conn = http_client.HTTPConnection(host, 80, timeout=4)
        conn.request("HEAD", "/", headers={"Host": host, "User-Agent": "CYESCO-ExposureScanner/1.0"})
        resp = conn.getresponse()
        result["available"] = True
        result["status"] = resp.status
        result["reason"] = resp.reason
        result["headers"] = {k: v for k, v in resp.getheaders()}
        conn.close()
    except Exception as exc:
        result["error"] = str(exc)
    return result

def _security_header_score(headers: Dict[str, str]) -> Tuple[int, List[str]]:
    score = 0
    findings: List[str] = []
    checks = {
        "content-security-policy": "Missing Content-Security-Policy header.",
        "x-frame-options": "Missing X-Frame-Options header.",
        "x-content-type-options": "Missing X-Content-Type-Options header.",
        "referrer-policy": "Missing Referrer-Policy header.",
        "permissions-policy": "Missing Permissions-Policy header.",
    }
    lowered = {k.lower(): v for k, v in headers.items()}
    for key, message in checks.items():
        if key in lowered:
            score += 1
        else:
            findings.append(message)
    if "server" in lowered:
        findings.append(f"Server header exposed: {lowered['server']}")
    if "strict-transport-security" in lowered:
        score += 1
    else:
        findings.append("Missing Strict-Transport-Security header for HTTPS.")
    return score, findings

def _build_exposure_scan(target: str) -> Dict[str, Any]:
    host = _normalize_target(target)
    resolved = _resolve_target(host)
    host_ip = resolved[0] if resolved else host

    open_ports = [port for port in COMMON_SCAN_PORTS if _probe_port(host_ip, port)]
    http_info = _http_head(host, "http")
    https_info = _http_head(host, "https")
    header_score_http, header_findings_http = _security_header_score(http_info.get("headers") or {})
    header_score_https, header_findings_https = _security_header_score(https_info.get("headers") or {})
    tls_info = _collect_tls_info(host)

    risk = 0
    risk += min(len(open_ports), 10)
    if len(open_ports) >= 8:
        risk += 2
    if http_info.get("available"):
        risk += 1
    if https_info.get("available"):
        risk += 1
    risk += max(0, 5 - max(header_score_http, header_score_https))

    if risk >= 12:
        level = "CRITICAL"
    elif risk >= 8:
        level = "HIGH"
    elif risk >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    recommendations = []
    if open_ports:
        recommendations.append("Review exposed services and close any ports that are not required.")
    if header_findings_http or header_findings_https:
        recommendations.append("Add missing HTTP security headers to reduce web exposure.")
    if tls_info.get("available"):
        recommendations.append("Check TLS certificate expiry and trust chain before deployment.")
    if not recommendations:
        recommendations.append("Exposure looks modest. Keep validating the service set and headers regularly.")

    return {
        "target": host,
        "resolved": resolved,
        "open_ports": open_ports,
        "http": http_info,
        "https": https_info,
        "tls": tls_info,
        "risk": risk,
        "risk_level": level,
        "recommendations": recommendations,
        "header_findings": {"http": header_findings_http, "https": header_findings_https},
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

def _write_exposure_report(payload: Dict[str, Any]) -> Dict[str, str]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"exposure_scan_{ts}"
    md_path = REPORT_DIR / f"{base}.md"
    log_path = REPORT_DIR / f"{base}.log"
    json_path = REPORT_DIR / f"{base}.json"

    md_lines = [
        "# CYESCO Exposure Scan Report",
        "",
        f"Target: {payload['target']}",
        f"Timestamp: {payload['timestamp']}",
        f"Risk Level: {payload['risk_level']}",
        f"Risk Score: {payload['risk']}",
        "",
        "## Open Ports",
    ]
    if payload["open_ports"]:
        md_lines.extend([f"- {p}" for p in payload["open_ports"]])
    else:
        md_lines.append("- None detected in the selected set.")

    md_lines.extend(["", "## HTTP Findings"])
    for scheme in ("http", "https"):
        info = payload[scheme]
        md_lines.append(f"### {scheme.upper()}")
        if info.get("available"):
            md_lines.append(f"- Status: {info.get('status')} {info.get('reason')}")
            hdrs = info.get("headers") or {}
            for key, value in sorted(hdrs.items()):
                md_lines.append(f"  - {key}: {value}")
        else:
            md_lines.append(f"- {info.get('error', 'Unavailable')}")

    md_lines.extend(["", "## TLS", f"- Available: {'Yes' if payload['tls'].get('available') else 'No'}"])
    if payload["tls"].get("available"):
        md_lines.extend([
            f"- Subject: {payload['tls'].get('subject')}",
            f"- Issuer: {payload['tls'].get('issuer')}",
            f"- Expires: {payload['tls'].get('not_after')}",
            f"- SAN: {payload['tls'].get('san')}",
        ])

    md_lines.extend(["", "## Recommendations"])
    md_lines.extend([f"- {item}" for item in payload["recommendations"]])
    md_lines.extend(["", "Created by Team DM", "Saved under logs/reports/"])

    md = "\n".join(md_lines)
    log = "\n".join([
        f"target={payload['target']}",
        f"timestamp={payload['timestamp']}",
        f"risk_level={payload['risk_level']}",
        f"risk_score={payload['risk']}",
        f"open_ports={payload['open_ports']}",
    ])

    md_path.write_text(md, encoding="utf-8")
    log_path.write_text(log, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    try:
        with open(SCAN_INDEX, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "name": md_path.name,
                "risk_level": payload["risk_level"],
                "risk_score": payload["risk"],
                "target": payload["target"],
                "modified": payload["timestamp"],
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

    return {"md": md_path.name, "log": log_path.name, "json": json_path.name}

@app.route("/scan-suite", methods=["GET", "POST"])
def scan_suite_page():
    target = ""
    result = None
    generated_report = None
    error = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            error = "Please enter a domain, IP, or URL."
        else:
            result = _build_exposure_scan(target)
            generated_report = _write_exposure_report(result)
    return render_template("scan_suite.html", target=target, result=result, generated_report=generated_report, error=error)

@app.route("/api/exposure-scan", methods=["POST"])
def api_exposure_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target is required."}), 400
    result = _build_exposure_scan(target)
    result["generated_report"] = _write_exposure_report(result)
    return jsonify(result)

@app.route("/api/exposure-scan/latest")
def api_exposure_scan_latest():
    if not REPORT_DIR.exists():
        return jsonify({"report": None})
    latest = None
    for path in sorted(REPORT_DIR.glob("exposure_scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        latest = path
        break
    if not latest:
        return jsonify({"report": None})
    try:
        payload = json.loads(latest.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    return jsonify({"report": latest.name, "payload": payload})
