"""
Advanced Network Security Toolkit (Single-File Project)
------------------------------------------------------
Modules:
 1. WiFi Network Analyzer
 2. Packet Sniffer & Mini IDS
 3. Multi-threaded Port Scanner + Banner Grabber
 4. Firewall Rule Analyzer (rule conflicts & shadowing)
 5. Honeypot System (low-interaction, per-IP stats, logs)
 6. OSINT-Based Attack Surface Analyzer (basic + GEOLOCATION)
 7. Endpoint Security Helper (connections + hosts check)

Requirements:
    pip install scapy psutil requests

Use only on systems / networks you own or have permission to test.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import io
from contextlib import redirect_stdout
import re

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)

import platform
import subprocess
import sys
import socket
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Set
from collections import Counter, defaultdict
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Third-party libraries ===
# ===========================================
# Scapy Sniffer Availability
# ===========================================
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf, L3RawSocket
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ====== Basic setup ======

LOG_DIR = "logs"


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


# ====== Simple Color Helpers (ANSI) ======

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE = "\033[34m"
    GREY = "\033[90m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{Color.RESET}"


# ============================================================
# 1) WiFi Network Analyzer
# ============================================================

@dataclass
class WifiNetwork:
    ssid: str
    bssid: str
    signal: str
    channel: str
    auth: str
    encryption: str

    @property
    def security_level(self) -> str:
        combo = (self.auth + " " + self.encryption).upper()
        if "OPEN" in combo or "NONE" in combo:
            return "VERY LOW (Open)"
        if "WEP" in combo:
            return "LOW (WEP)"
        if "WPA3" in combo:
            return "HIGH"
        if "WPA2" in combo:
            return "MEDIUM-HIGH"
        if "WPA" in combo:
            return "MEDIUM"
        return "UNKNOWN"


def run_command(cmd: List[str]) -> str:
    return subprocess.check_output(
        cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8"
    )


def scan_windows_wifi() -> List[WifiNetwork]:
    output = run_command(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    networks: List[WifiNetwork] = []

    current_ssid: Optional[str] = None
    current_auth: str = "Unknown"
    current_enc: str = "Unknown"
    current_bssid: Optional[str] = None
    current_signal: str = ""
    current_channel: str = ""

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("SSID "):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_ssid = parts[1].strip()
        elif line.startswith("Authentication"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_auth = parts[1].strip()
        elif line.startswith("Encryption"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_enc = parts[1].strip()
        elif line.startswith("BSSID "):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_bssid = parts[1].strip()
                current_signal = ""
                current_channel = ""
        elif line.startswith("Signal"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_signal = parts[1].strip()
        elif line.startswith("Channel"):
            parts = line.split(" : ", 1)
            if len(parts) == 2:
                current_channel = parts[1].strip()
                if current_ssid and current_bssid:
                    networks.append(
                        WifiNetwork(
                            ssid=current_ssid,
                            bssid=current_bssid,
                            signal=current_signal or "Unknown",
                            channel=current_channel,
                            auth=current_auth,
                            encryption=current_enc,
                        )
                    )
    return networks


def scan_linux_wifi() -> List[WifiNetwork]:
    try:
        output = run_command(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"]
        )
    except Exception:
        print(c("Could not run 'nmcli'. WiFi scanning not available.", Color.RED))
        return []

    networks: List[WifiNetwork] = []
    for line in output.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        ssid, bssid, chan, signal, security = parts[:5]
        auth = security or "Unknown"
        enc = security or "Unknown"
        networks.append(
            WifiNetwork(
                ssid=ssid or "<hidden>",
                bssid=bssid or "Unknown",
                signal=(signal + "%") if signal and not signal.endswith("%") else (signal or "Unknown"),
                channel=chan or "Unknown",
                auth=auth,
                encryption=enc,
            )
        )
    return networks


def print_wifi_networks(networks: List[WifiNetwork]) -> None:
    if not networks:
        print(c("No WiFi networks found.", Color.YELLOW))
        return

    # Sort strongest signal first if numeric %
    def sig_to_int(s: str) -> int:
        s = s.strip().replace("%", "")
        return int(s) if s.isdigit() else -1

    networks_sorted = sorted(networks, key=lambda n: sig_to_int(n.signal), reverse=True)

    print()
    print(c("Nearby WiFi Networks (sorted by signal strength):", Color.CYAN))
    print("-" * 95)
    header = f"{'SSID':25} {'Signal':8} {'Channel':8} {'Security':30} {'Level'}"
    print(c(header, Color.BOLD))
    print("-" * 95)
    for net in networks_sorted:
        sec = (net.auth + "/" + net.encryption)[:30]
        ssid = (net.ssid[:23] + "..") if len(net.ssid) > 25 else net.ssid

        level_color = Color.GREY
        if "VERY LOW" in net.security_level:
            level_color = Color.RED
        elif "LOW" in net.security_level:
            level_color = Color.YELLOW
        elif "MEDIUM" in net.security_level:
            level_color = Color.BLUE
        elif "HIGH" in net.security_level:
            level_color = Color.GREEN

        level_text = c(net.security_level, level_color)
        print(
            f"{ssid:25} {net.signal:8} {net.channel:8} {sec:30} {level_text}"
        )
    print("-" * 95)
    print(c(f"Total networks: {len(networks_sorted)}\n", Color.GREEN))


def export_wifi_to_csv(networks: List[WifiNetwork]):
    if not networks:
        print(c("Nothing to export.", Color.YELLOW))
        return
    ensure_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOG_DIR, f"wifi_scan_{ts}.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("SSID,BSSID,Signal,Channel,Auth,Encryption,SecurityLevel\n")
        for n in networks:
            row = f'"{n.ssid}","{n.bssid}",{n.signal},{n.channel},"{n.auth}","{n.encryption}","{n.security_level}"\n'
            f.write(row)
    print(c(f"Exported WiFi scan to {path}", Color.CYAN))


def wifi_analyzer_menu():
    os_name = platform.system().lower()
    print()
    print(c("=== WiFi Network Analyzer ===", Color.MAGENTA))

    if "windows" in os_name:
        scanner = scan_windows_wifi
    elif "linux" in os_name:
        scanner = scan_linux_wifi
    else:
        print(c("This feature supports only Windows and Linux.", Color.RED))
        return

    last_scan: List[WifiNetwork] = []

    while True:
        try:
            networks = scanner()
            last_scan = networks
            print_wifi_networks(networks)
            print(c("Options:", Color.GREEN))
            print("  Enter = rescan")
            print("  e      = export last scan to CSV")
            print("  b      = back to main menu")
            choice = input("Choice: ").strip().lower()
            if choice == "b":
                break
            elif choice == "e":
                export_wifi_to_csv(last_scan)
        except KeyboardInterrupt:
            print("\nReturning to main menu...\n")
            break


# ============================================================
# 2) Packet Sniffer & Mini IDS
# ============================================================

SUSPICIOUS_KEYWORDS = [b"password", b"passwd", b"login", b"select ", b"union ", b"drop ", b"cmd.exe"]


class NetworkAnalyzer:
    def __init__(self, filter_mode: str = "ALL"):
        self.filter_mode = filter_mode  # ALL / TCP / UDP / ICMP / ARP
        self.reset_stats()

    def reset_stats(self):
        self.start_time = datetime.now()
        self.total_packets = 0
        self.protocol_counts = Counter()
        self.top_talkers_src = Counter()
        self.top_talkers_dst = Counter()
        self.arp_table = defaultdict(set)  # ip -> set(mac)
        self.src_port_scan: Dict[str, Set[int]] = defaultdict(set)
        self.suspicious_payload_hits: List[Tuple[str, str, str]] = []  # (src, dst, keyword)

    def _update_arp(self, pkt):
        src_ip = pkt.psrc
        src_mac = pkt.hwsrc
        self.arp_table[src_ip].add(src_mac)

    def _filtered_out(self, proto: str) -> bool:
        if self.filter_mode == "ALL":
            return False
        return proto != self.filter_mode

    def process_packet(self, pkt):
        self.total_packets += 1

        proto = "OTHER"
        src = "?"
        dst = "?"

        if ARP in pkt:
            proto = "ARP"
            if self._filtered_out(proto):
                return
            self.protocol_counts["ARP"] += 1
            self._update_arp(pkt[ARP])
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst

        elif IP in pkt:
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst

            if TCP in pkt:
                proto = "TCP"
                if self._filtered_out(proto):
                    return
                self.protocol_counts["TCP"] += 1
                self._track_port_scan(src, pkt[TCP].dport)
                self._inspect_payload(pkt)
            elif UDP in pkt:
                proto = "UDP"
                if self._filtered_out(proto):
                    return
                self.protocol_counts["UDP"] += 1
                self._inspect_payload(pkt)
            elif ICMP in pkt:
                proto = "ICMP"
                if self._filtered_out(proto):
                    return
                self.protocol_counts["ICMP"] += 1
            else:
                proto = "IP-OTHER"
                if self._filtered_out(proto):
                    return
                self.protocol_counts["IP-OTHER"] += 1

            self.top_talkers_src[src] += 1
            self.top_talkers_dst[dst] += 1

        else:
            proto = "NON-IP"
            if self._filtered_out(proto):
                return
            self.protocol_counts["NON-IP"] += 1

        if self.total_packets <= 80 or self.total_packets % 25 == 0:
            print(
                f"[{self.total_packets:5}] "
                f"{c(proto, Color.CYAN):10} {c(src, Color.GREY)}  ->  {c(dst, Color.GREY)}"
            )

    def _track_port_scan(self, src_ip: str, dst_port: int):
        self.src_port_scan[src_ip].add(dst_port)

    def _inspect_payload(self, pkt):
        raw = bytes(pkt)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in raw:
                src = pkt[IP].src if IP in pkt else "?"
                dst = pkt[IP].dst if IP in pkt else "?"
                self.suspicious_payload_hits.append((src, dst, kw.decode(errors="ignore")))
                print(
                    c(
                        f"[ALERT] Suspicious payload keyword '{kw.decode(errors='ignore')}' "
                        f"from {src} -> {dst}",
                        Color.RED,
                    )
                )
                break

    def _detect_arp_spoofing(self):
        suspicious = {}
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                suspicious[ip] = macs
        return suspicious

    def _detect_port_scans(self):
        suspects = {}
        for src, ports in self.src_port_scan.items():
            if len(ports) >= 20:  # threshold
                suspects[src] = len(ports)
        return suspects

    def print_summary(self):
        ensure_log_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"packet_sniffer_summary_{ts}.txt")

        duration = datetime.now() - self.start_time
        seconds = max(duration.total_seconds(), 0.001)
        pps = self.total_packets / seconds

        lines = []
        lines.append("=" * 60)
        lines.append(" CAPTURE SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Capture duration : {duration}")
        lines.append(f"Total packets    : {self.total_packets}")
        lines.append(f"Packets / second : {pps:.2f}")
        lines.append("-" * 60)
        lines.append("Protocol counts:")
        for proto, count in self.protocol_counts.most_common():
            lines.append(f"  {proto:<10} : {count}")
        lines.append("-" * 60)
        lines.append("Top source IPs:")
        for ip, count in self.top_talkers_src.most_common(5):
            lines.append(f"  {ip:<20} {count:>6}")
        lines.append("-" * 60)
        lines.append("Top destination IPs:")
        for ip, count in self.top_talkers_dst.most_common(5):
            lines.append(f"  {ip:<20} {count:>6}")
        lines.append("-" * 60)

        arp_suspicious = self._detect_arp_spoofing()
        if arp_suspicious:
            lines.append("!! Possible ARP spoofing detected !!")
            for ip, macs in arp_suspicious.items():
                mac_list = ", ".join(macs)
                lines.append(f"  IP {ip} is associated with multiple MACs: {mac_list}")
        else:
            lines.append("No obvious ARP spoofing detected.")

        port_scan_suspects = self._detect_port_scans()
        lines.append("-" * 60)
        if port_scan_suspects:
            lines.append("Port-scan suspects (many distinct ports probed):")
            for src, count in port_scan_suspects.items():
                lines.append(f"  {src} -> {count} distinct ports")
        else:
            lines.append("No strong port-scan patterns detected.")

        if self.suspicious_payload_hits:
            lines.append("-" * 60)
            lines.append("Suspicious payload hits:")
            for src, dst, kw in self.suspicious_payload_hits:
                lines.append(f"  {src} -> {dst}, keyword='{kw}'")
        else:
            lines.append("No suspicious payload keywords detected.")

        lines.append("=" * 60)

        print("\n" + "\n".join(lines) + "\n")

        with open(log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(c(f"Summary saved to {log_path}", Color.CYAN))


def list_interfaces():
    print(c("Available interfaces:\n", Color.CYAN))
    for i, iface in enumerate(conf.ifaces.values()):
        desc = getattr(iface, "description", "") or ""
        print(f"[{i}] {iface.name}  {desc}")
    print()


def select_interface():
    list_interfaces()
    choice = input("Enter interface number (or press Enter for default): ").strip()
    if not choice:
        print("Using default interface:", conf.iface)
        return None
    try:
        idx = int(choice)
        iface = list(conf.ifaces.values())[idx]
        print("Using interface:", iface.name)
        return iface.name
    except (ValueError, IndexError):
        print(c("Invalid choice, using default interface.", Color.YELLOW))
        return None


def packet_sniffer_menu():
    
    print()
    print(c("=== Packet Sniffer & Mini IDS ===", Color.MAGENTA))
    print(c("Note: Run this as Administrator/root.\n", Color.YELLOW))

    print(c("Filter modes:", Color.GREEN))
    print("  1) ALL (default)")
    print("  2) TCP only")
    print("  3) UDP only")
    print("  4) ICMP only")
    print("  5) ARP only")
    f_choice = input("Choose filter (1-5): ").strip()
    filter_map = {"1": "ALL", "2": "TCP", "3": "UDP", "4": "ICMP", "5": "ARP"}
    filter_mode = filter_map.get(f_choice, "ALL")

    analyzer = NetworkAnalyzer(filter_mode=filter_mode)
    iface = select_interface()

    while True:
        try:
            count_str = input(
                "Enter number of packets to capture (0 = unlimited, ~200 good for demo): "
            ).strip()
            if not count_str:
                count = 0
            else:
                count = int(count_str)
            break
        except ValueError:
            print(c("Please enter a valid integer.", Color.YELLOW))

    print("\nStarting capture... Press Ctrl+C to stop.\n")
    try:
        if count > 0:
            sniff(iface=iface, prn=analyzer.process_packet, store=False, count=count)
        else:
            sniff(iface=iface, prn=analyzer.process_packet, store=False)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except PermissionError:
        print(c("\n[!] Permission error: run as Administrator/root.", Color.RED))
    except Exception as e:
        print(c(f"\n[!] Error while sniffing: {e}", Color.RED))

    analyzer.print_summary()




def sniffer_capture_output(filter_mode: str = "ALL", count: int = 200) -> str:
    """
    Run the packet sniffer once and return the text output as a string.

    This function does NOT rely on the global SCAPY_AVAILABLE flag.
    It directly tries to import scapy; if that fails, it returns a clear message.
    """
    import io
    import time
    from collections import Counter

    
    buf = io.StringIO()
    start_time = time.time()

    # Normalise filter mode
    mode = (filter_mode or "ALL").upper().strip()

    proto_counts = Counter()
    src_counts = Counter()
    dst_counts = Counter()

    def process_packet(pkt):
        nonlocal proto_counts, src_counts, dst_counts

        # Count protocols
        if pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1
        elif pkt.haslayer(ARP):
            proto_counts["ARP"] += 1
        else:
            proto_counts["OTHER"] += 1

        # Source / destination IPs
        if pkt.haslayer(IP):
            src_counts[pkt[IP].src] += 1
            dst_counts[pkt[IP].dst] += 1

    # Build a BPF filter based on mode
    bpf = None
    if mode == "TCP":
        bpf = "tcp"
    elif mode == "UDP":
        bpf = "udp"
    elif mode == "ICMP":
        bpf = "icmp"
    elif mode == "ARP":
        bpf = "arp"
    else:
        mode = "ALL"

    timeout_sec = 5
    if count <= 0:
        count = 0  # sniff until timeout only

    def run_sniff(use_layer3=False):
        if use_layer3:
            # Layer-3 mode so it works even without WinPcap/Npcap
            conf.L3socket = L3RawSocket
        sniff(
            prn=process_packet,
            store=False,
            count=count,
            timeout=timeout_sec,
            filter=bpf,
        )

    # 2) First try normal layer-2 sniff
    try:
        run_sniff(use_layer3=False)
    except Exception as e:
        print(f"[!] Error while sniffing at layer 2: {e}", file=buf)
        print("[!] Falling back to layer 3 (IP-level sniff, no WinPcap/Npcap needed)...", file=buf)
        try:
            run_sniff(use_layer3=True)
        except Exception as e2:
            print(f"[!] Layer-3 sniff also failed: {e2}", file=buf)

    # 3) Summary
    duration = time.time() - start_time
    total_packets = sum(proto_counts.values())

    print("=== Web Sniffer Run ===", file=buf)
    print(f"Filter mode : {mode}", file=buf)
    print(f"Packet count: {count}", file=buf)
    print("", file=buf)
    print("=========================================", file=buf)
    print(" CAPTURE SUMMARY", file=buf)
    print("=========================================", file=buf)
    print(f"Capture duration : {duration:0.4f} s", file=buf)
    print(f"Total packets    : {total_packets}", file=buf)
    pps = (total_packets / duration) if duration > 0 else 0.0
    print(f"Packets / second : {pps:0.2f}", file=buf)
    print("-----------------------------------------", file=buf)
    print("Protocol counts:", file=buf)
    print("-----------------------------------------", file=buf)
    if not proto_counts:
        print("No packets captured.", file=buf)
    else:
        for proto, c in proto_counts.most_common():
            print(f"{proto:>5}: {c}", file=buf)

    print("-----------------------------------------", file=buf)
    print("Top source IPs:", file=buf)
    print("-----------------------------------------", file=buf)
    if not src_counts:
        print("No source IPs captured.", file=buf)
    else:
        for ip, c in src_counts.most_common(5):
            print(f"{ip:>15} : {c}", file=buf)

    print("-----------------------------------------", file=buf)
    print("Top destination IPs:", file=buf)
    print("-----------------------------------------", file=buf)
    if not dst_counts:
        print("No destination IPs captured.", file=buf)
    else:
        for ip, c in dst_counts.most_common(5):
            print(f"{ip:>15} : {c}", file=buf)

    return buf.getvalue()


# ============================================================
# 3) Multi-threaded Port Scanner + Banner Grabber
# ============================================================

COMMON_PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}


def guess_service(port: int) -> str:
    return COMMON_PORT_SERVICES.get(port, "Unknown")


def grab_banner(sock: socket.socket, port: int) -> str:
    sock.settimeout(2)
    banner = ""
    try:
        if port in {80, 8080, 8000, 443}:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: test\r\n\r\n")
        try:
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
        except socket.timeout:
            pass
    except Exception:
        pass
    return banner or "<no banner>"


def calculate_vuln_score(open_ports: List[Tuple[int, str]]) -> Tuple[int, str]:
    score = 0
    for port, svc in open_ports:
        svc_u = svc.upper()
        if port in {20, 21, 23}:
            score += 4  # FTP/Telnet
        elif port in {22, 3389, 5900}:
            score += 3  # SSH/RDP/VNC
        elif port in {80, 8080}:
            score += 2
        elif port == 443:
            score += 1
        else:
            score += 1

        if "TELNET" in svc_u:
            score += 2
        if "FTP" in svc_u:
            score += 2

    if score == 0:
        level = "No Risk"
    elif score <= 4:
        level = "LOW"
    elif score <= 8:
        level = "MEDIUM"
    elif score <= 14:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level


def scan_single_port(target_ip: str, port: int, timeout: float = 0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            svc = guess_service(port)
            banner = grab_banner(sock, port)
            return port, "open", svc, banner
    except Exception:
        pass
    finally:
        sock.close()
    return None


def port_scanner_menu():
    print()
    print(c("=== Multi-threaded Port Scanner + Banner Grabber ===", Color.MAGENTA))
    target = input("Enter target IP or domain: ").strip()
    if not target:
        print(c("Target is required.", Color.RED))
        return

    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        print(c(f"Could not resolve target: {e}", Color.RED))
        return

    print(c(f"Resolved target: {target} -> {target_ip}", Color.CYAN))
    print(c("Scan modes:", Color.GREEN))
    print("  1) Common ports (20,21,22,23,25,53,80,110,143,443,3306,3389,5900,8080)")
    print("  2) Custom range (e.g. 1-1024)")
    mode = input("Choose mode (1/2): ").strip()

    if mode == "1":
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5900, 8080]
    else:
        try:
            port_range = input("Enter port range (e.g. 1-1024): ").strip()
            sp, ep = port_range.split("-")
            start_port, end_port = int(sp), int(ep)
            ports = list(range(start_port, end_port + 1))
        except Exception:
            print(c("Invalid range, using 1-1024.", Color.YELLOW))
            ports = list(range(1, 1025))

    print(c(f"Scanning {len(ports)} ports with threading...", Color.CYAN))
    ensure_log_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOG_DIR, f"port_scan_{target}_{ts}.txt")

    open_ports: List[Tuple[int, str]] = []
    results = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_single_port, target_ip, p): p for p in ports}
        for future in as_completed(future_to_port):
            res = future.result()
            if res:
                port, state, svc, banner = res
                open_ports.append((port, svc))
                results.append(res)
                print(
                    f"Port {port:5} {c('OPEN', Color.GREEN)}  Service: {svc:10}  Banner: {banner[:70]}"
                )

    print("\n" + "-" * 70)
    print(c("Scan Summary:", Color.BOLD))
    if not open_ports:
        print(c("No open ports detected in selected set.", Color.YELLOW))
        return

    lines = []
    for port, state, svc, banner in sorted(results, key=lambda x: x[0]):
        line = (
            f"Port {port:5} {state.upper():4}  "
            f"Service: {svc:10}  Banner: {banner[:100]}"
        )
        lines.append(line)
        print(line)

    score, level = calculate_vuln_score(open_ports)
    level_color = {
        "No Risk": Color.GREEN,
        "LOW": Color.GREEN,
        "MEDIUM": Color.YELLOW,
        "HIGH": Color.RED,
        "CRITICAL": Color.RED,
    }.get(level, Color.GREY)

    print("-" * 70)
    print(c(f"Vulnerability Score: {score}  Level: {level}", level_color))
    print("-" * 70 + "\n")

    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"Target: {target} ({target_ip})\n")
        f.write("\n".join(lines))
        f.write(f"\n\nVulnerability Score: {score}  Level: {level}\n")
    print(c(f"Port scan results saved to {log_path}", Color.CYAN))


# ============================================================
# 4) Firewall Rule Analyzer
# ============================================================

@dataclass
class FirewallRule:
    index: int
    action: str  # ALLOW or DENY
    src: str
    dst: str
    port: str
    proto: str


def parse_firewall_rules(path: str) -> List[FirewallRule]:
    rules: List[FirewallRule] = []
    if not os.path.exists(path):
        print(c("File does not exist.", Color.RED))
        return rules

    with open(path, "r", encoding="utf-8") as f:
        idx = 1
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 5:
                print(c(f"Skipping invalid line: {line}", Color.YELLOW))
                continue
            action, src, dst, port, proto = parts
            rules.append(
                FirewallRule(
                    index=idx,
                    action=action.upper(),
                    src=src.upper(),
                    dst=dst.upper(),
                    port=port.upper(),
                    proto=proto.upper(),
                )
            )
            idx += 1
    return rules


def match_same_traffic(r1: FirewallRule, r2: FirewallRule) -> bool:
    def eq_or_any(a, b):
        return a == b or a == "ANY" or b == "ANY"

    return (
        eq_or_any(r1.src, r2.src)
        and eq_or_any(r1.dst, r2.dst)
        and eq_or_any(r1.port, r2.port)
        and eq_or_any(r1.proto, r2.proto)
    )


def firewall_analyzer_menu():
    print()
    print(c("=== Firewall Rule Analyzer ===", Color.MAGENTA))
    print(
        c(
            "Custom rule file format (one per line):\n"
            "ACTION,SRC,DST,PORT,PROTO\n"
            "Example:\n"
            "ALLOW,192.168.1.0/24,ANY,80,TCP\n"
            "DENY,ANY,ANY,23,TCP\n"
            "ALLOW,ANY,ANY,ANY,ANY\n",
            Color.GREY,
        )
    )

    path = input("Enter path to firewall rule file: ").strip()
    if not path:
        print(c("Path is required.", Color.RED))
        return

    rules = parse_firewall_rules(path)
    if not rules:
        print(c("No valid rules found.", Color.YELLOW))
        return

    print(c(f"\nLoaded {len(rules)} rules:\n", Color.CYAN))
    for r in rules:
        print(f"{r.index:2}: {r.action:5} SRC={r.src:15} DST={r.dst:15} PORT={r.port:5} PROTO={r.proto}")

    # Simple statistics