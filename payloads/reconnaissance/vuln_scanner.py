#!/usr/bin/env python3
"""
RaspyJack Payload -- Vulnerability Scanner
============================================
Nmap service + vulnerability scanner using the vulners NSE script.
Parses CVE results from nmap XML output with CVSS severity color coding.

Views: SCAN → RESULTS (hosts with vuln counts) → DETAIL (CVEs per host)

Controls:
  OK         -- Start scan / select host
  UP / DOWN  -- Scroll
  KEY1       -- Cycle view
  KEY2       -- Export to loot
  KEY3       -- Exit
  LEFT       -- Back
"""

import os
import sys
import time
import json
import threading
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
GPIO.setmode(GPIO.BCM)
for pin in PINS.values():
    GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

LCD = LCD_1in44.LCD()
LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
WIDTH, HEIGHT = LCD.width, LCD.height
font = scaled_font()

LOOT_DIR = "/root/Raspyjack/loot/VulnScan"
os.makedirs(LOOT_DIR, exist_ok=True)
ROWS = 7
ROW_H = 14

C_BG = "BLACK"
C_TITLE = "CYAN"
C_CRIT = "#FF5252"
C_HIGH = "#FF9800"
C_MED = "#FFD740"
C_LOW = "#00E676"
C_INFO = "#888888"
C_SEL = "YELLOW"

lock = threading.Lock()
app_running = True
status_msg = "Ready"
view = "scan"  # scan | scanning | results | detail
hosts = []     # [{"ip","mac"}]
results = {}   # ip -> [{"cve","cvss","service","port"}]
scroll = 0
sel_idx = 0
detail_host = ""
detail_scroll = 0
scan_phase = ""


def _cvss_color(cvss):
    if cvss >= 9.0:
        return C_CRIT
    if cvss >= 7.0:
        return C_HIGH
    if cvss >= 4.0:
        return C_MED
    if cvss > 0:
        return C_LOW
    return C_INFO


def _get_default_iface():
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def _get_subnet(iface):
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1]
    except Exception:
        pass
    return ""


def _arp_discover(subnet):
    found = []
    try:
        r = subprocess.run(
            ["arp-scan", "--localnet", "--quiet", "--plain"],
            capture_output=True, text=True, timeout=15,
        )
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                found.append({"ip": parts[0], "mac": parts[1]})
    except Exception:
        pass
    if not found:
        try:
            r = subprocess.run(
                ["nmap", "-sn", subnet, "-oG", "-"],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines():
                if "Up" in line and "Host:" in line:
                    ip = line.split("Host:")[1].split("(")[0].strip()
                    if ip:
                        found.append({"ip": ip, "mac": ""})
        except Exception:
            pass
    return found


def _parse_vulners_xml(xml_text):
    """Parse nmap XML output with vulners script results."""
    host_vulns = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return host_vulns

    for host_el in root.findall(".//host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        vulns = []

        for port_el in host_el.findall(".//port"):
            portid = port_el.get("portid", "?")
            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "?") if svc_el is not None else "?"

            for script_el in port_el.findall("script[@id='vulners']"):
                output = script_el.get("output", "")
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        cve_id = parts[0]
                        if not (cve_id.startswith("CVE-") or cve_id.startswith("EXPLOITDB:") or
                                cve_id.startswith("MSF:") or cve_id.startswith("SSV:")):
                            continue
                        try:
                            cvss = float(parts[1])
                        except (ValueError, IndexError):
                            cvss = 0.0
                        vulns.append({
                            "cve": cve_id,
                            "cvss": cvss,
                            "port": portid,
                            "service": svc_name,
                        })

                for table_el in script_el.findall(".//table"):
                    for elem_el in table_el.findall("elem"):
                        key = elem_el.get("key", "")
                        if key == "id":
                            cve_id = elem_el.text or ""
                        elif key == "cvss" and cve_id:
                            try:
                                cvss = float(elem_el.text or "0")
                            except ValueError:
                                cvss = 0.0
                            if cve_id.startswith("CVE-") or cve_id.startswith("EXPLOITDB:"):
                                vulns.append({
                                    "cve": cve_id,
                                    "cvss": cvss,
                                    "port": portid,
                                    "service": svc_name,
                                })
                            cve_id = ""

        seen = set()
        deduped = []
        for v in vulns:
            k = (v["cve"], v["port"])
            if k not in seen:
                seen.add(k)
                deduped.append(v)
        deduped.sort(key=lambda v: v["cvss"], reverse=True)
        if deduped:
            host_vulns[ip] = deduped
    return host_vulns


def _discovery_thread():
    global hosts, status_msg, scan_phase
    iface = _get_default_iface()
    subnet = _get_subnet(iface)
    if not subnet:
        with lock:
            status_msg = "No network found"
        return
    with lock:
        scan_phase = "ARP discovery..."
        status_msg = f"Scanning {subnet}"
    found = _arp_discover(subnet)
    with lock:
        hosts = found
        status_msg = f"{len(found)} hosts found"
        scan_phase = ""


def _vuln_scan_thread(target):
    global results, view, status_msg, scan_phase
    with lock:
        view = "scanning"
        scan_phase = "Service detection..."
        status_msg = f"Scanning {target}"

    try:
        proc = subprocess.run(
            ["nmap", "-sV", "--script", "vulners", "-T4", "--open",
             "-oX", "-", target],
            capture_output=True, text=True, timeout=600,
        )
        xml_out = proc.stdout
    except subprocess.TimeoutExpired:
        with lock:
            status_msg = "Scan timed out"
            view = "scan"
        return
    except Exception as exc:
        with lock:
            status_msg = f"Error: {exc}"
            view = "scan"
        return

    with lock:
        scan_phase = "Parsing results..."

    parsed = _parse_vulners_xml(xml_out)

    with lock:
        results.update(parsed)
        total_vulns = sum(len(v) for v in results.values())
        status_msg = f"{len(results)} hosts, {total_vulns} vulns"
        view = "results"
        scan_phase = ""


def _export():
    global status_msg
    with lock:
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hosts": {},
        }
        for ip, vulns in results.items():
            data["hosts"][ip] = [
                {"cve": v["cve"], "cvss": v["cvss"],
                 "port": v["port"], "service": v["service"]}
                for v in vulns
            ]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"vulnscan_{ts}.json")
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        with lock:
            status_msg = "Exported to loot"
    except Exception as exc:
        with lock:
            status_msg = f"Export err: {exc}"


def _draw():
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)

    with lock:
        v = view
        st = status_msg
        ph = scan_phase
        h_list = list(hosts)
        r_dict = dict(results)
        sc = scroll
        si = sel_idx
        dh = detail_host
        ds = detail_scroll

    d.text((2, 2), "VULN SCANNER", fill=C_TITLE, font=font)

    if v == "scan":
        d.text((2, 14), st[:22], fill="WHITE", font=font)
        y = 28
        for i, h in enumerate(h_list[sc:sc + ROWS]):
            ri = sc + i
            pfx = ">" if ri == si else " "
            clr = C_SEL if ri == si else "WHITE"
            label = f"{pfx}{h['ip']}"
            d.text((2, y), label[:22], fill=clr, font=font)
            y += ROW_H
        d.text((2, 116), "OK=scan UP/DN K3=exit", fill="#555", font=font)

    elif v == "scanning":
        d.text((2, 40), ph[:22], fill="WHITE", font=font)
        d.text((2, 56), st[:22], fill=C_MED, font=font)
        dots = "." * (int(time.time()) % 4)
        d.text((2, 72), f"Please wait{dots}", fill="#888", font=font)

    elif v == "results":
        d.text((2, 14), st[:22], fill="WHITE", font=font)
        sorted_ips = sorted(r_dict.keys())
        y = 28
        for i, ip in enumerate(sorted_ips[sc:sc + ROWS]):
            ri = sc + i
            pfx = ">" if ri == si else " "
            clr = C_SEL if ri == si else "WHITE"
            vulns = r_dict.get(ip, [])
            n = len(vulns)
            max_cvss = max((v["cvss"] for v in vulns), default=0)
            sev_c = _cvss_color(max_cvss)
            d.text((2, y), f"{pfx}{ip}", fill=clr, font=font)
            d.text((95, y), f"{n}", fill=sev_c, font=font)
            y += ROW_H
        if not sorted_ips:
            d.text((2, 56), "No vulns found", fill="#888", font=font)
        d.text((2, 116), "OK=detail K2=exp K3=ex", fill="#555", font=font)

    elif v == "detail":
        vulns = r_dict.get(dh, [])
        d.text((2, 14), f"{dh} ({len(vulns)})", fill="WHITE", font=font)
        y = 28
        for vuln in vulns[ds:ds + ROWS]:
            cvss = vuln["cvss"]
            clr = _cvss_color(cvss)
            cve_short = vuln["cve"]
            if len(cve_short) > 15:
                cve_short = cve_short[:15]
            label = f"{cvss:4.1f} {cve_short}"
            d.text((2, y), label[:22], fill=clr, font=font)
            y += ROW_H
        if not vulns:
            d.text((2, 56), "No vulns for host", fill="#888", font=font)
        d.text((2, 116), "LEFT=back K2=export", fill="#555", font=font)

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global app_running, scroll, sel_idx, view, status_msg
    global detail_host, detail_scroll

    try:
        proc = subprocess.run(["which", "nmap"], capture_output=True)
        if proc.returncode != 0:
            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            d.text((4, 50), "nmap not found!", font=font, fill=C_CRIT)
            d.text((4, 64), "apt install nmap", font=font, fill="WHITE")
            LCD.LCD_ShowImage(img, 0, 0)
            time.sleep(3)
            GPIO.cleanup()
            return
    except Exception:
        pass

    threading.Thread(target=_discovery_thread, daemon=True).start()
    _draw()

    try:
        while app_running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "LEFT":
                with lock:
                    if view == "detail":
                        view = "results"
                        scroll = 0
                        sel_idx = 0
                    elif view == "results":
                        view = "scan"
                        scroll = 0
                        sel_idx = 0

            elif btn == "OK":
                with lock:
                    v = view
                if v == "scan":
                    with lock:
                        h_list = list(hosts)
                        si = sel_idx
                    if 0 <= si < len(h_list):
                        target = h_list[si]["ip"]
                        threading.Thread(
                            target=_vuln_scan_thread, args=(target,),
                            daemon=True,
                        ).start()
                elif v == "results":
                    with lock:
                        sorted_ips = sorted(results.keys())
                        si = sel_idx
                    if 0 <= si < len(sorted_ips):
                        with lock:
                            detail_host = sorted_ips[si]
                            detail_scroll = 0
                            view = "detail"

            elif btn == "UP":
                with lock:
                    v = view
                    if v in ("scan", "results"):
                        if sel_idx > 0:
                            sel_idx -= 1
                        if sel_idx < scroll:
                            scroll = sel_idx
                    elif v == "detail":
                        if detail_scroll > 0:
                            detail_scroll -= 1

            elif btn == "DOWN":
                with lock:
                    v = view
                    if v == "scan":
                        mx = len(hosts) - 1
                        if sel_idx < mx:
                            sel_idx += 1
                        if sel_idx >= scroll + ROWS:
                            scroll = sel_idx - ROWS + 1
                    elif v == "results":
                        mx = len(results) - 1
                        if sel_idx < mx:
                            sel_idx += 1
                        if sel_idx >= scroll + ROWS:
                            scroll = sel_idx - ROWS + 1
                    elif v == "detail":
                        vulns = results.get(detail_host, [])
                        mx = max(0, len(vulns) - ROWS)
                        if detail_scroll < mx:
                            detail_scroll += 1

            elif btn == "KEY1":
                with lock:
                    if view == "scan":
                        for h in hosts:
                            ip = h["ip"]
                            if ip not in results:
                                threading.Thread(
                                    target=_vuln_scan_thread, args=(ip,),
                                    daemon=True,
                                ).start()
                                break

            elif btn == "KEY2":
                with lock:
                    v = view
                if v in ("results", "detail") and results:
                    threading.Thread(target=_export, daemon=True).start()

            _draw()
            time.sleep(0.15)

    finally:
        app_running = False
        try:
            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            d.text((10, 56), "Scanner closed", fill=C_SEL, font=font)
            LCD.LCD_ShowImage(img, 0, 0)
        except Exception:
            pass
        GPIO.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
