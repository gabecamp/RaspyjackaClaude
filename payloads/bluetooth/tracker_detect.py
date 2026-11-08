#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Tracker Detector (Anti-Stalking)
=========================================================
Author: RaspyJack Contributors

Continuously scans BLE advertisements to detect tracking devices
(Apple AirTag / Find My, Samsung SmartTag, Tile, Chipolo, Google
Find My Device) and flags ones that follow you over time.

Alert levels
------------
  NEW        -- Just detected
  NEARBY     -- Seen in 3+ scan cycles
  FOLLOWING  -- Seen across 5+ minutes  (likely tracking)

Controls
--------
  OK         -- Start / stop scanning
  UP / DOWN  -- Scroll device list
  RIGHT      -- Show device detail
  LEFT       -- Back to list from detail
  KEY1       -- Cycle sort mode (alert / rssi / type / time)
  KEY2       -- Export JSON to loot
  KEY3       -- Exit (detail→list, list→quit)

Loot: /root/Raspyjack/loot/TrackerDetect/
"""

import os
import sys
import time
import json
import hashlib
import asyncio
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
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
LOOT_DIR = "/root/Raspyjack/loot/TrackerDetect"
ROWS_VISIBLE = 7
ROW_H = 12
SORT_MODES = ["alert", "rssi", "type", "time"]
NEARBY_THRESHOLD = 3
FOLLOWING_MINUTES = 5

APPLE_COMPANY = 0x004C
SAMSUNG_COMPANY = 0x0075
SAMSUNG_SVC = "0000fd5a-0000-1000-8000-00805f9b34fb"
TILE_SVCS = {
    "0000feed-0000-1000-8000-00805f9b34fb",
    "0000fe4d-0000-1000-8000-00805f9b34fb",
}
CHIPOLO_SVC = "0000fe33-0000-1000-8000-00805f9b34fb"
GOOGLE_FMD_SVC = "0000fe2c-0000-1000-8000-00805f9b34fb"

ALERT_ORDER = {"FOLLOWING": 0, "NEARBY": 1, "NEW": 2}

lock = threading.Lock()
trackers = {}
scanning = False
scroll_pos = 0
selected_idx = 0
sort_idx = 0
view = "list"
detail_lines = []
detail_scroll = 0
status_msg = "Idle"
scan_cycle = 0
_running = True


def _classify(device, adv_data):
    svc_uuids = set()
    for u in (adv_data.service_uuids or []):
        svc_uuids.add(u.lower())

    mfr = adv_data.manufacturer_data or {}

    if APPLE_COMPANY in mfr:
        payload = mfr[APPLE_COMPANY]
        if len(payload) >= 2 and payload[0] == 0x12:
            return "AirTag", payload
        if len(payload) >= 2 and payload[0] == 0x07:
            return "FindMy", payload
        return None, None

    if SAMSUNG_COMPANY in mfr:
        return "SmartTag", mfr[SAMSUNG_COMPANY]
    if svc_uuids & {SAMSUNG_SVC}:
        payload = mfr.get(SAMSUNG_COMPANY, b"")
        return "SmartTag", payload

    if svc_uuids & TILE_SVCS:
        for cid, p in mfr.items():
            return "Tile", p
        return "Tile", b""

    if CHIPOLO_SVC in svc_uuids:
        for cid, p in mfr.items():
            return "Chipolo", p
        return "Chipolo", b""

    if GOOGLE_FMD_SVC in svc_uuids:
        for cid, p in mfr.items():
            return "GoogleFMD", p
        return "GoogleFMD", b""

    return None, None


def _stable_key(tracker_type, payload_bytes):
    if payload_bytes and len(payload_bytes) >= 4:
        h = hashlib.sha256(payload_bytes).hexdigest()[:12]
        return f"{tracker_type}:{h}"
    return None


def _update_tracker(addr, tracker_type, rssi, payload_bytes, cycle):
    key = _stable_key(tracker_type, payload_bytes) or f"{tracker_type}:{addr}"
    now = time.time()
    now_str = datetime.now().strftime("%H:%M:%S")

    with lock:
        if key in trackers:
            t = trackers[key]
            t["rssi"] = rssi
            t["last_seen"] = now_str
            t["last_ts"] = now
            t["addr"] = addr
            if cycle != t.get("last_cycle"):
                t["cycles"] += 1
                t["last_cycle"] = cycle
            if payload_bytes:
                t["payload_hex"] = payload_bytes.hex()
        else:
            trackers[key] = {
                "key": key,
                "type": tracker_type,
                "addr": addr,
                "rssi": rssi,
                "first_seen": now_str,
                "last_seen": now_str,
                "first_ts": now,
                "last_ts": now,
                "cycles": 1,
                "last_cycle": cycle,
                "payload_hex": payload_bytes.hex() if payload_bytes else "",
            }


def _alert_level(t):
    duration_min = (t["last_ts"] - t["first_ts"]) / 60.0
    if duration_min >= FOLLOWING_MINUTES and t["cycles"] >= NEARBY_THRESHOLD:
        return "FOLLOWING"
    if t["cycles"] >= NEARBY_THRESHOLD:
        return "NEARBY"
    return "NEW"


def _hci_up():
    import subprocess
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    import subprocess
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


async def _bleak_scan(timeout=4):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    return found


def _scan_loop():
    global status_msg, scan_cycle

    _hci_up()
    time.sleep(0.3)

    while True:
        with lock:
            if not scanning:
                break

        try:
            results = asyncio.run(_bleak_scan(4))
            scan_cycle += 1

            for device, adv_data in results.values():
                with lock:
                    if not scanning:
                        break
                tracker_type, payload = _classify(device, adv_data)
                if tracker_type:
                    rssi = adv_data.rssi if hasattr(adv_data, "rssi") else -99
                    _update_tracker(device.address, tracker_type, rssi, payload, scan_cycle)

            with lock:
                n = len(trackers)
                status_msg = f"{n} trk c{scan_cycle}"

        except Exception as exc:
            with lock:
                status_msg = str(exc)[:18]
            time.sleep(1)


def _start_scan():
    global scanning, status_msg
    with lock:
        if scanning:
            return
        scanning = True
        status_msg = "Scanning..."
    threading.Thread(target=_scan_loop, daemon=True).start()


def _stop_scan():
    global scanning, status_msg
    with lock:
        scanning = False
        status_msg = "Stopped"
    time.sleep(0.3)
    _hci_reset()


def _sorted_trackers():
    with lock:
        items = list(trackers.values())
        mode = SORT_MODES[sort_idx]

    for t in items:
        t["_alert"] = _alert_level(t)

    if mode == "alert":
        items.sort(key=lambda t: (ALERT_ORDER.get(t["_alert"], 9), t["rssi"]))
    elif mode == "rssi":
        items.sort(key=lambda t: t["rssi"], reverse=True)
    elif mode == "type":
        items.sort(key=lambda t: t["type"])
    elif mode == "time":
        items.sort(key=lambda t: t["last_ts"], reverse=True)
    return items


def _build_detail(t):
    lines = [
        f"Type: {t['type']}",
        f"Alert: {t['_alert']}",
        f"Addr: {t['addr']}",
        f"RSSI: {t['rssi']} dBm",
        f"First: {t['first_seen']}",
        f"Last:  {t['last_seen']}",
        f"Cycles: {t['cycles']}",
        f"Duration: {(t['last_ts']-t['first_ts'])/60:.1f}m",
    ]
    ph = t.get("payload_hex", "")
    if ph:
        for i in range(0, len(ph), 40):
            lines.append(ph[i:i+40])
    return lines


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"trackers_{ts}.json")
    with lock:
        items = list(trackers.values())
    for t in items:
        t["alert"] = _alert_level(t)
        for k in ("_alert", "first_ts", "last_ts", "last_cycle"):
            t.pop(k, None)
    with open(path, "w") as fh:
        json.dump({"timestamp": ts, "trackers": items}, fh, indent=2)
    return path


ALERT_COLORS = {
    "FOLLOWING": "#FF0000",
    "NEARBY": "#FFAA00",
    "NEW": "#888888",
}

TYPE_SHORT = {
    "AirTag": "AT",
    "FindMy": "FM",
    "SmartTag": "ST",
    "Tile": "TL",
    "Chipolo": "CH",
    "GoogleFMD": "GF",
}


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        msg = status_msg
        sp = scroll_pos
        sel = selected_idx
        srt = SORT_MODES[sort_idx]
        cur_view = view
        d_lines = list(detail_lines)
        d_scroll = detail_scroll

    d.rectangle((0, 0, 127, 13), fill="#111")
    if cur_view == "list":
        d.text((2, 1), "TRACKER DETECT", font=font, fill="#FF5722")
    else:
        d.text((2, 1), "TRACKER DETAIL", font=font, fill="#FF5722")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "detail":
        end = min(d_scroll + 8, len(d_lines))
        for i in range(d_scroll, end):
            d.text((2, y), d_lines[i][:22], font=font, fill="#CCCCCC")
            y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "LEFT=Back U/D=Scroll", font=font, fill="#AAA")
    else:
        d.text((2, y), f"Sort:{srt} {msg[:14]}", font=font, fill="#888")
        y += 13

        devs = _sorted_trackers()
        end = min(sp + ROWS_VISIBLE, len(devs))
        for i in range(sp, end):
            t = devs[i]
            alert = t["_alert"]
            prefix = ">" if i == sel else " "
            short = TYPE_SHORT.get(t["type"], t["type"][:2])
            clr = ALERT_COLORS.get(alert, "#888") if i == sel else (
                ALERT_COLORS.get(alert, "#888") if alert == "FOLLOWING" else "#CCCCCC"
            )
            rssi = t["rssi"]
            txt = f"{prefix}{short} {rssi}dB {alert[:4]}"
            addr_tail = t["addr"][-5:]
            txt = f"{txt} {addr_tail}"
            d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H

        if not devs:
            d.text((2, y), "No trackers yet", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        lbl = "OK:Stop" if active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:Srt K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, sort_idx, status_msg
    global view, detail_lines, detail_scroll, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "TRACKER DETECT", font=font, fill="#FF5722")
    d.text((4, 28), "Detect AirTags,", font=font, fill="#888")
    d.text((4, 40), "SmartTags, Tile, etc.", font=font, fill="#888")
    d.text((4, 58), "Anti-stalking tool.", font=font, fill="#AAA")
    d.text((4, 76), "OK=Start  RIGHT=Detail", font=font, fill="#666")
    d.text((4, 88), "K1=Sort  K2=Export", font=font, fill="#666")
    d.text((4, 100), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view == "detail":
                    view = "list"
                    time.sleep(0.25)
                else:
                    break

            elif view == "detail":
                if btn == "LEFT":
                    view = "list"
                    time.sleep(0.25)
                elif btn == "UP":
                    detail_scroll = max(0, detail_scroll - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    detail_scroll = min(detail_scroll + 1,
                                        max(0, len(detail_lines) - 8))
                    time.sleep(0.2)

            else:
                if btn == "OK":
                    with lock:
                        active = scanning
                    if active:
                        _stop_scan()
                    else:
                        _start_scan()
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.2)

                elif btn == "DOWN":
                    devs = _sorted_trackers()
                    with lock:
                        selected_idx = min(len(devs) - 1, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)

                elif btn == "RIGHT":
                    devs = _sorted_trackers()
                    if devs and 0 <= selected_idx < len(devs):
                        t = devs[selected_idx]
                        detail_lines = _build_detail(t)
                        detail_scroll = 0
                        view = "detail"
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        sort_idx = (sort_idx + 1) % len(SORT_MODES)
                        status_msg = f"Sort: {SORT_MODES[sort_idx]}"
                    time.sleep(0.25)

                elif btn == "KEY2":
                    path = _export_json()
                    with lock:
                        status_msg = "Exported"
                    time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_scan()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
