#!/usr/bin/env python3
"""
RaspyJack Payload -- BT Lookout (Dee Dee Detector)
===================================================
Ported from CYM's BT Lookout.

Continuous BLE watchlist monitor.  Scans for BLE devices and alerts
when a device on your watchlist is detected nearby.  Useful for
anti-surveillance awareness and perimeter monitoring.

Watchlist is stored as JSON and persists between runs.

Controls
--------
  OK          Start / stop scanning
  UP / DOWN   Scroll current list
  LEFT/RIGHT  Switch dashboard (Scan | Watchlist | Sighting Log)
  KEY1        Add device to watchlist (scan view) / Remove (watchlist view)
  KEY2        Export sighting log to JSON
  KEY3        Exit

Loot: /root/Raspyjack/loot/BTLookout/
"""

import os
import sys
import time
import json
import asyncio
import threading
import subprocess
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
LOOT_DIR = "/root/Raspyjack/loot/BTLookout"
WATCHLIST_PATH = os.path.join(LOOT_DIR, "watchlist.json")
ROW_H = 12
ROWS_VISIBLE = 7
ALERT_WINDOW = 600
ALERT_THRESHOLD = 3
VIEWS = ["scan", "watchlist", "log"]

lock = threading.Lock()
scanned = {}
watchlist = []
sightings = []
scanning = False
view_idx = 0
scroll_pos = 0
selected_idx = 0
status_msg = "Idle"
flash_until = 0
_running = True


def _load_watchlist():
    global watchlist
    if os.path.isfile(WATCHLIST_PATH):
        try:
            with open(WATCHLIST_PATH) as f:
                watchlist = json.load(f)
        except Exception:
            watchlist = []


def _save_watchlist():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(WATCHLIST_PATH, "w") as f:
        json.dump(watchlist, f, indent=2)


def _is_watched(addr, name):
    addr_up = addr.upper()
    name_low = (name or "").lower()
    for w in watchlist:
        if w.get("mac", "").upper() == addr_up:
            return True
        wn = w.get("name", "").lower()
        if wn and name_low and wn in name_low:
            return True
    return False


def _alert_level(addr):
    now = time.time()
    count = sum(1 for s in sightings
                if s["mac"].upper() == addr.upper()
                and (now - s.get("_ts", 0)) < ALERT_WINDOW)
    return "ALERT" if count >= ALERT_THRESHOLD else "WATCH"


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


async def _bleak_scan(timeout=4):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [(d.address, d.name or "", getattr(d, "rssi", -99)) for d in found]


def _scan_loop():
    global status_msg, flash_until

    _hci_up()
    time.sleep(0.3)

    while True:
        with lock:
            if not scanning:
                break

        try:
            results = asyncio.run(_bleak_scan(4))
            now_str = datetime.now().strftime("%H:%M:%S")
            now_ts = time.time()

            for addr, name, rssi in results:
                with lock:
                    if not scanning:
                        break
                addr = addr.upper()
                with lock:
                    if addr in scanned:
                        prev = scanned[addr]
                        scanned[addr] = {
                            **prev,
                            "name": name or prev["name"],
                            "rssi": rssi,
                            "last_seen": now_str,
                            "count": prev["count"] + 1,
                        }
                    else:
                        scanned[addr] = {
                            "addr": addr, "name": name, "rssi": rssi,
                            "first_seen": now_str, "last_seen": now_str,
                            "count": 1,
                        }

                    if _is_watched(addr, name):
                        level = _alert_level(addr)
                        sightings.append({
                            "time": now_str, "mac": addr,
                            "name": name, "rssi": rssi,
                            "level": level, "_ts": now_ts,
                        })
                        flash_until = now_ts + 1.0
                        status_msg = f"{level}:{(name or addr)[:10]}"

        except Exception as exc:
            with lock:
                status_msg = str(exc)[:20]
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


def _sorted_scanned():
    with lock:
        items = list(scanned.values())
    watched = [d for d in items if _is_watched(d["addr"], d.get("name"))]
    unwatched = [d for d in items if not _is_watched(d["addr"], d.get("name"))]
    watched.sort(key=lambda d: d["rssi"], reverse=True)
    unwatched.sort(key=lambda d: d["rssi"], reverse=True)
    return watched + unwatched


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"sightings_{ts}.json")
    with lock:
        clean = [{k: v for k, v in s.items() if k != "_ts"} for s in sightings]
    with open(path, "w") as f:
        json.dump({"timestamp": ts, "sightings": clean}, f, indent=2)
    return path


def _add_to_watchlist(dev):
    global status_msg
    entry = {
        "mac": dev["addr"],
        "name": dev.get("name", ""),
        "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with lock:
        if not any(w.get("mac", "").upper() == dev["addr"].upper() for w in watchlist):
            watchlist.append(entry)
    _save_watchlist()
    status_msg = "Added"


def _remove_from_watchlist(idx):
    global status_msg
    with lock:
        if 0 <= idx < len(watchlist):
            watchlist.pop(idx)
    _save_watchlist()
    status_msg = "Removed"


def _draw_screen():
    now_ts = time.time()
    with lock:
        active = scanning
        msg = status_msg
        cur_view = VIEWS[view_idx]
        sp = scroll_pos
        sel = selected_idx
        flashing = now_ts < flash_until
        n_watch = len(watchlist)
        n_sight = len(sightings)
        log_copy = list(sightings[-50:])

    bg = "#300000" if flashing else "black"
    img = Image.new("RGB", (WIDTH, HEIGHT), bg)
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    titles = {"scan": "BT LOOKOUT", "watchlist": "WATCHLIST", "log": "SIGHTINGS"}
    d.text((2, 1), titles[cur_view], font=font, fill="#FF5722")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "scan":
        d.text((2, y), f"W:{n_watch} {msg[:14]}", font=font, fill="#888")
        y += 13
        devs = _sorted_scanned()
        end = min(sp + ROWS_VISIBLE, len(devs))
        for i in range(sp, end):
            dev = devs[i]
            watched = _is_watched(dev["addr"], dev.get("name"))
            prefix = ">" if i == sel else " "
            name = (dev.get("name") or dev["addr"][-8:])[:12]
            rssi = dev["rssi"]
            if watched:
                clr = "#FF0000" if i == sel else "#FF5722"
            else:
                clr = "#FFAA00" if i == sel else "#666666"
            d.text((2, y), f"{prefix}{name} {rssi}dB", font=font, fill=clr)
            y += ROW_H
        if not devs:
            d.text((2, y), "No devices yet", font=font, fill="#555")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K1:+Watch K2:Save", font=font, fill="#AAA")

    elif cur_view == "watchlist":
        d.text((2, y), f"Entries: {n_watch}", font=font, fill="#888")
        y += 13
        with lock:
            wl = list(watchlist)
        end = min(sp + ROWS_VISIBLE, len(wl))
        for i in range(sp, end):
            w = wl[i]
            prefix = ">" if i == sel else " "
            label = (w.get("name") or w.get("mac", "?"))[:18]
            clr = "#FFAA00" if i == sel else "#FF5722"
            d.text((2, y), f"{prefix}{label}", font=font, fill=clr)
            y += ROW_H
        if not wl:
            d.text((2, y), "Empty watchlist", font=font, fill="#555")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K1:Remove K3:X", font=font, fill="#AAA")

    elif cur_view == "log":
        d.text((2, y), f"Sightings: {n_sight}", font=font, fill="#888")
        y += 13
        entries = list(reversed(log_copy))
        end = min(sp + ROWS_VISIBLE, len(entries))
        for i in range(sp, end):
            s = entries[i]
            lvl = s.get("level", "?")[:1]
            name = (s.get("name") or s.get("mac", "?"))[:10]
            tm = s.get("time", "")
            clr = "#FF0000" if s.get("level") == "ALERT" else "#FF5722"
            d.text((2, y), f"{lvl} {name} {tm}", font=font, fill=clr)
            y += ROW_H
        if not entries:
            d.text((2, y), "No sightings", font=font, fill="#555")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K2:Export K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, view_idx, status_msg, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    _load_watchlist()

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BT LOOKOUT", font=font, fill="#FF5722")
    d.text((4, 28), "Dee Dee Detector", font=font, fill="#888")
    d.text((4, 46), "BLE watchlist monitor", font=font, fill="#888")
    d.text((4, 64), "OK=Start L/R=Views", font=font, fill="#666")
    d.text((4, 76), "K1=Add/Rm K2=Export", font=font, fill="#666")
    d.text((4, 88), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            cur_view = VIEWS[view_idx]

            if btn == "KEY3":
                break

            elif btn == "OK":
                with lock:
                    active = scanning
                if active:
                    _stop_scan()
                else:
                    _start_scan()
                time.sleep(0.3)

            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll_pos = 0
                selected_idx = 0
                time.sleep(0.25)

            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll_pos = 0
                selected_idx = 0
                time.sleep(0.25)

            elif btn == "UP":
                selected_idx = max(0, selected_idx - 1)
                if selected_idx < scroll_pos:
                    scroll_pos = selected_idx
                time.sleep(0.2)

            elif btn == "DOWN":
                if cur_view == "scan":
                    mx = max(0, len(_sorted_scanned()) - 1)
                elif cur_view == "watchlist":
                    mx = max(0, len(watchlist) - 1)
                else:
                    with lock:
                        mx = max(0, len(sightings) - 1)
                selected_idx = min(mx, selected_idx + 1)
                if selected_idx >= scroll_pos + ROWS_VISIBLE:
                    scroll_pos = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.2)

            elif btn == "KEY1":
                if cur_view == "scan":
                    devs = _sorted_scanned()
                    if devs and 0 <= selected_idx < len(devs):
                        _add_to_watchlist(devs[selected_idx])
                    time.sleep(0.3)
                elif cur_view == "watchlist":
                    _remove_from_watchlist(selected_idx)
                    with lock:
                        if selected_idx >= len(watchlist):
                            selected_idx = max(0, len(watchlist) - 1)
                    time.sleep(0.3)

            elif btn == "KEY2":
                path = _export_log()
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
