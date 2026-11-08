#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Honeypot (BlueDuck)
=============================================
Author: gabecamp

Advertises as realistic BLE devices (AirPods, keyboards, fitness
trackers, speakers, smart TVs) using persona profiles.  Monitors
for connection attempts and logs all interactions.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- hcitool / hciconfig / bluetoothctl (bluez package)
- btmon for connection monitoring

Controls
--------
  OK         -- Start / stop advertising
  UP / DOWN  -- Scroll log / persona list
  LEFT/RIGHT -- Switch dashboard (status / log / personas)
  KEY1       -- Cycle persona (when stopped)
  KEY2       -- Export log to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/BLEHoneypot/
"""

import os
import sys
import time
import json
import re
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
LOOT_DIR = "/root/Raspyjack/loot/BLEHoneypot"
ROW_H = 12
ROWS_VISIBLE = 7
VIEWS = ["status", "log", "personas"]

PERSONAS = [
    {
        "name": "AirPods Pro",
        "dev_name": "AirPods Pro",
        "dev_class": "0x240418",
        "mfr_id": "004c",
        "mfr_data": "0719010220",
        "svc_uuids": [],
        "icon": "APod",
    },
    {
        "name": "Fitbit Charge 6",
        "dev_name": "Charge 6",
        "dev_class": "0x000000",
        "mfr_id": "000a",
        "mfr_data": "0601",
        "svc_uuids": ["180d", "180f"],
        "icon": "FBit",
    },
    {
        "name": "JBL Flip 6",
        "dev_name": "JBL Flip 6",
        "dev_class": "0x240414",
        "mfr_id": "0057",
        "mfr_data": "0201",
        "svc_uuids": ["1108"],
        "icon": "JBL ",
    },
    {
        "name": "Samsung TV",
        "dev_name": "Samsung TV",
        "dev_class": "0x0c043c",
        "mfr_id": "0075",
        "mfr_data": "420401",
        "svc_uuids": [],
        "icon": "STV ",
    },
    {
        "name": "Logitech K380",
        "dev_name": "Keyboard K380",
        "dev_class": "0x002540",
        "mfr_id": "0046",
        "mfr_data": "0104",
        "svc_uuids": ["1812"],
        "icon": "KB  ",
    },
    {
        "name": "Xbox Controller",
        "dev_name": "Xbox Wireless",
        "dev_class": "0x002508",
        "mfr_id": "0006",
        "mfr_data": "0301",
        "svc_uuids": ["1812", "180f"],
        "icon": "Xbox",
    },
    {
        "name": "Galaxy Buds2",
        "dev_name": "Galaxy Buds2 Pro",
        "dev_class": "0x240418",
        "mfr_id": "0075",
        "mfr_data": "01000200",
        "svc_uuids": [],
        "icon": "GBud",
    },
    {
        "name": "Apple Watch",
        "dev_name": "Apple Watch",
        "dev_class": "0x000000",
        "mfr_id": "004c",
        "mfr_data": "0c0e00",
        "svc_uuids": [],
        "icon": "AWat",
    },
    {
        "name": "Bose QC45",
        "dev_name": "Bose QC45",
        "dev_class": "0x240418",
        "mfr_id": "009e",
        "mfr_data": "0401",
        "svc_uuids": ["1108"],
        "icon": "Bose",
    },
    {
        "name": "Chromecast",
        "dev_name": "Chromecast",
        "dev_class": "0x000000",
        "mfr_id": "00e0",
        "mfr_data": "0201",
        "svc_uuids": ["fe2c"],
        "icon": "CCst",
    },
]

lock = threading.Lock()
advertising = False
persona_idx = 0
conn_log = []
status_msg = "Idle"
view_idx = 0
scroll_pos = 0
_running = True
_adv_proc = None
_mon_proc = None


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


def _set_device_name(name):
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "name", name],
        capture_output=True, timeout=5)


def _set_device_class(dev_class):
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "class", dev_class],
        capture_output=True, timeout=5)


def _build_adv_data(persona):
    parts = []
    flags = "020106"
    parts.append(flags)
    name_bytes = persona["dev_name"].encode("utf-8")[:20]
    name_hex = name_bytes.hex()
    name_len = len(name_bytes) + 1
    parts.append(f"{name_len:02x}09{name_hex}")
    if persona["mfr_id"] and persona["mfr_data"]:
        mfr_bytes = bytes.fromhex(persona["mfr_id"]) + bytes.fromhex(persona["mfr_data"])
        mfr_len = len(mfr_bytes) + 1
        parts.append(f"{mfr_len:02x}ff{mfr_bytes.hex()}")
    for uuid in persona["svc_uuids"][:2]:
        parts.append(f"0302{uuid[2:4]}{uuid[0:2]}" if len(uuid) == 4 else "")
    raw = "".join(p for p in parts if p)
    if len(raw) > 62:
        raw = raw[:62]
    return raw


def _start_advertising():
    global advertising, _adv_proc, _mon_proc, status_msg

    persona = PERSONAS[persona_idx]
    _hci_up()
    time.sleep(0.2)

    _set_device_name(persona["dev_name"])
    _set_device_class(persona["dev_class"])

    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "piscan"],
        capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "leadv", "0"],
        capture_output=True, timeout=5)

    adv_data = _build_adv_data(persona)
    cmd_hex = " ".join(adv_data[i:i+2] for i in range(0, len(adv_data), 2))
    adv_len = len(adv_data) // 2
    subprocess.run(
        ["sudo", "hcitool", "-i", HCI_DEV, "cmd", "0x08", "0x0008",
         f"{adv_len:02x}"] + cmd_hex.split(),
        capture_output=True, timeout=5)

    with lock:
        advertising = True
        status_msg = "Advertising"

    _mon_proc = subprocess.Popen(
        ["sudo", "btmon", "-i", HCI_DEV],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1)
    threading.Thread(target=_monitor_loop, daemon=True).start()


def _stop_advertising():
    global advertising, _adv_proc, _mon_proc, status_msg

    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "noleadv"],
        capture_output=True, timeout=5)
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV, "noscan"],
        capture_output=True, timeout=5)

    if _mon_proc:
        try:
            _mon_proc.terminate()
            _mon_proc.wait(timeout=3)
        except Exception:
            try:
                _mon_proc.kill()
            except Exception:
                pass
        _mon_proc = None

    with lock:
        advertising = False
        status_msg = "Stopped"

    time.sleep(0.3)
    _hci_reset()


_CONN_RE = re.compile(r"(?:LE )?Connect(?:ion)? (?:Complete|Request).*?(?:Address|Peer):\s*([0-9A-Fa-f:]{17})", re.IGNORECASE)
_DISCONN_RE = re.compile(r"Disconnect", re.IGNORECASE)
_READ_RE = re.compile(r"ATT: Read (?:By Type |Group Type )?(?:Request|Response)", re.IGNORECASE)
_WRITE_RE = re.compile(r"ATT: Write (?:Request|Command)", re.IGNORECASE)
_PAIR_RE = re.compile(r"SMP: Pairing (?:Request|Response)", re.IGNORECASE)


def _monitor_loop():
    global status_msg
    buf = ""
    while True:
        with lock:
            if not advertising:
                break
        if not _mon_proc or _mon_proc.poll() is not None:
            break
        try:
            line = _mon_proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            buf += line
            now = datetime.now().strftime("%H:%M:%S")
            m = _CONN_RE.search(line)
            if m:
                entry = {"time": now, "event": "CONNECT", "mac": m.group(1).upper(),
                         "persona": PERSONAS[persona_idx]["name"]}
                with lock:
                    conn_log.append(entry)
                    status_msg = f"Conn:{m.group(1)[-8:]}"
                continue
            if _DISCONN_RE.search(line):
                entry = {"time": now, "event": "DISCONNECT", "mac": "",
                         "persona": PERSONAS[persona_idx]["name"]}
                with lock:
                    conn_log.append(entry)
                    status_msg = "Disconnected"
                continue
            if _PAIR_RE.search(line):
                entry = {"time": now, "event": "PAIR_ATTEMPT", "mac": "",
                         "persona": PERSONAS[persona_idx]["name"]}
                with lock:
                    conn_log.append(entry)
                continue
            if _READ_RE.search(line):
                entry = {"time": now, "event": "GATT_READ", "mac": "",
                         "persona": PERSONAS[persona_idx]["name"]}
                with lock:
                    conn_log.append(entry)
                continue
            if _WRITE_RE.search(line):
                entry = {"time": now, "event": "GATT_WRITE", "mac": "",
                         "persona": PERSONAS[persona_idx]["name"]}
                with lock:
                    conn_log.append(entry)
                continue
        except Exception:
            time.sleep(0.5)


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"honeypot_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "persona": PERSONAS[persona_idx]["name"],
            "events": list(conn_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = advertising
        msg = status_msg
        p_idx = persona_idx
        cur_view = VIEWS[view_idx]
        log_copy = list(conn_log)
        sp = scroll_pos

    persona = PERSONAS[p_idx]

    d.rectangle((0, 0, 127, 13), fill="#111")
    title = {"status": "HONEYPOT", "log": "CONN LOG", "personas": "PERSONAS"}[cur_view]
    d.text((2, 1), title, font=font, fill="#E91E63")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "status":
        d.text((2, y), f"Persona: {persona['icon']}", font=font, fill="#FFAA00")
        y += ROW_H
        d.text((2, y), persona["name"][:22], font=font, fill="#FFFFFF")
        y += ROW_H
        d.text((2, y), f"As: {persona['dev_name'][:18]}", font=font, fill="#CCCCCC")
        y += ROW_H + 4
        d.text((2, y), f"Status: {msg[:14]}", font=font,
               fill="#00FF00" if active else "#FF6600")
        y += ROW_H
        n_conn = sum(1 for e in log_copy if e["event"] == "CONNECT")
        n_pair = sum(1 for e in log_copy if e["event"] == "PAIR_ATTEMPT")
        d.text((2, y), f"Conns:{n_conn} Pairs:{n_pair}", font=font, fill="#888")
        y += ROW_H
        d.text((2, y), f"Events: {len(log_copy)}", font=font, fill="#888")
        y += ROW_H + 4
        svc = ",".join(persona["svc_uuids"][:3]) or "none"
        d.text((2, y), f"SVC:{svc[:18]}", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        lbl = "OK:Stop" if active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:Swap K3:X", font=font, fill="#AAA")

    elif cur_view == "log":
        d.text((2, y), f"Events: {len(log_copy)}", font=font, fill="#888")
        y += 13

        end = min(sp + ROWS_VISIBLE, len(log_copy))
        for i in range(sp, end):
            evt = log_copy[-(i + 1)] if i < len(log_copy) else None
            if evt:
                clr_map = {"CONNECT": "#00FF00", "DISCONNECT": "#FF6600",
                           "PAIR_ATTEMPT": "#FF0000", "GATT_READ": "#888",
                           "GATT_WRITE": "#FFAA00"}
                clr = clr_map.get(evt["event"], "#CCCCCC")
                mac_short = evt["mac"][-8:] if evt["mac"] else ""
                txt = f"{evt['time']} {evt['event'][:6]}"
                if mac_short:
                    txt += f" {mac_short}"
                d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H

        if not log_copy:
            d.text((2, y), "No events yet", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K2:Export U/D:Scrl", font=font, fill="#AAA")

    elif cur_view == "personas":
        end = min(sp + ROWS_VISIBLE, len(PERSONAS))
        for i in range(sp, end):
            p = PERSONAS[i]
            prefix = ">" if i == p_idx else " "
            clr = "#FFAA00" if i == p_idx else "#CCCCCC"
            d.text((2, y), f"{prefix}{p['icon']} {p['name'][:16]}", font=font, fill=clr)
            y += ROW_H

        d.rectangle((0, 116, 127, 127), fill="#111")
        hint = "K1:Select" if not active else "Stop first"
        d.text((2, 117), f"{hint} U/D:Scrl", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, persona_idx, status_msg, view_idx, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "BLE HONEYPOT", font=font, fill="#E91E63")
    d.text((4, 28), "Advertise as realistic", font=font, fill="#888")
    d.text((4, 40), "BLE devices & log", font=font, fill="#888")
    d.text((4, 52), "connection attempts.", font=font, fill="#888")
    d.text((4, 72), "OK=Start  K1=Persona", font=font, fill="#666")
    d.text((4, 84), "K2=Export  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "LEFT":
                with lock:
                    view_idx = (view_idx - 1) % len(VIEWS)
                    scroll_pos = 0
                time.sleep(0.25)

            elif btn == "RIGHT":
                with lock:
                    view_idx = (view_idx + 1) % len(VIEWS)
                    scroll_pos = 0
                time.sleep(0.25)

            elif btn == "OK":
                with lock:
                    active = advertising
                if active:
                    _stop_advertising()
                else:
                    _start_advertising()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    active = advertising
                if not active:
                    with lock:
                        persona_idx = (persona_idx + 1) % len(PERSONAS)
                        status_msg = PERSONAS[persona_idx]["name"][:16]
                time.sleep(0.25)

            elif btn == "KEY2":
                path = _export_json()
                with lock:
                    status_msg = "Exported"
                time.sleep(0.3)

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                cur_view = VIEWS[view_idx]
                max_scroll = len(PERSONAS) if cur_view == "personas" else len(conn_log)
                with lock:
                    scroll_pos = min(scroll_pos + 1, max(0, max_scroll - ROWS_VISIBLE))
                time.sleep(0.2)

            _draw_screen()
            time.sleep(0.05)

    finally:
        with lock:
            if advertising:
                pass
        _stop_advertising()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
