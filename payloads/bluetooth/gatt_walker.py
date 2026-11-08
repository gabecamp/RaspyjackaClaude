#!/usr/bin/env python3
"""
RaspyJack Payload -- GATT Walker
=================================
Full BLE GATT service/characteristic/descriptor enumeration client.
Scans for BLE devices, connects, enumerates the GATT tree, optionally
probe-reads readable characteristics, and exports results to JSON.

Controls
--------
  OK         -- Scan: connect to device / GATT: read characteristic
  UP / DOWN  -- Scroll
  LEFT       -- Back (GATT -> scan, detail -> GATT)
  RIGHT      -- GATT tree -> read detail
  KEY1       -- Toggle probe mode (auto-read on connect)
  KEY2       -- Export GATT map to JSON
  KEY3       -- Exit / disconnect

Loot: /root/Raspyjack/loot/GATTWalk/
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
LOOT_DIR = "/root/Raspyjack/loot/GATTWalk"
ROW_H = 12
ROWS_VISIBLE = 7

KNOWN_SERVICES = {
    "00001800": "Generic Access",
    "00001801": "Generic Attribute",
    "0000180a": "Device Info",
    "0000180d": "Heart Rate",
    "0000180f": "Battery",
    "00001812": "HID",
    "00001810": "Blood Pressure",
    "00001816": "Cycling Speed",
    "00001809": "Health Thermo",
    "00001802": "Immediate Alert",
    "00001803": "Link Loss",
    "00001804": "Tx Power",
}

KNOWN_CHARS = {
    "00002a00": "Device Name",
    "00002a01": "Appearance",
    "00002a19": "Battery Level",
    "00002a29": "Manufacturer",
    "00002a24": "Model Number",
    "00002a25": "Serial Number",
    "00002a26": "Firmware Rev",
    "00002a27": "Hardware Rev",
    "00002a28": "Software Rev",
    "00002a05": "Service Changed",
    "00002a37": "Heart Rate Meas",
    "00002a38": "Body Sensor Loc",
    "00002a04": "Periph Pref Conn",
    "00002a23": "System ID",
    "00002a50": "PnP ID",
}


def _uuid_short(uuid_str):
    u = uuid_str.lower().replace("-", "")
    if u.endswith("00001000800000805f9b34fb") and u[:4] == "0000":
        return u[4:8].upper()
    return uuid_str[:8]


def _uuid_name(uuid_str, db):
    u = uuid_str.lower().replace("-", "")
    prefix = u[:8]
    if prefix in db:
        return db[prefix]
    return None


def _props_str(props):
    flags = []
    for p in props:
        p = p.lower()
        if "read" in p:
            flags.append("R")
        elif "write" in p:
            flags.append("W")
        elif "notify" in p:
            flags.append("N")
        elif "indicate" in p:
            flags.append("I")
    return "".join(flags)


lock = threading.Lock()
devices = []
scanning = False
connecting = False
connected = False
gatt_tree = []
gatt_flat = []
read_values = {}
probe_mode = False
status_msg = "Idle"
view = "scan"
scroll_pos = 0
selected_idx = 0
detail_lines = []
detail_scroll = 0
_running = True
_client = None
_connected_addr = None


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


async def _bleak_scan(timeout=4):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        {"addr": d.address, "name": d.name or "", "rssi": getattr(d, "rssi", -99)}
        for d in found
    ]


def _scan_loop():
    global scanning, status_msg
    _hci_up()
    time.sleep(0.3)
    while True:
        with lock:
            if not scanning:
                break
        try:
            results = asyncio.run(_bleak_scan(4))
            with lock:
                if not scanning:
                    break
                seen = {d["addr"] for d in devices}
                for r in results:
                    if r["addr"] not in seen:
                        devices.append(r)
                        seen.add(r["addr"])
                    else:
                        for d in devices:
                            if d["addr"] == r["addr"]:
                                d["rssi"] = r["rssi"]
                                if r["name"]:
                                    d["name"] = r["name"]
                status_msg = f"Found {len(devices)}"
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
        devices.clear()
        status_msg = "Scanning..."
    threading.Thread(target=_scan_loop, daemon=True).start()


def _stop_scan():
    global scanning, status_msg
    with lock:
        scanning = False
        status_msg = "Stopped"
    time.sleep(0.3)
    _hci_reset()


async def _enumerate_gatt(addr, probe):
    from bleak import BleakClient
    tree = []
    flat = []
    vals = {}
    async with BleakClient(addr, timeout=10) as client:
        for svc in client.services:
            svc_name = _uuid_name(svc.uuid, KNOWN_SERVICES)
            svc_label = svc_name or _uuid_short(svc.uuid)
            svc_entry = {"uuid": svc.uuid, "name": svc_name, "chars": []}
            flat.append(("svc", svc.uuid, svc_label, ""))

            for char in svc.characteristics:
                char_name = _uuid_name(char.uuid, KNOWN_CHARS)
                char_label = char_name or _uuid_short(char.uuid)
                props = _props_str(char.properties)
                char_entry = {"uuid": char.uuid, "name": char_name,
                              "properties": list(char.properties),
                              "descriptors": [], "value": None}
                flat.append(("chr", char.uuid, f"  {char_label}", props))

                if probe and "read" in [p.lower() for p in char.properties]:
                    try:
                        raw = await client.read_gatt_char(char.uuid)
                        hex_str = raw.hex()
                        try:
                            ascii_str = raw.decode("utf-8", errors="replace")
                        except Exception:
                            ascii_str = ""
                        char_entry["value"] = hex_str
                        vals[char.uuid] = (hex_str, ascii_str)
                    except Exception:
                        vals[char.uuid] = ("err", "")

                for desc in char.descriptors:
                    desc_label = _uuid_short(desc.uuid)
                    char_entry["descriptors"].append({"uuid": desc.uuid})
                    flat.append(("dsc", desc.uuid, f"    D:{desc_label}", ""))

                svc_entry["chars"].append(char_entry)
            tree.append(svc_entry)
    return tree, flat, vals


def _connect_device(addr):
    global connecting, connected, gatt_tree, gatt_flat, read_values
    global status_msg, _connected_addr
    with lock:
        connecting = True
        status_msg = "Connecting..."

    try:
        with lock:
            do_probe = probe_mode
        tree, flat, vals = asyncio.run(_enumerate_gatt(addr, do_probe))
        with lock:
            gatt_tree = tree
            gatt_flat = flat
            read_values = vals
            connected = True
            _connected_addr = addr
            status_msg = f"{len(tree)} svcs"
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:18]
            connected = False
    finally:
        with lock:
            connecting = False


async def _read_char(addr, char_uuid):
    from bleak import BleakClient
    async with BleakClient(addr, timeout=10) as client:
        raw = await client.read_gatt_char(char_uuid)
        return raw.hex(), raw.decode("utf-8", errors="replace")


def _do_read_char(char_uuid):
    global status_msg, read_values
    with lock:
        addr = _connected_addr
    if not addr:
        return
    with lock:
        status_msg = "Reading..."
    try:
        hex_str, ascii_str = asyncio.run(_read_char(addr, char_uuid))
        with lock:
            read_values[char_uuid] = (hex_str, ascii_str)
            status_msg = "Read OK"
    except Exception as exc:
        with lock:
            read_values[char_uuid] = ("err", str(exc)[:20])
            status_msg = "Read fail"


def _disconnect():
    global connected, gatt_tree, gatt_flat, read_values, _connected_addr, status_msg
    with lock:
        connected = False
        gatt_tree = []
        gatt_flat = []
        read_values = {}
        _connected_addr = None
        status_msg = "Disconnected"


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"gatt_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "device": _connected_addr,
            "services": gatt_tree,
            "read_values": {k: v[0] for k, v in read_values.items()},
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _build_detail(char_uuid):
    lines = []
    with lock:
        for item in gatt_flat:
            if item[0] == "chr" and item[1] == char_uuid:
                lines.append(f"Char: {item[2].strip()}")
                lines.append(f"UUID: {char_uuid[:18]}")
                lines.append(f"      {char_uuid[18:]}")
                lines.append(f"Props: {item[3]}")
                break
        val = read_values.get(char_uuid)
    if val:
        hex_str, ascii_str = val
        lines.append(f"Hex: {hex_str[:18]}")
        if len(hex_str) > 18:
            lines.append(f"     {hex_str[18:36]}")
        if ascii_str and ascii_str != hex_str:
            lines.append(f"Txt: {ascii_str[:18]}")
    else:
        lines.append("(not read)")
    return lines


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        msg = status_msg
        cur_view = view
        is_connected = connected
        is_scanning = scanning
        is_connecting = connecting
        sp = scroll_pos
        sel = selected_idx
        devs = list(devices)
        flat = list(gatt_flat)
        d_lines = list(detail_lines)
        d_scroll = detail_scroll
        prb = probe_mode

    d.rectangle((0, 0, 127, 13), fill="#111")
    if cur_view == "scan":
        title = "GATT WALK"
    elif cur_view == "gatt":
        title = "GATT TREE"
    else:
        title = "CHAR DETAIL"
    d.text((2, 1), title, font=font, fill="#4CAF50")
    if prb:
        d.text((90, 1), "PRB", font=font, fill="#FF9800")
    color = "#00FF00" if (is_scanning or is_connected) else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=color)

    y = 15

    if cur_view == "detail":
        end = min(d_scroll + 8, len(d_lines))
        for i in range(d_scroll, end):
            d.text((2, y), d_lines[i][:22], font=font, fill="#CCCCCC")
            y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "LEFT=Back OK=Read", font=font, fill="#AAA")

    elif cur_view == "gatt":
        d.text((2, y), f"Items:{len(flat)} {msg[:10]}", font=font, fill="#888")
        y += 13
        end = min(sp + ROWS_VISIBLE, len(flat))
        for i in range(sp, end):
            kind, uuid, label, props = flat[i]
            clr = "#FFAA00" if i == sel else (
                "#4CAF50" if kind == "svc" else
                "#CCCCCC" if kind == "chr" else "#888888")
            prefix = ">" if i == sel else " "
            txt = f"{prefix}{label[:16]}"
            if props:
                txt += f" [{props}]"
            d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H
        if not flat:
            d.text((2, y), "No GATT data", font=font, fill="#555")
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Rd R:Det K3:Disc", font=font, fill="#AAA")

    else:
        d.text((2, y), f"Devs:{len(devs)} {msg[:12]}", font=font, fill="#888")
        y += 13
        end = min(sp + ROWS_VISIBLE, len(devs))
        for i in range(sp, end):
            dev = devs[i]
            prefix = ">" if i == sel else " "
            name = (dev["name"] or dev["addr"][-8:])[:12]
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{name} {dev['rssi']}dB"[:22],
                   font=font, fill=clr)
            y += ROW_H
        if not devs:
            d.text((2, y), "No devices yet", font=font, fill="#555")
        d.rectangle((0, 116, 127, 127), fill="#111")
        if is_connecting:
            lbl = "Connecting..."
        elif is_scanning:
            lbl = "OK:Stop"
        else:
            lbl = "OK:Scan/Conn"
        d.text((2, 117), f"{lbl} K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, status_msg, HCI_DEV
    global view, detail_lines, detail_scroll, probe_mode, _running

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "GATT WALKER", font=font, fill="#4CAF50")
    d.text((4, 28), "BLE GATT enumeration", font=font, fill="#888")
    d.text((4, 40), "& read probe tool.", font=font, fill="#888")
    d.text((4, 60), "OK=Scan/Connect", font=font, fill="#666")
    d.text((4, 72), "K1=Probe K2=Export", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if view == "detail":
                    view = "gatt"
                    scroll_pos = 0
                    time.sleep(0.25)
                elif view == "gatt":
                    _disconnect()
                    view = "scan"
                    scroll_pos = 0
                    selected_idx = 0
                    time.sleep(0.25)
                else:
                    _stop_scan()
                    break

            elif view == "detail":
                if btn == "LEFT":
                    view = "gatt"
                    time.sleep(0.25)
                elif btn == "UP":
                    detail_scroll = max(0, detail_scroll - 1)
                    time.sleep(0.2)
                elif btn == "DOWN":
                    detail_scroll = min(detail_scroll + 1,
                                        max(0, len(detail_lines) - 8))
                    time.sleep(0.2)
                elif btn == "OK":
                    with lock:
                        flat = list(gatt_flat)
                        sel = selected_idx
                    if 0 <= sel < len(flat) and flat[sel][0] == "chr":
                        threading.Thread(
                            target=_do_read_char,
                            args=(flat[sel][1],), daemon=True).start()
                        time.sleep(0.5)
                        detail_lines = _build_detail(flat[sel][1])
                    time.sleep(0.25)

            elif view == "gatt":
                if btn == "LEFT":
                    _disconnect()
                    view = "scan"
                    scroll_pos = 0
                    selected_idx = 0
                    time.sleep(0.25)
                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.2)
                elif btn == "DOWN":
                    with lock:
                        mx = len(gatt_flat) - 1
                        selected_idx = min(mx, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)
                elif btn == "RIGHT" or btn == "OK":
                    with lock:
                        flat = list(gatt_flat)
                        sel = selected_idx
                    if 0 <= sel < len(flat) and flat[sel][0] == "chr":
                        if btn == "OK":
                            threading.Thread(
                                target=_do_read_char,
                                args=(flat[sel][1],), daemon=True).start()
                            time.sleep(0.5)
                        detail_lines = _build_detail(flat[sel][1])
                        detail_scroll = 0
                        view = "detail"
                    time.sleep(0.25)
                elif btn == "KEY2":
                    path = _export_json()
                    with lock:
                        status_msg = "Exported"
                    time.sleep(0.3)

            else:
                if btn == "OK":
                    with lock:
                        is_scanning = scanning
                        is_connecting = connecting
                        is_connected = connected
                    if is_connecting:
                        pass
                    elif is_scanning:
                        _stop_scan()
                        time.sleep(0.2)
                        with lock:
                            devs = list(devices)
                            sel = selected_idx
                        if devs and 0 <= sel < len(devs):
                            addr = devs[sel]["addr"]
                            threading.Thread(
                                target=_connect_device,
                                args=(addr,), daemon=True).start()
                            time.sleep(1)
                            with lock:
                                if connected:
                                    view = "gatt"
                                    scroll_pos = 0
                                    selected_idx = 0
                    elif not is_connected:
                        with lock:
                            devs = list(devices)
                            sel = selected_idx
                        if devs and 0 <= sel < len(devs):
                            addr = devs[sel]["addr"]
                            threading.Thread(
                                target=_connect_device,
                                args=(addr,), daemon=True).start()
                            time.sleep(1)
                            with lock:
                                if connected:
                                    view = "gatt"
                                    scroll_pos = 0
                                    selected_idx = 0
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
                    with lock:
                        mx = len(devices) - 1
                        selected_idx = min(mx, selected_idx + 1)
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.2)
                elif btn == "KEY1":
                    probe_mode = not probe_mode
                    with lock:
                        status_msg = f"Probe:{'ON' if probe_mode else 'OFF'}"
                    time.sleep(0.25)
                elif btn == "KEY2":
                    if connected:
                        path = _export_json()
                        with lock:
                            status_msg = "Exported"
                    time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_scan()
        _disconnect()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
