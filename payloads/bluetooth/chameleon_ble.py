#!/usr/bin/env python3
"""
RaspyJack Payload -- Chameleon Ultra/Lite BLE Client
====================================================
Author: gabecamp (ported from CYM chameleon_ble.c)

Connects to Chameleon Ultra or Chameleon Lite NFC emulator devices
over BLE (Nordic UART Service), reads device info, battery level,
and slot configuration.  Allows switching the active slot.

Prerequisites
-------------
- Bluetooth adapter (hci0+)
- bleak (pip install bleak)
- Chameleon Ultra or Lite in BLE range

Controls
--------
  OK         -- Connect to selected / set active slot
  UP / DOWN  -- Scroll list
  LEFT/RIGHT -- Switch screen (Scanner / Info / Slots)
  KEY1       -- Refresh device info
  KEY2       -- Export to JSON loot
  KEY3       -- Disconnect / Exit

Loot: /root/Raspyjack/loot/ChameleonBLE/
"""

import os
import sys
import time
import json
import struct
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

NUS_SVC = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
NUS_TX  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
NUS_RX  = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

SOF = 0x11
CMD_GET_MODEL      = 0x03E8
CMD_GET_VERSION     = 0x03E9
CMD_GET_ACTIVE_SLOT = 0x03F0
CMD_SET_ACTIVE_SLOT = 0x03F1
CMD_GET_SLOT_INFO   = 0x03F2
CMD_GET_BATTERY     = 0x0406

TAG_TYPES = {
    0: "---", 1: "EM4100", 2: "T5577", 3: "EM4305",
    10: "MIFARE Mini", 11: "MIFARE 1K", 12: "MIFARE 2K", 13: "MIFARE 4K",
    14: "NTAG213", 15: "NTAG215", 16: "NTAG216",
    20: "iCLASS", 21: "iCLASS Elite", 30: "NTAG424",
}

HCI_DEV = None
LOOT_DIR = "/root/Raspyjack/loot/ChameleonBLE"
ROWS_VISIBLE = 7
ROW_H = 12
SCREENS = ["scan", "info", "slots"]

lock = threading.Lock()
found_devices = []
scroll_pos = 0
selected_idx = 0
screen_idx = 0
status_msg = "Idle"
_running = True

device_info = {"model": "?", "version": "?", "battery": 0, "active_slot": 0}
slot_info = [{"hf": 0, "lf": 0} for _ in range(8)]
connected = False
_client = None
_loop = None
_resp_event = None
_resp_data = b""


def _build_frame(cmd, data=b""):
    length = 10 + len(data)
    hdr = struct.pack(">BHHHH", SOF, length, cmd, 0, len(data))
    frame = hdr + data
    lrc = 0
    for b in frame:
        lrc ^= b
    return frame + bytes([lrc])


def _parse_frame(raw):
    if len(raw) < 11 or raw[0] != SOF:
        return None, None, None
    length = struct.unpack(">H", raw[1:3])[0]
    cmd = struct.unpack(">H", raw[3:5])[0]
    status = struct.unpack(">H", raw[5:7])[0]
    dlen = struct.unpack(">H", raw[7:9])[0]
    data = raw[9:9 + dlen] if dlen else b""
    return cmd, status, data


def _on_notify(sender, data):
    global _resp_data
    _resp_data = bytes(data)
    if _resp_event:
        _resp_event.set()


async def _send_cmd(client, cmd, data=b"", timeout=3.0):
    global _resp_data, _resp_event
    _resp_event = asyncio.Event()
    _resp_data = b""
    frame = _build_frame(cmd, data)
    await client.write_gatt_char(NUS_TX, frame, response=False)
    try:
        await asyncio.wait_for(_resp_event.wait(), timeout)
    except asyncio.TimeoutError:
        return None, None, None
    return _parse_frame(_resp_data)


async def _scan_devices(timeout=4):
    from bleak import BleakScanner
    devs = await BleakScanner.discover(timeout=timeout)
    result = []
    for d in devs:
        name = d.name or ""
        if "chameleon" in name.lower():
            result.append({"addr": d.address, "name": name,
                           "rssi": getattr(d, "rssi", -99)})
    return result


async def _connect_and_read(addr):
    global connected, _client, device_info, slot_info
    from bleak import BleakClient

    client = BleakClient(addr)
    await client.connect()
    _client = client
    await client.start_notify(NUS_RX, _on_notify)
    connected = True

    with lock:
        status_msg_local = "Reading..."

    _, _, data = await _send_cmd(client, CMD_GET_MODEL)
    if data:
        model_id = data[0] if data else 0
        model = "Ultra" if model_id == 0 else "Lite" if model_id == 1 else f"#{model_id}"
        with lock:
            device_info["model"] = f"Chameleon {model}"

    _, _, data = await _send_cmd(client, CMD_GET_VERSION)
    if data:
        with lock:
            device_info["version"] = data.decode(errors="replace").strip("\x00")

    _, _, data = await _send_cmd(client, CMD_GET_BATTERY)
    if data and len(data) >= 1:
        with lock:
            device_info["battery"] = data[0]

    _, _, data = await _send_cmd(client, CMD_GET_ACTIVE_SLOT)
    if data and len(data) >= 1:
        with lock:
            device_info["active_slot"] = data[0]

    _, _, data = await _send_cmd(client, CMD_GET_SLOT_INFO)
    if data:
        with lock:
            for i in range(min(8, len(data) // 2)):
                slot_info[i] = {"hf": data[i * 2], "lf": data[i * 2 + 1]}

    with lock:
        global status_msg
        status_msg = "Connected"


async def _set_slot(slot_num):
    global device_info
    if _client and _client.is_connected:
        await _send_cmd(_client, CMD_SET_ACTIVE_SLOT, bytes([slot_num]))
        with lock:
            device_info["active_slot"] = slot_num


async def _disconnect():
    global connected, _client
    if _client:
        try:
            await _client.disconnect()
        except Exception:
            pass
    _client = None
    connected = False


def _run_async(coro):
    if _loop and _loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, _loop).result(timeout=10)


def _bg_loop():
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    _loop.run_forever()


def _start_scan():
    global found_devices, status_msg
    with lock:
        status_msg = "Scanning..."

    async def do_scan():
        global found_devices, status_msg
        devs = await _scan_devices()
        with lock:
            found_devices = devs
            status_msg = f"Found {len(devs)}"

    if _loop:
        asyncio.run_coroutine_threadsafe(do_scan(), _loop)


def _do_connect(addr):
    global status_msg
    with lock:
        status_msg = "Connecting..."

    if _loop:
        asyncio.run_coroutine_threadsafe(_connect_and_read(addr), _loop)


def _do_disconnect():
    if _loop:
        asyncio.run_coroutine_threadsafe(_disconnect(), _loop)


def _do_set_slot(n):
    if _loop:
        asyncio.run_coroutine_threadsafe(_set_slot(n), _loop)


def _do_refresh():
    global status_msg
    if not _client:
        return
    with lock:
        status_msg = "Refreshing..."

    async def refresh():
        global status_msg
        _, _, data = await _send_cmd(_client, CMD_GET_BATTERY)
        if data and len(data) >= 1:
            with lock:
                device_info["battery"] = data[0]
        _, _, data = await _send_cmd(_client, CMD_GET_ACTIVE_SLOT)
        if data and len(data) >= 1:
            with lock:
                device_info["active_slot"] = data[0]
        _, _, data = await _send_cmd(_client, CMD_GET_SLOT_INFO)
        if data:
            with lock:
                for i in range(min(8, len(data) // 2)):
                    slot_info[i] = {"hf": data[i * 2], "lf": data[i * 2 + 1]}
        with lock:
            status_msg = "Refreshed"

    if _loop:
        asyncio.run_coroutine_threadsafe(refresh(), _loop)


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"chameleon_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "device": dict(device_info),
            "slots": [
                {"slot": i,
                 "hf": TAG_TYPES.get(s["hf"], f"0x{s['hf']:02X}"),
                 "lf": TAG_TYPES.get(s["lf"], f"0x{s['lf']:02X}"),
                 "active": i == device_info["active_slot"]}
                for i, s in enumerate(slot_info)
            ],
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        scr = SCREENS[screen_idx]
        msg = status_msg
        conn = connected
        sel = selected_idx
        sp = scroll_pos
        di = dict(device_info)
        si = list(slot_info)
        devs = list(found_devices)

    d.rectangle((0, 0, 127, 13), fill="#111")
    titles = {"scan": "CHAM SCAN", "info": "CHAM INFO", "slots": "CHAM SLOTS"}
    d.text((2, 1), titles[scr], font=font, fill="#FF9800")
    clr = "#00FF00" if conn else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=clr)

    y = 15

    if scr == "scan":
        d.text((2, y), f"Devices: {len(devs)} {msg[:10]}", font=font, fill="#888")
        y += 13
        if not devs:
            d.text((2, y), "OK to scan", font=font, fill="#555")
        else:
            end = min(sp + ROWS_VISIBLE, len(devs))
            for i in range(sp, end):
                dev = devs[i]
                prefix = ">" if i == sel else " "
                name = dev["name"][:14]
                rssi = dev["rssi"]
                c = "#FFAA00" if i == sel else "#CCCCCC"
                d.text((2, y), f"{prefix}{name} {rssi}dB", font=font, fill=c)
                y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:Scan/Conn K3:X", font=font, fill="#AAA")

    elif scr == "info":
        lines = [
            f"Model: {di['model']}",
            f"FW: {di['version'][:18]}",
            f"Battery: {di['battery']}%",
            f"Active: Slot {di['active_slot']}",
            "",
            f"Status: {msg[:16]}",
        ]
        for line in lines:
            d.text((2, y), line[:22], font=font, fill="#CCCCCC")
            y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "K1:Refresh K2:Save", font=font, fill="#AAA")

    elif scr == "slots":
        end = min(sp + ROWS_VISIBLE, 8)
        for i in range(sp, end):
            s = si[i]
            active = "*" if i == di["active_slot"] else " "
            prefix = ">" if i == sel else " "
            hf = TAG_TYPES.get(s["hf"], f"?{s['hf']:02X}")[:8]
            lf = TAG_TYPES.get(s["lf"], f"?{s['lf']:02X}")[:6]
            c = "#FFAA00" if i == sel else "#CCCCCC"
            d.text((2, y), f"{prefix}{active}{i}:{hf}/{lf}", font=font, fill=c)
            y += ROW_H
        d.rectangle((0, 116, 127, 127), fill="#111")
        d.text((2, 117), "OK:SetSlot K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, screen_idx, status_msg
    global HCI_DEV, _running

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    _hci_up()
    bg = threading.Thread(target=_bg_loop, daemon=True)
    bg.start()
    time.sleep(0.3)

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "CHAMELEON BLE", font=font, fill="#FF9800")
    d.text((4, 28), "NFC emulator client", font=font, fill="#888")
    d.text((4, 46), "Scan for Chameleon", font=font, fill="#888")
    d.text((4, 58), "Ultra / Lite devices", font=font, fill="#888")
    d.text((4, 80), "OK=Scan  L/R=Screen", font=font, fill="#666")
    d.text((4, 92), "K2=Export  K3=Exit", font=font, fill="#666")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)
            scr = SCREENS[screen_idx]

            if btn == "KEY3":
                if connected:
                    _do_disconnect()
                    with lock:
                        status_msg = "Disconnected"
                    time.sleep(0.3)
                else:
                    break

            elif btn == "LEFT":
                with lock:
                    screen_idx = (screen_idx - 1) % len(SCREENS)
                    scroll_pos = 0
                    selected_idx = 0
                time.sleep(0.25)

            elif btn == "RIGHT":
                with lock:
                    screen_idx = (screen_idx + 1) % len(SCREENS)
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
                if scr == "scan":
                    mx = max(0, len(found_devices) - 1)
                elif scr == "slots":
                    mx = 7
                else:
                    mx = 0
                with lock:
                    selected_idx = min(mx, selected_idx + 1)
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.2)

            elif btn == "OK":
                if scr == "scan":
                    if not connected and found_devices and selected_idx < len(found_devices):
                        addr = found_devices[selected_idx]["addr"]
                        _do_connect(addr)
                        time.sleep(0.5)
                    elif not connected:
                        _start_scan()
                        time.sleep(0.5)
                elif scr == "slots" and connected:
                    _do_set_slot(selected_idx)
                    time.sleep(0.3)

            elif btn == "KEY1":
                if connected:
                    _do_refresh()
                else:
                    _start_scan()
                time.sleep(0.3)

            elif btn == "KEY2":
                if connected:
                    path = _export_json()
                    with lock:
                        status_msg = "Exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        if connected:
            try:
                _do_disconnect()
            except Exception:
                pass
        if _loop:
            _loop.call_soon_threadsafe(_loop.stop)
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
