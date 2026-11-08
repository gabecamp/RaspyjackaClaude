#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Channel Sniffer (RTL-SDR)
====================================================
Sniff BLE advertisement channels at 2.4 GHz using RTL-SDR.
Requires RTL-SDR V4 or E4000-based tuner for 2.4 GHz range.
Demodulates GFSK and extracts BLE advertising PDUs.

Controls:
  OK         Start / Stop capture
  UP / DOWN  Scroll packets / devices
  KEY1       Cycle view (Capture / Packets / Devices / Raw)
  KEY2       Export to loot
  LEFT/RIGHT Switch BLE channel (37/38/39)
  KEY3       Exit
"""

import os
import sys
import time
import json
import struct
import hashlib
import subprocess
import threading
from datetime import datetime
from collections import OrderedDict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr, is_v4

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/ble_sniff"
DEBOUNCE = 0.18
VIEWS = ["capture", "packets", "devices", "raw"]

BLE_CHANNELS = {
    37: 2_402_000_000,
    38: 2_426_000_000,
    39: 2_480_000_000,
}
BLE_ACCESS_ADDR = 0x8E89BED6
SAMPLE_RATE = 2_000_000

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
ROW_H = S(12)

PDU_TYPES = {
    0: "ADV_IND",
    1: "ADV_DIRECT",
    2: "ADV_NONCONN",
    3: "SCAN_REQ",
    4: "SCAN_RSP",
    5: "CONNECT",
    6: "ADV_SCAN",
}

packets = []
devices = OrderedDict()
raw_hex = []
lock = threading.Lock()
_shutdown = threading.Event()
_running = False
_view = 0
_scroll = 0
_chan_idx = 0
_chan_list = [37, 38, 39]
_last_btn = 0.0
_pkt_count = 0
_capture_thread = None

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def _demod_gfsk(iq_bytes):
    """Basic GFSK demodulation to bit stream."""
    if not HAS_NUMPY or len(iq_bytes) < 100:
        return b""
    samples = []
    for i in range(0, len(iq_bytes) - 1, 2):
        iv = (iq_bytes[i] - 127.5) / 127.5
        qv = (iq_bytes[i + 1] - 127.5) / 127.5
        samples.append(complex(iv, qv))
    arr = np.array(samples)
    phase = np.angle(arr)
    freq = np.diff(np.unwrap(phase))
    bits = (freq > 0).astype(np.uint8)
    return bytes(bits)


def _find_access_addr(bits):
    """Search for BLE access address in bit stream."""
    target = []
    aa = BLE_ACCESS_ADDR
    for i in range(32):
        target.append((aa >> i) & 1)
    results = []
    for i in range(len(bits) - 80):
        match = True
        for j in range(32):
            if bits[i + j] != target[j]:
                match = False
                break
        if match:
            results.append(i + 32)
    return results


def _extract_pdu(bits, offset):
    """Extract BLE advertising PDU header + address."""
    if offset + 16 > len(bits):
        return None
    header_bits = bits[offset:offset + 16]
    header = 0
    for i, b in enumerate(header_bits):
        header |= (b << i)
    pdu_type = header & 0x0F
    length = (header >> 8) & 0x3F
    if length < 6 or length > 37:
        return None
    addr_start = offset + 16
    if addr_start + 48 > len(bits):
        return None
    addr_bytes = []
    for i in range(6):
        byte_val = 0
        for j in range(8):
            idx = addr_start + i * 8 + j
            if idx < len(bits):
                byte_val |= (bits[idx] << j)
        addr_bytes.append(byte_val)
    addr = ":".join(f"{b:02X}" for b in reversed(addr_bytes))
    return {
        "type": pdu_type,
        "type_name": PDU_TYPES.get(pdu_type, f"0x{pdu_type:02X}"),
        "length": length,
        "addr": addr,
        "raw_header": f"{header:04X}",
    }


def _capture_loop():
    global _pkt_count
    chan = _chan_list[_chan_idx]
    freq = BLE_CHANNELS[chan]
    chunk_size = 262144
    cmd = [
        "rtl_sdr", "-f", str(freq), "-s", str(SAMPLE_RATE),
        "-g", "20", "-",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        return
    try:
        while not _shutdown.is_set():
            data = proc.stdout.read(chunk_size)
            if not data:
                break
            bits = _demod_gfsk(data)
            if not bits:
                continue
            offsets = _find_access_addr(bits)
            for off in offsets:
                pdu = _extract_pdu(bits, off)
                if pdu is None:
                    continue
                ts = datetime.utcnow().strftime("%H:%M:%S.%f")[:12]
                pdu["time"] = ts
                pdu["channel"] = chan
                with lock:
                    _pkt_count += 1
                    packets.append(pdu)
                    if len(packets) > 500:
                        del packets[:100]
                    addr = pdu["addr"]
                    if addr not in devices:
                        devices[addr] = {"addr": addr, "first": ts, "count": 0, "types": set()}
                    devices[addr]["count"] += 1
                    devices[addr]["last"] = ts
                    devices[addr]["types"].add(pdu["type_name"])
                    hex_line = f"{ts} ch{chan} {pdu['raw_header']} {addr}"
                    raw_hex.append(hex_line)
                    if len(raw_hex) > 300:
                        del raw_hex[:50]
    finally:
        proc.terminate()
        try:
            proc.wait(2)
        except Exception:
            proc.kill()


def _start():
    global _running, _capture_thread
    if _running:
        return
    _shutdown.clear()
    _running = True
    _capture_thread = threading.Thread(target=_capture_loop, daemon=True)
    _capture_thread.start()


def _stop():
    global _running
    _shutdown.set()
    _running = False


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ble_sniff_{ts}.json")
    with lock:
        dev_data = {}
        for addr, d in devices.items():
            dev_data[addr] = {
                "addr": d["addr"],
                "first": d["first"],
                "last": d.get("last", ""),
                "count": d["count"],
                "types": list(d["types"]),
            }
        data = {"packets": packets[-100:], "devices": dev_data}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def _draw(image, draw, font):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH, S(11))], fill=C_HEADER)
    chan = _chan_list[_chan_idx]
    freq_mhz = BLE_CHANNELS[chan] / 1e6
    draw.text((S(2), S(1)), f"BLE ch{chan} {freq_mhz:.0f}M", fill=C_CYAN, font=font)
    state = "RUN" if _running else "STOP"
    draw.text((WIDTH - S(28), S(1)), state, fill=C_GREEN if _running else C_RED, font=font)

    with lock:
        pkt_list = list(packets[-30:])
        dev_list = list(devices.values())
        raw_list = list(raw_hex[-20:])
        pc = _pkt_count

    v = VIEWS[_view]
    y = S(14)

    if v == "capture":
        draw.text((S(2), y), f"Packets: {pc}", fill=C_CYAN, font=font)
        y += ROW_H
        draw.text((S(2), y), f"Devices: {len(dev_list)}", fill=C_GREEN, font=font)
        y += ROW_H
        draw.text((S(2), y), f"Channel: {chan}", fill="WHITE", font=font)
        y += ROW_H
        if not is_v4():
            y += ROW_H
            draw.text((S(2), y), "Warning: V4 tuner", fill=C_YELLOW, font=font)
            y += ROW_H
            draw.text((S(2), y), "recommended for 2.4G", fill=C_YELLOW, font=font)
        y += ROW_H * 2
        for p in pkt_list[-3:]:
            txt = f"{p['type_name'][:10]} {p['addr'][-8:]}"
            draw.text((S(2), y), txt, fill="WHITE", font=font)
            y += ROW_H

    elif v == "packets":
        if not pkt_list:
            draw.text((S(2), y), "No packets yet", fill=C_MUTED, font=font)
        else:
            for p in pkt_list[_scroll:_scroll + 7]:
                txt = f"{p['time'][-8:]} {p['type_name'][:8]} {p['addr'][-8:]}"
                draw.text((S(2), y), txt, fill="WHITE", font=font)
                y += ROW_H

    elif v == "devices":
        if not dev_list:
            draw.text((S(2), y), "No devices yet", fill=C_MUTED, font=font)
        else:
            for d in dev_list[_scroll:_scroll + 7]:
                types = ",".join(list(d["types"])[:2])
                txt = f"{d['addr'][-8:]} x{d['count']} {types[:8]}"
                draw.text((S(2), y), txt, fill="WHITE", font=font)
                y += ROW_H

    elif v == "raw":
        if not raw_list:
            draw.text((S(2), y), "No data", fill=C_MUTED, font=font)
        else:
            for line in raw_list[_scroll:_scroll + 8]:
                draw.text((S(2), y), line[:24], fill=C_PURPLE, font=font)
                y += ROW_H

    draw.text((S(2), HEIGHT - S(10)), f"[{VIEWS[_view].upper()}]", fill=C_MUTED, font=font)


def main():
    global _view, _scroll, _chan_idx, _last_btn

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD = LCD_1in44.LCD()
    LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    font = scaled_font()

    found, label, _ = detect_sdr()
    if not found:
        image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        draw = ScaledDraw(image)
        draw.text((S(4), S(40)), "No SDR found", fill=C_RED, font=font)
        LCD.LCD_ShowImage(image, 0, 0)
        time.sleep(3)
        return 0

    try:
        while True:
            image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            draw = ScaledDraw(image)
            _draw(image, draw, font)
            LCD.LCD_ShowImage(image, 0, 0)

            btn = get_button(PINS, timeout=0.15)
            now = time.time()
            if btn and now - _last_btn < DEBOUNCE:
                btn = None
            if btn:
                _last_btn = now

            if btn == "OK":
                if _running:
                    _stop()
                else:
                    _start()
            elif btn == "KEY1":
                _view = (_view + 1) % len(VIEWS)
                _scroll = 0
            elif btn == "UP":
                _scroll = max(0, _scroll - 1)
            elif btn == "DOWN":
                _scroll += 1
            elif btn == "LEFT":
                if not _running:
                    _chan_idx = (_chan_idx - 1) % len(_chan_list)
            elif btn == "RIGHT":
                if not _running:
                    _chan_idx = (_chan_idx + 1) % len(_chan_list)
            elif btn == "KEY2":
                _export()
            elif btn == "KEY3":
                break
    finally:
        _stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
