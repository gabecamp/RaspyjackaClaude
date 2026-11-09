#!/usr/bin/env python3
"""
RaspyJack Payload -- ISM Band Device Logger
=============================================
Passive IoT/smart-home RF logger on 433.92/868/915 MHz.
Uses rtl_433 to decode and log all detected devices in range.
Tracks unique devices over time, alerts on new devices.

Controls:
  OK         Start / Stop logging
  UP / DOWN  Scroll device list
  KEY1       Cycle view (Dashboard / Devices / Detail / Timeline)
  KEY2       Export session to loot
  KEY3       Exit
"""

import os
import sys
import time
import json
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
from payloads.sdr._sdr_core import detect_sdr

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/ism"
DEBOUNCE = 0.18
VIEWS = ["dashboard", "devices", "detail", "timeline"]
BANDS = {"433": "433.92M", "868": "868M", "915": "915M"}

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
ROW_H = S(12)

# ── state ──
devices = OrderedDict()
timeline = []
lock = threading.Lock()
_shutdown = threading.Event()
_proc = None
_running = False
_view = 0
_scroll = 0
_sel_dev = None
_band = "433"
_last_btn = 0.0
_new_alert = ""


def _dev_key(obj):
    model = obj.get("model", "unknown")
    dev_id = str(obj.get("id", obj.get("channel", "")))
    return f"{model}_{dev_id}"


def _parse_loop():
    global _proc, _new_alert
    cmd = [
        "rtl_433", "-f", BANDS[_band], "-F", "json", "-M", "time:utc",
        "-M", "level", "-C", "si",
    ]
    try:
        _proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        return
    while not _shutdown.is_set() and _proc.poll() is None:
        line = _proc.stdout.readline()
        if not line:
            continue
        try:
            obj = json.loads(line.strip())
        except (json.JSONDecodeError, ValueError):
            continue
        key = _dev_key(obj)
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with lock:
            is_new = key not in devices
            if is_new:
                devices[key] = {
                    "model": obj.get("model", "?"),
                    "id": str(obj.get("id", "")),
                    "first_seen": ts,
                    "count": 0,
                    "readings": [],
                }
                _new_alert = f"NEW: {obj.get('model', '?')}"
            dev = devices[key]
            dev["last_seen"] = ts
            dev["count"] += 1
            reading = {"time": ts}
            for k in ("temperature_C", "humidity", "battery_ok", "pressure_kPa",
                       "wind_avg_km_h", "rain_mm", "rssi", "snr"):
                if k in obj:
                    reading[k] = obj[k]
            dev["readings"].append(reading)
            if len(dev["readings"]) > 200:
                dev["readings"] = dev["readings"][-200:]
            timeline.append({"time": ts, "key": key, "model": dev["model"]})
            if len(timeline) > 500:
                del timeline[:100]


def _start():
    global _running
    if _running:
        return
    _shutdown.clear()
    _running = True
    threading.Thread(target=_parse_loop, daemon=True).start()


def _stop():
    global _running, _proc
    _shutdown.set()
    _running = False
    if _proc and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(3)
        except Exception:
            _proc.kill()
    _proc = None


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ism_{ts}.json")
    with lock:
        data = {"band": _band, "devices": dict(devices), "timeline": timeline[-200:]}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def _draw(image, draw, font):
    global _new_alert
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH, S(11))], fill=C_HEADER)
    hdr = f"ISM {_band}MHz"
    state = "RUN" if _running else "STOP"
    draw.text((S(2), S(1)), hdr, fill=C_CYAN, font=font)
    draw.text((WIDTH - S(30), S(1)), state, fill=C_GREEN if _running else C_RED, font=font)

    with lock:
        dev_list = list(devices.values())
        tl = list(timeline[-60:])

    v = VIEWS[_view]
    y = S(14)

    if v == "dashboard":
        draw.text((S(2), y), f"Devices: {len(dev_list)}", fill=C_CYAN, font=font)
        y += ROW_H
        draw.text((S(2), y), f"Events: {sum(d['count'] for d in dev_list)}", fill=C_GREEN, font=font)
        y += ROW_H
        draw.text((S(2), y), f"Band: {_band} MHz", fill=C_MUTED, font=font)
        y += ROW_H * 2
        if _new_alert:
            draw.text((S(2), y), _new_alert[:20], fill=C_YELLOW, font=font)
            y += ROW_H
        for d in dev_list[-4:]:
            txt = f"{d['model'][:12]} x{d['count']}"
            draw.text((S(2), y), txt, fill="WHITE", font=font)
            y += ROW_H
            if y > HEIGHT - S(4):
                break

    elif v == "devices":
        if not dev_list:
            draw.text((S(2), y), "No devices yet", fill=C_MUTED, font=font)
        else:
            visible = dev_list[_scroll:_scroll + 8]
            for i, d in enumerate(visible):
                color = C_CYAN if (i + _scroll) == _scroll else "WHITE"
                txt = f"{d['model'][:14]} ({d['count']})"
                draw.text((S(2), y), txt, fill=color, font=font)
                y += ROW_H

    elif v == "detail":
        if _sel_dev and _sel_dev in devices:
            d = devices[_sel_dev]
            draw.text((S(2), y), d["model"][:20], fill=C_CYAN, font=font)
            y += ROW_H
            draw.text((S(2), y), f"ID: {d['id']}", fill=C_MUTED, font=font)
            y += ROW_H
            draw.text((S(2), y), f"First: {d['first_seen']}", fill=C_MUTED, font=font)
            y += ROW_H
            draw.text((S(2), y), f"Last: {d.get('last_seen', '?')}", fill=C_GREEN, font=font)
            y += ROW_H
            draw.text((S(2), y), f"Count: {d['count']}", fill="WHITE", font=font)
            y += ROW_H * 2
            for r in d["readings"][-3:]:
                parts = []
                if "temperature_C" in r:
                    parts.append(f"{r['temperature_C']:.1f}C")
                if "humidity" in r:
                    parts.append(f"{r['humidity']}%")
                if "battery_ok" in r:
                    parts.append("bat" if r["battery_ok"] else "LOW")
                draw.text((S(2), y), " ".join(parts)[:22] if parts else r["time"], fill="WHITE", font=font)
                y += ROW_H
        else:
            draw.text((S(2), y), "Select a device", fill=C_MUTED, font=font)

    elif v == "timeline":
        if not tl:
            draw.text((S(2), y), "No events yet", fill=C_MUTED, font=font)
        else:
            for ev in tl[-(8):]:
                txt = f"{ev['time']} {ev['model'][:12]}"
                draw.text((S(2), y), txt, fill="WHITE", font=font)
                y += ROW_H
                if y > HEIGHT - S(4):
                    break

    draw.text((S(2), HEIGHT - S(10)), f"[{VIEWS[_view].upper()}]", fill=C_MUTED, font=font)
    _new_alert = ""


def main():
    global _view, _scroll, _sel_dev, _band, _last_btn

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
                with lock:
                    mx = max(0, len(devices) - 8)
                _scroll = min(_scroll + 1, mx)
            elif btn == "RIGHT":
                with lock:
                    keys = list(devices.keys())
                if keys and _scroll < len(keys):
                    _sel_dev = keys[_scroll]
                    _view = 2
            elif btn == "LEFT":
                if _view == 2:
                    _view = 1
                else:
                    _scroll = 0
            elif btn == "KEY2":
                path = _export()
            elif btn == "KEY3":
                break
    finally:
        _stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
