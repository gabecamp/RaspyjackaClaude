#!/usr/bin/env python3
"""
RaspyJack Payload -- TPMS Tire Pressure Decoder
=================================================
Decode tire pressure monitoring systems via RTL-SDR.
315 MHz (US) and 433.92 MHz (EU) bands.
Groups tires by vehicle, displays pressure/temp/battery.

Controls:
  OK         Start / Stop decoding
  UP / DOWN  Scroll readings
  KEY1       Cycle view (Live / Vehicles / History / Config)
  KEY2       Export to loot
  LEFT/RIGHT Change band in Config view
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
LOOT_DIR = "/root/Raspyjack/loot/SDR/tpms"
DEBOUNCE = 0.18
VIEWS = ["live", "vehicles", "history", "config"]
FREQ_BANDS = {"US 315": "315M", "EU 433": "433.92M"}

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
ROW_H = S(12)

tires = OrderedDict()
vehicles = {}
history = []
lock = threading.Lock()
_shutdown = threading.Event()
_proc = None
_running = False
_view = 0
_scroll = 0
_band_idx = 0
_last_btn = 0.0


def _tire_key(obj):
    return str(obj.get("id", obj.get("code", "?")))


def _group_vehicles():
    with lock:
        seen_times = {}
        for tid, t in tires.items():
            ts = t.get("last_seen", "")
            if ts not in seen_times:
                seen_times[ts] = []
            seen_times[ts].append(tid)
        groups = {}
        vid = 0
        assigned = set()
        for ts_ids in seen_times.values():
            unassigned = [t for t in ts_ids if t not in assigned]
            if len(unassigned) >= 2:
                vid += 1
                vname = f"Vehicle {vid}"
                groups[vname] = unassigned
                assigned.update(unassigned)
        for tid in tires:
            if tid not in assigned:
                vid += 1
                groups[f"Vehicle {vid}"] = [tid]
        return groups


def _parse_loop():
    global _proc
    bands = list(FREQ_BANDS.values())
    freq = bands[_band_idx]
    cmd = [
        "rtl_433", "-f", freq, "-F", "json", "-M", "time:utc",
        "-R", "59", "-R", "60", "-R", "82", "-R", "88",
        "-R", "89", "-R", "90", "-R", "91", "-R", "100",
        "-R", "110", "-R", "139", "-R", "150", "-R", "168",
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
        tid = _tire_key(obj)
        ts = datetime.utcnow().strftime("%H:%M:%S")
        with lock:
            if tid not in tires:
                tires[tid] = {"id": tid, "model": obj.get("model", "?"), "readings": []}
            t = tires[tid]
            t["last_seen"] = ts
            reading = {"time": ts}
            for k in ("pressure_kPa", "pressure_PSI", "temperature_C",
                       "battery_ok", "flags", "rssi"):
                if k in obj:
                    reading[k] = obj[k]
            if "pressure_kPa" in reading and "pressure_PSI" not in reading:
                reading["pressure_PSI"] = round(reading["pressure_kPa"] * 0.145038, 1)
            t["readings"].append(reading)
            if len(t["readings"]) > 100:
                t["readings"] = t["readings"][-100:]
            history.append({"time": ts, "id": tid, **reading})
            if len(history) > 500:
                del history[:100]


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
    path = os.path.join(LOOT_DIR, f"tpms_{ts}.json")
    with lock:
        data = {"tires": dict(tires), "history": history[-200:]}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def _pressure_color(psi):
    if psi is None:
        return C_MUTED
    if psi < 25:
        return C_RED
    if psi < 30:
        return C_YELLOW
    return C_GREEN


def _draw(image, draw, font):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH, S(11))], fill=C_HEADER)
    bands = list(FREQ_BANDS.keys())
    hdr = f"TPMS {bands[_band_idx]}"
    state = "RUN" if _running else "STOP"
    draw.text((S(2), S(1)), hdr, fill=C_CYAN, font=font)
    draw.text((WIDTH - S(28), S(1)), state, fill=C_GREEN if _running else C_RED, font=font)

    with lock:
        tire_list = list(tires.values())
        hist = list(history[-30:])

    v = VIEWS[_view]
    y = S(14)

    if v == "live":
        if not tire_list:
            draw.text((S(2), y), "Waiting for TPMS...", fill=C_MUTED, font=font)
        else:
            draw.text((S(2), y), f"Tires: {len(tire_list)}", fill=C_CYAN, font=font)
            y += ROW_H
            for t in tire_list[_scroll:_scroll + 6]:
                r = t["readings"][-1] if t["readings"] else {}
                psi = r.get("pressure_PSI")
                temp = r.get("temperature_C")
                psi_s = f"{psi:.0f}psi" if psi is not None else "?"
                temp_s = f"{temp:.0f}C" if temp is not None else ""
                txt = f"{t['id'][-6:]} {psi_s} {temp_s}"
                draw.text((S(2), y), txt, fill=_pressure_color(psi), font=font)
                y += ROW_H

    elif v == "vehicles":
        groups = _group_vehicles()
        if not groups:
            draw.text((S(2), y), "No vehicles yet", fill=C_MUTED, font=font)
        else:
            for vname, tids in list(groups.items())[:4]:
                draw.text((S(2), y), vname, fill=C_CYAN, font=font)
                y += ROW_H
                for tid in tids[:4]:
                    t = tires.get(tid)
                    if not t:
                        continue
                    r = t["readings"][-1] if t["readings"] else {}
                    psi = r.get("pressure_PSI")
                    psi_s = f"{psi:.0f}psi" if psi is not None else "?"
                    draw.text((S(6), y), f"{tid[-6:]} {psi_s}", fill=_pressure_color(psi), font=font)
                    y += ROW_H
                    if y > HEIGHT - S(14):
                        break

    elif v == "history":
        if not hist:
            draw.text((S(2), y), "No history", fill=C_MUTED, font=font)
        else:
            for h in hist[-(7):]:
                psi = h.get("pressure_PSI")
                psi_s = f"{psi:.0f}" if psi is not None else "?"
                txt = f"{h['time']} {h['id'][-6:]} {psi_s}psi"
                draw.text((S(2), y), txt, fill="WHITE", font=font)
                y += ROW_H

    elif v == "config":
        draw.text((S(2), y), "Band:", fill=C_MUTED, font=font)
        y += ROW_H
        for i, b in enumerate(bands):
            color = C_CYAN if i == _band_idx else C_MUTED
            marker = ">" if i == _band_idx else " "
            draw.text((S(4), y), f"{marker} {b}", fill=color, font=font)
            y += ROW_H
        y += ROW_H
        draw.text((S(2), y), "LEFT/RIGHT to change", fill=C_MUTED, font=font)
        y += ROW_H
        draw.text((S(2), y), "Restart to apply", fill=C_MUTED, font=font)

    draw.text((S(2), HEIGHT - S(10)), f"[{VIEWS[_view].upper()}]", fill=C_MUTED, font=font)


def main():
    global _view, _scroll, _band_idx, _last_btn

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
                    mx = max(0, len(tires) - 6)
                _scroll = min(_scroll + 1, mx)
            elif btn == "LEFT":
                if _view == 3:
                    _band_idx = (_band_idx - 1) % len(FREQ_BANDS)
                else:
                    _scroll = 0
            elif btn == "RIGHT":
                if _view == 3:
                    _band_idx = (_band_idx + 1) % len(FREQ_BANDS)
            elif btn == "KEY2":
                _export()
            elif btn == "KEY3":
                break
    finally:
        _stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
