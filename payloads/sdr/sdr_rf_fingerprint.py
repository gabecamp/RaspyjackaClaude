#!/usr/bin/env python3
"""
RaspyJack Payload -- RF Transmitter Fingerprinter
===================================================
Capture IQ bursts and compute unique transmitter fingerprints.
Each radio has subtle hardware variations (frequency offset, rise time,
spectral shape) that create a unique signature.

Controls:
  OK         Capture IQ burst / save fingerprint
  UP / DOWN  Scroll / adjust frequency
  KEY1       Cycle view (Capture / Analyze / Database / Compare)
  KEY2       Export database to loot
  LEFT/RIGHT Adjust frequency step
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

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr, recommended_gain

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/fingerprint"
DB_PATH = os.path.join(LOOT_DIR, "fingerprints.json")
DEBOUNCE = 0.18
VIEWS = ["capture", "analyze", "database", "compare"]

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
ROW_H = S(12)

_view = 0
_scroll = 0
_freq_hz = 433_920_000
_freq_step = 100_000
_sample_rate = 2_048_000
_capture_len = 262144
_last_btn = 0.0
_capturing = False
_analysis = None
_db = []
_match_result = None

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


def _load_db():
    global _db
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH) as f:
                _db = json.load(f)
        except Exception:
            _db = []


def _save_db():
    os.makedirs(LOOT_DIR, exist_ok=True)
    with open(DB_PATH, "w") as f:
        json.dump(_db, f, indent=2)


def _capture_iq():
    global _capturing, _analysis
    _capturing = True
    _analysis = None
    tmp = "/tmp/rj_rf_fp.bin"
    gain = recommended_gain(_freq_hz)
    cmd = [
        "rtl_sdr", "-f", str(_freq_hz), "-s", str(_sample_rate),
        "-g", str(gain), "-n", str(_capture_len * 2), tmp,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=10)
    except Exception:
        _capturing = False
        return
    try:
        with open(tmp, "rb") as f:
            raw = f.read()
        os.unlink(tmp)
    except Exception:
        _capturing = False
        return

    if len(raw) < 512:
        _capturing = False
        return

    _analysis = _analyze_iq(raw)
    _capturing = False


def _analyze_iq(raw):
    samples = []
    for i in range(0, len(raw) - 1, 2):
        i_val = (raw[i] - 127.5) / 127.5
        q_val = (raw[i + 1] - 127.5) / 127.5
        samples.append(complex(i_val, q_val))

    n = len(samples)
    if n < 64:
        return None

    if HAS_NUMPY:
        arr = np.array(samples)
        power = np.abs(arr) ** 2
        mean_power = float(np.mean(power))
        peak_power = float(np.max(power))

        fft = np.fft.fftshift(np.fft.fft(arr[:min(n, 2048)]))
        mag = np.abs(fft)
        peak_bin = int(np.argmax(mag))
        fft_len = len(mag)
        freq_offset = (peak_bin - fft_len // 2) / fft_len * _sample_rate

        above_thresh = mag > (np.max(mag) * 0.5)
        bw_bins = int(np.sum(above_thresh))
        bandwidth = bw_bins / fft_len * _sample_rate

        threshold = mean_power + (peak_power - mean_power) * 0.3
        rise_idx = 0
        for j in range(min(n, 10000)):
            if power[j] > threshold:
                rise_idx = j
                break
        rise_time = rise_idx / _sample_rate * 1e6
    else:
        power = [abs(s) ** 2 for s in samples]
        mean_power = sum(power) / len(power)
        peak_power = max(power)
        freq_offset = 0.0
        bandwidth = 0.0
        threshold = mean_power + (peak_power - mean_power) * 0.3
        rise_idx = 0
        for j in range(min(n, 10000)):
            if power[j] > threshold:
                rise_idx = j
                break
        rise_time = rise_idx / _sample_rate * 1e6

    sig = f"{freq_offset:.0f}:{bandwidth:.0f}:{rise_time:.1f}:{mean_power:.6f}:{peak_power:.6f}"
    fp_hash = hashlib.sha256(sig.encode()).hexdigest()[:16]

    return {
        "freq_hz": _freq_hz,
        "freq_offset_hz": round(freq_offset, 1),
        "bandwidth_hz": round(bandwidth, 1),
        "rise_time_us": round(rise_time, 2),
        "mean_power": round(mean_power, 6),
        "peak_power": round(peak_power, 6),
        "fingerprint": fp_hash,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _find_match(fp):
    if not fp:
        return None
    for entry in _db:
        if entry.get("fingerprint") == fp["fingerprint"]:
            return entry
        freq_close = abs(entry.get("freq_offset_hz", 0) - fp["freq_offset_hz"]) < 500
        bw_close = abs(entry.get("bandwidth_hz", 0) - fp["bandwidth_hz"]) < 5000
        rise_close = abs(entry.get("rise_time_us", 0) - fp["rise_time_us"]) < 2.0
        if freq_close and bw_close and rise_close:
            return entry
    return None


def _draw(image, draw, font):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH, S(11))], fill=C_HEADER)
    freq_mhz = _freq_hz / 1e6
    draw.text((S(2), S(1)), f"RF FP {freq_mhz:.3f}MHz", fill=C_CYAN, font=font)

    v = VIEWS[_view]
    y = S(14)

    if v == "capture":
        draw.text((S(2), y), f"Freq: {freq_mhz:.3f} MHz", fill="WHITE", font=font)
        y += ROW_H
        step_khz = _freq_step / 1000
        draw.text((S(2), y), f"Step: {step_khz:.0f} kHz", fill=C_MUTED, font=font)
        y += ROW_H * 2
        if _capturing:
            draw.text((S(2), y), "Capturing...", fill=C_YELLOW, font=font)
        else:
            draw.text((S(2), y), "OK = Capture burst", fill=C_GREEN, font=font)
        y += ROW_H * 2
        draw.text((S(2), y), f"DB: {len(_db)} prints", fill=C_MUTED, font=font)

    elif v == "analyze":
        if _analysis is None:
            draw.text((S(2), y), "No capture yet", fill=C_MUTED, font=font)
        else:
            a = _analysis
            draw.text((S(2), y), f"FP: {a['fingerprint']}", fill=C_CYAN, font=font)
            y += ROW_H
            draw.text((S(2), y), f"Offset: {a['freq_offset_hz']:.0f} Hz", fill="WHITE", font=font)
            y += ROW_H
            draw.text((S(2), y), f"BW: {a['bandwidth_hz']:.0f} Hz", fill="WHITE", font=font)
            y += ROW_H
            draw.text((S(2), y), f"Rise: {a['rise_time_us']:.1f} us", fill="WHITE", font=font)
            y += ROW_H
            draw.text((S(2), y), f"Mean: {a['mean_power']:.4f}", fill=C_MUTED, font=font)
            y += ROW_H
            draw.text((S(2), y), f"Peak: {a['peak_power']:.4f}", fill=C_MUTED, font=font)
            y += ROW_H * 2
            draw.text((S(2), y), "OK = Save to DB", fill=C_GREEN, font=font)

    elif v == "database":
        if not _db:
            draw.text((S(2), y), "No fingerprints", fill=C_MUTED, font=font)
        else:
            draw.text((S(2), y), f"{len(_db)} fingerprints", fill=C_CYAN, font=font)
            y += ROW_H
            for entry in _db[_scroll:_scroll + 6]:
                label = entry.get("label", entry["fingerprint"][:12])
                freq = entry.get("freq_hz", 0) / 1e6
                draw.text((S(2), y), f"{label} {freq:.1f}M", fill="WHITE", font=font)
                y += ROW_H

    elif v == "compare":
        if _analysis is None:
            draw.text((S(2), y), "Capture first", fill=C_MUTED, font=font)
        elif _match_result is None:
            draw.text((S(2), y), "No match found", fill=C_YELLOW, font=font)
            y += ROW_H
            draw.text((S(2), y), f"FP: {_analysis['fingerprint']}", fill=C_MUTED, font=font)
        else:
            draw.text((S(2), y), "MATCH FOUND!", fill=C_GREEN, font=font)
            y += ROW_H
            label = _match_result.get("label", _match_result["fingerprint"][:12])
            draw.text((S(2), y), f"Device: {label}", fill=C_CYAN, font=font)
            y += ROW_H
            draw.text((S(2), y), f"FP: {_match_result['fingerprint']}", fill="WHITE", font=font)
            y += ROW_H
            draw.text((S(2), y), f"Saved: {_match_result.get('timestamp', '?')}", fill=C_MUTED, font=font)

    draw.text((S(2), HEIGHT - S(10)), f"[{VIEWS[_view].upper()}]", fill=C_MUTED, font=font)


def main():
    global _view, _scroll, _freq_hz, _freq_step, _last_btn, _analysis, _match_result

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

    _load_db()

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
            if _view == 0 and not _capturing:
                threading.Thread(target=_capture_iq, daemon=True).start()
            elif _view == 1 and _analysis:
                _analysis["label"] = f"dev_{len(_db)+1}"
                _db.append(dict(_analysis))
                _save_db()
            elif _view == 3 and _analysis:
                _match_result = _find_match(_analysis)
        elif btn == "KEY1":
            _view = (_view + 1) % len(VIEWS)
            _scroll = 0
            if _view == 3 and _analysis:
                _match_result = _find_match(_analysis)
        elif btn == "UP":
            if _view == 0:
                _freq_hz += _freq_step
            else:
                _scroll = max(0, _scroll - 1)
        elif btn == "DOWN":
            if _view == 0:
                _freq_hz = max(24_000_000, _freq_hz - _freq_step)
            else:
                _scroll = min(_scroll + 1, max(0, len(_db) - 6))
        elif btn == "LEFT":
            _freq_step = max(1000, _freq_step // 10)
        elif btn == "RIGHT":
            _freq_step = min(10_000_000, _freq_step * 10)
        elif btn == "KEY2":
            os.makedirs(LOOT_DIR, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(LOOT_DIR, f"rfdb_{ts}.json")
            with open(path, "w") as f:
                json.dump(_db, f, indent=2)
        elif btn == "KEY3":
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
