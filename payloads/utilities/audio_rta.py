#!/usr/bin/env python3
"""
RaspyJack Payload -- Audio Real-Time Analyzer
==============================================
24-band 1/3-octave spectrum analyzer with peak hold, gain control,
and freeze mode.  Captures audio from the auto-detected ALSA capture
device (USB mic preferred) and displays a colour-coded bar graph on
the 128x128 LCD.

Controls
--------
  OK       -- Start / stop capture
  UP/DOWN  -- Adjust dB range (zoom)
  KEY1     -- Cycle gain (0 / +6 / +12 / +20 dB)
  KEY2     -- Toggle freeze (display pauses, capture continues)
  KEY3     -- Exit
"""

import math
import os
import struct
import subprocess
import sys
import threading
import time

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._audio_helper import get_capture_dev, get_capture_label

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

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

RATE = 44100
CHUNK = 2048
NUM_BANDS = 24
BAND_CENTERS = [
    31, 40, 50, 63, 80, 100, 125, 160, 200, 250, 315, 400,
    500, 630, 800, 1000, 1250, 1600, 2000, 2500, 3150, 4000, 5000, 6300,
]
GAIN_STEPS = [1.0, 2.0, 4.0, 10.0]
GAIN_LABELS = ["0dB", "+6", "+12", "+20"]
DB_FLOOR = -60.0
SMOOTHING = 0.3
PEAK_DECAY = 0.4

BAR_AREA_TOP = 14
BAR_AREA_BOTTOM = 116
BAR_AREA_H = BAR_AREA_BOTTOM - BAR_AREA_TOP
BAR_W = 4
BAR_GAP = 1
BAR_STEP = BAR_W + BAR_GAP

lock = threading.Lock()
bands_db = [DB_FLOOR] * NUM_BANDS
peaks_db = [DB_FLOOR] * NUM_BANDS
peak_db_max = DB_FLOOR
capturing = False
frozen = False
gain_idx = 0
db_range = 60.0
_running = True
_proc = None


def _build_band_bins():
    freq_per_bin = RATE / CHUNK
    edges = []
    for i, fc in enumerate(BAND_CENTERS):
        lo = fc / (2 ** (1 / 6))
        hi = fc * (2 ** (1 / 6))
        edges.append((max(1, int(lo / freq_per_bin)), min(CHUNK // 2, int(hi / freq_per_bin) + 1)))
    return edges

BAND_BINS = _build_band_bins()


def _bar_color(db, db_floor, db_ceil):
    frac = max(0.0, min(1.0, (db - db_floor) / (db_ceil - db_floor)))
    if frac < 0.5:
        r = int(255 * frac * 2)
        g = 255
    else:
        r = 255
        g = int(255 * (1.0 - (frac - 0.5) * 2))
    return f"#{r:02x}{g:02x}00"


def _process_chunk(raw):
    global peak_db_max
    n_samples = len(raw) // 2
    gain = GAIN_STEPS[gain_idx]

    if HAS_NUMPY:
        samples = np.frombuffer(raw[:n_samples * 2], dtype=np.int16).astype(np.float64) * gain
        spectrum = np.abs(np.fft.rfft(samples * np.hanning(len(samples))))
    else:
        samples = struct.unpack(f"<{n_samples}h", raw[:n_samples * 2])
        if gain != 1.0:
            samples = [s * gain for s in samples]
        spectrum = _dft_magnitudes(samples)

    ref = 32768.0 * (n_samples / 2)
    new_bands = []
    for lo, hi in BAND_BINS:
        hi = min(hi, len(spectrum))
        if lo >= hi:
            new_bands.append(DB_FLOOR)
            continue
        if HAS_NUMPY:
            mag = float(np.max(spectrum[lo:hi]))
        else:
            mag = max(spectrum[lo:hi])
        if mag < 1.0:
            mag = 1.0
        db = 20.0 * math.log10(mag / ref)
        new_bands.append(max(DB_FLOOR, db))

    with lock:
        pk = DB_FLOOR
        for i in range(NUM_BANDS):
            bands_db[i] = bands_db[i] * SMOOTHING + new_bands[i] * (1 - SMOOTHING)
            if new_bands[i] > peaks_db[i]:
                peaks_db[i] = new_bands[i]
            else:
                peaks_db[i] = max(DB_FLOOR, peaks_db[i] - PEAK_DECAY)
            if bands_db[i] > pk:
                pk = bands_db[i]
        peak_db_max = pk


def _dft_magnitudes(samples):
    n = len(samples)
    half = n // 2 + 1
    mags = [0.0] * half
    for k in range(half):
        re_sum = 0.0
        im_sum = 0.0
        for t in range(n):
            angle = 2.0 * math.pi * k * t / n
            re_sum += samples[t] * math.cos(angle)
            im_sum -= samples[t] * math.sin(angle)
        mags[k] = math.sqrt(re_sum * re_sum + im_sum * im_sum)
    return mags


def _capture_loop():
    global _proc
    dev = get_capture_dev()
    _proc = subprocess.Popen(
        ["arecord", "-D", dev, "-f", "S16_LE", "-c", "1",
         "-r", str(RATE), "-t", "raw", "--buffer-size", str(CHUNK * 4)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
    )
    chunk_bytes = CHUNK * 2
    try:
        while True:
            with lock:
                if not capturing:
                    break
            raw = _proc.stdout.read(chunk_bytes)
            if not raw or len(raw) < chunk_bytes:
                break
            _process_chunk(raw)
    finally:
        try:
            _proc.terminate()
            _proc.wait(timeout=2)
        except Exception:
            try:
                _proc.kill()
            except Exception:
                pass
        _proc = None


def _start_capture():
    global capturing
    with lock:
        if capturing:
            return
        capturing = True
    threading.Thread(target=_capture_loop, daemon=True).start()


def _stop_capture():
    global capturing
    with lock:
        capturing = False
    time.sleep(0.3)


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = capturing
        frz = frozen
        gi = gain_idx
        dr = db_range
        cur_bands = list(bands_db)
        cur_peaks = list(peaks_db)
        pk_max = peak_db_max

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "AUDIO RTA", font=font, fill="#4CAF50")
    state = "FRZ" if frz else ("RUN" if active else "OFF")
    pk_str = f"{pk_max:.0f}dB" if active else "--"
    d.text((64, 1), f"{state} {pk_str} G:{GAIN_LABELS[gi]}", font=font, fill="#AAA")

    db_ceil = 0.0
    db_floor = -dr
    x_start = 4

    for i in range(NUM_BANDS):
        x = x_start + i * BAR_STEP
        frac = max(0.0, min(1.0, (cur_bands[i] - db_floor) / (db_ceil - db_floor)))
        bar_h = int(frac * BAR_AREA_H)
        y_top = BAR_AREA_BOTTOM - bar_h

        if bar_h > 0:
            color = _bar_color(cur_bands[i], db_floor, db_ceil)
            d.rectangle((x, y_top, x + BAR_W - 1, BAR_AREA_BOTTOM), fill=color)

        pk_frac = max(0.0, min(1.0, (cur_peaks[i] - db_floor) / (db_ceil - db_floor)))
        pk_y = BAR_AREA_BOTTOM - int(pk_frac * BAR_AREA_H)
        if pk_frac > 0.01:
            d.rectangle((x, pk_y, x + BAR_W - 1, pk_y + 1), fill="#FFFFFF")

    d.rectangle((0, 117, 127, 127), fill="#111")
    d.text((2, 118), "100", font=font, fill="#666")
    d.text((48, 118), "1k", font=font, fill="#666")
    d.text((92, 118), "4k", font=font, fill="#666")
    rng_str = f"-{int(dr)}dB"
    d.text((108, 118), rng_str, font=font, fill="#555")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global frozen, gain_idx, db_range

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    label = get_capture_label()
    d.text((8, 10), "AUDIO RTA", font=font, fill="#4CAF50")
    d.text((4, 28), "24-band spectrum", font=font, fill="#888")
    d.text((4, 40), f"Dev: {label[:18]}", font=font, fill="#888")
    d.text((4, 60), "OK=Start K1=Gain", font=font, fill="#666")
    d.text((4, 72), "K2=Freeze U/D=Range", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    if not HAS_NUMPY:
        d.text((4, 100), "numpy missing: slow", font=font, fill="#FF5555")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with lock:
                    active = capturing
                if active:
                    _stop_capture()
                else:
                    _start_capture()
                time.sleep(0.3)

            elif btn == "KEY1":
                with lock:
                    gain_idx = (gain_idx + 1) % len(GAIN_STEPS)
                time.sleep(0.25)

            elif btn == "KEY2":
                with lock:
                    frozen = not frozen
                time.sleep(0.25)

            elif btn == "UP":
                with lock:
                    db_range = max(20.0, db_range - 10.0)
                time.sleep(0.2)

            elif btn == "DOWN":
                with lock:
                    db_range = min(96.0, db_range + 10.0)
                time.sleep(0.2)

            if not frozen:
                _draw_screen()
            time.sleep(0.03)

    finally:
        _stop_capture()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
