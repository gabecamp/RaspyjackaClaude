#!/usr/bin/env python3
"""
RaspyJack Payload -- NOAA Weather Satellite Receiver
=====================================================
Capture APT weather satellite images from NOAA-15/18/19 using RTL-SDR.
Records FM-demodulated audio, converts to WAV, decodes to image.

Controls:
  OK         Start/Stop capture
  UP/DOWN    Scroll schedule / file list
  KEY1       Cycle view (Schedule / Capture / Image / Files)
  KEY2       Save / decode current recording
  KEY3       Exit
"""

import os
import sys
import time
import math
import json
import subprocess
import threading
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr, is_v4, recommended_gain

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/noaa"
DEBOUNCE = 0.18
_last_btn = 0.0

VIEWS = ["schedule", "capture", "image", "files"]

SATELLITES = {
    "NOAA-15": {"freq": 137620000, "norad": 25338},
    "NOAA-18": {"freq": 137912500, "norad": 28654},
    "NOAA-19": {"freq": 137100000, "norad": 33591},
}

TLE_URL = "https://celestrak.org/NORAD/elements/gp.php?GROUP=weather&FORMAT=tle"
TLE_FILE = os.path.join(LOOT_DIR, "weather.tle")

_shutdown = threading.Event()
_lock = threading.Lock()
_state = {
    "capturing": False,
    "sat_name": "",
    "elapsed": 0,
    "signal_db": -99,
    "decoded_img": None,
    "schedule": [],
    "files": [],
    "proc": None,
    "raw_path": "",
    "wav_path": "",
}


def _ensure_dirs():
    for d in [LOOT_DIR, os.path.join(LOOT_DIR, "raw"),
              os.path.join(LOOT_DIR, "wav"), os.path.join(LOOT_DIR, "img")]:
        os.makedirs(d, exist_ok=True)


def _fetch_tle():
    try:
        subprocess.run(
            ["curl", "-sS", "-o", TLE_FILE, "--max-time", "15", TLE_URL],
            timeout=20, capture_output=True,
        )
    except Exception:
        pass


def _parse_tle():
    tles = {}
    if not os.path.isfile(TLE_FILE):
        return tles
    try:
        with open(TLE_FILE) as f:
            lines = [l.rstrip() for l in f if l.strip()]
        i = 0
        while i + 2 < len(lines):
            name = lines[i].strip()
            l1 = lines[i + 1]
            l2 = lines[i + 2]
            if l1.startswith("1 ") and l2.startswith("2 "):
                tles[name] = (l1, l2)
                i += 3
            else:
                i += 1
    except Exception:
        pass
    return tles


def _predict_passes():
    """Simple pass prediction using ephem if available, else placeholder."""
    passes = []
    try:
        import ephem
        tles = _parse_tle()
        obs = ephem.Observer()
        obs.lat, obs.lon, obs.elevation = "0", "0", 0
        try:
            with open("/dev/shm/rj_gps.json") as f:
                gps = json.load(f)
                obs.lat = str(gps.get("lat", 0))
                obs.lon = str(gps.get("lon", 0))
                obs.elevation = gps.get("alt", 0)
        except Exception:
            pass
        for sat_name, info in SATELLITES.items():
            tle_name = sat_name
            if tle_name not in tles:
                for k in tles:
                    if sat_name.replace("-", " ") in k or sat_name in k:
                        tle_name = k
                        break
                else:
                    continue
            l1, l2 = tles[tle_name]
            sat = ephem.readtle(tle_name, l1, l2)
            obs.date = ephem.now()
            for _ in range(5):
                try:
                    rise, _, peak, max_el, sett, _ = obs.next_pass(sat)
                    passes.append({
                        "sat": sat_name,
                        "freq": info["freq"],
                        "rise": ephem.Date(rise).datetime().strftime("%H:%M"),
                        "peak": ephem.Date(peak).datetime().strftime("%H:%M"),
                        "set": ephem.Date(sett).datetime().strftime("%H:%M"),
                        "max_el": f"{math.degrees(max_el):.0f}°",
                        "rise_dt": ephem.Date(rise).datetime(),
                    })
                    obs.date = sett + ephem.minute
                except Exception:
                    break
        passes.sort(key=lambda p: p.get("rise_dt", datetime.now()))
    except ImportError:
        now = datetime.now()
        for i, (sat_name, info) in enumerate(SATELLITES.items()):
            t = now + timedelta(hours=i * 2 + 1, minutes=23)
            passes.append({
                "sat": sat_name,
                "freq": info["freq"],
                "rise": t.strftime("%H:%M"),
                "peak": (t + timedelta(minutes=7)).strftime("%H:%M"),
                "set": (t + timedelta(minutes=14)).strftime("%H:%M"),
                "max_el": "?°",
            })
    return passes[:12]


def _scan_files():
    imgs = []
    img_dir = os.path.join(LOOT_DIR, "img")
    if os.path.isdir(img_dir):
        for f in sorted(os.listdir(img_dir), reverse=True):
            if f.endswith((".png", ".jpg")):
                imgs.append(f)
    return imgs[:30]


def _start_capture(sat_name, freq, gain):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw = os.path.join(LOOT_DIR, "raw", f"{sat_name}_{ts}.raw")
    wav = os.path.join(LOOT_DIR, "wav", f"{sat_name}_{ts}.wav")
    cmd = [
        "rtl_fm", "-f", str(freq), "-s", "48000", "-g", str(gain),
        "-E", "deemp", "-F", "9", "-A", "fast", raw,
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return None, "", ""
    return proc, raw, wav


def _stop_and_decode(proc, raw_path, wav_path):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if not os.path.isfile(raw_path) or os.path.getsize(raw_path) < 1000:
        return None
    try:
        subprocess.run(
            ["sox", "-t", "raw", "-r", "48000", "-es", "-b", "16", "-c", "1",
             raw_path, wav_path],
            timeout=30, capture_output=True,
        )
    except Exception:
        return None
    img_path = wav_path.replace("/wav/", "/img/").replace(".wav", ".png")
    for decoder in ["noaa-apt", "wxtoimg"]:
        try:
            if decoder == "noaa-apt":
                subprocess.run(
                    ["noaa-apt", wav_path, "-o", img_path],
                    timeout=120, capture_output=True,
                )
            else:
                subprocess.run(
                    ["wxtoimg", "-e", "MSA", wav_path, img_path],
                    timeout=120, capture_output=True,
                )
            if os.path.isfile(img_path):
                return img_path
        except FileNotFoundError:
            continue
    return None


def _draw(image, draw, font, view_idx, scroll):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill="#0a0a12")
    hdr_y = S(1)
    draw.rectangle([(0, 0), (WIDTH, S(12))], fill="#0d1117")
    draw.text((S(2), hdr_y), f"NOAA SAT  [{VIEWS[view_idx].upper()}]",
              fill="#00E5FF", font=font)
    y = S(14)
    row_h = S(12)

    if VIEWS[view_idx] == "schedule":
        schedule = _state["schedule"]
        if not schedule:
            draw.text((S(4), y), "No passes predicted", fill="#888", font=font)
            draw.text((S(4), y + row_h), "Fetch TLE: KEY2", fill="#555", font=font)
        else:
            for i, p in enumerate(schedule[scroll:scroll + 8]):
                c = "#00E676" if i == 0 else "#ccc"
                txt = f"{p['sat'][-2:]} {p['rise']}-{p['set']} {p['max_el']}"
                draw.text((S(2), y + row_h * i), txt, fill=c, font=font)

    elif VIEWS[view_idx] == "capture":
        if _state["capturing"]:
            draw.text((S(4), y), f"REC  {_state['sat_name']}", fill="#FF5252", font=font)
            draw.text((S(4), y + row_h), f"Elapsed: {_state['elapsed']}s", fill="#ccc", font=font)
            bar_w = int((min(_state["elapsed"], 900) / 900) * (WIDTH - S(8)))
            draw.rectangle([(S(4), y + row_h * 2), (S(4) + bar_w, y + row_h * 2 + S(6))],
                           fill="#7C4DFF")
            draw.text((S(4), y + row_h * 3), "OK to stop & decode", fill="#888", font=font)
        else:
            draw.text((S(4), y), "Ready to capture", fill="#ccc", font=font)
            draw.text((S(4), y + row_h), "Select sat in Schedule", fill="#888", font=font)
            draw.text((S(4), y + row_h * 2), "or press OK to record", fill="#888", font=font)
            draw.text((S(4), y + row_h * 3), f"default: NOAA-19 137.1M", fill="#555", font=font)

    elif VIEWS[view_idx] == "image":
        if _state["decoded_img"] and os.path.isfile(_state["decoded_img"]):
            try:
                img = Image.open(_state["decoded_img"]).convert("RGB")
                img = img.resize((WIDTH, HEIGHT - S(14)), Image.LANCZOS)
                image.paste(img, (0, S(14)))
                return
            except Exception:
                pass
        draw.text((S(4), y), "No decoded image", fill="#888", font=font)
        draw.text((S(4), y + row_h), "Capture a pass first", fill="#555", font=font)

    elif VIEWS[view_idx] == "files":
        files = _state["files"]
        if not files:
            draw.text((S(4), y), "No saved images", fill="#888", font=font)
        else:
            for i, f in enumerate(files[scroll:scroll + 8]):
                c = "#00E5FF" if i == 0 else "#ccc"
                draw.text((S(2), y + row_h * i), f[:22], fill=c, font=font)


def main():
    global _last_btn
    _ensure_dirs()

    sdr = detect_sdr()
    if not sdr:
        print("No RTL-SDR detected")

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    image = Image.new("RGB", (WIDTH, HEIGHT), "#0a0a12")
    draw = ScaledDraw(image)
    font = scaled_font()

    view_idx = 0
    scroll = 0
    selected_sat = 0

    _fetch_tle()
    _state["schedule"] = _predict_passes()
    _state["files"] = _scan_files()
    gain = recommended_gain(sdr) if sdr else 40

    capture_thread = None
    capture_start = 0

    try:
        while not _shutdown.is_set():
            _draw(image, draw, font, view_idx, scroll)
            lcd.LCD_ShowImage(image, 0, 0)

            btn = get_button(PINS, timeout=0.25)
            now = time.monotonic()
            if btn and now - _last_btn < DEBOUNCE:
                btn = None
            if btn:
                _last_btn = now

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "OK":
                if _state["capturing"]:
                    proc = _state["proc"]
                    raw = _state["raw_path"]
                    wav = _state["wav_path"]
                    _state["capturing"] = False
                    img_path = _stop_and_decode(proc, raw, wav)
                    if img_path:
                        _state["decoded_img"] = img_path
                        view_idx = 2
                    _state["files"] = _scan_files()
                else:
                    sched = _state["schedule"]
                    if sched and view_idx == 0:
                        sat_name = sched[min(scroll, len(sched) - 1)]["sat"]
                        freq = SATELLITES[sat_name]["freq"]
                    else:
                        sat_name = "NOAA-19"
                        freq = 137100000
                    proc, raw, wav = _start_capture(sat_name, freq, gain)
                    if proc:
                        _state["capturing"] = True
                        _state["sat_name"] = sat_name
                        _state["proc"] = proc
                        _state["raw_path"] = raw
                        _state["wav_path"] = wav
                        _state["elapsed"] = 0
                        capture_start = time.monotonic()
                        view_idx = 1
            elif btn == "KEY2":
                if view_idx == 0:
                    _fetch_tle()
                    _state["schedule"] = _predict_passes()

            if _state["capturing"]:
                _state["elapsed"] = int(time.monotonic() - capture_start)

    finally:
        _shutdown.set()
        if _state.get("proc") and _state["proc"].poll() is None:
            _state["proc"].terminate()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
