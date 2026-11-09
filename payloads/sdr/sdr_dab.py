#!/usr/bin/env python3
"""
RaspyJack Payload -- DAB+ Digital Radio Receiver
==================================================
DAB+ digital broadcast receiver using RTL-SDR + welle-cli or dabtools.
Scan Band III (174-240 MHz) for multiplexes, list stations, play audio.

Controls:
  OK         Start scan / Select station / Play-Pause
  UP/DOWN    Scroll station list / change channel
  KEY1       Cycle view (Scan / Stations / Playing / Info)
  KEY2       Save station preset
  KEY3       Exit
"""

import os
import sys
import time
import json
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
from payloads.sdr._sdr_core import detect_sdr, is_v4, recommended_gain

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/dab"
DEBOUNCE = 0.18
_last_btn = 0.0

VIEWS = ["scan", "stations", "playing", "info"]

DAB_CHANNELS = {
    "5A": 174928, "5B": 176640, "5C": 178352, "5D": 180064,
    "6A": 181936, "6B": 183648, "6C": 185360, "6D": 187072,
    "7A": 188928, "7B": 190640, "7C": 192352, "7D": 194064,
    "8A": 195936, "8B": 197648, "8C": 199360, "8D": 201072,
    "9A": 202928, "9B": 204640, "9C": 206352, "9D": 208064,
    "10A": 209936, "10B": 211648, "10C": 213360, "10D": 215072,
    "10N": 210096, "11A": 216928, "11B": 218640, "11C": 220352,
    "11D": 222064, "11N": 217088, "12A": 223936, "12B": 225648,
    "12C": 227360, "12D": 229072, "12N": 224096, "13A": 230784,
    "13B": 232496, "13C": 234208, "13D": 235776, "13E": 237488,
    "13F": 239200,
}

_shutdown = threading.Event()
_lock = threading.Lock()
_state = {
    "scanning": False,
    "playing": False,
    "scan_progress": 0,
    "scan_total": len(DAB_CHANNELS),
    "scan_channel": "",
    "ensembles": [],
    "stations": [],
    "station_idx": 0,
    "now_playing": "",
    "ensemble_name": "",
    "channel": "",
    "bitrate": "",
    "codec": "",
    "proc": None,
    "presets": [],
}

PRESETS_FILE = os.path.join(LOOT_DIR, "presets.json")


def _ensure_dirs():
    os.makedirs(LOOT_DIR, exist_ok=True)


def _load_presets():
    if os.path.isfile(PRESETS_FILE):
        try:
            with open(PRESETS_FILE) as f:
                _state["presets"] = json.load(f)
        except Exception:
            pass


def _save_presets():
    try:
        with open(PRESETS_FILE, "w") as f:
            json.dump(_state["presets"], f, indent=2)
    except Exception:
        pass


def _find_decoder():
    for cmd in ["welle-cli", "dab-scanner", "dablin"]:
        try:
            subprocess.run([cmd, "--help"], capture_output=True, timeout=3)
            return cmd
        except FileNotFoundError:
            continue
    return None


def _scan_channel(ch_name, freq_khz, gain):
    """Scan a single DAB channel for ensemble/services."""
    freq = freq_khz * 1000
    stations = []
    ensemble = ""
    try:
        proc = subprocess.run(
            ["rtl_sdr", "-f", str(freq), "-s", "2048000", "-g", str(gain),
             "-n", str(2048000 * 2), "/dev/null"],
            capture_output=True, timeout=5,
        )
        stderr = proc.stderr.decode(errors="replace")
        if "Signal" in stderr or proc.returncode == 0:
            try:
                result = subprocess.run(
                    ["welle-cli", "-c", ch_name, "-D", "-C", "1"],
                    capture_output=True, timeout=10,
                )
                output = result.stdout.decode(errors="replace")
                for line in output.splitlines():
                    if "ensemble" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            ensemble = parts[1].strip()
                    if "service" in line.lower() and ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            svc = parts[1].strip()
                            if svc and svc not in [s["name"] for s in stations]:
                                stations.append({
                                    "name": svc,
                                    "channel": ch_name,
                                    "freq_khz": freq_khz,
                                    "ensemble": ensemble,
                                })
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    except (subprocess.TimeoutExpired, Exception):
        pass
    return ensemble, stations


def _scan_all(gain):
    with _lock:
        _state["scanning"] = True
        _state["ensembles"] = []
        _state["stations"] = []
        _state["scan_progress"] = 0
    channels = sorted(DAB_CHANNELS.items(), key=lambda x: x[1])
    for i, (ch_name, freq_khz) in enumerate(channels):
        if _shutdown.is_set() or not _state["scanning"]:
            break
        with _lock:
            _state["scan_progress"] = i + 1
            _state["scan_channel"] = ch_name
        ensemble, stations = _scan_channel(ch_name, freq_khz, gain)
        if stations:
            with _lock:
                if ensemble and ensemble not in _state["ensembles"]:
                    _state["ensembles"].append(ensemble)
                _state["stations"].extend(stations)
    with _lock:
        _state["scanning"] = False


def _start_playback(station, gain):
    _stop_playback()
    ch = station["channel"]
    name = station["name"]
    decoder = _find_decoder()
    if decoder == "welle-cli":
        proc = subprocess.Popen(
            ["welle-cli", "-c", ch, "-p", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    elif decoder == "dablin":
        proc = subprocess.Popen(
            ["dablin", "-c", ch, "-s", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    else:
        freq = station["freq_khz"] * 1000
        proc = subprocess.Popen(
            ["rtl_fm", "-f", str(freq), "-M", "raw", "-s", "2048000",
             "-g", str(gain)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    with _lock:
        _state["proc"] = proc
        _state["playing"] = True
        _state["now_playing"] = name
        _state["channel"] = ch
        _state["ensemble_name"] = station.get("ensemble", "")


def _stop_playback():
    p = _state.get("proc")
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
    with _lock:
        _state["proc"] = None
        _state["playing"] = False


def _draw(image, draw, font, view_idx, scroll):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill="#0a0a12")
    draw.rectangle([(0, 0), (WIDTH, S(12))], fill="#0d1117")
    draw.text((S(2), S(1)), f"DAB+ RADIO [{VIEWS[view_idx].upper()}]",
              fill="#00E5FF", font=font)
    y = S(14)
    row_h = S(12)

    if VIEWS[view_idx] == "scan":
        if _state["scanning"]:
            prog = _state["scan_progress"]
            total = _state["scan_total"]
            ch = _state["scan_channel"]
            draw.text((S(4), y), f"Scanning: {ch}", fill="#FFD740", font=font)
            draw.text((S(4), y + row_h), f"{prog}/{total} channels", fill="#ccc", font=font)
            bar_w = int((prog / max(total, 1)) * (WIDTH - S(8)))
            draw.rectangle([(S(4), y + row_h * 2), (S(4) + bar_w, y + row_h * 2 + S(6))],
                           fill="#7C4DFF")
            draw.text((S(4), y + row_h * 3),
                      f"Found: {len(_state['stations'])} stations", fill="#00E676", font=font)
            draw.text((S(4), y + row_h * 4),
                      f"Ensembles: {len(_state['ensembles'])}", fill="#888", font=font)
        else:
            draw.text((S(4), y), "DAB+ Band III Scanner", fill="#ccc", font=font)
            draw.text((S(4), y + row_h), f"{len(DAB_CHANNELS)} channels", fill="#888", font=font)
            draw.text((S(4), y + row_h * 2), f"{len(_state['stations'])} stations found",
                      fill="#888", font=font)
            draw.text((S(4), y + row_h * 3), "OK to start scan", fill="#555", font=font)
            decoder = _find_decoder()
            if decoder:
                draw.text((S(4), y + row_h * 5), f"Decoder: {decoder}", fill="#00E676", font=font)
            else:
                draw.text((S(4), y + row_h * 5), "No DAB decoder found", fill="#FF5252", font=font)
                draw.text((S(4), y + row_h * 6), "Install welle-cli", fill="#888", font=font)

    elif VIEWS[view_idx] == "stations":
        stations = _state["stations"]
        if not stations:
            draw.text((S(4), y), "No stations found", fill="#888", font=font)
            draw.text((S(4), y + row_h), "Run scan first", fill="#555", font=font)
        else:
            for i, stn in enumerate(stations[scroll:scroll + 8]):
                is_sel = (i + scroll) == _state["station_idx"]
                c = "#00E676" if is_sel else "#ccc"
                txt = f"{stn['channel']} {stn['name'][:14]}"
                draw.text((S(2), y + row_h * i), txt, fill=c, font=font)

    elif VIEWS[view_idx] == "playing":
        if _state["playing"]:
            draw.text((S(4), y), "NOW PLAYING", fill="#7C4DFF", font=font)
            draw.text((S(4), y + row_h * 1.5), _state["now_playing"][:20],
                      fill="#00E5FF", font=font)
            draw.text((S(4), y + row_h * 3), f"CH: {_state['channel']}",
                      fill="#ccc", font=font)
            draw.text((S(4), y + row_h * 4), _state["ensemble_name"][:20],
                      fill="#888", font=font)
            for bx in range(10):
                import random
                bh = S(random.randint(2, 10))
                draw.rectangle(
                    [(S(4) + bx * S(10), HEIGHT - S(4) - bh),
                     (S(4) + bx * S(10) + S(7), HEIGHT - S(4))],
                    fill="#7C4DFF",
                )
        else:
            draw.text((S(4), y), "Not playing", fill="#888", font=font)
            draw.text((S(4), y + row_h), "Select station first", fill="#555", font=font)

    elif VIEWS[view_idx] == "info":
        draw.text((S(4), y), "DAB+ Info", fill="#00E5FF", font=font)
        draw.text((S(4), y + row_h), f"Ensembles: {len(_state['ensembles'])}",
                  fill="#ccc", font=font)
        draw.text((S(4), y + row_h * 2), f"Stations: {len(_state['stations'])}",
                  fill="#ccc", font=font)
        draw.text((S(4), y + row_h * 3), f"Presets: {len(_state['presets'])}",
                  fill="#ccc", font=font)
        for i, ens in enumerate(_state["ensembles"][:4]):
            draw.text((S(4), y + row_h * (4 + i)), ens[:22], fill="#888", font=font)


def main():
    global _last_btn
    _ensure_dirs()
    _load_presets()

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
    gain = recommended_gain(sdr) if sdr else 40
    scan_thread = None

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
                if view_idx == 1:
                    _state["station_idx"] = max(0, _state["station_idx"] - 1)
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                if view_idx == 1:
                    _state["station_idx"] = min(
                        len(_state["stations"]) - 1, _state["station_idx"] + 1)
                scroll += 1
            elif btn == "OK":
                if view_idx == 0:
                    if _state["scanning"]:
                        _state["scanning"] = False
                    else:
                        scan_thread = threading.Thread(
                            target=_scan_all, args=(gain,), daemon=True)
                        scan_thread.start()
                elif view_idx == 1:
                    if _state["stations"]:
                        stn = _state["stations"][_state["station_idx"]]
                        _start_playback(stn, gain)
                        view_idx = 2
                elif view_idx == 2:
                    if _state["playing"]:
                        _stop_playback()
                    elif _state["stations"]:
                        stn = _state["stations"][_state["station_idx"]]
                        _start_playback(stn, gain)
            elif btn == "KEY2":
                if _state["stations"] and view_idx == 1:
                    stn = _state["stations"][_state["station_idx"]]
                    if stn not in _state["presets"]:
                        _state["presets"].append(stn)
                        _save_presets()

    finally:
        _shutdown.set()
        _state["scanning"] = False
        _stop_playback()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
