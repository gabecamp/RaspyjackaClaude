#!/usr/bin/env python3
"""
RaspyJack Payload -- P25 Digital Trunked Radio
================================================
Decode P25 Phase 1 digital radio using RTL-SDR + DSD-FME/OP25.
Scan public safety frequencies, decode talkgroups, play audio.

Controls:
  OK         Start/Stop scanning/listening
  UP/DOWN    Scroll frequency/talkgroup list
  KEY1       Cycle view (Scanner / Listen / Talkgroups / Config)
  KEY2       Add frequency / save talkgroup
  KEY3       Exit
"""

import os
import sys
import time
import json
import subprocess
import threading
import struct
from datetime import datetime
from collections import OrderedDict

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
LOOT_DIR = "/root/Raspyjack/loot/SDR/p25"
DEBOUNCE = 0.18
_last_btn = 0.0

VIEWS = ["scanner", "listen", "talkgroups", "config"]

DEFAULT_FREQS = [
    {"freq": 851250000, "label": "Public Safety 1"},
    {"freq": 852250000, "label": "Public Safety 2"},
    {"freq": 853250000, "label": "Fire/EMS"},
    {"freq": 854250000, "label": "Law Enforcement"},
    {"freq": 855250000, "label": "Interop"},
    {"freq": 856250000, "label": "Federal"},
    {"freq": 857250000, "label": "State"},
    {"freq": 858250000, "label": "County"},
    {"freq": 460050000, "label": "UHF PS 1"},
    {"freq": 460100000, "label": "UHF PS 2"},
    {"freq": 155370000, "label": "VHF PS 1"},
    {"freq": 155475000, "label": "VHF PS 2"},
]

_shutdown = threading.Event()
_lock = threading.Lock()
_state = {
    "scanning": False,
    "listening": False,
    "freq_idx": 0,
    "freqs": list(DEFAULT_FREQS),
    "activity": {},
    "active_tg": 0,
    "tg_name": "",
    "encrypted": False,
    "audio_active": False,
    "talkgroups": OrderedDict(),
    "proc": None,
    "audio_proc": None,
    "log": [],
}

CONFIG_FILE = os.path.join(LOOT_DIR, "p25_config.json")
TG_FILE = os.path.join(LOOT_DIR, "talkgroups.json")


def _ensure_dirs():
    os.makedirs(LOOT_DIR, exist_ok=True)
    os.makedirs(os.path.join(LOOT_DIR, "audio"), exist_ok=True)


def _load_config():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                _state["freqs"] = cfg.get("freqs", _state["freqs"])
        except Exception:
            pass
    if os.path.isfile(TG_FILE):
        try:
            with open(TG_FILE) as f:
                _state["talkgroups"] = OrderedDict(json.load(f))
        except Exception:
            pass


def _save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump({"freqs": _state["freqs"]}, f, indent=2)
    except Exception:
        pass


def _save_talkgroups():
    try:
        with open(TG_FILE, "w") as f:
            json.dump(dict(_state["talkgroups"]), f, indent=2)
    except Exception:
        pass


def _freq_str(freq):
    if freq >= 1_000_000:
        return f"{freq / 1_000_000:.3f}M"
    return f"{freq / 1000:.1f}k"


def _scan_frequency(freq, gain, duration=0.5):
    """Quick power check on a frequency using rtl_power or rtl_fm."""
    try:
        proc = subprocess.run(
            ["rtl_fm", "-f", str(freq), "-s", "12500", "-g", str(gain),
             "-n", str(int(12500 * duration))],
            capture_output=True, timeout=duration + 3,
        )
        data = proc.stdout
        if len(data) < 100:
            return -99
        samples = struct.unpack(f"<{len(data) // 2}h", data)
        rms = (sum(s * s for s in samples) / len(samples)) ** 0.5
        if rms < 1:
            return -99
        import math
        return 20 * math.log10(rms / 32768) + 90
    except Exception:
        return -99


def _start_listen(freq, gain):
    """Start DSD-FME or rtl_fm + dsd pipeline for P25 decode."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    audio_path = os.path.join(LOOT_DIR, "audio", f"p25_{ts}.wav")

    for decoder in ["dsd-fme", "dsd"]:
        try:
            subprocess.run([decoder, "--help"], capture_output=True, timeout=3)
            rtl = subprocess.Popen(
                ["rtl_fm", "-f", str(freq), "-s", "48000", "-g", str(gain),
                 "-p", "0", "-E", "dc"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            dsd = subprocess.Popen(
                [decoder, "-i", "-", "-o", audio_path, "-fd", "-fr"],
                stdin=rtl.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            return rtl, dsd, audio_path
        except FileNotFoundError:
            continue

    rtl = subprocess.Popen(
        ["rtl_fm", "-f", str(freq), "-M", "fm", "-s", "48000", "-g", str(gain)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    play = subprocess.Popen(
        ["aplay", "-r", "48000", "-f", "S16_LE", "-t", "raw", "-c", "1"],
        stdin=rtl.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return rtl, play, audio_path


def _stop_procs():
    for key in ("proc", "audio_proc"):
        p = _state.get(key)
        if p and hasattr(p, "poll") and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        _state[key] = None


def _parse_dsd_output(proc):
    """Read DSD stderr for talkgroup and encryption info."""
    if not proc or not proc.stderr:
        return
    try:
        while not _shutdown.is_set():
            line = proc.stderr.readline()
            if not line:
                break
            line = line.decode(errors="replace").strip()
            if "tg=" in line.lower() or "talkgroup" in line.lower():
                for part in line.split():
                    if part.startswith("tg=") or part.startswith("TG="):
                        try:
                            tg = int(part.split("=")[1])
                            with _lock:
                                _state["active_tg"] = tg
                                tg_s = str(tg)
                                if tg_s in _state["talkgroups"]:
                                    _state["tg_name"] = _state["talkgroups"][tg_s]
                                else:
                                    _state["tg_name"] = f"TG {tg}"
                                    _state["talkgroups"][tg_s] = f"TG {tg}"
                        except ValueError:
                            pass
            if "encrypt" in line.lower():
                with _lock:
                    _state["encrypted"] = "encrypted" in line.lower()
            with _lock:
                _state["audio_active"] = True
                _state["log"].append(line[:60])
                if len(_state["log"]) > 100:
                    _state["log"] = _state["log"][-50:]
    except Exception:
        pass


def _draw(image, draw, font, view_idx, scroll):
    draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill="#0a0a12")
    draw.rectangle([(0, 0), (WIDTH, S(12))], fill="#0d1117")
    draw.text((S(2), S(1)), f"P25 RADIO [{VIEWS[view_idx].upper()}]",
              fill="#00E5FF", font=font)
    y = S(14)
    row_h = S(12)

    if VIEWS[view_idx] == "scanner":
        freqs = _state["freqs"]
        for i, entry in enumerate(freqs[scroll:scroll + 8]):
            is_sel = (i + scroll) == _state["freq_idx"]
            freq_s = _freq_str(entry["freq"])
            act = _state["activity"].get(entry["freq"], -99)
            if act > -30:
                c_bar = "#FF5252"
            elif act > -60:
                c_bar = "#FFD740"
            else:
                c_bar = "#555"
            bar_w = max(0, int((act + 99) / 99 * S(30)))
            by = y + row_h * i + S(2)
            draw.rectangle([(WIDTH - S(32), by), (WIDTH - S(32) + bar_w, by + S(6))],
                           fill=c_bar)
            c = "#00E676" if is_sel else "#ccc"
            draw.text((S(2), y + row_h * i), f"{freq_s} {entry['label'][:10]}",
                      fill=c, font=font)

        if _state["scanning"]:
            draw.rectangle([(S(2), HEIGHT - S(10)), (S(20), HEIGHT - S(3))], fill="#FF5252")
            draw.text((S(22), HEIGHT - S(11)), "SCANNING", fill="#FF5252", font=font)

    elif VIEWS[view_idx] == "listen":
        if _state["listening"]:
            freq = _state["freqs"][_state["freq_idx"]]["freq"]
            draw.text((S(4), y), f"FREQ: {_freq_str(freq)}", fill="#00E5FF", font=font)
            draw.text((S(4), y + row_h), f"TG: {_state['active_tg']}", fill="#ccc", font=font)
            draw.text((S(4), y + row_h * 2), _state["tg_name"][:20], fill="#888", font=font)
            enc_c = "#FF5252" if _state["encrypted"] else "#00E676"
            enc_t = "ENCRYPTED" if _state["encrypted"] else "CLEAR"
            draw.text((S(4), y + row_h * 3), enc_t, fill=enc_c, font=font)
            if _state["audio_active"]:
                for bx in range(8):
                    bh = S(2 + (bx * 3 % 7))
                    draw.rectangle(
                        [(S(4) + bx * S(8), y + row_h * 5 - bh),
                         (S(4) + bx * S(8) + S(5), y + row_h * 5)],
                        fill="#7C4DFF",
                    )
        else:
            draw.text((S(4), y), "Not listening", fill="#888", font=font)
            draw.text((S(4), y + row_h), "Press OK to tune", fill="#555", font=font)

    elif VIEWS[view_idx] == "talkgroups":
        tgs = list(_state["talkgroups"].items())
        if not tgs:
            draw.text((S(4), y), "No talkgroups yet", fill="#888", font=font)
        else:
            for i, (tg_id, name) in enumerate(tgs[scroll:scroll + 8]):
                c = "#00E5FF" if str(tg_id) == str(_state["active_tg"]) else "#ccc"
                draw.text((S(2), y + row_h * i), f"{tg_id}: {name[:16]}", fill=c, font=font)

    elif VIEWS[view_idx] == "config":
        draw.text((S(4), y), "P25 Configuration", fill="#00E5FF", font=font)
        draw.text((S(4), y + row_h), f"Freqs: {len(_state['freqs'])}", fill="#ccc", font=font)
        draw.text((S(4), y + row_h * 2), f"TGs: {len(_state['talkgroups'])}", fill="#ccc", font=font)
        draw.text((S(4), y + row_h * 3), "KEY2: save config", fill="#888", font=font)
        draw.text((S(4), y + row_h * 4), "Decoders: DSD-FME", fill="#888", font=font)
        for dec in ["dsd-fme", "dsd", "op25"]:
            try:
                subprocess.run([dec, "--help"], capture_output=True, timeout=2)
                draw.text((S(4), y + row_h * 5), f"{dec}: installed", fill="#00E676", font=font)
                break
            except FileNotFoundError:
                continue
        else:
            draw.text((S(4), y + row_h * 5), "No P25 decoder found", fill="#FF5252", font=font)
            draw.text((S(4), y + row_h * 6), "Install dsd-fme", fill="#888", font=font)


def main():
    global _last_btn
    _ensure_dirs()
    _load_config()

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
    dsd_thread = None

    def _scan_loop():
        while not _shutdown.is_set() and _state["scanning"]:
            for entry in _state["freqs"]:
                if _shutdown.is_set() or not _state["scanning"]:
                    break
                db = _scan_frequency(entry["freq"], gain, 0.3)
                with _lock:
                    _state["activity"][entry["freq"]] = db
                time.sleep(0.1)
            time.sleep(0.5)

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
                if view_idx == 0:
                    _state["freq_idx"] = max(0, _state["freq_idx"] - 1)
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                if view_idx == 0:
                    _state["freq_idx"] = min(len(_state["freqs"]) - 1, _state["freq_idx"] + 1)
                scroll += 1
            elif btn == "OK":
                if view_idx == 0:
                    if _state["scanning"]:
                        _state["scanning"] = False
                    else:
                        _state["scanning"] = True
                        scan_thread = threading.Thread(target=_scan_loop, daemon=True)
                        scan_thread.start()
                elif view_idx == 1:
                    if _state["listening"]:
                        _state["listening"] = False
                        _stop_procs()
                    else:
                        freq = _state["freqs"][_state["freq_idx"]]["freq"]
                        try:
                            rtl, dec, audio_path = _start_listen(freq, gain)
                            _state["proc"] = rtl
                            _state["audio_proc"] = dec
                            _state["listening"] = True
                            _state["audio_active"] = False
                            dsd_thread = threading.Thread(
                                target=_parse_dsd_output, args=(dec,), daemon=True)
                            dsd_thread.start()
                        except Exception:
                            pass
            elif btn == "KEY2":
                if view_idx == 3:
                    _save_config()
                    _save_talkgroups()

    finally:
        _shutdown.set()
        _state["scanning"] = False
        _state["listening"] = False
        _stop_procs()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
