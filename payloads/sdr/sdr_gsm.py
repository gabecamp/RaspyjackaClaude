#!/usr/bin/env python3
"""
RaspyJack Payload -- GSM Cell Tower Scanner
=============================================
Passive GSM cell tower scanner and IMSI catcher detector.
Scans GSM900/DCS1800/PCS1900 bands using kalibrate-rtl (kal),
lists discovered towers with ARFCN/frequency/power, and flags
suspicious towers that may be rogue base stations.

Controls:
  OK         Start / stop scan
  UP / DOWN  Scroll list
  KEY1       Cycle view (SCAN / TOWERS / DETAIL / ALERTS)
  KEY2       Export to loot
  KEY3       Exit
"""

import os
import sys
import re
import time
import json
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font, S
from payloads._input_helper import get_button
from payloads.sdr._sdr_core import detect_sdr, recommended_gain

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
LOOT_DIR = "/root/Raspyjack/loot/SDR/gsm"
DEBOUNCE = 0.18
VIEWS = ["SCAN", "TOWERS", "DETAIL", "ALERTS"]
ROW_H = S(12)

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
C_WHITE = "#FFFFFF"

GSM_BANDS = {
    "GSM900":  {"label": "GSM 900",  "flag": "GSM900"},
    "DCS1800": {"label": "DCS 1800", "flag": "DCS1800"},
    "PCS1900": {"label": "PCS 1900", "flag": "PCS1900"},
}

towers = []
alerts = []
lock = threading.Lock()
_shutdown = threading.Event()
_scan_status = "Idle"
_scan_progress = 0
_scan_band = ""
_last_btn = 0


def _btn():
    global _last_btn
    b = get_button(PINS)
    if b and time.time() - _last_btn > DEBOUNCE:
        _last_btn = time.time()
        return b
    return None


def _parse_kal_output(text, band):
    """Parse kalibrate-rtl output for channel/power entries."""
    results = []
    for line in text.splitlines():
        m = re.match(
            r"\s*chan:\s*(\d+)\s*\((\d+\.\d+)MHz.*power:\s*([-\d.]+)",
            line,
        )
        if m:
            results.append({
                "arfcn": int(m.group(1)),
                "freq_mhz": float(m.group(2)),
                "power": float(m.group(3)),
                "band": band,
                "mcc": "",
                "mnc": "",
                "lac": "",
                "cell_id": "",
                "neighbors": 0,
                "first_seen": datetime.now().strftime("%H:%M:%S"),
                "flagged": False,
            })
    return results


def _parse_grgsm_output(text):
    """Parse grgsm_scanner output."""
    results = []
    for line in text.splitlines():
        m = re.match(
            r"\s*ARFCN:\s*(\d+),\s*Freq:\s*([\d.]+)M.*CID:\s*(\w+).*LAC:\s*(\w+).*MCC:\s*(\d+).*MNC:\s*(\d+).*Pwr:\s*([-\d.]+)",
            line,
        )
        if m:
            results.append({
                "arfcn": int(m.group(1)),
                "freq_mhz": float(m.group(2)),
                "power": float(m.group(7)),
                "band": "GSM",
                "mcc": m.group(5),
                "mnc": m.group(6),
                "lac": m.group(4),
                "cell_id": m.group(3),
                "neighbors": 0,
                "first_seen": datetime.now().strftime("%H:%M:%S"),
                "flagged": False,
            })
    return results


def _check_suspicious(tower_list):
    """Flag towers with IMSI catcher characteristics."""
    flagged = []
    if not tower_list:
        return flagged
    powers = [t["power"] for t in tower_list]
    avg_power = sum(powers) / len(powers) if powers else -80
    for t in tower_list:
        reasons = []
        if t["power"] > avg_power + 15:
            reasons.append("Abnormally high power")
        if t["neighbors"] == 0 and t["cell_id"]:
            reasons.append("No neighbor cells advertised")
        if t["lac"] and t["lac"] not in [
            x["lac"] for x in tower_list if x is not t and x["lac"]
        ]:
            reasons.append("Unique LAC (not seen on other towers)")
        if reasons:
            t["flagged"] = True
            flagged.append({"tower": t, "reasons": reasons})
    return flagged


def _scan_thread():
    global _scan_status, _scan_progress, _scan_band, towers, alerts
    _scan_status = "Scanning..."
    _scan_progress = 0
    all_results = []

    has_kal = subprocess.run(
        ["which", "kal"], capture_output=True
    ).returncode == 0
    has_grgsm = subprocess.run(
        ["which", "grgsm_scanner"], capture_output=True
    ).returncode == 0

    if has_grgsm:
        _scan_band = "grgsm"
        _scan_status = "grgsm_scanner..."
        try:
            r = subprocess.run(
                ["grgsm_scanner", "--speed", "4"],
                capture_output=True, text=True, timeout=120,
            )
            all_results.extend(_parse_grgsm_output(r.stdout + r.stderr))
        except Exception:
            pass
        _scan_progress = 100
    elif has_kal:
        band_list = list(GSM_BANDS.keys())
        for i, band_key in enumerate(band_list):
            if _shutdown.is_set():
                break
            band = GSM_BANDS[band_key]
            _scan_band = band["label"]
            _scan_status = f"Scanning {band['label']}..."
            _scan_progress = int((i / len(band_list)) * 100)
            try:
                gain = recommended_gain(900_000_000)
                r = subprocess.run(
                    ["kal", "-s", band["flag"], "-g", str(gain)],
                    capture_output=True, text=True, timeout=60,
                )
                all_results.extend(
                    _parse_kal_output(r.stdout + r.stderr, band_key)
                )
            except Exception:
                pass
        _scan_progress = 100
    else:
        _scan_status = "rtl_power fallback..."
        _scan_band = "925-960 MHz"
        try:
            r = subprocess.run(
                [
                    "rtl_power", "-f", "925M:960M:12.5k",
                    "-g", str(recommended_gain(940_000_000)),
                    "-i", "10", "-1",
                ],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines():
                parts = line.split(",")
                if len(parts) >= 7:
                    try:
                        freq = float(parts[2])
                        pwr = max(float(x) for x in parts[6:] if x.strip())
                        if pwr > -40:
                            all_results.append({
                                "arfcn": int((freq / 1e6 - 935) / 0.2),
                                "freq_mhz": freq / 1e6,
                                "power": pwr,
                                "band": "GSM900",
                                "mcc": "", "mnc": "", "lac": "", "cell_id": "",
                                "neighbors": 0,
                                "first_seen": datetime.now().strftime("%H:%M:%S"),
                                "flagged": False,
                            })
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        _scan_progress = 100

    all_results.sort(key=lambda t: t["power"], reverse=True)
    new_alerts = _check_suspicious(all_results)
    with lock:
        towers = all_results
        alerts = new_alerts
    _scan_status = f"Done — {len(all_results)} towers"


def _draw_header(d, font, title, extra=""):
    d.rectangle([(0, 0), (WIDTH, S(13))], fill=C_HEADER)
    d.text((S(2), S(1)), title, font=font, fill=C_CYAN)
    if extra:
        d.text((WIDTH - S(2) - len(extra) * S(5), S(1)), extra, font=font, fill=C_MUTED)


def _draw_scan(d, font):
    _draw_header(d, font, "GSM SCAN", _scan_band[:10])
    y = S(18)
    d.text((S(4), y), _scan_status[:22], font=font, fill=C_WHITE)
    y += ROW_H + S(4)
    bar_w = WIDTH - S(16)
    d.rectangle([(S(8), y), (S(8) + bar_w, y + S(8))], outline=C_MUTED)
    fill_w = int(bar_w * _scan_progress / 100)
    if fill_w > 0:
        d.rectangle([(S(8), y), (S(8) + fill_w, y + S(8))], fill=C_GREEN)
    d.text((S(8), y + S(12)), f"{_scan_progress}%", font=font, fill=C_MUTED)
    with lock:
        n = len(towers)
    d.text((S(4), y + S(24)), f"Towers found: {n}", font=font, fill=C_YELLOW)
    with lock:
        n_alert = len(alerts)
    if n_alert:
        d.text((S(4), y + S(36)), f"Alerts: {n_alert}", font=font, fill=C_RED)


def _draw_towers(d, font, scroll):
    with lock:
        tlist = list(towers)
    _draw_header(d, font, "TOWERS", f"{len(tlist)}")
    if not tlist:
        d.text((S(4), S(50)), "No towers yet", font=font, fill=C_MUTED)
        return
    y = S(15)
    visible = (HEIGHT - S(15)) // ROW_H
    for i in range(scroll, min(scroll + visible, len(tlist))):
        t = tlist[i]
        color = C_RED if t["flagged"] else C_WHITE
        arfcn = f"A{t['arfcn']:>4}"
        freq = f"{t['freq_mhz']:.1f}M"
        pwr = f"{t['power']:+.0f}"
        row = f"{arfcn} {freq:>8} {pwr:>4}"
        d.text((S(2), y), row, font=font, fill=color)
        y += ROW_H


def _draw_detail(d, font, scroll):
    with lock:
        tlist = list(towers)
    if not tlist or scroll >= len(tlist):
        _draw_header(d, font, "DETAIL")
        d.text((S(4), S(50)), "Select a tower", font=font, fill=C_MUTED)
        return
    t = tlist[scroll]
    _draw_header(d, font, f"ARFCN {t['arfcn']}", t["band"][:8])
    y = S(16)
    lines = [
        f"Freq:  {t['freq_mhz']:.3f} MHz",
        f"Power: {t['power']:+.1f} dB",
        f"Band:  {t['band']}",
        f"MCC:   {t['mcc'] or '?'}",
        f"MNC:   {t['mnc'] or '?'}",
        f"LAC:   {t['lac'] or '?'}",
        f"CID:   {t['cell_id'] or '?'}",
        f"Seen:  {t['first_seen']}",
    ]
    for line in lines:
        if y > HEIGHT - ROW_H:
            break
        color = C_RED if t["flagged"] else C_WHITE
        d.text((S(4), y), line[:24], font=font, fill=color)
        y += ROW_H


def _draw_alerts(d, font, scroll):
    with lock:
        alist = list(alerts)
    _draw_header(d, font, "ALERTS", f"{len(alist)}")
    if not alist:
        d.text((S(4), S(50)), "No suspicious towers", font=font, fill=C_GREEN)
        return
    y = S(15)
    for i in range(scroll, len(alist)):
        if y > HEIGHT - ROW_H:
            break
        a = alist[i]
        t = a["tower"]
        d.text((S(2), y), f"ARFCN {t['arfcn']} {t['freq_mhz']:.1f}M", font=font, fill=C_RED)
        y += ROW_H
        for reason in a["reasons"]:
            if y > HEIGHT - ROW_H:
                break
            d.text((S(6), y), f"! {reason[:20]}", font=font, fill=C_YELLOW)
            y += ROW_H


def _export(ts):
    os.makedirs(LOOT_DIR, exist_ok=True)
    with lock:
        data = {
            "timestamp": ts,
            "towers": list(towers),
            "alerts": [
                {"arfcn": a["tower"]["arfcn"], "reasons": a["reasons"]}
                for a in alerts
            ],
        }
    path = os.path.join(LOOT_DIR, f"gsm_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def main():
    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    d = ScaledDraw(img)
    d.text((S(4), S(50)), "Detecting SDR...", font=font, fill=C_YELLOW)
    lcd.LCD_ShowImage(img, 0, 0)

    found, desc, _backend = detect_sdr()
    if not found:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((S(4), S(50)), "No RTL-SDR!", font=font, fill=C_RED)
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    scanning = False
    scan_t = None
    view_idx = 0
    scroll = 0

    try:
        while True:
            btn = _btn()
            if btn == "KEY3":
                break
            if btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
            if btn == "OK":
                if not scanning:
                    scanning = True
                    _shutdown.clear()
                    scan_t = threading.Thread(target=_scan_thread, daemon=True)
                    scan_t.start()
                else:
                    _shutdown.set()
                    scanning = False
            if btn == "UP":
                scroll = max(0, scroll - 1)
            if btn == "DOWN":
                scroll += 1
            if btn == "KEY2":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = _export(ts)
                img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                d = ScaledDraw(img)
                d.text((S(4), S(50)), "Exported!", font=font, fill=C_GREEN)
                d.text((S(4), S(64)), os.path.basename(path)[:22], font=font, fill=C_MUTED)
                lcd.LCD_ShowImage(img, 0, 0)
                time.sleep(1.5)
                continue

            if scan_t and not scan_t.is_alive():
                scanning = False

            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            view = VIEWS[view_idx]
            if view == "SCAN":
                _draw_scan(d, font)
            elif view == "TOWERS":
                _draw_towers(d, font, scroll)
            elif view == "DETAIL":
                _draw_detail(d, font, scroll)
            elif view == "ALERTS":
                _draw_alerts(d, font, scroll)
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.15)
    finally:
        _shutdown.set()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
