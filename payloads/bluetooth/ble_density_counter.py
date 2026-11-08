#!/usr/bin/env python3
"""
RaspyJack Payload -- BLE Density Counter
=========================================
Author: RaspyJack Contributors

Continuously scans BLE advertisements and counts unique devices per
time window, classifying them by manufacturer.  Useful for crowd
density estimation and SIGINT recon.

Views
-----
  COUNTER    -- Big device count + mini bar chart of recent windows
  BREAKDOWN  -- Device type counts with colored bars
  HISTORY    -- Scrollable time series of counts
  GPS        -- Maidenhead grid square (if GPS available)

Controls
--------
  OK         -- Start / stop scanning
  UP / DOWN  -- Scroll in list views
  KEY1       -- Cycle view
  KEY2       -- Export CSV to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/BLEDensity/
"""

import os
import sys
import csv
import time
import asyncio
import threading
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
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
ROW_H = 12

LOOT_DIR = "/root/Raspyjack/loot/BLEDensity"
WINDOW_SEC = 30
MAX_HISTORY = 120

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_ORANGE = "#FF9100"
C_BLUE = "#448AFF"
C_PINK = "#FF4081"
C_MUTED = "#888888"
C_DIM = "#444444"
C_HEADER = "#0d1117"

VIEWS = ["COUNTER", "BREAKDOWN", "HISTORY", "GPS"]

MANUFACTURERS = {
    0x004C: ("Apple", C_CYAN),
    0x0075: ("Samsung", C_BLUE),
    0x0006: ("Microsoft", C_GREEN),
    0x000A: ("Fitbit", C_PINK),
}
TILE_UUIDS = {"0000feed-0000-1000-8000-00805f9b34fb", "0000fe4d-0000-1000-8000-00805f9b34fb"}
GOOGLE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

# ---------------------------------------------------------------------------
# GPS (optional)
# ---------------------------------------------------------------------------
_gps_lat = 0.0
_gps_lon = 0.0
_gps_valid = False

def _start_gps():
    global _gps_lat, _gps_lon, _gps_valid
    try:
        from payloads._gps_helper import start_gps
        reader = start_gps()
        if reader is None:
            return
        def _poll():
            global _gps_lat, _gps_lon, _gps_valid
            while not _stop.is_set():
                try:
                    pos = reader.position()
                    if pos and pos[0] != 0.0:
                        _gps_lat, _gps_lon = pos[0], pos[1]
                        _gps_valid = True
                except Exception:
                    pass
                time.sleep(2)
        t = threading.Thread(target=_poll, daemon=True)
        t.start()
    except Exception:
        pass

def _maidenhead(lat, lon):
    lon += 180.0
    lat += 90.0
    a = ord('A')
    g = chr(a + int(lon / 20))
    g += chr(a + int(lat / 10))
    g += str(int((lon % 20) / 2))
    g += str(int(lat % 10))
    g += chr(a + int((lon % 2) * 12))
    g += chr(a + int((lat % 1) * 24))
    return g

# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
_stop = threading.Event()
_lock = threading.Lock()
_scanning = False
_current_window = {}  # addr_hash -> category
_history = deque(maxlen=MAX_HISTORY)
_window_start = 0.0

CATEGORIES = ["apple", "samsung", "google", "microsoft", "fitbit", "tile", "other"]
CAT_COLORS = {
    "apple": C_CYAN, "samsung": C_BLUE, "google": C_YELLOW,
    "microsoft": C_GREEN, "fitbit": C_PINK, "tile": C_ORANGE, "other": C_MUTED,
}

def _classify(device, adv_data):
    mfr = getattr(adv_data, "manufacturer_data", {})
    svc = set(getattr(adv_data, "service_uuids", []) or [])
    svc_lower = {s.lower() for s in svc}
    if GOOGLE_UUID in svc_lower:
        return "google"
    if svc_lower & TILE_UUIDS:
        return "tile"
    for cid, (name, _) in MANUFACTURERS.items():
        if cid in mfr:
            return name.lower()
    return "other"

def _addr_hash(addr):
    return addr.upper()

def _flush_window():
    global _current_window, _window_start
    with _lock:
        counts = {c: 0 for c in CATEGORIES}
        for cat in _current_window.values():
            counts[cat] = counts.get(cat, 0) + 1
        total = sum(counts.values())
        entry = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total": total,
            "lat": _gps_lat if _gps_valid else 0.0,
            "lon": _gps_lon if _gps_valid else 0.0,
        }
        entry.update(counts)
        _history.append(entry)
        _current_window = {}
        _window_start = time.time()

async def _scan_loop(adapter):
    from bleak import BleakScanner
    global _window_start
    _window_start = time.time()
    kwargs = {}
    if adapter and adapter != "hci0":
        kwargs["adapter"] = adapter
    def _cb(device, adv_data):
        cat = _classify(device, adv_data)
        h = _addr_hash(device.address)
        with _lock:
            _current_window[h] = cat
    scanner = BleakScanner(detection_callback=_cb, **kwargs)
    await scanner.start()
    try:
        while not _stop.is_set():
            await asyncio.sleep(1)
            if time.time() - _window_start >= WINDOW_SEC:
                _flush_window()
    finally:
        await scanner.stop()

def _scan_thread(adapter):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_scan_loop(adapter))
    except Exception:
        pass
    finally:
        loop.close()

# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _draw_header(draw, title):
    draw.rectangle([(0, 0), (WIDTH, ROW_H)], fill=C_HEADER)
    draw.text((2, 0), title, fill=C_CYAN, font=font)
    if _scanning:
        draw.text((WIDTH - 18, 0), "LIVE", fill=C_GREEN, font=font)

def _current_total():
    with _lock:
        return len(_current_window)

def _current_counts():
    with _lock:
        counts = {c: 0 for c in CATEGORIES}
        for cat in _current_window.values():
            counts[cat] = counts.get(cat, 0) + 1
        return counts

def _draw_counter(draw):
    _draw_header(draw, "BLE Density")
    total = _current_total()
    big_font = scaled_font(24)
    txt = str(total)
    bbox = draw.textbbox((0, 0), txt, font=big_font)
    tw = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw) // 2, 20), txt, fill=C_CYAN, font=big_font)
    draw.text(((WIDTH - 50) // 2, 48), "devices now", fill=C_MUTED, font=font)
    # mini bar chart of last 10 windows
    hist = list(_history)[-10:]
    if hist:
        bar_w = max(1, (WIDTH - 10) // 10)
        max_v = max(e["total"] for e in hist) or 1
        y_base = HEIGHT - 4
        chart_h = HEIGHT - 68
        for i, e in enumerate(hist):
            x = 5 + i * bar_w
            h = max(1, int(e["total"] / max_v * chart_h))
            draw.rectangle([(x, y_base - h), (x + bar_w - 2, y_base)], fill=C_BLUE)
    else:
        draw.text((10, 70), "Waiting for data...", fill=C_DIM, font=font)
    elapsed = int(time.time() - _window_start) if _scanning else 0
    draw.text((2, HEIGHT - ROW_H), f"Window: {elapsed}/{WINDOW_SEC}s", fill=C_DIM, font=font)

def _draw_breakdown(draw):
    _draw_header(draw, "Breakdown")
    counts = _current_counts()
    total = sum(counts.values()) or 1
    y = ROW_H + 4
    max_bar = WIDTH - 60
    for cat in CATEGORIES:
        n = counts.get(cat, 0)
        color = CAT_COLORS.get(cat, C_MUTED)
        draw.text((2, y), f"{cat[:7]:7s}", fill=color, font=font)
        bar_len = max(0, int(n / total * max_bar))
        if bar_len > 0:
            draw.rectangle([(52, y + 1), (52 + bar_len, y + ROW_H - 3)], fill=color)
        draw.text((WIDTH - 20, y), str(n), fill=C_MUTED, font=font)
        y += ROW_H
        if y > HEIGHT - ROW_H:
            break
    draw.text((2, HEIGHT - ROW_H), f"Total: {sum(counts.values())}", fill=C_CYAN, font=font)

def _draw_history(draw, scroll):
    _draw_header(draw, "History")
    hist = list(_history)
    if not hist:
        draw.text((10, 40), "No data yet", fill=C_DIM, font=font)
        return
    max_rows = (HEIGHT - ROW_H * 2) // ROW_H
    start = max(0, len(hist) - max_rows - scroll)
    end = min(len(hist), start + max_rows)
    y = ROW_H + 2
    for i in range(start, end):
        e = hist[i]
        ts_short = e["ts"][11:16]
        draw.text((2, y), ts_short, fill=C_MUTED, font=font)
        draw.text((36, y), str(e["total"]), fill=C_CYAN, font=font)
        bar_w = min(e["total"], WIDTH - 60)
        if bar_w > 0:
            draw.rectangle([(56, y + 1), (56 + bar_w, y + ROW_H - 3)], fill=C_BLUE)
        y += ROW_H
    draw.text((2, HEIGHT - ROW_H), f"{len(hist)} windows", fill=C_DIM, font=font)

def _draw_gps(draw):
    _draw_header(draw, "GPS Info")
    if not _gps_valid:
        draw.text((10, 30), "No GPS fix", fill=C_RED, font=font)
        draw.text((10, 50), "Connect GPS for", fill=C_DIM, font=font)
        draw.text((10, 62), "location tagging", fill=C_DIM, font=font)
        return
    grid = _maidenhead(_gps_lat, _gps_lon)
    big_font = scaled_font(18)
    bbox = draw.textbbox((0, 0), grid, font=big_font)
    tw = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw) // 2, 20), grid, fill=C_GREEN, font=big_font)
    draw.text((4, 50), f"Lat: {_gps_lat:.6f}", fill=C_CYAN, font=font)
    draw.text((4, 64), f"Lon: {_gps_lon:.6f}", fill=C_CYAN, font=font)
    n_gps = sum(1 for e in _history if e.get("lat", 0) != 0)
    draw.text((4, 84), f"GPS-tagged: {n_gps}/{len(_history)}", fill=C_MUTED, font=font)

# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_csv():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"density_{ts}.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "total_count"] + CATEGORIES + ["lat", "lon"])
        for e in _history:
            row = [e["ts"], e["total"]]
            row += [e.get(c, 0) for c in CATEGORIES]
            row += [e.get("lat", 0.0), e.get("lon", 0.0)]
            w.writerow(row)
    return path

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _scanning
    adapter = select_bt_interface()
    _start_gps()
    image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(image)

    view_idx = 0
    scroll = 0
    scan_thread = None
    status_msg = ""
    status_until = 0.0

    try:
        while True:
            image.paste(C_BG, (0, 0, WIDTH, HEIGHT))
            view = VIEWS[view_idx]
            if view == "COUNTER":
                _draw_counter(draw)
            elif view == "BREAKDOWN":
                _draw_breakdown(draw)
            elif view == "HISTORY":
                _draw_history(draw, scroll)
            elif view == "GPS":
                _draw_gps(draw)

            if time.time() < status_until:
                draw.rectangle([(0, HEIGHT - ROW_H), (WIDTH, HEIGHT)], fill="#222")
                draw.text((2, HEIGHT - ROW_H), status_msg, fill=C_GREEN, font=font)

            LCD.LCD_ShowImage(image, 0, 0)

            btn = get_button(PINS, timeout=0.3)
            if btn is None:
                continue

            if btn == "OK":
                if not _scanning:
                    _stop.clear()
                    scan_thread = threading.Thread(target=_scan_thread, args=(adapter,), daemon=True)
                    scan_thread.start()
                    _scanning = True
                    status_msg = "Scanning started"
                    status_until = time.time() + 2
                else:
                    _stop.set()
                    _scanning = False
                    _flush_window()
                    status_msg = "Scanning stopped"
                    status_until = time.time() + 2

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0

            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            elif btn == "LEFT":
                if view_idx > 0:
                    view_idx -= 1
                    scroll = 0

            elif btn == "KEY2":
                if _history:
                    path = _export_csv()
                    status_msg = f"Saved {os.path.basename(path)}"
                    status_until = time.time() + 3
                else:
                    status_msg = "No data to export"
                    status_until = time.time() + 2

            elif btn == "KEY3":
                break

    finally:
        _stop.set()
        if scan_thread and scan_thread.is_alive():
            scan_thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
