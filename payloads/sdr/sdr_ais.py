#!/usr/bin/env python3
"""
RaspyJack Payload -- AIS Ship Tracker
=======================================
Decode AIS marine transponders on 161.975 / 162.025 MHz using RTL-SDR.
Parses MMSI, vessel name, position, speed, heading, and ship type.
Shows vessels sorted by distance when GPS is available.

Controls:
  OK         Start / stop tracking
  UP / DOWN  Scroll vessel list
  KEY1       Cycle view (LIST / DETAIL / MAP / STATS)
  KEY2       Export to loot
  KEY3       Exit
"""

import os
import sys
import re
import time
import math
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
LOOT_DIR = "/root/Raspyjack/loot/SDR/ais"
DEBOUNCE = 0.18
VIEWS = ["LIST", "DETAIL", "MAP", "STATS"]
ROW_H = S(12)

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_BLUE = "#448AFF"
C_MUTED = "#888888"
C_HEADER = "#0d1117"
C_WHITE = "#FFFFFF"

AIS_FREQ_A = "161975000"
AIS_FREQ_B = "162025000"
AIS_SAMPLE_RATE = "48000"

SHIP_TYPES = {
    range(20, 30): "WIG",
    range(30, 36): "Fishing",
    range(36, 40): "Sailing",
    range(40, 50): "HSC",
    range(60, 70): "Passenger",
    range(70, 80): "Cargo",
    range(80, 90): "Tanker",
}

vessels = {}
lock = threading.Lock()
_shutdown = threading.Event()
_rx_count = 0
_last_btn = 0
_my_lat = None
_my_lon = None


def _btn():
    global _last_btn
    b = get_button(PINS)
    if b and time.time() - _last_btn > DEBOUNCE:
        _last_btn = time.time()
        return b
    return None


def _ship_type_str(code):
    for r, name in SHIP_TYPES.items():
        if code in r:
            return name
    return "Other"


def _haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _bearing(lat1, lon1, lat2, lon2):
    dlon = math.radians(lon2 - lon1)
    y = math.sin(dlon) * math.cos(math.radians(lat2))
    x = (math.cos(math.radians(lat1)) * math.sin(math.radians(lat2)) -
         math.sin(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.cos(dlon))
    return (math.degrees(math.atan2(y, x)) + 360) % 360


def _decode_ais_payload(bits):
    """Minimal AIS message type 1/2/3 decoder from 6-bit ASCII payload."""
    if len(bits) < 168:
        return None
    msg_type = int(bits[0:6], 2)
    if msg_type not in (1, 2, 3, 5, 18, 24):
        return None
    mmsi = str(int(bits[8:38], 2))
    result = {"mmsi": mmsi, "type": msg_type}
    if msg_type in (1, 2, 3):
        sog = int(bits[50:60], 2) / 10.0
        lon = int(bits[61:89], 2)
        if lon >= (1 << 27):
            lon -= 1 << 28
        lon /= 600000.0
        lat = int(bits[89:116], 2)
        if lat >= (1 << 26):
            lat -= 1 << 27
        lat /= 600000.0
        cog = int(bits[116:128], 2) / 10.0
        hdg = int(bits[128:137], 2)
        result.update({"lat": lat, "lon": lon, "sog": sog, "cog": cog, "hdg": hdg})
    elif msg_type == 18:
        sog = int(bits[46:56], 2) / 10.0
        lon = int(bits[57:85], 2)
        if lon >= (1 << 27):
            lon -= 1 << 28
        lon /= 600000.0
        lat = int(bits[85:112], 2)
        if lat >= (1 << 26):
            lat -= 1 << 27
        lat /= 600000.0
        result.update({"lat": lat, "lon": lon, "sog": sog, "cog": 0, "hdg": 0})
    return result


def _ais_bits_from_nmea(payload_str):
    """Convert NMEA-style 6-bit ASCII AIS payload to binary string."""
    bits = ""
    for ch in payload_str:
        val = ord(ch) - 48
        if val > 40:
            val -= 8
        bits += format(val, "06b")
    return bits


def _parse_aivdm(line):
    """Parse !AIVDM sentence."""
    if "!AIVDM" not in line and "!AIVDO" not in line:
        return None
    parts = line.strip().split(",")
    if len(parts) < 6:
        return None
    payload = parts[5]
    if not payload:
        return None
    bits = _ais_bits_from_nmea(payload)
    return _decode_ais_payload(bits)


def _receiver_thread():
    global _rx_count
    proc_fm = None
    proc_dec = None
    try:
        gain = recommended_gain(162_000_000)
        proc_fm = subprocess.Popen(
            [
                "rtl_fm", "-f", AIS_FREQ_A, "-s", AIS_SAMPLE_RATE,
                "-g", str(gain), "-p", "0", "-",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        has_aisdecoder = subprocess.run(
            ["which", "aisdecoder"], capture_output=True
        ).returncode == 0
        if has_aisdecoder:
            proc_dec = subprocess.Popen(
                ["aisdecoder", "-h", "127.0.0.1", "-p", "10110",
                 "-a", "stdin", "-c", "mono", "-d", "-f", "/dev/stdin"],
                stdin=proc_fm.stdout, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )
        else:
            proc_dec = subprocess.Popen(
                ["multimon-ng", "-a", "AFSK1200", "-A", "-t", "raw", "-"],
                stdin=proc_fm.stdout, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )

        while not _shutdown.is_set():
            line = proc_dec.stdout.readline()
            if not line:
                break
            parsed = _parse_aivdm(line)
            if not parsed:
                continue
            _rx_count += 1
            mmsi = parsed["mmsi"]
            with lock:
                if mmsi not in vessels:
                    vessels[mmsi] = {
                        "mmsi": mmsi, "name": "", "type_code": 0,
                        "lat": 0.0, "lon": 0.0, "sog": 0.0,
                        "cog": 0.0, "hdg": 0, "msg_count": 0,
                        "first_seen": datetime.now().strftime("%H:%M:%S"),
                        "last_seen": datetime.now().strftime("%H:%M:%S"),
                    }
                v = vessels[mmsi]
                v["msg_count"] += 1
                v["last_seen"] = datetime.now().strftime("%H:%M:%S")
                if "lat" in parsed and abs(parsed["lat"]) < 90:
                    v["lat"] = parsed["lat"]
                    v["lon"] = parsed["lon"]
                if "sog" in parsed:
                    v["sog"] = parsed["sog"]
                if "cog" in parsed:
                    v["cog"] = parsed["cog"]
    except Exception:
        pass
    finally:
        for p in (proc_dec, proc_fm):
            if p:
                try:
                    p.terminate()
                except Exception:
                    pass


def _gps_thread():
    global _my_lat, _my_lon
    try:
        from payloads._gps_helper import start_gps
        gps = start_gps()
        while not _shutdown.is_set():
            try:
                import gpsd
                pkt = gpsd.get_current()
                if pkt.mode >= 2:
                    _my_lat = pkt.lat
                    _my_lon = pkt.lon
            except Exception:
                pass
            _shutdown.wait(5)
    except Exception:
        pass


def _sorted_vessels():
    with lock:
        vlist = list(vessels.values())
    if _my_lat is not None:
        for v in vlist:
            if abs(v["lat"]) > 0.01:
                v["_dist"] = _haversine(_my_lat, _my_lon, v["lat"], v["lon"])
            else:
                v["_dist"] = 99999
        vlist.sort(key=lambda v: v["_dist"])
    else:
        vlist.sort(key=lambda v: v["msg_count"], reverse=True)
    return vlist


def _draw_header(d, font, title, extra=""):
    d.rectangle([(0, 0), (WIDTH, S(13))], fill=C_HEADER)
    d.text((S(2), S(1)), title, font=font, fill=C_CYAN)
    if extra:
        d.text((WIDTH - S(2) - len(extra) * S(5), S(1)), extra, font=font, fill=C_MUTED)


def _draw_list(d, font, scroll):
    vlist = _sorted_vessels()
    gps_str = "GPS" if _my_lat else "noGPS"
    _draw_header(d, font, "AIS VESSELS", f"{len(vlist)} {gps_str}")
    if not vlist:
        d.text((S(4), S(50)), "No vessels yet", font=font, fill=C_MUTED)
        return
    y = S(15)
    visible = (HEIGHT - S(15)) // ROW_H
    for i in range(scroll, min(scroll + visible, len(vlist))):
        v = vlist[i]
        name = v["name"][:8] or v["mmsi"][:9]
        dist = ""
        if "_dist" in v and v["_dist"] < 9999:
            dist = f"{v['_dist']:.1f}km"
        sog = f"{v['sog']:.0f}kn"
        row = f"{name:<9} {dist:>7} {sog:>4}"
        d.text((S(2), y), row, font=font, fill=C_WHITE)
        y += ROW_H


def _draw_detail(d, font, scroll):
    vlist = _sorted_vessels()
    if not vlist or scroll >= len(vlist):
        _draw_header(d, font, "DETAIL")
        d.text((S(4), S(50)), "No vessel", font=font, fill=C_MUTED)
        return
    v = vlist[scroll]
    _draw_header(d, font, v["name"][:12] or v["mmsi"][:12])
    y = S(16)
    lines = [
        f"MMSI:  {v['mmsi']}",
        f"Lat:   {v['lat']:.5f}" if v["lat"] else "Lat:   ---",
        f"Lon:   {v['lon']:.5f}" if v["lon"] else "Lon:   ---",
        f"SOG:   {v['sog']:.1f} kn",
        f"COG:   {v['cog']:.0f} deg",
        f"Msgs:  {v['msg_count']}",
        f"First: {v['first_seen']}",
        f"Last:  {v['last_seen']}",
    ]
    if "_dist" in v and v["_dist"] < 9999:
        brg = _bearing(_my_lat, _my_lon, v["lat"], v["lon"])
        lines.insert(3, f"Dist:  {v['_dist']:.1f} km @{brg:.0f}")
    for line in lines:
        if y > HEIGHT - ROW_H:
            break
        d.text((S(4), y), line[:24], font=font, fill=C_WHITE)
        y += ROW_H


def _draw_map(d, font):
    vlist = _sorted_vessels()
    _draw_header(d, font, "AIS MAP", f"{len(vlist)}")
    if not vlist:
        d.text((S(4), S(50)), "No positions", font=font, fill=C_MUTED)
        return
    valid = [v for v in vlist if abs(v["lat"]) > 0.01]
    if not valid:
        d.text((S(4), S(50)), "No GPS fixes", font=font, fill=C_MUTED)
        return
    min_lat = min(v["lat"] for v in valid)
    max_lat = max(v["lat"] for v in valid)
    min_lon = min(v["lon"] for v in valid)
    max_lon = max(v["lon"] for v in valid)
    span_lat = max(max_lat - min_lat, 0.01)
    span_lon = max(max_lon - min_lon, 0.01)
    map_y0, map_y1 = S(16), HEIGHT - S(2)
    map_x0, map_x1 = S(2), WIDTH - S(2)
    for v in valid:
        px = map_x0 + int((v["lon"] - min_lon) / span_lon * (map_x1 - map_x0))
        py = map_y1 - int((v["lat"] - min_lat) / span_lat * (map_y1 - map_y0))
        px = max(map_x0, min(map_x1, px))
        py = max(map_y0, min(map_y1, py))
        d.ellipse([(px - 2, py - 2), (px + 2, py + 2)], fill=C_BLUE)
    if _my_lat:
        px = map_x0 + int((_my_lon - min_lon) / span_lon * (map_x1 - map_x0))
        py = map_y1 - int((_my_lat - min_lat) / span_lat * (map_y1 - map_y0))
        d.ellipse([(px - 3, py - 3), (px + 3, py + 3)], fill=C_GREEN)


def _draw_stats(d, font):
    _draw_header(d, font, "AIS STATS")
    with lock:
        n = len(vessels)
    y = S(18)
    d.text((S(4), y), f"Vessels:   {n}", font=font, fill=C_WHITE); y += ROW_H
    d.text((S(4), y), f"Messages:  {_rx_count}", font=font, fill=C_WHITE); y += ROW_H
    d.text((S(4), y), f"GPS:       {'Yes' if _my_lat else 'No'}", font=font, fill=C_GREEN if _my_lat else C_RED)


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {"timestamp": ts, "vessels": list(vessels.values()), "rx_count": _rx_count}
    path = os.path.join(LOOT_DIR, f"ais_{ts}.json")
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

    found, desc, _ = detect_sdr()
    if not found:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((S(4), S(50)), "No RTL-SDR!", font=font, fill=C_RED)
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    tracking = False
    rx_thread = None
    gps_t = None
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
                if not tracking:
                    tracking = True
                    _shutdown.clear()
                    rx_thread = threading.Thread(target=_receiver_thread, daemon=True)
                    rx_thread.start()
                    gps_t = threading.Thread(target=_gps_thread, daemon=True)
                    gps_t.start()
                else:
                    _shutdown.set()
                    tracking = False
            if btn == "UP":
                scroll = max(0, scroll - 1)
            if btn == "DOWN":
                scroll += 1
            if btn == "KEY2":
                path = _export()
                img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                d = ScaledDraw(img)
                d.text((S(4), S(50)), "Exported!", font=font, fill=C_GREEN)
                lcd.LCD_ShowImage(img, 0, 0)
                time.sleep(1.5)
                continue

            img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            d = ScaledDraw(img)
            view = VIEWS[view_idx]
            if view == "LIST":
                _draw_list(d, font, scroll)
            elif view == "DETAIL":
                _draw_detail(d, font, scroll)
            elif view == "MAP":
                _draw_map(d, font)
            elif view == "STATS":
                _draw_stats(d, font)
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.15)
    finally:
        _shutdown.set()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
