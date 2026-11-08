#!/usr/bin/env python3
"""
RaspyJack Payload -- GPS NTP Server
=====================================
Ported from CYM (Cheap Yellow Monster)

Stratum-1 NTP time server using GPS as reference clock.  Displays
a real-time UTC/local clock, Maidenhead grid square, and NTP server
stats on the LCD.

Setup / Prerequisites
---------------------
- GPS module (USB or GPIO serial) recognised by gpsd
- payloads._gps_helper for auto-detection

Controls
--------
  OK         -- Start / stop NTP server
  LEFT/RIGHT -- Switch dashboard (Clock / NTP / GPS)
  UP / DOWN  -- Scroll GPS info
  KEY1       -- Toggle UTC / local time
  KEY2       -- Export GPS log to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/GPS_NTP/
"""

import os
import sys
import time
import json
import socket
import struct
import threading
import math
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

GPS_OK = False
try:
    from payloads._gps_helper import start_gps, detect_gps
    if start_gps():
        import gpsd as gpsd_mod
        gpsd_mod.connect()
        GPS_OK = True
except Exception:
    pass

if not GPS_OK:
    try:
        import gpsd as gpsd_mod
        gpsd_mod.connect()
        GPS_OK = True
    except Exception:
        pass

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
font_big = scaled_font(12)

LOOT_DIR = "/root/Raspyjack/loot/GPS_NTP"
NTP_PORT = 123
NTP_EPOCH_OFFSET = 2208988800
DASHBOARDS = ["clock", "ntp", "gps"]

lock = threading.Lock()
_running = True
gps_data = {
    "lat": 0.0, "lon": 0.0, "alt": 0.0, "speed": 0.0,
    "heading": 0.0, "sats": 0, "fix": False, "utc": None,
}
ntp_stats = {"serving": False, "queries": 0, "last_client": "", "ip": ""}
show_utc = True
dashboard_idx = 0
gps_scroll = 0


def _maidenhead(lat, lon):
    lon += 180.0
    lat += 90.0
    f_lon = int(lon / 20)
    f_lat = int(lat / 10)
    s_lon = int((lon - f_lon * 20) / 2)
    s_lat = int(lat - f_lat * 10)
    ss_lon = int((lon - f_lon * 20 - s_lon * 2) * 12)
    ss_lat = int((lat - f_lat * 10 - s_lat) * 24)
    return (chr(65 + f_lon) + chr(65 + f_lat) +
            str(s_lon) + str(s_lat) +
            chr(97 + ss_lon) + chr(97 + ss_lat))


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _time_to_ntp(t):
    ntp_ts = t + NTP_EPOCH_OFFSET
    secs = int(ntp_ts)
    frac = int((ntp_ts - secs) * (2 ** 32))
    return secs, frac


class GpsPoller(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)

    def run(self):
        while _running:
            if not GPS_OK:
                time.sleep(1)
                continue
            try:
                pkt = gpsd_mod.get_current()
                with lock:
                    gps_data["lat"] = getattr(pkt, "lat", 0.0)
                    gps_data["lon"] = getattr(pkt, "lon", 0.0)
                    gps_data["alt"] = getattr(pkt, "alt", 0.0)
                    gps_data["speed"] = pkt.speed() if hasattr(pkt, "speed") else 0.0
                    gps_data["heading"] = getattr(pkt, "track", 0.0)
                    gps_data["sats"] = getattr(pkt, "sats", 0)
                    gps_data["fix"] = pkt.mode >= 2 if hasattr(pkt, "mode") else False
                    if hasattr(pkt, "time") and pkt.time:
                        gps_data["utc"] = str(pkt.time)
            except Exception:
                pass
            time.sleep(0.5)


class NtpServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._sock = None

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", NTP_PORT))
            self._sock.settimeout(1.0)
        except Exception:
            with lock:
                ntp_stats["serving"] = False
            return

        with lock:
            ntp_stats["serving"] = True
            ntp_stats["ip"] = _get_local_ip()

        while _running and ntp_stats["serving"]:
            try:
                data, addr = self._sock.recvfrom(256)
                if len(data) < 48:
                    continue
                recv_time = time.time()
                recv_s, recv_f = _time_to_ntp(recv_time)

                orig_ts = data[40:48]

                ref_s, ref_f = _time_to_ntp(recv_time)
                tx_time = time.time()
                tx_s, tx_f = _time_to_ntp(tx_time)

                li_vn_mode = (0 << 6) | (4 << 3) | 4
                response = struct.pack(
                    "!BBBb II I II II II II",
                    li_vn_mode,
                    1,
                    6,
                    -20,
                    0, 0,
                    0x47505300,
                    ref_s, ref_f,
                    struct.unpack("!I", orig_ts[:4])[0],
                    struct.unpack("!I", orig_ts[4:])[0],
                    recv_s, recv_f,
                    tx_s, tx_f,
                )

                self._sock.sendto(response, addr)
                with lock:
                    ntp_stats["queries"] += 1
                    ntp_stats["last_client"] = addr[0]
            except socket.timeout:
                continue
            except Exception:
                time.sleep(0.1)

        if self._sock:
            self._sock.close()

    def stop(self):
        with lock:
            ntp_stats["serving"] = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


ntp_server = None


def _start_ntp():
    global ntp_server
    if ntp_server and ntp_stats["serving"]:
        return
    ntp_server = NtpServer()
    ntp_server.start()


def _stop_ntp():
    global ntp_server
    if ntp_server:
        ntp_server.stop()
        ntp_server = None
    with lock:
        ntp_stats["serving"] = False


def _export_log():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"gps_ntp_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "gps": dict(gps_data),
            "maidenhead": _maidenhead(gps_data["lat"], gps_data["lon"]) if gps_data["fix"] else "",
            "ntp": dict(ntp_stats),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        gd = dict(gps_data)
        ns = dict(ntp_stats)
        dash = DASHBOARDS[dashboard_idx]
        utc_mode = show_utc
        scroll = gps_scroll

    d.rectangle((0, 0, 127, 13), fill="#111")
    titles = {"clock": "GPS CLOCK", "ntp": "NTP SERVER", "gps": "GPS INFO"}
    d.text((2, 1), titles[dash], font=font, fill="#4CAF50")
    fix_clr = "#00FF00" if gd["fix"] else "#FF0000"
    d.ellipse((118, 3, 126, 11), fill=fix_clr)

    y = 16

    if dash == "clock":
        now = datetime.now(timezone.utc) if utc_mode else datetime.now()
        time_str = now.strftime("%H:%M:%S")
        date_str = now.strftime("%Y-%m-%d")
        tz_label = "UTC" if utc_mode else "LOC"

        d.text((10, y + 2), time_str, font=font_big, fill="#FFFFFF")
        y += 20
        d.text((20, y), date_str, font=font, fill="#AAAAAA")
        y += 14
        d.text((2, y), f"TZ: {tz_label}   Sats: {gd['sats']}", font=font, fill="#888")
        y += 13
        if gd["fix"]:
            grid = _maidenhead(gd["lat"], gd["lon"])
            d.text((2, y), f"Grid: {grid}", font=font, fill="#4CAF50")
            y += 13
            d.text((2, y), f"Alt: {gd['alt']:.0f}m", font=font, fill="#888")
        else:
            d.text((2, y), "No GPS fix", font=font, fill="#FF5555")

        y += 14
        serving = "ON" if ns["serving"] else "OFF"
        d.text((2, y), f"NTP: {serving}  Q:{ns['queries']}", font=font, fill="#888")

    elif dash == "ntp":
        serving = ns["serving"]
        clr = "#00FF00" if serving else "#FF5555"
        d.text((2, y), f"Status: {'SERVING' if serving else 'STOPPED'}", font=font, fill=clr)
        y += 13
        d.text((2, y), f"Stratum: 1 (GPS)", font=font, fill="#CCC")
        y += 13
        d.text((2, y), f"IP: {ns['ip']}", font=font, fill="#CCC")
        y += 13
        d.text((2, y), f"Port: {NTP_PORT}", font=font, fill="#CCC")
        y += 13
        d.text((2, y), f"Queries: {ns['queries']}", font=font, fill="#FFAA00")
        y += 13
        last = ns["last_client"] or "none"
        d.text((2, y), f"Last: {last[:18]}", font=font, fill="#888")
        y += 13
        fix_txt = "GPS FIX" if gd["fix"] else "NO FIX"
        d.text((2, y), f"Ref: {fix_txt} ({gd['sats']}sat)", font=font, fill="#888")

    elif dash == "gps":
        lines = [
            f"Lat:  {gd['lat']:.6f}",
            f"Lon:  {gd['lon']:.6f}",
            f"Alt:  {gd['alt']:.1f}m",
            f"Spd:  {gd['speed']:.1f} m/s",
            f"Hdg:  {gd['heading']:.1f} deg",
            f"Sats: {gd['sats']}",
            f"Fix:  {'3D' if gd['fix'] else 'None'}",
        ]
        if gd["fix"]:
            lines.append(f"Grid: {_maidenhead(gd['lat'], gd['lon'])}")
        if gd.get("utc"):
            lines.append(f"UTC:  {str(gd['utc'])[:19]}")

        end = min(scroll + 8, len(lines))
        for i in range(scroll, end):
            d.text((2, y), lines[i][:22], font=font, fill="#CCC")
            y += 12

    d.rectangle((0, 116, 127, 127), fill="#111")
    if dash == "clock":
        lbl = "OK:Stop" if ns["serving"] else "OK:Start"
        d.text((2, 117), f"{lbl} K1:TZ K3:X", font=font, fill="#AAA")
    elif dash == "ntp":
        lbl = "OK:Stop" if ns["serving"] else "OK:Start"
        d.text((2, 117), f"{lbl} K2:Exp K3:X", font=font, fill="#AAA")
    else:
        d.text((2, 117), "U/D:Scrl K2:Exp K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global dashboard_idx, show_utc, gps_scroll, _running

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 10), "GPS NTP SERVER", font=font, fill="#4CAF50")
    d.text((4, 28), "Stratum-1 time server", font=font, fill="#888")
    d.text((4, 40), "from GPS reference.", font=font, fill="#888")
    d.text((4, 60), "OK=Start NTP server", font=font, fill="#666")
    d.text((4, 72), "L/R=Dash K1=UTC/Loc", font=font, fill="#666")
    d.text((4, 84), "K2=Export K3=Exit", font=font, fill="#666")
    gps_txt = "GPS: OK" if GPS_OK else "GPS: not found"
    gps_clr = "#00FF00" if GPS_OK else "#FF5555"
    d.text((4, 100), gps_txt, font=font, fill=gps_clr)
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    poller = GpsPoller()
    poller.start()

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break
            elif btn == "OK":
                if ntp_stats["serving"]:
                    _stop_ntp()
                else:
                    _start_ntp()
                time.sleep(0.3)
            elif btn == "RIGHT":
                dashboard_idx = (dashboard_idx + 1) % len(DASHBOARDS)
                gps_scroll = 0
                time.sleep(0.25)
            elif btn == "LEFT":
                dashboard_idx = (dashboard_idx - 1) % len(DASHBOARDS)
                gps_scroll = 0
                time.sleep(0.25)
            elif btn == "KEY1":
                show_utc = not show_utc
                time.sleep(0.25)
            elif btn == "KEY2":
                _export_log()
                time.sleep(0.3)
            elif btn == "UP":
                gps_scroll = max(0, gps_scroll - 1)
                time.sleep(0.2)
            elif btn == "DOWN":
                gps_scroll = min(gps_scroll + 1, 4)
                time.sleep(0.2)

            _draw_screen()
            time.sleep(0.05)
    finally:
        _running = False
        _stop_ntp()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
