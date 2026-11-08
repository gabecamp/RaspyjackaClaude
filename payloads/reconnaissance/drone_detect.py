#!/usr/bin/env python3
"""
RaspyJack Payload -- Drone Remote ID Detector
==============================================

Passively detects nearby drones by parsing legally-mandated Remote ID
broadcasts over BLE (ASTM F3411 service data UUID 0xFFFA) and DJI
proprietary BLE advertisements (company ID 0x2CA5).  Optionally sniffs
WiFi Remote ID beacons via scapy on a monitor-mode interface.

Displays drone serial numbers, locations, altitude, speed and distance
from the Pi (when GPS is available).

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- Optional: GPS module (for distance calculation)
- Optional: WiFi adapter in monitor mode + scapy (for WiFi Remote ID)

Controls
--------
  OK          -- Start / stop scanning
  UP / DOWN   -- Scroll drone list
  LEFT / RIGHT-- Switch dashboard (List / Detail / Radar)
  KEY1        -- Toggle WiFi monitor scanning
  KEY2        -- Export JSON to loot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/DroneDetect/
"""

import os
import sys
import time
import json
import math
import struct
import asyncio
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_bt_interface

GPS_OK = False
try:
    from payloads._gps_helper import start_gps
    if start_gps():
        import gpsd as gpsd_module
        gpsd_module.connect()
        GPS_OK = True
except Exception:
    pass

if not GPS_OK:
    try:
        import gpsd as gpsd_module
        gpsd_module.connect()
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

HCI_DEV = None
LOOT_DIR = "/root/Raspyjack/loot/DroneDetect"
ROWS_VISIBLE = 7
ROW_H = 12
VIEWS = ["list", "detail", "radar"]

ASTM_SVC_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"
DJI_COMPANY_ID = 0x2CA5

lock = threading.Lock()
drones = {}
scanning = False
wifi_scanning = False
scroll_pos = 0
selected_idx = 0
view_idx = 0
status_msg = "Idle"
_running = True
my_lat = 0.0
my_lon = 0.0
my_fix = False


def _haversine(lat1, lon1, lat2, lon2):
    R = 6371000
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


def _bearing_arrow(deg):
    arrows = "↑↗→↘↓↙←↖"
    return arrows[int((deg + 22.5) % 360 / 45)]


def _parse_astm_rid(data):
    if len(data) < 3:
        return None
    msg_type = (data[0] >> 4) & 0x0F
    result = {"source": "ASTM"}

    if msg_type == 0 and len(data) >= 22:
        id_type = data[1] & 0x0F
        serial = bytes(data[2:22]).split(b"\x00", 1)[0].decode(errors="replace").strip()
        if serial:
            result["serial"] = serial
            result["id_type"] = id_type

    elif msg_type == 1 and len(data) >= 19:
        lat = struct.unpack_from("<i", bytes(data), 4)[0] / 1e7
        lon = struct.unpack_from("<i", bytes(data), 8)[0] / 1e7
        alt_press = struct.unpack_from("<H", bytes(data), 12)[0] * 0.5 - 1000
        speed = data[18] * 0.25
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            result["lat"] = lat
            result["lon"] = lon
            result["alt"] = round(alt_press, 1)
            result["speed"] = round(speed, 1)

    elif msg_type == 4 and len(data) >= 18:
        op_lat = struct.unpack_from("<i", bytes(data), 1)[0] / 1e7
        op_lon = struct.unpack_from("<i", bytes(data), 5)[0] / 1e7
        if -90 <= op_lat <= 90 and -180 <= op_lon <= 180:
            result["op_lat"] = op_lat
            result["op_lon"] = op_lon

    elif msg_type == 0xF and len(data) >= 25:
        offset = 1
        while offset + 25 <= len(data):
            sub = _parse_astm_rid(data[offset:offset + 25])
            if sub:
                for k, v in sub.items():
                    if k != "source":
                        result[k] = v
            offset += 25

    return result if len(result) > 1 else None


def _parse_dji_rid(data):
    if len(data) < 20:
        return None
    result = {"source": "DJI"}
    try:
        serial = bytes(data[6:22]).split(b"\x00", 1)[0].decode(errors="replace").strip()
        if serial and serial.isprintable():
            result["serial"] = serial
        if len(data) >= 34:
            lat = struct.unpack_from("<i", bytes(data), 22)[0] / 1e7
            lon = struct.unpack_from("<i", bytes(data), 26)[0] / 1e7
            alt = struct.unpack_from("<h", bytes(data), 30)[0]
            if -90 <= lat <= 90 and -180 <= lon <= 180 and lat != 0:
                result["lat"] = lat
                result["lon"] = lon
                result["alt"] = alt
        if len(data) >= 36:
            speed_raw = struct.unpack_from("<H", bytes(data), 34)[0]
            result["speed"] = round(speed_raw * 0.01, 1)
    except Exception:
        pass
    return result if len(result) > 1 else None


def _update_drone(addr, rssi, parsed):
    now = datetime.now().strftime("%H:%M:%S")
    serial = parsed.get("serial", addr[-8:])
    key = serial if serial != addr[-8:] else addr

    with lock:
        if key in drones:
            d = drones[key]
            d["rssi"] = rssi
            d["last_seen"] = now
            d["count"] += 1
            for f in ("lat", "lon", "alt", "speed", "op_lat", "op_lon", "serial"):
                if f in parsed:
                    d[f] = parsed[f]
        else:
            drones[key] = {
                "key": key,
                "addr": addr,
                "serial": serial,
                "source": parsed.get("source", "?"),
                "rssi": rssi,
                "lat": parsed.get("lat", 0),
                "lon": parsed.get("lon", 0),
                "alt": parsed.get("alt", 0),
                "speed": parsed.get("speed", 0),
                "op_lat": parsed.get("op_lat", 0),
                "op_lon": parsed.get("op_lon", 0),
                "first_seen": now,
                "last_seen": now,
                "count": 1,
            }


def _gps_poll():
    global my_lat, my_lon, my_fix
    while _running:
        try:
            pkt = gpsd_module.get_current()
            my_lat = pkt.lat if hasattr(pkt, "lat") else 0.0
            my_lon = pkt.lon if hasattr(pkt, "lon") else 0.0
            my_fix = pkt.mode >= 2 if hasattr(pkt, "mode") else False
        except Exception:
            pass
        time.sleep(1)


def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


async def _ble_scan_loop():
    from bleak import BleakScanner

    def _callback(device, adv_data):
        if not scanning:
            return
        rssi = adv_data.rssi or -99

        if hasattr(adv_data, "service_data") and adv_data.service_data:
            for svc_uuid, svc_bytes in adv_data.service_data.items():
                if "fffa" in svc_uuid.lower():
                    parsed = _parse_astm_rid(svc_bytes)
                    if parsed:
                        _update_drone(device.address, rssi, parsed)
                        return

        if hasattr(adv_data, "manufacturer_data") and adv_data.manufacturer_data:
            for cid, mfr_bytes in adv_data.manufacturer_data.items():
                if cid == DJI_COMPANY_ID:
                    parsed = _parse_dji_rid(mfr_bytes)
                    if parsed:
                        _update_drone(device.address, rssi, parsed)
                        return

    scanner = BleakScanner(detection_callback=_callback)
    await scanner.start()
    while scanning and _running:
        await asyncio.sleep(1)
    await scanner.stop()


def _ble_thread():
    global status_msg
    _hci_up()
    time.sleep(0.3)
    try:
        asyncio.run(_ble_scan_loop())
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]


def _wifi_thread():
    global status_msg
    try:
        from scapy.all import sniff as scapy_sniff, Dot11Beacon, Dot11Elt
    except ImportError:
        with lock:
            status_msg = "No scapy"
        return

    def _handle(pkt):
        if not wifi_scanning or not _running:
            return
        if not pkt.haslayer(Dot11Beacon):
            return
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 221 and len(elt.info) >= 7:
                oui = elt.info[:3]
                if oui == b"\xfa\x0b\xbd":
                    parsed = _parse_astm_rid(elt.info[4:])
                    if parsed:
                        addr = pkt.addr2 or "00:00:00:00:00:00"
                        _update_drone(addr.upper(), -80, parsed)
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    try:
        from payloads._iface_helper import select_interface
    except ImportError:
        with lock:
            status_msg = "No WiFi mon"
        return

    with lock:
        status_msg = "WiFi scan..."
    try:
        scapy_sniff(iface="wlan1mon", prn=_handle, store=0,
                    timeout=0, stop_filter=lambda _: not wifi_scanning or not _running)
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]


def _start_scan():
    global scanning, status_msg
    with lock:
        if scanning:
            return
        scanning = True
        status_msg = "Scanning..."
    threading.Thread(target=_ble_thread, daemon=True).start()


def _stop_scan():
    global scanning, status_msg
    with lock:
        scanning = False
        status_msg = "Stopped"


def _toggle_wifi():
    global wifi_scanning, status_msg
    with lock:
        if wifi_scanning:
            wifi_scanning = False
            status_msg = "WiFi off"
        else:
            wifi_scanning = True
            status_msg = "WiFi on"
            threading.Thread(target=_wifi_thread, daemon=True).start()


def _sorted_drones():
    with lock:
        items = list(drones.values())
    items.sort(key=lambda d: d["rssi"], reverse=True)
    return items


def _export_json():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"drones_{ts}.json")
    with lock:
        data = {"timestamp": ts, "drones": list(drones.values()),
                "my_lat": my_lat, "my_lon": my_lon}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _draw_screen():
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        msg = status_msg
        n_dr = len(drones)
        sp = scroll_pos
        sel = selected_idx
        vi = view_idx
        wf = wifi_scanning

    cur_view = VIEWS[vi % len(VIEWS)]

    d.rectangle((0, 0, 127, 13), fill="#111")
    title = {"list": "DRONE RID", "detail": "DRONE DTL", "radar": "DRONE RAD"}[cur_view]
    d.text((2, 1), title, font=font, fill="#FF5722")
    color = "#00FF00" if active else "#FF0000"
    d.ellipse((108, 3, 116, 11), fill=color)
    if wf:
        d.text((118, 1), "W", font=font, fill="#2196F3")

    y = 15
    items = _sorted_drones()

    if cur_view == "detail":
        if items and 0 <= sel < len(items):
            dr = items[sel]
            lines = [
                f"SN:{dr['serial'][:18]}",
                f"Src:{dr['source']} MAC:{dr['addr'][-8:]}",
                f"RSSI:{dr['rssi']}dB  x{dr['count']}",
            ]
            if dr["lat"] != 0:
                lines.append(f"Lat:{dr['lat']:.5f}")
                lines.append(f"Lon:{dr['lon']:.5f}")
            if dr["alt"] != 0:
                lines.append(f"Alt:{dr['alt']}m Spd:{dr['speed']}m/s")
            if dr["op_lat"] != 0:
                lines.append(f"OpLat:{dr['op_lat']:.5f}")
                lines.append(f"OpLon:{dr['op_lon']:.5f}")
            if my_fix and dr["lat"] != 0:
                dist = _haversine(my_lat, my_lon, dr["lat"], dr["lon"])
                brg = _bearing(my_lat, my_lon, dr["lat"], dr["lon"])
                lines.append(f"Dist:{dist:.0f}m {_bearing_arrow(brg)}{brg:.0f}")
            lines.append(f"First:{dr['first_seen']}")
            lines.append(f"Last:{dr['last_seen']}")
            for line in lines[:8]:
                d.text((2, y), line[:22], font=font, fill="#CCCCCC")
                y += ROW_H
        else:
            d.text((2, y), "No drone selected", font=font, fill="#555")

    elif cur_view == "radar":
        cx, cy = 64, 70
        radius = 45
        d.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), outline="#333")
        d.ellipse((cx - radius // 2, cy - radius // 2, cx + radius // 2, cy + radius // 2), outline="#222")
        d.line((cx, cy - radius, cx, cy + radius), fill="#222")
        d.line((cx - radius, cy, cx + radius, cy), fill="#222")
        d.text((cx - 2, cy - radius - 10), "N", font=font, fill="#555")

        if my_fix:
            max_dist = 2000
            for dr in items:
                if dr["lat"] == 0:
                    continue
                dist = _haversine(my_lat, my_lon, dr["lat"], dr["lon"])
                brg = math.radians(_bearing(my_lat, my_lon, dr["lat"], dr["lon"]))
                r = min(dist / max_dist, 1.0) * radius
                px = int(cx + r * math.sin(brg))
                py = int(cy - r * math.cos(brg))
                clr = "#FF0000" if dist < 200 else "#FFAA00" if dist < 500 else "#00FF00"
                d.ellipse((px - 3, py - 3, px + 3, py + 3), fill=clr)
            d.text((2, 118), f"GPS OK {len(items)}dr", font=font, fill="#888")
        else:
            d.text((2, 118), "No GPS fix", font=font, fill="#FF0000")

    else:
        d.text((2, y), f"Drones:{n_dr} {msg[:10]}", font=font, fill="#888")
        y += 13
        end = min(sp + ROWS_VISIBLE, len(items))
        for i in range(sp, end):
            dr = items[i]
            prefix = ">" if i == sel else " "
            sn = (dr["serial"])[:10]
            rssi = dr["rssi"]
            alt = dr["alt"]
            dist_str = ""
            if my_fix and dr["lat"] != 0:
                dist = _haversine(my_lat, my_lon, dr["lat"], dr["lon"])
                dist_str = f" {dist:.0f}m"
            else:
                dist_str = f" {alt}m" if alt else ""
            clr = "#FFAA00" if i == sel else "#CCCCCC"
            txt = f"{prefix}{sn} {rssi}{dist_str}"
            d.text((2, y), txt[:22], font=font, fill=clr)
            y += ROW_H

        if not items:
            d.text((2, y), "No drones detected", font=font, fill="#555")

        d.rectangle((0, 116, 127, 127), fill="#111")
        lbl = "OK:Stop" if active else "OK:Go"
        d.text((2, 117), f"{lbl} K1:WiFi K3:X", font=font, fill="#AAA")

    LCD.LCD_ShowImage(img, 0, 0)


def main():
    global scroll_pos, selected_idx, view_idx, status_msg, HCI_DEV

    HCI_DEV = select_bt_interface(LCD, font, PINS, GPIO)
    if not HCI_DEV:
        GPIO.cleanup()
        return 1

    if GPS_OK:
        threading.Thread(target=_gps_poll, daemon=True).start()

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 10), "DRONE DETECTOR", font=font, fill="#FF5722")
    d.text((4, 28), "Remote ID scanner", font=font, fill="#888")
    d.text((4, 40), "ASTM F3411 + DJI", font=font, fill="#888")
    d.text((4, 60), "OK=Start L/R=View", font=font, fill="#666")
    d.text((4, 72), "K1=WiFi  K2=Export", font=font, fill="#666")
    d.text((4, 84), "K3=Exit", font=font, fill="#666")
    gps_txt = "GPS: OK" if GPS_OK else "GPS: N/A"
    d.text((4, 100), gps_txt, font=font, fill="#00FF00" if GPS_OK else "#FF0000")
    LCD.LCD_ShowImage(img, 0, 0)
    time.sleep(1.0)

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                break

            elif btn == "OK":
                with lock:
                    active = scanning
                if active:
                    _stop_scan()
                else:
                    _start_scan()
                time.sleep(0.3)

            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                time.sleep(0.25)

            elif btn == "RIGHT":
                view_idx = (view_idx + 1) % len(VIEWS)
                time.sleep(0.25)

            elif btn == "UP":
                with lock:
                    selected_idx = max(0, selected_idx - 1)
                    if selected_idx < scroll_pos:
                        scroll_pos = selected_idx
                time.sleep(0.2)

            elif btn == "DOWN":
                items = _sorted_drones()
                with lock:
                    selected_idx = min(len(items) - 1, selected_idx + 1)
                    if selected_idx >= scroll_pos + ROWS_VISIBLE:
                        scroll_pos = selected_idx - ROWS_VISIBLE + 1
                time.sleep(0.2)

            elif btn == "KEY1":
                _toggle_wifi()
                time.sleep(0.3)

            elif btn == "KEY2":
                _export_json()
                with lock:
                    status_msg = "Exported"
                time.sleep(0.3)

            _draw_screen()
            time.sleep(0.05)

    finally:
        _stop_scan()
        try:
            LCD.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
