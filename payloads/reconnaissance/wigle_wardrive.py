#!/usr/bin/env python3
"""
RaspyJack Payload -- Wigle Wardrive
====================================
Author: RaspyJack Contributors

Standalone WiFi + BLE wardriving with GPS correlation and Wigle CSV
export.  No external hardware beyond the Pi's WiFi (monitor mode) and
an optional BLE adapter + GPS receiver.

Controls
--------
  OK         -- Start / stop scanning
  UP / DOWN  -- Scroll lists
  KEY1       -- Cycle view (DASHBOARD / AP_LIST / BLE_LIST / EXPORT)
  LEFT       -- Back
  KEY2       -- Export Wigle CSV now
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/Wigle/
"""

import os
import sys
import csv
import time
import threading
import subprocess
from datetime import datetime
from collections import OrderedDict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

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
LOOT_DIR = "/root/Raspyjack/loot/Wigle"
AUTOSAVE_INTERVAL = 60

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_YELLOW = "#FFD740"
C_RED = "#FF5252"
C_MUTED = "#888888"
C_WHITE = "#FFFFFF"
C_HEADER = "#0d1117"

WIGLE_HDR = (
    "WigleWifi-1.6,appRelease=RaspyjackaClaude,model=RPi,release=1.0,"
    "device=Raspyjack,display=LCD128,board=RPi,brand=Raspyjack,"
    "star=Sol,body=3,subBody=0"
)
WIGLE_COLS = (
    "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,"
    "CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type"
)

VIEWS = ["DASHBOARD", "AP_LIST", "BLE_LIST", "EXPORT"]

# ---------------------------------------------------------------------------
# GPS helper
# ---------------------------------------------------------------------------

_gps_lat = 0.0
_gps_lon = 0.0
_gps_alt = 0.0
_gps_fix = False

def _gps_thread(stop_evt):
    global _gps_lat, _gps_lon, _gps_alt, _gps_fix
    try:
        import gpsd
        gpsd.connect()
        while not stop_evt.is_set():
            try:
                pkt = gpsd.get_current()
                if pkt.mode >= 2:
                    _gps_lat = pkt.lat
                    _gps_lon = pkt.lon
                    _gps_alt = getattr(pkt, "alt", 0.0) or 0.0
                    _gps_fix = True
                else:
                    _gps_fix = False
            except Exception:
                _gps_fix = False
            stop_evt.wait(1.0)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# WiFi scanner (scapy monitor mode)
# ---------------------------------------------------------------------------

_wifi_devices: OrderedDict = OrderedDict()
_wifi_lock = threading.Lock()

def _parse_crypto(pkt):
    from scapy.all import Dot11Elt
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    crypto = set()
    if "privacy" in cap:
        crypto.add("WEP")
    p = pkt
    while p:
        if p.haslayer(Dot11Elt):
            elt = p.getlayer(Dot11Elt)
            if elt.ID == 48:
                crypto.discard("WEP")
                crypto.add("WPA2")
            elif elt.ID == 221 and elt.info and elt.info.startswith(b"\x00\x50\xf2\x01"):
                crypto.discard("WEP")
                crypto.add("WPA")
        p = p.payload if hasattr(p, "payload") and p.payload and p.payload != p else None
    if not crypto:
        crypto.add("OPEN")
    return "/".join(sorted(crypto))


def _wifi_sniffer(iface, stop_evt):
    try:
        from scapy.all import sniff, Dot11Beacon, Dot11ProbeResp, Dot11, RadioTap
    except ImportError:
        return
    def handler(pkt):
        if stop_evt.is_set():
            return
        if not pkt.haslayer(Dot11):
            return
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
            if not bssid:
                return
            bssid = bssid.upper()
            try:
                ssid = pkt[Dot11].info.decode("utf-8", errors="replace") if pkt[Dot11].info else ""
            except Exception:
                ssid = ""
            rssi = int(pkt[RadioTap].dBm_AntSignal) if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal") else -100
            channel = 0
            try:
                from scapy.all import Dot11Elt
                elt = pkt
                while elt:
                    if elt.haslayer(Dot11Elt) and elt[Dot11Elt].ID == 3:
                        channel = int.from_bytes(elt[Dot11Elt].info[:1], "little")
                        break
                    elt = elt.payload if hasattr(elt, "payload") and elt.payload and elt.payload != elt else None
            except Exception:
                pass
            crypto = _parse_crypto(pkt)
            with _wifi_lock:
                if bssid not in _wifi_devices:
                    _wifi_devices[bssid] = {
                        "mac": bssid, "ssid": ssid, "auth": crypto,
                        "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                        "channel": channel, "rssi": rssi,
                        "lat": _gps_lat, "lon": _gps_lon, "alt": _gps_alt,
                    }
                else:
                    entry = _wifi_devices[bssid]
                    entry["rssi"] = max(entry["rssi"], rssi)
                    if _gps_fix:
                        entry["lat"] = _gps_lat
                        entry["lon"] = _gps_lon
                        entry["alt"] = _gps_alt
    while not stop_evt.is_set():
        try:
            sniff(iface=iface, prn=handler, timeout=3, store=False)
        except Exception:
            stop_evt.wait(1.0)

# ---------------------------------------------------------------------------
# BLE scanner (bleak)
# ---------------------------------------------------------------------------

_ble_devices: OrderedDict = OrderedDict()
_ble_lock = threading.Lock()

def _ble_scanner(adapter, stop_evt):
    import asyncio
    try:
        from bleak import BleakScanner
    except ImportError:
        return
    async def _scan():
        while not stop_evt.is_set():
            try:
                kwargs = {"timeout": 4.0}
                if adapter and adapter != "hci0":
                    kwargs["adapter"] = adapter
                devices = await BleakScanner.discover(**kwargs)
                with _ble_lock:
                    for d in devices:
                        mac = d.address.upper()
                        if mac not in _ble_devices:
                            _ble_devices[mac] = {
                                "mac": mac,
                                "name": d.name or "",
                                "rssi": d.rssi if d.rssi else -100,
                                "first_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                                "lat": _gps_lat, "lon": _gps_lon, "alt": _gps_alt,
                            }
                        else:
                            entry = _ble_devices[mac]
                            if d.rssi and d.rssi > entry["rssi"]:
                                entry["rssi"] = d.rssi
                            if _gps_fix:
                                entry["lat"] = _gps_lat
                                entry["lon"] = _gps_lon
                                entry["alt"] = _gps_alt
            except Exception:
                await asyncio.sleep(2)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_scan())
    loop.close()

# ---------------------------------------------------------------------------
# Wigle CSV export
# ---------------------------------------------------------------------------

def _export_wigle():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"wigle_{ts}.csv")
    with open(path, "w", newline="") as f:
        f.write(WIGLE_HDR + "\n")
        f.write(WIGLE_COLS + "\n")
        with _wifi_lock:
            for d in _wifi_devices.values():
                f.write(f'{d["mac"]},{d["ssid"]},{d["auth"]},{d["first_seen"]},'
                        f'{d["channel"]},{d["rssi"]},{d["lat"]:.6f},{d["lon"]:.6f},'
                        f'{d["alt"]:.1f},0.0,WIFI\n')
        with _ble_lock:
            for d in _ble_devices.values():
                f.write(f'{d["mac"]},{d["name"]},,{d["first_seen"]},'
                        f'0,{d["rssi"]},{d["lat"]:.6f},{d["lon"]:.6f},'
                        f'{d["alt"]:.1f},0.0,BLE\n')
    return path

# ---------------------------------------------------------------------------
# Monitor-mode helpers
# ---------------------------------------------------------------------------

def _enable_monitor(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
        subprocess.run(["iw", iface, "set", "type", "monitor"], capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False

def _disable_monitor(iface):
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True, timeout=5)
        subprocess.run(["iw", iface, "set", "type", "managed"], capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, timeout=5)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _draw_header(draw, title, view):
    draw.rectangle([(0, 0), (WIDTH, ROW_H + 1)], fill=C_HEADER)
    draw.text((2, 1), title, fill=C_CYAN, font=font)
    draw.text((WIDTH - font.getlength(view) - 2, 1), view, fill=C_MUTED, font=font)

def _draw_row(draw, y, label, value, color=C_WHITE):
    draw.text((2, y), label, fill=C_MUTED, font=font)
    draw.text((WIDTH - font.getlength(str(value)) - 2, y), str(value), fill=color, font=font)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(image)

    scanning = False
    stop_evt = threading.Event()
    threads = []
    view_idx = 0
    scroll = 0
    start_time = None
    last_save = 0
    last_export_path = ""
    wifi_iface = None
    bt_adapter = None

    # Interface selection screen
    _draw_header(draw, "Wigle Wardrive", "SETUP")
    draw.text((2, 20), "Selecting WiFi iface...", fill=C_YELLOW, font=font)
    LCD.LCD_ShowImage(image, 0, 0)

    try:
        from payloads._iface_helper import select_interface
        wifi_iface = select_interface()
    except Exception:
        wifi_iface = "wlan0"

    try:
        from payloads._iface_helper import select_bt_interface
        bt_adapter = select_bt_interface()
    except Exception:
        bt_adapter = "hci0"

    def start_scan():
        nonlocal scanning, start_time, last_save
        stop_evt.clear()
        _wifi_devices.clear()
        _ble_devices.clear()
        scanning = True
        start_time = time.time()
        last_save = time.time()
        if wifi_iface:
            _enable_monitor(wifi_iface)
            t = threading.Thread(target=_wifi_sniffer, args=(wifi_iface, stop_evt), daemon=True)
            t.start()
            threads.append(t)
        t = threading.Thread(target=_ble_scanner, args=(bt_adapter, stop_evt), daemon=True)
        t.start()
        threads.append(t)
        t = threading.Thread(target=_gps_thread, args=(stop_evt,), daemon=True)
        t.start()
        threads.append(t)

    def stop_scan():
        nonlocal scanning
        stop_evt.set()
        scanning = False
        for t in threads:
            t.join(timeout=3)
        threads.clear()
        if wifi_iface:
            _disable_monitor(wifi_iface)

    try:
        while True:
            image.paste(C_BG, [0, 0, WIDTH, HEIGHT])
            view = VIEWS[view_idx]

            if view == "DASHBOARD":
                _draw_header(draw, "Wigle Wardrive", "DASH")
                with _wifi_lock:
                    ap_count = len(_wifi_devices)
                with _ble_lock:
                    ble_count = len(_ble_devices)
                elapsed = ""
                if start_time:
                    secs = int(time.time() - start_time)
                    elapsed = f"{secs // 60}m{secs % 60:02d}s"
                y = ROW_H + 4
                _draw_row(draw, y, "Status:", "SCANNING" if scanning else "IDLE",
                          C_GREEN if scanning else C_RED)
                y += ROW_H
                _draw_row(draw, y, "WiFi APs:", str(ap_count), C_CYAN)
                y += ROW_H
                _draw_row(draw, y, "BLE Devs:", str(ble_count), C_CYAN)
                y += ROW_H
                _draw_row(draw, y, "GPS:", "FIX" if _gps_fix else "NO FIX",
                          C_GREEN if _gps_fix else C_RED)
                y += ROW_H
                if _gps_fix:
                    _draw_row(draw, y, "Lat:", f"{_gps_lat:.5f}", C_WHITE)
                    y += ROW_H
                    _draw_row(draw, y, "Lon:", f"{_gps_lon:.5f}", C_WHITE)
                    y += ROW_H
                if elapsed:
                    _draw_row(draw, y, "Time:", elapsed, C_YELLOW)
                    y += ROW_H
                total = ap_count + ble_count
                _draw_row(draw, y, "Total:", str(total), C_GREEN)

            elif view == "AP_LIST":
                _draw_header(draw, "WiFi APs", f"{len(_wifi_devices)}")
                with _wifi_lock:
                    aps = sorted(_wifi_devices.values(), key=lambda x: x["rssi"], reverse=True)
                max_rows = (HEIGHT - ROW_H - 2) // ROW_H
                scroll = max(0, min(scroll, max(0, len(aps) - max_rows)))
                visible = aps[scroll:scroll + max_rows]
                y = ROW_H + 2
                for ap in visible:
                    ssid = ap["ssid"][:12] or ap["mac"][-8:]
                    rssi_str = f"{ap['rssi']}dB"
                    color = C_GREEN if ap["rssi"] > -60 else (C_YELLOW if ap["rssi"] > -75 else C_RED)
                    draw.text((2, y), ssid, fill=C_WHITE, font=font)
                    draw.text((WIDTH - font.getlength(rssi_str) - 2, y), rssi_str, fill=color, font=font)
                    y += ROW_H

            elif view == "BLE_LIST":
                _draw_header(draw, "BLE Devices", f"{len(_ble_devices)}")
                with _ble_lock:
                    devs = sorted(_ble_devices.values(), key=lambda x: x["rssi"], reverse=True)
                max_rows = (HEIGHT - ROW_H - 2) // ROW_H
                scroll = max(0, min(scroll, max(0, len(devs) - max_rows)))
                visible = devs[scroll:scroll + max_rows]
                y = ROW_H + 2
                for d in visible:
                    name = d["name"][:12] or d["mac"][-8:]
                    rssi_str = f"{d['rssi']}dB"
                    color = C_GREEN if d["rssi"] > -60 else (C_YELLOW if d["rssi"] > -75 else C_RED)
                    draw.text((2, y), name, fill=C_WHITE, font=font)
                    draw.text((WIDTH - font.getlength(rssi_str) - 2, y), rssi_str, fill=color, font=font)
                    y += ROW_H

            elif view == "EXPORT":
                _draw_header(draw, "Export", "CSV")
                y = ROW_H + 4
                with _wifi_lock:
                    ac = len(_wifi_devices)
                with _ble_lock:
                    bc = len(_ble_devices)
                _draw_row(draw, y, "WiFi:", str(ac), C_CYAN); y += ROW_H
                _draw_row(draw, y, "BLE:", str(bc), C_CYAN); y += ROW_H
                _draw_row(draw, y, "Total:", str(ac + bc), C_GREEN); y += ROW_H
                y += ROW_H
                if last_export_path:
                    fname = os.path.basename(last_export_path)
                    draw.text((2, y), "Last export:", fill=C_MUTED, font=font)
                    y += ROW_H
                    draw.text((2, y), fname[:20], fill=C_GREEN, font=font)
                else:
                    draw.text((2, y), "KEY2 to export CSV", fill=C_YELLOW, font=font)

            LCD.LCD_ShowImage(image, 0, 0)

            # Auto-save
            if scanning and time.time() - last_save >= AUTOSAVE_INTERVAL:
                total = len(_wifi_devices) + len(_ble_devices)
                if total > 0:
                    last_export_path = _export_wigle()
                last_save = time.time()

            btn = get_button(PINS, timeout=0.3)
            if btn == "OK":
                if scanning:
                    stop_scan()
                    if len(_wifi_devices) + len(_ble_devices) > 0:
                        last_export_path = _export_wigle()
                else:
                    start_scan()
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1
            elif btn == "LEFT":
                if view_idx > 0:
                    view_idx = 0
                    scroll = 0
            elif btn == "KEY2":
                if len(_wifi_devices) + len(_ble_devices) > 0:
                    last_export_path = _export_wigle()
            elif btn == "KEY3":
                break

    finally:
        if scanning:
            stop_scan()
        LCD.LCD_Clear()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
