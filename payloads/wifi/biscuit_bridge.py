#!/usr/bin/env python3
"""
RaspyJack Payload -- Biscuit Bridge
====================================
Author: RaspyJack Community

BLE GATT client that pairs with a Biscuit (Pro/DIY/Crumb/Ultra)
ESP32-C5 wireless security device and streams its scan results to
the LCD with GPS-tagged Wigle-compatible CSV logging.

Turns the Pi into a headless Biscuit controller: wardrive, BT scan,
Flock/AirTag detection — all displayed on the LCD and saved to loot.

Prerequisites
-------------
- Bluetooth adapter (hci0 or select at launch)
- bleak (pip3 install bleak)
- Optional: gpsd for GPS tagging

Biscuit Protocol (BLE GATT)
----------------------------
Service:  4fafc201-1fb5-459e-8fcc-c5c9c331914b
Command:  beb5483e-36e1-4688-b7f5-ea07361b26a8 (Write)
Response: beb5483e-36e1-4688-b7f5-ea07361b26a9 (Notify)
Status:   beb5483e-36e1-4688-b7f5-ea07361b26aa (Read)
Settings: beb5483e-36e1-4688-b7f5-ea07361b26ab (Read/Write/Notify)

Data format: TYPE:SUBTYPE:PAYLOAD\\n
  DATA:AP:SSID,BSSID,Channel,RSSI,Security
  DATA:BT:Name,MAC,RSSI,Type[,Payload][,SF=XX]
  DATA:FLOCK:MAC,Name,RSSI,Serial,Method[,Radio]
  DATA:NODEAP:SSID,BSSID,Channel,RSSI,Security,NodeMAC
  DATA:NODEBT:Name,MAC,RSSI,Type,NodeMAC[,SF=XX]
  DATA:STATS:Beacons,Probes,Deauths,Data,EAPOL,MinRSSI,MaxRSSI

Controls
--------
  OK          Connect / Start wardrive scan
  KEY1        Cycle scan mode (wardrive / BT / flock / all)
  KEY2        Toggle dashboard (live / stats / BT / flock)
  LEFT/RIGHT  Switch dashboard page
  UP/DOWN     Scroll
  KEY3        Stop scan & disconnect / Exit
"""

import os
import sys
import time
import csv
import json
import signal
import asyncio
import threading
from datetime import datetime, timezone
from collections import Counter

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button

try:
    from bleak import BleakClient, BleakScanner
    BLEAK_OK = True
except ImportError:
    BLEAK_OK = False

# ---------------------------------------------------------------------------
# GPS (optional -- reuse _gps_helper auto-detect, then gpsd)
# ---------------------------------------------------------------------------
GPS_OK = False
try:
    from payloads._gps_helper import start_gps, detect_gps
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


class GpsReader:
    """Thread-safe GPS reader using gpsd."""

    def __init__(self):
        self.lat = 0.0
        self.lon = 0.0
        self.alt = 0.0
        self.sats = 0
        self.fix = False
        self._lock = threading.Lock()
        self._running = True

    def start(self):
        if not GPS_OK:
            return
        threading.Thread(target=self._poll, daemon=True).start()

    def _poll(self):
        while self._running:
            try:
                pkt = gpsd_module.get_current()
                with self._lock:
                    self.lat = pkt.lat if hasattr(pkt, "lat") else 0.0
                    self.lon = pkt.lon if hasattr(pkt, "lon") else 0.0
                    self.alt = pkt.alt if hasattr(pkt, "alt") else 0.0
                    self.sats = pkt.sats if hasattr(pkt, "sats") else 0
                    self.fix = pkt.mode >= 2 if hasattr(pkt, "mode") else False
            except Exception:
                pass
            time.sleep(1)

    def get(self):
        with self._lock:
            return {"lat": self.lat, "lon": self.lon, "alt": self.alt,
                    "sats": self.sats, "fix": self.fix}

    def stop(self):
        self._running = False


# ---------------------------------------------------------------------------
# Biscuit BLE Protocol Constants
# ---------------------------------------------------------------------------
BISCUIT_SERVICE = "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
CHAR_COMMAND    = "beb5483e-36e1-4688-b7f5-ea07361b26a8"
CHAR_RESPONSE   = "beb5483e-36e1-4688-b7f5-ea07361b26a9"
CHAR_STATUS     = "beb5483e-36e1-4688-b7f5-ea07361b26aa"
CHAR_SETTINGS   = "beb5483e-36e1-4688-b7f5-ea07361b26ab"

SCAN_MODES = ["wardriveall", "wardrive", "wardrive5g", "btwardrive",
              "flockwardrive", "btflockwardrive"]
SCAN_MODE_LABELS = ["All", "2.4GHz", "5GHz", "BT", "Flock", "BT+Flock"]

# ---------------------------------------------------------------------------
# Hardware setup
# ---------------------------------------------------------------------------
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}

LOOT_DIR = "/root/Raspyjack/loot/Biscuit"
FONT = scaled_font(8)
FONT_BIG = scaled_font(10)
FONT_SM = scaled_font(7)

_running = True


def _sig(s, f):
    global _running
    _running = False


signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)


# ---------------------------------------------------------------------------
# Wigle CSV Logger
# ---------------------------------------------------------------------------

class WardLogger:
    WIGLE_HEADER = ("WigleWifi-1.4,appRelease=RaspyJack,model=RPi,"
                    "release=1.0,device=Biscuit,display=LCD,board=RPi,"
                    "brand=RaspyJack")
    COLUMNS = ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
               "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
               "AccuracyMeters", "Type"]

    def __init__(self):
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(LOOT_DIR, f"biscuit_ward_{ts}.csv")
        self._file = open(self.csv_path, "w", newline="")
        self._writer = csv.writer(self._file)
        self._writer.writerow([self.WIGLE_HEADER])
        self._writer.writerow(self.COLUMNS)
        self._count = 0
        self._seen = set()
        self._enc_counter = Counter()
        self._ch_counter = Counter()

    def log(self, bssid, ssid, sec, channel, rssi, gps, dtype="WIFI"):
        first_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        is_new = bssid not in self._seen
        self._writer.writerow([
            bssid, ssid, sec, first_seen, channel, rssi,
            f"{gps['lat']:.8f}" if gps["fix"] else "",
            f"{gps['lon']:.8f}" if gps["fix"] else "",
            f"{gps['alt']:.1f}" if gps["fix"] else "",
            "", dtype,
        ])
        self._file.flush()
        self._count += 1
        self._seen.add(bssid)
        sec_short = sec.strip("[]")
        self._enc_counter[sec_short] += 1
        try:
            self._ch_counter[int(channel)] += 1
        except (ValueError, TypeError):
            pass
        return is_new

    @property
    def total(self):
        return self._count

    @property
    def unique(self):
        return len(self._seen)

    def close(self):
        try:
            self._file.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# BT / Flock logger
# ---------------------------------------------------------------------------

class BtLogger:
    def __init__(self):
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_path = os.path.join(LOOT_DIR, f"biscuit_bt_{ts}.json")
        self._devices = {}  # mac -> {name, rssi, type, count, first, last, ...}
        self._flock = {}    # mac -> {name, serial, method, rssi, first, last}
        self._lock = threading.Lock()

    def log_bt(self, name, mac, rssi, devtype, extra=None):
        with self._lock:
            now = datetime.now().strftime("%H:%M:%S")
            if mac in self._devices:
                self._devices[mac]["rssi"] = rssi
                self._devices[mac]["last"] = now
                self._devices[mac]["count"] += 1
                if name:
                    self._devices[mac]["name"] = name
            else:
                self._devices[mac] = {
                    "name": name, "mac": mac, "rssi": rssi,
                    "type": devtype, "count": 1,
                    "first": now, "last": now, "extra": extra or "",
                }

    def log_flock(self, mac, name, rssi, serial, method, radio=""):
        with self._lock:
            now = datetime.now().strftime("%H:%M:%S")
            if mac in self._flock:
                self._flock[mac]["rssi"] = rssi
                self._flock[mac]["last"] = now
                self._flock[mac]["count"] += 1
            else:
                self._flock[mac] = {
                    "name": name, "mac": mac, "rssi": rssi,
                    "serial": serial, "method": method, "radio": radio,
                    "count": 1, "first": now, "last": now,
                }

    def save(self):
        with self._lock:
            data = {
                "bt_devices": list(self._devices.values()),
                "flock_devices": list(self._flock.values()),
                "saved": datetime.now().isoformat(),
            }
        try:
            with open(self.json_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    @property
    def bt_count(self):
        with self._lock:
            return len(self._devices)

    @property
    def flock_count(self):
        with self._lock:
            return len(self._flock)

    def bt_list(self):
        with self._lock:
            return sorted(self._devices.values(),
                          key=lambda d: d["rssi"], reverse=True)

    def flock_list(self):
        with self._lock:
            return sorted(self._flock.values(),
                          key=lambda d: d["rssi"], reverse=True)


# ---------------------------------------------------------------------------
# Biscuit BLE Client
# ---------------------------------------------------------------------------

class BiscuitClient:
    """Async BLE GATT client for Biscuit devices."""

    def __init__(self, gps, ward_logger, bt_logger):
        self.gps = gps
        self.ward = ward_logger
        self.bt_log = bt_logger
        self.client = None
        self.connected = False
        self.scanning = False
        self.device_name = ""
        self.device_addr = ""
        self.battery = -1
        self.status_code = 0
        self.status_text = "Idle"
        self.scan_mode_idx = 0

        # Live feed for LCD
        self._lock = threading.Lock()
        self.ap_feed = []       # most recent first
        self.bt_feed = []
        self.flock_feed = []
        self.event_log = []     # raw log for debug

        # Stats from DATA:STATS lines
        self.stats = {"beacons": 0, "probes": 0, "deauths": 0,
                      "data": 0, "eapol": 0, "min_rssi": 0, "max_rssi": 0}

        self._buf = ""          # partial line buffer
        self._loop = None
        self._thread = None

    # ── BLE scan + connect ──────────────────────────────────────────────

    async def _find_biscuit(self, timeout=12):
        """Scan for a device advertising the Biscuit service UUID."""
        scanner = BleakScanner(service_uuids=[BISCUIT_SERVICE])
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        devices = scanner.discovered_devices_and_advertisement_data
        for dev, adv in devices.values():
            if BISCUIT_SERVICE.lower() in [s.lower() for s in adv.service_uuids]:
                return dev
            # Also match by name
            if dev.name and "biscuit" in dev.name.lower():
                return dev
        return None

    def _on_notify(self, sender, data: bytearray):
        """Handle incoming BLE notifications (may contain multiple lines)."""
        text = data.decode("utf-8", errors="replace")
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line:
                self._process_line(line)

    def _process_line(self, line):
        """Parse a single Biscuit protocol line."""
        with self._lock:
            self.event_log.insert(0, line[:60])
            if len(self.event_log) > 200:
                self.event_log = self.event_log[:200]

        parts = line.split(":", 2)
        if len(parts) < 2:
            return

        msg_type = parts[0]
        subtype = parts[1] if len(parts) > 1 else ""
        payload = parts[2] if len(parts) > 2 else ""

        if msg_type == "DATA":
            self._handle_data(subtype, payload)
        elif msg_type == "STATUS":
            self.status_code = int(subtype) if subtype.isdigit() else 0
            self.status_text = payload or subtype
        elif msg_type == "RSP":
            pass  # acknowledgements
        elif msg_type == "TIME" and subtype == "REQUEST":
            # Queue time sync response
            if self._loop and self.client and self.client.is_connected:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
                asyncio.run_coroutine_threadsafe(
                    self._send(f"TIME:SYNC:{now}"), self._loop)
        elif msg_type == "ERROR":
            with self._lock:
                self.status_text = f"ERR:{payload or subtype}"

    def _handle_data(self, subtype, payload):
        """Parse DATA:AP/BT/FLOCK/NODEAP/NODEBT/STATS lines."""
        fields = payload.split(",") if payload else []
        gps = self.gps.get()

        if subtype in ("AP", "NODEAP"):
            # SSID,BSSID,Channel,RSSI,Security[,NodeMAC]
            if len(fields) >= 5:
                ssid, bssid, ch, rssi_str, sec = fields[0], fields[1], fields[2], fields[3], fields[4]
                try:
                    rssi = int(rssi_str)
                except ValueError:
                    rssi = -99
                self.ward.log(bssid, ssid, sec, ch, rssi, gps)
                node = fields[5] if len(fields) > 5 else ""
                entry = {"ssid": ssid, "bssid": bssid, "ch": ch,
                         "rssi": rssi, "sec": sec, "node": node,
                         "time": datetime.now().strftime("%H:%M:%S")}
                with self._lock:
                    self.ap_feed.insert(0, entry)
                    if len(self.ap_feed) > 500:
                        self.ap_feed = self.ap_feed[:500]

        elif subtype in ("BT", "NODEBT"):
            # Name,MAC,RSSI,Type[,Payload][,SF=XX][,NodeMAC]
            if len(fields) >= 4:
                name, mac, rssi_str, devtype = fields[0], fields[1], fields[2], fields[3]
                try:
                    rssi = int(rssi_str)
                except ValueError:
                    rssi = -99
                extra = ",".join(fields[4:])
                self.bt_log.log_bt(name, mac, rssi, devtype, extra)
                entry = {"name": name, "mac": mac, "rssi": rssi,
                         "type": devtype, "time": datetime.now().strftime("%H:%M:%S")}
                with self._lock:
                    self.bt_feed.insert(0, entry)
                    if len(self.bt_feed) > 500:
                        self.bt_feed = self.bt_feed[:500]

        elif subtype == "FLOCK":
            # MAC,Name,RSSI,Serial,Method[,Radio]
            if len(fields) >= 5:
                mac, name, rssi_str, serial, method = fields[:5]
                radio = fields[5] if len(fields) > 5 else ""
                try:
                    rssi = int(rssi_str)
                except ValueError:
                    rssi = -99
                self.bt_log.log_flock(mac, name, rssi, serial, method, radio)
                entry = {"mac": mac, "name": name, "rssi": rssi,
                         "serial": serial, "method": method,
                         "time": datetime.now().strftime("%H:%M:%S")}
                with self._lock:
                    self.flock_feed.insert(0, entry)
                    if len(self.flock_feed) > 200:
                        self.flock_feed = self.flock_feed[:200]

        elif subtype == "STATS":
            # Beacons,Probes,Deauths,Data,EAPOL,MinRSSI,MaxRSSI
            if len(fields) >= 7:
                try:
                    self.stats = {
                        "beacons": int(fields[0]), "probes": int(fields[1]),
                        "deauths": int(fields[2]), "data": int(fields[3]),
                        "eapol": int(fields[4]),
                        "min_rssi": int(fields[5]), "max_rssi": int(fields[6]),
                    }
                except ValueError:
                    pass

        elif subtype == "FLOCKSIG":
            pass  # Advanced IE-fingerprint data — log only

    # ── Commands ────────────────────────────────────────────────────────

    async def _send(self, cmd):
        """Send a command to the Biscuit."""
        if self.client and self.client.is_connected:
            try:
                data = (cmd + "\n").encode("utf-8")
                await self.client.write_gatt_char(CHAR_COMMAND, data,
                                                  response=False)
            except Exception:
                pass

    async def send_scan(self, mode_idx=0):
        mode = SCAN_MODES[mode_idx % len(SCAN_MODES)]
        await self._send(f"CMD:{mode}:")

    async def send_stop(self):
        await self._send("CMD:stopscan:")

    async def read_status(self):
        """Read the JSON status characteristic."""
        if self.client and self.client.is_connected:
            try:
                raw = await self.client.read_gatt_char(CHAR_STATUS)
                data = json.loads(raw.decode("utf-8", errors="replace"))
                self.battery = data.get("battery", -1)
                self.status_code = data.get("status", 0)
                return data
            except Exception:
                return {}
        return {}

    # ── Async event loop (runs in a thread) ─────────────────────────────

    async def _run(self):
        """Main async loop: scan, connect, subscribe, keep alive."""
        self.status_text = "Scanning BLE..."
        dev = await self._find_biscuit(timeout=15)
        if not dev:
            self.status_text = "No Biscuit found"
            return False

        self.device_name = dev.name or "Biscuit"
        self.device_addr = dev.address
        self.status_text = f"Connecting {dev.address[:8]}..."

        try:
            self.client = BleakClient(dev.address)
            await self.client.connect(timeout=15)
        except Exception as e:
            self.status_text = f"Connect fail: {str(e)[:20]}"
            return False

        if not self.client.is_connected:
            self.status_text = "Connection failed"
            return False

        self.connected = True
        self.status_text = f"Connected: {self.device_name}"

        # Subscribe to notifications
        try:
            await self.client.start_notify(CHAR_RESPONSE, self._on_notify)
        except Exception as e:
            self.status_text = f"Notify fail: {str(e)[:20]}"
            await self.client.disconnect()
            self.connected = False
            return False

        # Read initial status
        await self.read_status()

        # Stay connected until stopped
        try:
            while _running and self.connected and self.client.is_connected:
                await asyncio.sleep(0.5)
        except Exception:
            pass

        # Cleanup
        try:
            if self.scanning:
                await self.send_stop()
                await asyncio.sleep(0.3)
            await self.client.stop_notify(CHAR_RESPONSE)
            await self.client.disconnect()
        except Exception:
            pass

        self.connected = False
        self.status_text = "Disconnected"
        return True

    def start(self):
        """Start the BLE client in a background thread."""
        def _thread():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run())
            self._loop.close()
            self._loop = None

        self._thread = threading.Thread(target=_thread, daemon=True)
        self._thread.start()

    def request_scan(self, mode_idx):
        """Request a scan start (thread-safe, from main loop)."""
        self.scan_mode_idx = mode_idx
        self.scanning = True
        if self._loop:
            asyncio.run_coroutine_threadsafe(
                self.send_scan(mode_idx), self._loop)

    def request_stop_scan(self):
        """Request scan stop (thread-safe)."""
        self.scanning = False
        if self._loop:
            asyncio.run_coroutine_threadsafe(self.send_stop(), self._loop)

    def disconnect(self):
        """Disconnect (thread-safe)."""
        self.connected = False
        self.scanning = False


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def _rssi_color(rssi):
    if rssi > -50:
        return "#00FF00"
    if rssi > -70:
        return "#FFAA00"
    return "#FF4444"


def _bar(d, x, y, w, h, pct, fill, bg="#222"):
    d.rectangle((x, y, x + w, y + h), fill=bg)
    bar_h = max(1, int(h * min(1.0, pct)))
    d.rectangle((x, y + h - bar_h, x + w, y + h), fill=fill)


def draw_splash(lcd, line1, line2="", color="#00CCFF"):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)
    d.rectangle((0, 0, w - 1, 14), fill="#001122")
    d.text((2, 1), "BISCUIT BRIDGE", font=FONT_BIG, fill=color)
    d.text((10, 30), line1[:22], font=FONT, fill="#FFFFFF")
    if line2:
        d.text((10, 45), line2[:22], font=FONT_SM, fill="#888888")
    lcd.LCD_ShowImage(img, 0, 0)


# ── Dashboard: AP live feed ────────────────────────────────────────────

def draw_ap_live(lcd, client, gps, scroll):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    # Header
    d.rectangle((0, 0, 127, 13), fill="#001133")
    mode_label = SCAN_MODE_LABELS[client.scan_mode_idx % len(SCAN_MODE_LABELS)]
    d.text((2, 1), f"AP {mode_label}", font=FONT_BIG, fill="#00CCFF")
    d.text((60, 2), f"U:{client.ward.unique} T:{client.ward.total}",
           font=FONT_SM, fill="#FFAA00")

    # GPS / Battery
    g = gps.get()
    if GPS_OK and g["fix"]:
        d.text((108, 2), f"S{g['sats']}", font=FONT_SM, fill="#00FF00")
    elif GPS_OK:
        d.text((104, 2), "noFix", font=FONT_SM, fill="#FF4444")

    # AP list
    with client._lock:
        aps = list(client.ap_feed)
    visible = aps[scroll:scroll + 7]
    for i, ap in enumerate(visible):
        y = 15 + i * 14
        ssid = ap["ssid"][:10] or "Hidden"
        d.text((2, y), ssid, font=FONT, fill="#FFFFFF")
        d.text((66, y), str(ap["rssi"]), font=FONT, fill=_rssi_color(ap["rssi"]))
        d.text((88, y), f"c{ap['ch']}", font=FONT_SM, fill="#58a6ff")
        sec_short = ap["sec"][:5]
        sc = "#00FF00" if "WPA" in ap["sec"] else "#FF4444" if "Open" in ap["sec"] else "#888"
        d.text((106, y), sec_short, font=FONT_SM, fill=sc)

    if not aps:
        if client.scanning:
            d.text((10, 40), "Scanning...", font=FONT, fill="#666")
        elif client.connected:
            d.text((10, 40), "OK: start scan", font=FONT, fill="#666")
        else:
            d.text((10, 40), "OK: connect", font=FONT, fill="#666")

    # Status bar
    d.rectangle((0, 116, 127, 127), fill="#111")
    bat = f"B{client.battery}%" if client.battery >= 0 else ""
    d.text((2, 117), f"K1:Mode K2:Dash {bat}", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(aps)


# ── Dashboard: Stats ───────────────────────────────────────────────────

def draw_stats(lcd, client, gps):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#001133")
    d.text((2, 1), "STATS", font=FONT_BIG, fill="#00CCFF")
    if client.battery >= 0:
        d.text((90, 2), f"BAT:{client.battery}%", font=FONT_SM, fill="#FFAA00")

    y = 16
    d.text((2, y), f"WiFi Unique: {client.ward.unique}", font=FONT, fill="#00FF00")
    y += 12
    d.text((2, y), f"WiFi Total:  {client.ward.total}", font=FONT, fill="#CCCCCC")
    y += 12
    d.text((2, y), f"BT Devices:  {client.bt_log.bt_count}", font=FONT, fill="#58a6ff")
    y += 12
    d.text((2, y), f"Flock/Tags:  {client.bt_log.flock_count}", font=FONT, fill="#FF66FF")
    y += 14

    # Biscuit radio stats
    s = client.stats
    d.text((2, y), "Radio Stats:", font=FONT, fill="#888")
    y += 11
    d.text((6, y), f"Beacons: {s['beacons']}", font=FONT_SM, fill="#AAA")
    y += 10
    d.text((6, y), f"Probes:  {s['probes']}", font=FONT_SM, fill="#AAA")
    y += 10
    d.text((6, y), f"Deauths: {s['deauths']}", font=FONT_SM, fill="#FF6666")
    y += 10
    d.text((6, y), f"EAPOL:   {s['eapol']}", font=FONT_SM, fill="#FFAA00")

    # GPS
    g = gps.get()
    if GPS_OK and g["fix"]:
        d.text((2, 107), f"{g['lat']:.5f},{g['lon']:.5f}", font=FONT_SM, fill="#00FF00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), f"L/R:Dash  {client.status_text[:14]}", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ── Dashboard: BT devices ─────────────────────────────────────────────

def draw_bt_live(lcd, client, scroll):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#110033")
    d.text((2, 1), "BLUETOOTH", font=FONT_BIG, fill="#9966FF")
    d.text((75, 2), f"{client.bt_log.bt_count} dev", font=FONT_SM, fill="#FFAA00")

    devs = client.bt_log.bt_list()
    visible = devs[scroll:scroll + 7]
    for i, dev in enumerate(visible):
        y = 15 + i * 14
        name = dev["name"][:12] or dev["mac"][-8:]
        d.text((2, y), name, font=FONT, fill="#FFFFFF")
        d.text((78, y), str(dev["rssi"]), font=FONT, fill=_rssi_color(dev["rssi"]))
        d.text((100, y), dev["type"][:4], font=FONT_SM, fill="#9966FF")

    if not devs:
        d.text((10, 40), "No BT devices yet", font=FONT, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash UP/DN:Scroll", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(devs)


# ── Dashboard: Flock / tracker detection ──────────────────────────────

def draw_flock_live(lcd, client, scroll):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#330011")
    d.text((2, 1), "FLOCK/TAGS", font=FONT_BIG, fill="#FF66FF")
    d.text((80, 2), f"{client.bt_log.flock_count}", font=FONT_SM, fill="#FFAA00")

    devs = client.bt_log.flock_list()
    visible = devs[scroll:scroll + 7]
    for i, dev in enumerate(visible):
        y = 15 + i * 14
        name = dev["name"][:10] or dev["mac"][-8:]
        d.text((2, y), name, font=FONT, fill="#FFFFFF")
        d.text((68, y), str(dev["rssi"]), font=FONT, fill=_rssi_color(dev["rssi"]))
        method = dev["method"][:6]
        d.text((90, y), method, font=FONT_SM, fill="#FF66FF")

    if not devs:
        d.text((10, 40), "No trackers found", font=FONT, fill="#666")
        d.text((10, 55), "AirTag, FindMy, etc", font=FONT, fill="#444")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash UP/DN:Scroll", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    return len(devs)


# ── Dashboard: Connection / device info ───────────────────────────────

def draw_connection(lcd, client):
    w, h = lcd.width, lcd.height
    img = Image.new("RGB", (w, h), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#001133")
    d.text((2, 1), "BISCUIT", font=FONT_BIG, fill="#00CCFF")

    y = 18
    if client.connected:
        d.text((2, y), client.device_name[:20], font=FONT, fill="#00FF00")
        y += 12
        d.text((2, y), client.device_addr, font=FONT_SM, fill="#888")
        y += 12
        if client.battery >= 0:
            d.text((2, y), f"Battery: {client.battery}%", font=FONT, fill="#FFAA00")
            # Battery bar
            _bar(d, 75, y + 1, 50, 7, client.battery / 100,
                 "#00FF00" if client.battery > 30 else "#FF4444")
            y += 12
        d.text((2, y), f"Status: {client.status_text[:18]}", font=FONT_SM, fill="#CCC")
        y += 14
        if client.scanning:
            mode = SCAN_MODE_LABELS[client.scan_mode_idx % len(SCAN_MODE_LABELS)]
            d.text((2, y), f"Scanning: {mode}", font=FONT, fill="#00FF00")
        else:
            d.text((2, y), "OK to start scan", font=FONT, fill="#666")
    else:
        d.text((2, y), "Not connected", font=FONT, fill="#FF4444")
        y += 14
        d.text((2, y), client.status_text[:22], font=FONT_SM, fill="#888")
        y += 14
        d.text((2, y), "OK to connect", font=FONT, fill="#666")

    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), "L/R:Dash OK:Action K3:X", font=FONT_SM, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DASH_NAMES = ["AP", "Stats", "BT", "Flock", "Info"]
DASH_COUNT = len(DASH_NAMES)


def main():
    global _running

    if not BLEAK_OK:
        print("ERROR: bleak not installed. Run: pip3 install bleak")
        return 1

    GPIO.setmode(GPIO.BCM)
    for p in PINS.values():
        GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    # GPS
    gps = GpsReader()
    gps.start()
    gps_label = "GPS OK" if GPS_OK else "No GPS"
    draw_splash(lcd, "Starting...", gps_label)
    time.sleep(1)

    # Loggers
    ward_logger = WardLogger()
    bt_logger = BtLogger()

    # Biscuit client
    client = BiscuitClient(gps, ward_logger, bt_logger)

    # UI state
    dash = 0        # 0=AP live, 1=stats, 2=BT, 3=flock, 4=info
    scroll = 0
    scan_mode_idx = 0  # index into SCAN_MODES

    draw_splash(lcd, "OK to connect", "K3 to exit")

    try:
        while _running:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                if client.scanning:
                    client.request_stop_scan()
                    time.sleep(0.3)
                break

            elif btn == "OK":
                if not client.connected:
                    # Start BLE connection
                    draw_splash(lcd, "Scanning BLE...", "Looking for Biscuit")
                    client.start()
                    # Wait for connection (up to 20s)
                    for _ in range(40):
                        if client.connected:
                            break
                        time.sleep(0.5)
                    if not client.connected:
                        draw_splash(lcd, client.status_text[:22], "OK to retry", "#FF4444")
                        time.sleep(1)
                elif not client.scanning:
                    # Start scan
                    client.request_scan(scan_mode_idx)
                    time.sleep(0.2)
                else:
                    # Stop scan
                    client.request_stop_scan()
                    time.sleep(0.2)

            elif btn == "KEY1":
                # Cycle scan mode
                scan_mode_idx = (scan_mode_idx + 1) % len(SCAN_MODES)
                time.sleep(0.2)

            elif btn == "KEY2":
                # Save BT/Flock log
                bt_logger.save()
                time.sleep(0.2)

            elif btn == "RIGHT":
                dash = (dash + 1) % DASH_COUNT
                scroll = 0
                time.sleep(0.2)

            elif btn == "LEFT":
                dash = (dash - 1) % DASH_COUNT
                scroll = 0
                time.sleep(0.2)

            elif btn == "UP":
                scroll = max(0, scroll - 1)

            elif btn == "DOWN":
                scroll += 1

            # Draw
            if dash == 0:
                max_items = draw_ap_live(lcd, client, gps, scroll)
                scroll = min(scroll, max(0, max_items - 7))
            elif dash == 1:
                draw_stats(lcd, client, gps)
                scroll = 0
            elif dash == 2:
                max_items = draw_bt_live(lcd, client, scroll)
                scroll = min(scroll, max(0, max_items - 7))
            elif dash == 3:
                max_items = draw_flock_live(lcd, client, scroll)
                scroll = min(scroll, max(0, max_items - 7))
            elif dash == 4:
                draw_connection(lcd, client)
                scroll = 0

            time.sleep(0.05)

    finally:
        _running = False
        client.disconnect()
        ward_logger.close()
        bt_logger.save()
        gps.stop()
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
