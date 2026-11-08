#!/usr/bin/env python3
"""
RaspyJack Payload -- Pwnagotchi Detector
=========================================
Author: gabecamp / Claude

Detects Pwnagotchi devices by sniffing WiFi beacon frames in monitor mode.
Pwnagotchis embed JSON metadata in vendor-specific Information Elements
(IE 222) containing fields like identity, version, pwnd_run, pwnd_tot,
uptime, and epoch.  Also flags ESSIDs matching common Pwnagotchi naming
patterns as candidates even without the custom IE.

Setup / Prerequisites
---------------------
- WiFi adapter supporting monitor mode (wlan1mon)
- scapy (python3-scapy)

Controls
--------
  OK         -- Start / stop scanning
  UP / DOWN  -- Scroll device list
  RIGHT      -- Show device details
  KEY1       -- Reset all data
  KEY2       -- Export JSON to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/PwnDetect/
"""

import os
import sys
import json
import time
import re
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image, ImageDraw, ImageFont
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/PwnDetect"
ROW_H = 12
ROWS_VISIBLE = 6
IFACE = None

PWN_ESSID_RE = re.compile(r"(pwnagotchi|pwn[^a-z]|pwny)", re.IGNORECASE)
PWN_JSON_KEYS = {"identity", "version", "pwnd_run", "pwnd_tot", "uptime", "epoch"}

lock = threading.Lock()
running = True
scanning = False
status_msg = "Idle"
scroll_pos = 0
selected_idx = 0

devices = {}


def _parse_pwnagotchi_ie(pkt):
    from scapy.all import Dot11Elt
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 222 and elt.info:
            try:
                raw = elt.info
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="ignore")
                start = raw.find("{")
                if start >= 0:
                    data = json.loads(raw[start:])
                    if isinstance(data, dict) and len(PWN_JSON_KEYS & set(data.keys())) >= 3:
                        return data
            except (json.JSONDecodeError, ValueError):
                pass
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return None


def _get_essid(pkt):
    from scapy.all import Dot11Elt
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0 and elt.info:
            try:
                return elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return ""


def _get_channel(pkt):
    from scapy.all import Dot11Elt
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and elt.info and len(elt.info) >= 1:
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return 0


def _sniff_thread():
    global scanning, status_msg
    from scapy.all import sniff, Dot11Beacon, RadioTap

    with lock:
        scanning = True
        status_msg = "Scanning..."

    def _process(pkt):
        if not running or not scanning:
            return

        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt.addr2
        if not bssid:
            return
        bssid = bssid.upper()

        essid = _get_essid(pkt)
        channel = _get_channel(pkt)
        rssi = getattr(pkt, "dBm_AntSignal", -99) if pkt.haslayer(RadioTap) else -99

        pwn_data = _parse_pwnagotchi_ie(pkt)
        is_name_match = bool(PWN_ESSID_RE.search(essid)) if essid else False

        if not pwn_data and not is_name_match:
            return

        now_str = datetime.now().strftime("%H:%M:%S")
        name = ""
        version = ""
        pwnd_run = 0
        pwnd_tot = 0
        uptime = 0
        identity = ""
        confirmed = False

        if pwn_data:
            confirmed = True
            name = str(pwn_data.get("name", pwn_data.get("identity", essid)))
            version = str(pwn_data.get("version", "?"))
            pwnd_run = int(pwn_data.get("pwnd_run", 0))
            pwnd_tot = int(pwn_data.get("pwnd_tot", 0))
            uptime = int(pwn_data.get("uptime", 0))
            identity = str(pwn_data.get("identity", ""))
        else:
            name = essid

        with lock:
            if bssid in devices:
                prev = devices[bssid]
                devices[bssid] = {
                    **prev,
                    "name": name or prev["name"],
                    "rssi": rssi,
                    "channel": channel or prev["channel"],
                    "last_seen": now_str,
                    "count": prev["count"] + 1,
                    "confirmed": confirmed or prev["confirmed"],
                    "version": version or prev["version"],
                    "pwnd_run": max(pwnd_run, prev["pwnd_run"]),
                    "pwnd_tot": max(pwnd_tot, prev["pwnd_tot"]),
                    "uptime": max(uptime, prev["uptime"]),
                    "identity": identity or prev["identity"],
                }
            else:
                devices[bssid] = {
                    "bssid": bssid,
                    "name": name,
                    "essid": essid,
                    "rssi": rssi,
                    "channel": channel,
                    "first_seen": now_str,
                    "last_seen": now_str,
                    "count": 1,
                    "confirmed": confirmed,
                    "version": version,
                    "pwnd_run": pwnd_run,
                    "pwnd_tot": pwnd_tot,
                    "uptime": uptime,
                    "identity": identity,
                }

    try:
        sniff(
            iface=IFACE,
            prn=_process,
            store=False,
            stop_filter=lambda _: not running or not scanning,
        )
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:14]}"
    finally:
        with lock:
            scanning = False
            if "Err" not in status_msg:
                status_msg = "Stopped"


def _sorted_devices():
    with lock:
        items = list(devices.values())
    items.sort(key=lambda d: (not d["confirmed"], d["rssi"] * -1))
    return items


def _export_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"pwn_detect_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "interface": IFACE,
            "devices": list(devices.values()),
        }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


def _draw_header(d, fnt, active):
    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "PWN DETECT", font=fnt, fill="#FF00FF")
    d.ellipse((118, 3, 122, 7), fill="#00FF00" if active else "#FF0000")


def _draw_footer(d, fnt, text):
    d.rectangle((0, 116, 127, 127), fill="#111")
    d.text((2, 117), text[:24], font=fnt, fill="#AAA")


def _draw_main(lcd, fnt):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    with lock:
        active = scanning
        st = status_msg
        n = len(devices)
        sel = selected_idx
        sc = scroll_pos

    _draw_header(d, fnt, active)
    d.text((2, 15), f"{st[:14]} Found:{n}", font=fnt, fill="#888")

    devs = _sorted_devices()
    if not devs:
        d.text((6, 40), "No Pwnagotchi yet", font=fnt, fill="#666")
        d.text((6, 52), "Listening for beacons", font=fnt, fill="#666")
        d.text((6, 64), "with PWN metadata...", font=fnt, fill="#666")
    else:
        visible = devs[sc:sc + ROWS_VISIBLE]
        for i, dev in enumerate(visible):
            y = 28 + i * ROW_H
            idx = sc + i
            prefix = ">" if idx == sel else " "
            tag = "*" if dev["confirmed"] else "?"
            name = (dev["name"] or dev["bssid"][-8:])[:10]
            rssi = dev["rssi"]
            clr = "#00FF00" if dev["confirmed"] else "#FFAA00"
            line = f"{prefix}{tag}{name} {rssi}dB"
            d.text((1, y), line[:22], font=fnt, fill=clr)

        if len(devs) > ROWS_VISIBLE:
            bar_h = max(4, int(ROWS_VISIBLE / len(devs) * 80))
            bar_y = 28 + int(sc / len(devs) * 80)
            d.rectangle((126, bar_y, 127, bar_y + bar_h), fill="#444")

    lbl = "OK:Stop" if active else "OK:Scan"
    _draw_footer(d, fnt, f"{lbl} K2:Save K3:X")
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_detail(lcd, fnt, dev):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    tag = "CONFIRMED" if dev["confirmed"] else "CANDIDATE"
    d.text((2, 1), tag, font=fnt, fill="#FF00FF")

    lines = [
        f"Name: {dev['name'][:16]}",
        f"BSSID: {dev['bssid']}",
        f"ESSID: {dev['essid'][:16]}",
        f"Ch:{dev['channel']} RSSI:{dev['rssi']}dB",
        f"Ver: {dev['version']}" if dev["version"] else "",
        f"Pwnd: {dev['pwnd_run']}/{dev['pwnd_tot']}" if dev["confirmed"] else "",
        f"Up: {dev['uptime']}s" if dev["uptime"] else "",
        f"ID: {dev['identity'][:16]}" if dev["identity"] else "",
        f"First: {dev['first_seen']}",
        f"Last: {dev['last_seen']} x{dev['count']}",
    ]
    lines = [l for l in lines if l]

    y = 16
    for line in lines[:8]:
        d.text((2, y), line[:22], font=fnt, fill="#CCCCCC")
        y += ROW_H

    _draw_footer(d, fnt, "Any key: back")
    lcd.LCD_ShowImage(img, 0, 0)


def _show_message(lcd, fnt, line1, line2=""):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((10, 50), line1, font=fnt, fill="#00FF00")
    if line2:
        d.text((4, 65), line2, font=fnt, fill="#888")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)


def main():
    global running, scanning, scroll_pos, selected_idx, devices, IFACE, status_msg

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    fnt = scaled_font()

    selected = select_interface(lcd, fnt, PINS, GPIO, iface_type="wifi")
    if not selected:
        GPIO.cleanup()
        return 1
    IFACE = selected

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 16), "PWNAGOTCHI DETECT", font=fnt, fill="#FF00FF")
    d.text((4, 32), "Finds Pwnagotchi by", font=fnt, fill="#888")
    d.text((4, 44), "beacon frame metadata", font=fnt, fill="#888")
    d.text((4, 56), "(IE 222 JSON payload)", font=fnt, fill="#888")
    d.text((4, 72), f"Iface: {IFACE}", font=fnt, fill="#666")
    d.text((4, 84), "OK:Scan K2:Export", font=fnt, fill="#666")
    d.text((4, 96), "K3:Exit", font=fnt, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(1.5)

    detail_view = False
    scan_thread = None

    try:
        while True:
            btn = get_button(PINS, GPIO)

            if btn == "KEY3":
                running = False
                scanning = False
                if devices:
                    _export_loot()
                break

            if detail_view:
                if btn is not None:
                    detail_view = False
                    time.sleep(0.2)
            else:
                if btn == "OK":
                    with lock:
                        active = scanning
                    if active:
                        scanning = False
                        with lock:
                            status_msg = "Stopped"
                    else:
                        running = True
                        scan_thread = threading.Thread(target=_sniff_thread, daemon=True)
                        scan_thread.start()
                    time.sleep(0.3)

                elif btn == "RIGHT":
                    devs = _sorted_devices()
                    with lock:
                        sel = selected_idx
                    if devs and 0 <= sel < len(devs):
                        _draw_detail(lcd, fnt, devs[sel])
                        detail_view = True
                    time.sleep(0.3)

                elif btn == "KEY1":
                    with lock:
                        devices = {}
                        scroll_pos = 0
                        selected_idx = 0
                    _show_message(lcd, fnt, "Data reset")
                    time.sleep(0.2)

                elif btn == "KEY2":
                    with lock:
                        has_data = len(devices) > 0
                    if has_data:
                        path = _export_loot()
                        _show_message(lcd, fnt, "Exported!", path[-20:])
                    else:
                        _show_message(lcd, fnt, "No data yet")
                    time.sleep(0.3)

                elif btn == "UP":
                    with lock:
                        selected_idx = max(0, selected_idx - 1)
                        if selected_idx < scroll_pos:
                            scroll_pos = selected_idx
                    time.sleep(0.15)

                elif btn == "DOWN":
                    devs = _sorted_devices()
                    with lock:
                        selected_idx = min(selected_idx + 1, max(0, len(devs) - 1))
                        if selected_idx >= scroll_pos + ROWS_VISIBLE:
                            scroll_pos = selected_idx - ROWS_VISIBLE + 1
                    time.sleep(0.15)

            if not detail_view:
                _draw_main(lcd, fnt)

            time.sleep(0.05)

    finally:
        running = False
        scanning = False
        time.sleep(0.3)
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
