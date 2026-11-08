#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Channel Activity Monitor
====================================================
Real-time 2.4 GHz channel spectrum analyzer inspired by ESP32 Marauder.
Hops channels 1-13 with scapy in monitor mode, counts packets per channel,
and draws a live bar chart colour-coded by congestion.

Controls
--------
  OK          -- Start / stop monitoring
  KEY1        -- Cycle view (SPECTRUM / AP_MAP / DETAIL)
  UP / DOWN   -- Scroll in list views / select channel in spectrum
  LEFT        -- Back / exit
  KEY2        -- Export snapshot to loot
  KEY3        -- Exit

Loot: /root/Raspyjack/loot/ChannelMonitor/
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface, supports_monitor

try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp,
        RadioTap, sniff as scapy_sniff, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

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

LOOT_DIR = "/root/Raspyjack/loot/ChannelMonitor"
CHANNELS = list(range(1, 14))
DWELL_SEC = 0.30
VIEWS = ["SPECTRUM", "AP_MAP", "DETAIL"]
ROW_H = 12
ROWS_VIS = 7

C_BG = "#0a0a12"
C_HEADER = "#0d1117"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_YELLOW = "#FFD740"
C_RED = "#FF5252"
C_MUTED = "#888888"
C_DIM = "#444444"
C_WHITE = "#FFFFFF"
C_PURPLE = "#7C4DFF"

lock = threading.Lock()
pkt_counts = defaultdict(int)
ap_db = {}
cur_channel = 1
monitoring = False
mon_iface = None
view_idx = 0
scroll_pos = 0
sel_channel = 1
status_msg = "Idle"
_running = True
_selected_iface = None


def _enable_monitor(iface):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   capture_output=True, timeout=5)
    return iface


def _disable_monitor(iface):
    try:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "iw", iface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def _set_channel(iface, ch):
    subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)],
                   capture_output=True, timeout=3)


def _pkt_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    ch = cur_channel
    with lock:
        pkt_counts[ch] += 1

    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = (pkt[Dot11].addr2 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return
        ssid = ""
        elt = pkt[Dot11Elt]
        if elt and elt.ID == 0:
            try:
                ssid = elt.info.decode("utf-8", errors="replace")
            except Exception:
                pass
        beacon_ch = 0
        e = pkt[Dot11Elt]
        while e:
            if e.ID == 3 and e.info:
                beacon_ch = e.info[0]
                break
            e = e.payload if hasattr(e, "payload") and isinstance(e.payload, Dot11Elt) else None
        signal = -100
        if pkt.haslayer(RadioTap):
            try:
                signal = pkt[RadioTap].dBm_AntSignal
            except Exception:
                pass
        real_ch = beacon_ch if beacon_ch else ch
        with lock:
            key = bssid
            if key not in ap_db:
                ap_db[key] = {
                    "ssid": ssid, "bssid": bssid, "channel": real_ch,
                    "signal": signal, "seen": 1,
                }
            else:
                entry = ap_db[key]
                entry["ssid"] = ssid or entry["ssid"]
                entry["channel"] = real_ch or entry["channel"]
                entry["signal"] = signal if signal > -100 else entry["signal"]
                entry["seen"] += 1


def _channel_hop():
    global cur_channel
    idx = 0
    while True:
        with lock:
            if not monitoring:
                break
            iface = mon_iface
        if not iface:
            break
        ch = CHANNELS[idx]
        cur_channel = ch
        _set_channel(iface, ch)
        idx = (idx + 1) % len(CHANNELS)
        time.sleep(DWELL_SEC)


def _sniff_loop():
    global status_msg
    with lock:
        iface = mon_iface
    if not iface:
        return
    try:
        scapy_sniff(
            iface=iface,
            prn=_pkt_handler,
            store=False,
            stop_filter=lambda _: not monitoring,
            timeout=300,
        )
    except Exception as exc:
        status_msg = f"Sniff err: {exc}"[:28]


def _bar_color(count, max_count):
    if max_count == 0:
        return C_GREEN
    ratio = count / max_count
    if ratio < 0.33:
        return C_GREEN
    elif ratio < 0.66:
        return C_YELLOW
    return C_RED


def _draw_spectrum(draw):
    draw.rectangle([(0, 0), (WIDTH - 1, HEIGHT - 1)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH - 1, 11)], fill=C_HEADER)
    draw.text((2, 1), "CH SPECTRUM", fill=C_CYAN, font=font)
    total = sum(pkt_counts[ch] for ch in CHANNELS)
    draw.text((WIDTH - 40, 1), f"{total}pkt", fill=C_MUTED, font=font)

    bar_area_top = 14
    bar_area_bot = HEIGHT - 14
    bar_h = bar_area_bot - bar_area_top
    bar_w = max(1, (WIDTH - 4) // 13 - 1)
    margin = max(1, ((WIDTH - 4) - 13 * (bar_w + 1)) // 2)

    with lock:
        counts = [pkt_counts[ch] for ch in CHANNELS]
    max_c = max(counts) if counts else 1
    if max_c == 0:
        max_c = 1

    for i, ch in enumerate(CHANNELS):
        x = 2 + margin + i * (bar_w + 1)
        c = counts[i]
        h = max(1, int(c / max_c * bar_h)) if c > 0 else 0
        color = _bar_color(c, max_c)
        if ch == sel_channel:
            draw.rectangle([(x - 1, bar_area_top - 1), (x + bar_w, bar_area_bot + 1)],
                           outline=C_CYAN, width=1)
        if h > 0:
            draw.rectangle([(x, bar_area_bot - h), (x + bar_w - 1, bar_area_bot)],
                           fill=color)
        draw.text((x, bar_area_bot + 2), str(ch), fill=C_DIM, font=font)

    aps_on_sel = sum(1 for a in ap_db.values() if a["channel"] == sel_channel)
    info = f"Ch{sel_channel}: {counts[sel_channel - 1]}pkt {aps_on_sel}AP"
    draw.text((2, HEIGHT - 12), info, fill=C_WHITE, font=font)
    st_color = C_GREEN if monitoring else C_MUTED
    draw.text((WIDTH - 22, HEIGHT - 12), "RUN" if monitoring else "IDLE", fill=st_color, font=font)


def _draw_ap_map(draw):
    draw.rectangle([(0, 0), (WIDTH - 1, HEIGHT - 1)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH - 1, 11)], fill=C_HEADER)
    draw.text((2, 1), "AP MAP", fill=C_CYAN, font=font)
    draw.text((WIDTH - 40, 1), f"{len(ap_db)}AP", fill=C_MUTED, font=font)

    ch_aps = defaultdict(list)
    with lock:
        for ap in ap_db.values():
            ch_aps[ap["channel"]].append(ap)
    lines = []
    for ch in CHANNELS:
        aps = ch_aps.get(ch, [])
        if aps:
            lines.append((f"Ch{ch:2d} [{len(aps)}]", C_CYAN, True))
            for ap in sorted(aps, key=lambda a: a["signal"], reverse=True)[:3]:
                ssid = ap["ssid"][:14] or "<hidden>"
                lines.append((f" {ssid} {ap['signal']}dB", C_WHITE, False))

    if not lines:
        lines.append(("No APs found", C_MUTED, False))

    visible = lines[scroll_pos:scroll_pos + ROWS_VIS]
    for i, (text, color, _) in enumerate(visible):
        draw.text((2, 14 + i * ROW_H), text, fill=color, font=font)

    if len(lines) > ROWS_VIS:
        pct = scroll_pos / max(1, len(lines) - ROWS_VIS)
        sb_h = max(4, int(ROWS_VIS / len(lines) * (ROWS_VIS * ROW_H)))
        sb_y = int(14 + pct * (ROWS_VIS * ROW_H - sb_h))
        draw.rectangle([(WIDTH - 3, sb_y), (WIDTH - 1, sb_y + sb_h)], fill=C_DIM)


def _draw_detail(draw):
    draw.rectangle([(0, 0), (WIDTH - 1, HEIGHT - 1)], fill=C_BG)
    draw.rectangle([(0, 0), (WIDTH - 1, 11)], fill=C_HEADER)
    draw.text((2, 1), f"CH {sel_channel} DETAIL", fill=C_CYAN, font=font)

    with lock:
        aps = [a for a in ap_db.values() if a["channel"] == sel_channel]
        count = pkt_counts[sel_channel]
    draw.text((WIDTH - 40, 1), f"{count}pkt", fill=C_MUTED, font=font)

    lines = []
    aps_sorted = sorted(aps, key=lambda a: a["signal"], reverse=True)
    for ap in aps_sorted:
        ssid = ap["ssid"][:16] or "<hidden>"
        lines.append((ssid, C_WHITE))
        lines.append((f" {ap['bssid'][:17]}", C_DIM))
        lines.append((f" Sig:{ap['signal']}dB Seen:{ap['seen']}", C_MUTED))

    if not lines:
        lines.append(("No APs on this channel", C_MUTED))

    visible = lines[scroll_pos:scroll_pos + ROWS_VIS]
    for i, (text, color) in enumerate(visible):
        draw.text((2, 14 + i * ROW_H), text, fill=color, font=font)


def _export_snapshot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "channels": {},
        "aps": [],
    }
    with lock:
        for ch in CHANNELS:
            ch_aps = [a["bssid"] for a in ap_db.values() if a["channel"] == ch]
            data["channels"][ch] = {"packets": pkt_counts[ch], "aps": ch_aps}
        for ap in ap_db.values():
            data["aps"].append({
                "ssid": ap["ssid"], "bssid": ap["bssid"],
                "channel": ap["channel"], "signal": ap["signal"],
                "seen": ap["seen"],
            })
    path = os.path.join(LOOT_DIR, f"channel_snap_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def main():
    global monitoring, mon_iface, view_idx, scroll_pos, sel_channel
    global status_msg, _running, _selected_iface

    if not SCAPY_OK:
        image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        draw = ScaledDraw(image)
        draw.text((4, 50), "scapy not found", fill=C_RED, font=font)
        LCD.LCD_ShowImage(image, 0, 0)
        time.sleep(3)
        return 0

    _selected_iface = select_interface(
        LCD, font, PINS, need_monitor=True,
        title="Chan Monitor",
    )
    if not _selected_iface:
        return 0

    hop_thread = None
    sniff_thread = None

    try:
        while _running:
            image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
            draw = ScaledDraw(image)

            view = VIEWS[view_idx]
            if view == "SPECTRUM":
                _draw_spectrum(draw)
            elif view == "AP_MAP":
                _draw_ap_map(draw)
            else:
                _draw_detail(draw)

            LCD.LCD_ShowImage(image, 0, 0)

            btn = get_button(PINS, timeout=0.25)
            if not btn:
                continue

            if btn == "KEY3" or (btn == "LEFT" and not monitoring):
                _running = False
                break

            elif btn == "OK":
                if not monitoring:
                    status_msg = "Starting..."
                    mon_iface = _enable_monitor(_selected_iface)
                    monitoring = True
                    hop_thread = threading.Thread(target=_channel_hop, daemon=True)
                    sniff_thread = threading.Thread(target=_sniff_loop, daemon=True)
                    hop_thread.start()
                    sniff_thread.start()
                    status_msg = "Monitoring"
                else:
                    monitoring = False
                    status_msg = "Stopped"
                    if hop_thread:
                        hop_thread.join(timeout=2)
                    if sniff_thread:
                        sniff_thread.join(timeout=2)

            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll_pos = 0

            elif btn == "UP":
                if view == "SPECTRUM":
                    sel_channel = max(1, sel_channel - 1)
                else:
                    scroll_pos = max(0, scroll_pos - 1)

            elif btn == "DOWN":
                if view == "SPECTRUM":
                    sel_channel = min(13, sel_channel + 1)
                else:
                    scroll_pos += 1

            elif btn == "KEY2":
                path = _export_snapshot()
                status_msg = "Exported!"
                image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
                draw = ScaledDraw(image)
                draw.text((4, 50), "Snapshot saved", fill=C_GREEN, font=font)
                draw.text((4, 64), os.path.basename(path)[:20], fill=C_MUTED, font=font)
                LCD.LCD_ShowImage(image, 0, 0)
                time.sleep(1.5)

    finally:
        monitoring = False
        if hop_thread:
            hop_thread.join(timeout=2)
        if sniff_thread:
            sniff_thread.join(timeout=2)
        if mon_iface:
            _disable_monitor(mon_iface)
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
