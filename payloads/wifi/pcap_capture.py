#!/usr/bin/env python3
"""
RaspyJack Payload -- PCAP Packet Capture
==========================================
Inspired by ESP32 Marauder raw capture mode.

Captures raw WiFi frames in monitor mode to .pcap files with live stats.

Controls:
  CONFIG:   UP/DOWN=change setting  OK=start capture  KEY1=cycle view  KEY3=exit
  CAPTURE:  OK=stop  KEY1=cycle view  KEY2=mark timestamp  KEY3=exit
  FILES:    UP/DOWN=scroll  OK=open detail  KEY1=cycle view  KEY3=exit
"""

import os
import sys
import time
import threading
import subprocess
from datetime import datetime
from collections import deque

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
        sniff as scapy_sniff, conf, PcapWriter,
        Dot11, RadioTap,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "OK": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16,
}
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT

LOOT_DIR = "/root/Raspyjack/loot/PCAP"
MAX_FILE_BYTES = 50 * 1024 * 1024
RATE_WINDOW = 60

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#B388FF"
C_MUTED = "#888888"
C_DIM = "#444444"
C_WHITE = "#FFFFFF"
C_HEADER = "#0d1117"

VIEWS = ["CONFIG", "CAPTURE", "FILES"]
FILTERS = ["ALL", "MGMT", "DATA", "CTRL"]
CHANNELS = [0] + list(range(1, 15))


def _run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT,
                                       timeout=10).decode(errors="replace").strip()
    except Exception:
        return ""


def _setup_monitor(iface):
    _run(f"nmcli device set {iface} managed no")
    _run(f"pkill -f 'wpa_supplicant.*{iface}'")
    time.sleep(0.5)
    info = _run(f"iw dev {iface} info")
    if "type monitor" in info:
        return True, iface
    _run(f"ip link set {iface} down")
    time.sleep(0.3)
    _run(f"iw dev {iface} set type monitor")
    time.sleep(0.3)
    _run(f"ip link set {iface} up")
    time.sleep(0.5)
    if "type monitor" in _run(f"iw dev {iface} info"):
        return True, iface
    _run(f"airmon-ng start {iface}")
    for cand in (f"{iface}mon", iface):
        if "type monitor" in _run(f"iw dev {cand} info"):
            return True, cand
    return False, iface


def _set_channel(iface, ch):
    if ch > 0:
        _run(f"iw dev {iface} set channel {ch}")


def _restore_managed(iface):
    base = iface.replace("mon", "")
    _run(f"ip link set {iface} down")
    time.sleep(0.3)
    _run(f"iw dev {iface} set type managed")
    time.sleep(0.3)
    _run(f"ip link set {base} up")
    _run(f"nmcli device set {base} managed yes")


def _human_size(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f}{u}" if b != int(b) else f"{int(b)}{u}"
        b /= 1024
    return f"{b:.1f}TB"


def _list_pcaps():
    if not os.path.isdir(LOOT_DIR):
        return []
    files = []
    for f in sorted(os.listdir(LOOT_DIR), reverse=True):
        if f.endswith(".pcap"):
            fp = os.path.join(LOOT_DIR, f)
            files.append((f, os.path.getsize(fp)))
    return files


def main():
    if not SCAPY_OK:
        print("scapy required")
        return 1

    os.makedirs(LOOT_DIR, exist_ok=True)
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for p in PINS.values():
        GPIO.setup(p, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(8)
    font_lg = scaled_font(10)
    ROW_H = 12

    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(img)

    iface = select_interface(lcd, font, PINS, GPIO, iface_type="wifi",
                             require_monitor=True)
    if not iface:
        return 0

    view_idx = 0
    cfg_row = 0
    filt_idx = 0
    chan_idx = 0
    capturing = False
    stop_evt = threading.Event()
    mon_iface = iface

    pkt_count = 0
    file_size = 0
    start_time = 0.0
    rate_hist = deque(maxlen=RATE_WINDOW)
    writer = None
    current_file = ""
    file_num = 0
    marks = []
    files_scroll = 0

    def _bpf():
        f = FILTERS[filt_idx]
        if f == "MGMT":
            return "type mgt"
        elif f == "DATA":
            return "type data"
        elif f == "CTRL":
            return "type ctl"
        return ""

    def _new_writer():
        nonlocal writer, current_file, file_num, file_size
        file_num += 1
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"cap_{ts}_{file_num:03d}.pcap"
        current_file = os.path.join(LOOT_DIR, fname)
        writer = PcapWriter(current_file, append=True, sync=True)
        file_size = 0

    def _pkt_handler(pkt):
        nonlocal pkt_count, file_size, writer
        if stop_evt.is_set():
            return
        try:
            writer.write(pkt)
            pkt_count += 1
            pkt_len = len(bytes(pkt))
            file_size += pkt_len
            if file_size >= MAX_FILE_BYTES:
                writer.close()
                _new_writer()
        except Exception:
            pass

    def _sniff_thread():
        try:
            bpf = _bpf()
            kwargs = dict(iface=mon_iface, prn=_pkt_handler, store=False,
                          stop_filter=lambda _: stop_evt.is_set())
            if bpf:
                kwargs["filter"] = bpf
            scapy_sniff(**kwargs)
        except Exception:
            pass

    def _rate_thread():
        prev = 0
        while not stop_evt.is_set():
            time.sleep(1)
            cur = pkt_count
            rate_hist.append(cur - prev)
            prev = cur

    def _draw_header(title):
        draw.rectangle([(0, 0), (WIDTH, 11)], fill=C_HEADER)
        draw.text((2, 0), title, fill=C_CYAN, font=font)
        v = VIEWS[view_idx]
        vw = font.getlength(v) if hasattr(font, "getlength") else len(v) * 5
        draw.text((WIDTH - int(vw) - 2, 0), v, fill=C_MUTED, font=font)

    def _draw_config():
        img.paste(C_BG, [0, 0, WIDTH, HEIGHT])
        _draw_header("PCAP Capture")
        y = 14
        items = [
            ("Interface", mon_iface),
            ("Channel", "Hop" if CHANNELS[chan_idx] == 0 else str(CHANNELS[chan_idx])),
            ("Filter", FILTERS[filt_idx]),
        ]
        for i, (label, val) in enumerate(items):
            c = C_CYAN if i == cfg_row else C_MUTED
            bg = "#1a1a2e" if i == cfg_row else C_BG
            draw.rectangle([(0, y), (WIDTH, y + ROW_H - 1)], fill=bg)
            draw.text((4, y + 1), label, fill=c, font=font)
            draw.text((WIDTH // 2, y + 1), val, fill=C_WHITE, font=font)
            y += ROW_H
        y += 4
        draw.text((4, y), "OK = Start capture", fill=C_GREEN, font=font)
        y += ROW_H
        draw.text((4, y), "KEY1 = Views  KEY3 = Exit", fill=C_DIM, font=font)
        lcd.LCD_ShowImage(img, 0, 0)

    def _draw_capture():
        img.paste(C_BG, [0, 0, WIDTH, HEIGHT])
        _draw_header("CAPTURING")
        elapsed = time.time() - start_time if start_time else 0
        mins, secs = divmod(int(elapsed), 60)
        hrs, mins = divmod(mins, 60)
        y = 14
        draw.text((4, y), f"Time: {hrs:02d}:{mins:02d}:{secs:02d}", fill=C_WHITE, font=font)
        y += ROW_H
        draw.text((4, y), f"Packets: {pkt_count:,}", fill=C_GREEN, font=font)
        y += ROW_H
        draw.text((4, y), f"Size: {_human_size(file_size)}", fill=C_CYAN, font=font)
        y += ROW_H
        cur_rate = rate_hist[-1] if rate_hist else 0
        draw.text((4, y), f"Rate: {cur_rate} pkt/s", fill=C_YELLOW, font=font)
        y += ROW_H
        draw.text((4, y), f"Filter: {FILTERS[filt_idx]}", fill=C_MUTED, font=font)
        y += ROW_H
        ch = CHANNELS[chan_idx]
        draw.text((4, y), f"Ch: {'Hop' if ch == 0 else ch}", fill=C_MUTED, font=font)
        y += ROW_H + 2

        # Sparkline
        if len(rate_hist) > 1:
            spark_w = WIDTH - 8
            spark_h = HEIGHT - y - 14
            if spark_h > 4:
                draw.rectangle([(4, y), (4 + spark_w, y + spark_h)], fill="#111122")
                mx = max(rate_hist) or 1
                pts = list(rate_hist)
                n = len(pts)
                step = max(1, spark_w / max(n - 1, 1))
                for i in range(1, n):
                    x0 = 4 + (i - 1) * step
                    x1 = 4 + i * step
                    y0 = y + spark_h - int(pts[i - 1] / mx * spark_h)
                    y1 = y + spark_h - int(pts[i] / mx * spark_h)
                    draw.line([(x0, y0), (x1, y1)], fill=C_GREEN, width=1)
                y += spark_h + 2

        draw.text((4, HEIGHT - 11), "OK=Stop  K2=Mark  K3=Exit", fill=C_DIM, font=font)
        if marks:
            draw.text((WIDTH - 20, HEIGHT - 11), f"M:{len(marks)}", fill=C_PURPLE, font=font)
        lcd.LCD_ShowImage(img, 0, 0)

    def _draw_files():
        img.paste(C_BG, [0, 0, WIDTH, HEIGHT])
        _draw_header("Saved PCAPs")
        pcaps = _list_pcaps()
        if not pcaps:
            draw.text((4, 50), "No captures yet", fill=C_MUTED, font=font)
            lcd.LCD_ShowImage(img, 0, 0)
            return
        max_rows = (HEIGHT - 26) // ROW_H
        visible = pcaps[files_scroll:files_scroll + max_rows]
        y = 14
        for i, (name, sz) in enumerate(visible):
            c = C_WHITE if i == 0 else C_MUTED
            short = name[:16] if len(name) > 16 else name
            draw.text((4, y), short, fill=c, font=font)
            draw.text((WIDTH - 40, y), _human_size(sz), fill=C_CYAN, font=font)
            y += ROW_H
        total = sum(s for _, s in pcaps)
        draw.text((4, HEIGHT - 11), f"{len(pcaps)} files  {_human_size(total)}", fill=C_DIM, font=font)
        lcd.LCD_ShowImage(img, 0, 0)

    def _start_capture():
        nonlocal capturing, pkt_count, file_size, start_time, mon_iface
        nonlocal rate_hist, marks, writer
        stop_evt.clear()
        ok, mon_iface = _setup_monitor(iface)
        if not ok:
            img.paste(C_BG, [0, 0, WIDTH, HEIGHT])
            draw.text((4, 50), "Monitor mode failed!", fill=C_RED, font=font)
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(2)
            return False
        ch = CHANNELS[chan_idx]
        if ch > 0:
            _set_channel(mon_iface, ch)
        pkt_count = 0
        file_size = 0
        start_time = time.time()
        rate_hist = deque(maxlen=RATE_WINDOW)
        marks = []
        _new_writer()
        capturing = True
        threading.Thread(target=_sniff_thread, daemon=True).start()
        threading.Thread(target=_rate_thread, daemon=True).start()
        if ch == 0:
            threading.Thread(target=_hop_thread, daemon=True).start()
        return True

    def _hop_thread():
        ch = 1
        while not stop_evt.is_set():
            _set_channel(mon_iface, ch)
            ch = ch % 14 + 1
            time.sleep(0.3)

    def _stop_capture():
        nonlocal capturing
        stop_evt.set()
        time.sleep(0.5)
        capturing = False
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        _restore_managed(mon_iface)

    try:
        _draw_config()
        while True:
            btn = get_button(PINS, GPIO, timeout=0.3 if capturing else None)

            if btn == "KEY3":
                if capturing:
                    _stop_capture()
                break

            if btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                if not capturing and view_idx == 1:
                    view_idx = 2

            if not capturing:
                v = VIEWS[view_idx]
                if v == "CONFIG":
                    if btn == "UP":
                        cfg_row = (cfg_row - 1) % 3
                    elif btn == "DOWN":
                        cfg_row = (cfg_row + 1) % 3
                    elif btn in ("LEFT", "RIGHT"):
                        d = 1 if btn == "RIGHT" else -1
                        if cfg_row == 1:
                            chan_idx = (chan_idx + d) % len(CHANNELS)
                        elif cfg_row == 2:
                            filt_idx = (filt_idx + d) % len(FILTERS)
                    elif btn == "OK":
                        if _start_capture():
                            view_idx = 1
                    _draw_config()
                elif v == "FILES":
                    pcaps = _list_pcaps()
                    if btn == "UP":
                        files_scroll = max(0, files_scroll - 1)
                    elif btn == "DOWN":
                        files_scroll = min(max(0, len(pcaps) - 5), files_scroll + 1)
                    _draw_files()
            else:
                if btn == "OK":
                    _stop_capture()
                    view_idx = 2
                    _draw_files()
                elif btn == "KEY2":
                    marks.append((time.time() - start_time, pkt_count))
                _draw_capture()

    except KeyboardInterrupt:
        pass
    finally:
        if capturing:
            _stop_capture()
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
