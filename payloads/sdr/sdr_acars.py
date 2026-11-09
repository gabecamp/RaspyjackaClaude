#!/usr/bin/env python3
"""
RaspyJack Payload -- ACARS Decoder
====================================
Decode aircraft ACARS messages on 129.125, 130.025, 131.550 MHz
using RTL-SDR + acarsdec. Displays flight ID, registration,
message type, and text content.

Controls:
  OK         Start / stop decoding
  UP / DOWN  Scroll messages
  KEY1       Cycle view (MESSAGES / DETAIL / STATS / FREQ)
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
from collections import defaultdict

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
LOOT_DIR = "/root/Raspyjack/loot/SDR/acars"
DEBOUNCE = 0.18
VIEWS = ["MESSAGES", "DETAIL", "STATS", "FREQ"]
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

ACARS_FREQS = ["129.125", "130.025", "131.550"]
ACARS_FREQS_HZ = [129125000, 130025000, 131550000]

MSG_LABELS = {
    "H1": "HF data link",
    "5Z": "Squawk code",
    "SQ": "OOOI departure",
    "RA": "OOOI arrival",
    "_d": "Command",
    "Q0": "Link test",
    "SA": "Weather",
    "B6": "Takeoff report",
    "B9": "Landing report",
}

messages = []
freq_counts = defaultdict(int)
lock = threading.Lock()
_shutdown = threading.Event()
_last_btn = 0


def _btn():
    global _last_btn
    b = get_button(PINS)
    if b and time.time() - _last_btn > DEBOUNCE:
        _last_btn = time.time()
        return b
    return None


def _parse_acars_json(line):
    """Parse acarsdec JSON output line."""
    try:
        data = json.loads(line)
        return {
            "time": data.get("timestamp", datetime.now().strftime("%H:%M:%S")),
            "freq": data.get("freq", 0),
            "channel": data.get("channel", 0),
            "flight": data.get("flight", "").strip(),
            "reg": data.get("tail", "").strip(),
            "label": data.get("label", "").strip(),
            "blk_id": data.get("block_id", ""),
            "ack": data.get("ack", ""),
            "mode": data.get("mode", ""),
            "text": data.get("text", "").strip(),
            "level": data.get("level", 0),
            "error": data.get("error", 0),
        }
    except (json.JSONDecodeError, KeyError):
        return None


def _parse_acars_text(line):
    """Parse acarsdec text output (fallback)."""
    m = re.match(
        r"\[#(\d+)\s.*?(\d+\.\d+)\s+.*?Mode:\s*(\S+).*?Reg:\s*(\S+).*?"
        r"Flight:\s*(\S*).*?Label:\s*(\S*).*?Blk:\s*(\S*).*?Ack:\s*(\S*)"
        r"(?:.*?Msg:\s*(.*))?",
        line, re.DOTALL,
    )
    if not m:
        return None
    return {
        "time": datetime.now().strftime("%H:%M:%S"),
        "freq": float(m.group(2)) if m.group(2) else 0,
        "channel": int(m.group(1)),
        "flight": m.group(5).strip(),
        "reg": m.group(4).strip(),
        "label": m.group(6).strip(),
        "blk_id": m.group(7).strip(),
        "ack": m.group(8).strip(),
        "mode": m.group(3).strip(),
        "text": (m.group(9) or "").strip(),
        "level": 0,
        "error": 0,
    }


def _label_desc(label):
    return MSG_LABELS.get(label, "")


def _receiver_thread():
    proc = None
    try:
        gain = recommended_gain(131_000_000)
        has_acarsdec = subprocess.run(
            ["which", "acarsdec"], capture_output=True
        ).returncode == 0
        if has_acarsdec:
            cmd = [
                "acarsdec", "-j", "-g", str(gain), "-r", "0",
            ]
            for freq in ACARS_FREQS:
                cmd.append(freq)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
        else:
            freq_str = ",".join(str(f) for f in ACARS_FREQS_HZ)
            proc = subprocess.Popen(
                [
                    "rtl_fm", "-M", "am", "-f", str(ACARS_FREQS_HZ[0]),
                    "-s", "12500", "-g", str(gain), "-",
                ],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )

        if not proc or not proc.stdout:
            return

        while not _shutdown.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            if isinstance(line, bytes):
                continue
            line = line.strip()
            if not line:
                continue
            msg = _parse_acars_json(line)
            if not msg:
                msg = _parse_acars_text(line)
            if not msg:
                continue
            freq_key = f"{msg.get('freq', 0):.3f}" if msg.get("freq") else "unk"
            with lock:
                messages.append(msg)
                if len(messages) > 500:
                    messages.pop(0)
                freq_counts[freq_key] += 1
    except Exception:
        pass
    finally:
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass


def _draw_header(d, font, title, extra=""):
    d.rectangle([(0, 0), (WIDTH, S(13))], fill=C_HEADER)
    d.text((S(2), S(1)), title, font=font, fill=C_CYAN)
    if extra:
        d.text((WIDTH - S(2) - len(extra) * S(5), S(1)), extra, font=font, fill=C_MUTED)


def _draw_messages(d, font, scroll):
    with lock:
        mlist = list(messages)
    _draw_header(d, font, "ACARS", f"{len(mlist)} msgs")
    if not mlist:
        d.text((S(4), S(50)), "No messages yet", font=font, fill=C_MUTED)
        return
    y = S(15)
    visible = (HEIGHT - S(15)) // ROW_H
    display = list(reversed(mlist))
    for i in range(scroll, min(scroll + visible, len(display))):
        m = display[i]
        t = m["time"][-5:]
        flt = m["flight"][:7] or m["reg"][:7] or "---"
        lbl = m["label"][:2] or "??"
        txt = m["text"][:8] or ""
        row = f"{t} {flt:<7} {lbl} {txt}"
        d.text((S(2), y), row[:24], font=font, fill=C_WHITE)
        y += ROW_H


def _draw_detail(d, font, scroll):
    with lock:
        mlist = list(reversed(messages))
    if not mlist or scroll >= len(mlist):
        _draw_header(d, font, "DETAIL")
        d.text((S(4), S(50)), "No message", font=font, fill=C_MUTED)
        return
    m = mlist[scroll]
    _draw_header(d, font, m["flight"][:8] or m["reg"][:8] or "ACARS")
    y = S(16)
    lines = [
        f"Time:   {m['time']}",
        f"Flight: {m['flight'] or '---'}",
        f"Reg:    {m['reg'] or '---'}",
        f"Label:  {m['label']} {_label_desc(m['label'])[:12]}",
        f"Mode:   {m['mode']}",
        f"Block:  {m['blk_id']}  Ack:{m['ack']}",
    ]
    if m["text"]:
        words = m["text"]
        while words:
            lines.append(words[:22])
            words = words[22:]
    for line in lines:
        if y > HEIGHT - ROW_H:
            break
        d.text((S(4), y), line[:24], font=font, fill=C_WHITE)
        y += ROW_H


def _draw_stats(d, font):
    with lock:
        n = len(messages)
        flights = len(set(m["flight"] for m in messages if m["flight"]))
        regs = len(set(m["reg"] for m in messages if m["reg"]))
        labels = defaultdict(int)
        for m in messages:
            if m["label"]:
                labels[m["label"]] += 1
    _draw_header(d, font, "ACARS STATS")
    y = S(18)
    d.text((S(4), y), f"Messages:  {n}", font=font, fill=C_WHITE); y += ROW_H
    d.text((S(4), y), f"Flights:   {flights}", font=font, fill=C_WHITE); y += ROW_H
    d.text((S(4), y), f"Aircraft:  {regs}", font=font, fill=C_WHITE); y += ROW_H
    y += S(4)
    d.text((S(4), y), "Top labels:", font=font, fill=C_YELLOW); y += ROW_H
    top = sorted(labels.items(), key=lambda x: x[1], reverse=True)[:4]
    for lbl, cnt in top:
        desc = _label_desc(lbl)[:14]
        d.text((S(6), y), f"{lbl}: {cnt:>3}  {desc}", font=font, fill=C_MUTED)
        y += ROW_H
        if y > HEIGHT - ROW_H:
            break


def _draw_freq(d, font):
    with lock:
        fc = dict(freq_counts)
    _draw_header(d, font, "FREQ ACTIVITY")
    y = S(18)
    if not fc:
        d.text((S(4), S(50)), "No data yet", font=font, fill=C_MUTED)
        return
    total = sum(fc.values()) or 1
    for freq_str in ACARS_FREQS:
        key = freq_str
        cnt = fc.get(key, 0)
        pct = cnt / total * 100
        bar_w = int((WIDTH - S(80)) * pct / 100)
        d.text((S(4), y), f"{freq_str}", font=font, fill=C_WHITE)
        d.rectangle([(S(60), y + S(1)), (S(60) + max(bar_w, 1), y + S(9))], fill=C_BLUE)
        d.text((S(60) + bar_w + S(3), y), f"{cnt}", font=font, fill=C_MUTED)
        y += ROW_H + S(4)
    for key, cnt in sorted(fc.items(), key=lambda x: x[1], reverse=True):
        if key in ACARS_FREQS:
            continue
        if y > HEIGHT - ROW_H:
            break
        d.text((S(4), y), f"{key}: {cnt}", font=font, fill=C_MUTED)
        y += ROW_H


def _export():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with lock:
        data = {"timestamp": ts, "messages": list(messages), "freq_counts": dict(freq_counts)}
    path = os.path.join(LOOT_DIR, f"acars_{ts}.json")
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

    has_acarsdec = subprocess.run(
        ["which", "acarsdec"], capture_output=True
    ).returncode == 0
    if not has_acarsdec:
        img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
        d = ScaledDraw(img)
        d.text((S(4), S(40)), "acarsdec not found", font=font, fill=C_RED)
        d.text((S(4), S(54)), "apt install acarsdec", font=font, fill=C_MUTED)
        lcd.LCD_ShowImage(img, 0, 0)
        time.sleep(3)
        GPIO.cleanup()
        return 1

    tracking = False
    rx_thread = None
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
            if view == "MESSAGES":
                _draw_messages(d, font, scroll)
            elif view == "DETAIL":
                _draw_detail(d, font, scroll)
            elif view == "STATS":
                _draw_stats(d, font)
            elif view == "FREQ":
                _draw_freq(d, font)
            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.15)
    finally:
        _shutdown.set()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
