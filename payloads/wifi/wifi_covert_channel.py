#!/usr/bin/env python3
"""
RaspyJack Payload -- WiFi Covert Channel
=========================================
Author: RaspyJack Contributors

Steganographic data channel over 802.11 beacon frames.  Data is encoded
in vendor-specific Information Elements (IE 221) with a private OUI
marker.  No association is required -- both ends operate in monitor mode,
making the channel invisible to standard WiFi tools.

Modes
-----
  SEND     -- Craft beacons carrying data chunks
  RECEIVE  -- Sniff beacons, reassemble messages

Controls
--------
  OK         -- Start / stop TX or RX
  UP / DOWN  -- Scroll messages / adjust settings
  KEY1       -- Cycle view  (SEND / RECEIVE / CONFIG)
  LEFT       -- Back
  KEY2       -- Export conversation log to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/CovertChannel/
"""

import os
import sys
import time
import json
import random
import string
import struct
import threading
from datetime import datetime
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import RPi.GPIO as GPIO
import LCD_1in44
import LCD_Config
from PIL import Image
from payloads._display_helper import ScaledDraw, scaled_font
from payloads._input_helper import get_button
from payloads._iface_helper import select_interface

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

LOOT_DIR = "/root/Raspyjack/loot/CovertChannel"
OUI = b"\xDE\xAD\x01"
CHUNK_DATA_MAX = 200
VIEWS = ["SEND", "RECEIVE", "CONFIG"]

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_MUTED = "#888888"
C_HEADER = "#0d1117"

# ---------------------------------------------------------------------------
# Covert protocol helpers
# ---------------------------------------------------------------------------

def _random_tag(n=4):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _make_ssid():
    return f"covert_{_random_tag()}"


def _encode_chunks(msg_bytes, msg_id, total_chunks=None):
    chunks = []
    for i in range(0, len(msg_bytes), CHUNK_DATA_MAX):
        chunk = msg_bytes[i:i + CHUNK_DATA_MAX]
        chunks.append(chunk)
    if not chunks:
        chunks = [b""]
    total = len(chunks)
    encoded = []
    for idx, chunk in enumerate(chunks):
        header = struct.pack("!BBH", msg_id & 0xFF, idx, total)
        encoded.append(OUI + header + chunk)
    return encoded


def _decode_ie(payload):
    if len(payload) < 7 or payload[:3] != OUI:
        return None
    msg_id, idx, total = struct.unpack("!BBH", payload[3:7])
    data = payload[7:]
    return msg_id, idx, total, data


# ---------------------------------------------------------------------------
# TX / RX engines
# ---------------------------------------------------------------------------

class CovertTX:
    def __init__(self, iface, channel):
        self.iface = iface
        self.channel = channel
        self.ssid = _make_ssid()
        self.running = False
        self._thread = None
        self._stop = threading.Event()
        self.tx_count = 0
        self.msg_id = random.randint(0, 255)
        self._queue = []
        self._lock = threading.Lock()

    def enqueue(self, text):
        self.msg_id = (self.msg_id + 1) & 0xFF
        chunks = _encode_chunks(text.encode("utf-8", errors="replace"), self.msg_id)
        with self._lock:
            self._queue.extend(chunks)

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.running = False

    def _loop(self):
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp
        except ImportError:
            self.running = False
            return
        os.system(f"iwconfig {self.iface} channel {self.channel} 2>/dev/null")
        src_mac = "DE:AD:BE:EF:%02X:%02X" % (random.randint(0, 255), random.randint(0, 255))
        while not self._stop.is_set():
            with self._lock:
                if not self._queue:
                    self._stop.wait(0.2)
                    continue
                ie_data = self._queue.pop(0)
            frame = (
                RadioTap()
                / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                        addr2=src_mac, addr3=src_mac)
                / Dot11Beacon(cap="ESS")
                / Dot11Elt(ID=0, info=self.ssid.encode())
                / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96")
                / Dot11Elt(ID=3, info=struct.pack("B", self.channel))
                / Dot11Elt(ID=221, info=ie_data)
            )
            try:
                sendp(frame, iface=self.iface, verbose=False, count=3, inter=0.02)
                self.tx_count += 1
            except Exception:
                pass
            self._stop.wait(0.1)
        self.running = False


class CovertRX:
    def __init__(self, iface, channel):
        self.iface = iface
        self.channel = channel
        self.running = False
        self._thread = None
        self._stop = threading.Event()
        self.rx_count = 0
        self.messages = []
        self._partial = defaultdict(dict)
        self._lock = threading.Lock()

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.running = False

    def _loop(self):
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
        except ImportError:
            self.running = False
            return
        os.system(f"iwconfig {self.iface} channel {self.channel} 2>/dev/null")

        def _handle(pkt):
            if self._stop.is_set():
                return
            if not pkt.haslayer(Dot11Beacon):
                return
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 221 and elt.info and len(elt.info) >= 7:
                    result = _decode_ie(bytes(elt.info))
                    if result:
                        self._on_chunk(*result)
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        while not self._stop.is_set():
            try:
                sniff(iface=self.iface, prn=_handle, timeout=2,
                      store=False, monitor=True)
            except Exception:
                self._stop.wait(1)
        self.running = False

    def _on_chunk(self, msg_id, idx, total, data):
        self.rx_count += 1
        key = msg_id
        with self._lock:
            self._partial[key][idx] = data
            if len(self._partial[key]) >= total and total > 0:
                ordered = b"".join(self._partial[key].get(i, b"")
                                   for i in range(total))
                try:
                    text = ordered.decode("utf-8", errors="replace")
                except Exception:
                    text = ordered.hex()
                ts = datetime.now().strftime("%H:%M:%S")
                self.messages.append({"time": ts, "text": text})
                del self._partial[key]


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_header(draw, title, active):
    draw.rectangle([(0, 0), (WIDTH, ROW_H + 2)], fill=C_HEADER)
    draw.text((2, 1), title, fill=C_CYAN, font=font)
    dot_color = C_GREEN if active else C_RED
    draw.ellipse([(WIDTH - 10, 3), (WIDTH - 4, 9)], fill=dot_color)


def _draw_send(draw, tx, sent_texts, scroll):
    _draw_header(draw, "TX COVERT", tx.running)
    y = ROW_H + 4
    draw.text((2, y), f"SSID: {tx.ssid}", fill=C_CYAN, font=font)
    y += ROW_H
    draw.text((2, y), f"CH: {tx.channel}  TX: {tx.tx_count}", fill=C_GREEN, font=font)
    y += ROW_H
    draw.text((2, y), f"Queue: {len(tx._queue)}", fill=C_YELLOW, font=font)
    y += ROW_H + 2
    draw.line([(0, y), (WIDTH, y)], fill=C_MUTED)
    y += 3
    draw.text((2, y), "Sent:", fill=C_MUTED, font=font)
    y += ROW_H
    visible = sent_texts[-(HEIGHT - y) // ROW_H:]
    for i, msg in enumerate(visible):
        if y + ROW_H > HEIGHT:
            break
        txt = msg[:20] if len(msg) > 20 else msg
        draw.text((2, y), txt, fill="#FFFFFF", font=font)
        y += ROW_H


def _draw_receive(draw, rx, scroll):
    _draw_header(draw, "RX COVERT", rx.running)
    y = ROW_H + 4
    draw.text((2, y), f"CH: {rx.channel}  RX: {rx.rx_count}", fill=C_GREEN, font=font)
    y += ROW_H
    draw.text((2, y), f"Msgs: {len(rx.messages)}", fill=C_CYAN, font=font)
    y += ROW_H + 2
    draw.line([(0, y), (WIDTH, y)], fill=C_MUTED)
    y += 3
    max_rows = (HEIGHT - y) // ROW_H
    msgs = rx.messages
    start = max(0, len(msgs) - max_rows - scroll)
    end = start + max_rows
    for m in msgs[start:end]:
        if y + ROW_H > HEIGHT:
            break
        txt = m["text"][:18]
        draw.text((2, y), f"{m['time']}", fill=C_MUTED, font=font)
        draw.text((50, y), txt, fill="#FFFFFF", font=font)
        y += ROW_H


def _draw_config(draw, channel, interval):
    _draw_header(draw, "CONFIG", False)
    y = ROW_H + 6
    items = [
        ("Channel", str(channel)),
        ("TX interval", f"{interval}ms"),
        ("OUI", "DE:AD:01"),
        ("Chunk size", f"{CHUNK_DATA_MAX}B"),
        ("Protocol", "Beacon IE 221"),
    ]
    for label, val in items:
        draw.text((2, y), f"{label}:", fill=C_MUTED, font=font)
        draw.text((70, y), val, fill=C_CYAN, font=font)
        y += ROW_H + 2


# ---------------------------------------------------------------------------
# Predefined messages for quick send
# ---------------------------------------------------------------------------

QUICK_MSGS = [
    "PING", "ACK", "READY", "ABORT", "EXFIL START",
    "EXFIL DONE", "MOVE TO CH6", "ALL CLEAR", "COMPROMISED",
    "STANDBY", "GO", "EXTRACT", "HELLO", "GOODBYE",
]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    iface = select_interface()
    if not iface:
        return 0

    channel = 6
    interval = 100
    view_idx = 0
    scroll = 0
    msg_cursor = 0
    sent_texts = []

    tx = CovertTX(iface, channel)
    rx = CovertRX(iface, channel)

    image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(image)

    try:
        while True:
            image.paste(C_BG, (0, 0, WIDTH, HEIGHT))
            view = VIEWS[view_idx]

            if view == "SEND":
                _draw_send(draw, tx, sent_texts, scroll)
            elif view == "RECEIVE":
                _draw_receive(draw, rx, scroll)
            else:
                _draw_config(draw, channel, interval)

            LCD.LCD_ShowImage(image, 0, 0)
            btn = get_button(PINS, timeout=0.15)
            if btn is None:
                continue

            if btn == "KEY3":
                break
            elif btn == "KEY1":
                view_idx = (view_idx + 1) % len(VIEWS)
                scroll = 0
            elif btn == "LEFT":
                view_idx = (view_idx - 1) % len(VIEWS)
                scroll = 0

            elif view == "SEND":
                if btn == "OK":
                    if not tx.running:
                        tx.channel = channel
                        tx.start()
                    else:
                        msg = QUICK_MSGS[msg_cursor % len(QUICK_MSGS)]
                        tx.enqueue(msg)
                        sent_texts.append(msg)
                elif btn == "UP":
                    msg_cursor = (msg_cursor - 1) % len(QUICK_MSGS)
                elif btn == "DOWN":
                    msg_cursor = (msg_cursor + 1) % len(QUICK_MSGS)
                elif btn == "RIGHT":
                    msg = QUICK_MSGS[msg_cursor % len(QUICK_MSGS)]
                    tx.enqueue(msg)
                    sent_texts.append(msg)

            elif view == "RECEIVE":
                if btn == "OK":
                    if not rx.running:
                        rx.channel = channel
                        rx.start()
                    else:
                        rx.stop()
                elif btn == "UP":
                    scroll = min(scroll + 1, max(0, len(rx.messages) - 3))
                elif btn == "DOWN":
                    scroll = max(0, scroll - 1)

            elif view == "CONFIG":
                if btn == "UP":
                    channel = min(13, channel + 1)
                elif btn == "DOWN":
                    channel = max(1, channel - 1)
                elif btn == "RIGHT":
                    interval = min(1000, interval + 50)
                elif btn == "OK":
                    interval = max(50, interval - 50)

            if btn == "KEY2":
                os.makedirs(LOOT_DIR, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = os.path.join(LOOT_DIR, f"covert_{ts}.json")
                with open(path, "w") as f:
                    json.dump({
                        "sent": sent_texts,
                        "received": rx.messages,
                        "channel": channel,
                        "ssid": tx.ssid,
                        "tx_count": tx.tx_count,
                        "rx_count": rx.rx_count,
                    }, f, indent=2)
    finally:
        tx.stop()
        rx.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
