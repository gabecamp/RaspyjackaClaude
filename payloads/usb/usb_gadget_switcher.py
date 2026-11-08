#!/usr/bin/env python3
"""
RaspyJack Payload -- USB Gadget Mode Switcher
===============================================
Inspired by P4wnP1.

Hot-switch between USB personalities using Linux configfs.
Supports HID keyboard, HID mouse, serial (ACM), RNDIS ethernet,
mass storage, and composite combinations.

Controls:
  OK         -- Apply selected profile
  UP / DOWN  -- Scroll profiles / toggle functions
  KEY1       -- Cycle view (STATUS / SELECT / CUSTOM)
  KEY2       -- Remove current gadget (unbind)
  KEY3       -- Exit
"""

import os
import sys
import glob
import time
import threading
from datetime import datetime

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

ROW_H = 12
ROWS_VISIBLE = 7
GADGET_BASE = "/sys/kernel/config/usb_gadget"
GADGET_NAME = "rj_gadget"
GADGET_PATH = os.path.join(GADGET_BASE, GADGET_NAME)
MASS_STORAGE_IMG = "/root/Raspyjack/loot/mass_storage.img"
LOOT_DIR = "/root/Raspyjack/loot/GadgetSwitcher"
os.makedirs(LOOT_DIR, exist_ok=True)

C_BG = "#0a0a12"
C_CYAN = "#00E5FF"
C_GREEN = "#00E676"
C_RED = "#FF5252"
C_YELLOW = "#FFD740"
C_PURPLE = "#7C4DFF"
C_MUTED = "#888888"
C_DIM = "#444444"
C_HEADER = "#0d1117"
C_WHITE = "#FFFFFF"

VIEWS = ["STATUS", "SELECT", "CUSTOM"]

# ---------------------------------------------------------------------------
# Gadget function definitions
# ---------------------------------------------------------------------------

FUNC_HID_KB = "hid.usb0"
FUNC_HID_MOUSE = "hid.usb1"
FUNC_ACM = "acm.usb0"
FUNC_RNDIS = "rndis.usb0"
FUNC_ECM = "ecm.usb0"
FUNC_MASS = "mass_storage.usb0"

PROFILES = [
    ("Keyboard Only", [FUNC_HID_KB]),
    ("Mouse Only", [FUNC_HID_MOUSE]),
    ("Serial Console", [FUNC_ACM]),
    ("RNDIS Network", [FUNC_RNDIS]),
    ("ECM Network", [FUNC_ECM]),
    ("Mass Storage", [FUNC_MASS]),
    ("KB+Mouse+Storage", [FUNC_HID_KB, FUNC_HID_MOUSE, FUNC_MASS]),
    ("KB+RNDIS (Attack)", [FUNC_HID_KB, FUNC_RNDIS]),
    ("Serial+RNDIS", [FUNC_ACM, FUNC_RNDIS]),
    ("KB+Mouse+RNDIS", [FUNC_HID_KB, FUNC_HID_MOUSE, FUNC_RNDIS]),
]

ALL_FUNCTIONS = [
    (FUNC_HID_KB, "HID Keyboard"),
    (FUNC_HID_MOUSE, "HID Mouse"),
    (FUNC_ACM, "Serial ACM"),
    (FUNC_RNDIS, "RNDIS Net"),
    (FUNC_ECM, "ECM Net"),
    (FUNC_MASS, "Mass Storage"),
]

# HID report descriptors
KB_REPORT_DESC = bytes([
    0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07,
    0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
    0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01,
    0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07,
    0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0,
])

MOUSE_REPORT_DESC = bytes([
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01,
    0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03,
    0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01,
    0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38,
    0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03,
    0x81, 0x06, 0xC0, 0xC0,
])


# ---------------------------------------------------------------------------
# configfs helpers
# ---------------------------------------------------------------------------

def _write(path, data):
    try:
        if isinstance(data, bytes):
            with open(path, "wb") as f:
                f.write(data)
        else:
            with open(path, "w") as f:
                f.write(str(data))
        return True
    except Exception:
        return False


def _read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def _find_udc():
    udcs = glob.glob("/sys/class/udc/*/")
    if udcs:
        return os.path.basename(udcs[0].rstrip("/"))
    return ""


def _gadget_exists():
    return os.path.isdir(GADGET_PATH)


def _get_bound_udc():
    if not _gadget_exists():
        return ""
    return _read(os.path.join(GADGET_PATH, "UDC"))


def _get_active_functions():
    cfg_path = os.path.join(GADGET_PATH, "configs", "c.1")
    if not os.path.isdir(cfg_path):
        return []
    funcs = []
    try:
        for entry in os.listdir(cfg_path):
            full = os.path.join(cfg_path, entry)
            if os.path.islink(full):
                funcs.append(entry)
    except Exception:
        pass
    return sorted(funcs)


def _unbind_gadget():
    if not _gadget_exists():
        return True
    _write(os.path.join(GADGET_PATH, "UDC"), "")
    time.sleep(0.3)
    cfg_path = os.path.join(GADGET_PATH, "configs", "c.1")
    if os.path.isdir(cfg_path):
        for entry in os.listdir(cfg_path):
            full = os.path.join(cfg_path, entry)
            if os.path.islink(full):
                try:
                    os.unlink(full)
                except Exception:
                    pass
        try:
            strings_dir = os.path.join(cfg_path, "strings", "0x409")
            if os.path.isdir(strings_dir):
                os.rmdir(strings_dir)
            os.rmdir(cfg_path)
        except Exception:
            pass
    func_base = os.path.join(GADGET_PATH, "functions")
    if os.path.isdir(func_base):
        for func in os.listdir(func_base):
            try:
                os.rmdir(os.path.join(func_base, func))
            except Exception:
                pass
    strings_dir = os.path.join(GADGET_PATH, "strings", "0x409")
    if os.path.isdir(strings_dir):
        try:
            os.rmdir(strings_dir)
        except Exception:
            pass
    try:
        os.rmdir(GADGET_PATH)
    except Exception:
        pass
    return not _gadget_exists()


def _create_function(func_name):
    func_path = os.path.join(GADGET_PATH, "functions", func_name)
    os.makedirs(func_path, exist_ok=True)

    if func_name == FUNC_HID_KB:
        _write(os.path.join(func_path, "protocol"), "1")
        _write(os.path.join(func_path, "subclass"), "1")
        _write(os.path.join(func_path, "report_length"), "8")
        _write(os.path.join(func_path, "report_desc"), KB_REPORT_DESC)
    elif func_name == FUNC_HID_MOUSE:
        _write(os.path.join(func_path, "protocol"), "2")
        _write(os.path.join(func_path, "subclass"), "1")
        _write(os.path.join(func_path, "report_length"), "4")
        _write(os.path.join(func_path, "report_desc"), MOUSE_REPORT_DESC)
    elif func_name == FUNC_RNDIS:
        _write(os.path.join(func_path, "host_addr"), "48:6f:73:74:50:43")
        _write(os.path.join(func_path, "dev_addr"), "42:61:64:55:53:42")
    elif func_name == FUNC_ECM:
        _write(os.path.join(func_path, "host_addr"), "48:6f:73:74:50:43")
        _write(os.path.join(func_path, "dev_addr"), "42:61:64:55:53:42")
    elif func_name == FUNC_MASS:
        if not os.path.exists(MASS_STORAGE_IMG):
            try:
                os.makedirs(os.path.dirname(MASS_STORAGE_IMG), exist_ok=True)
                os.system(f"dd if=/dev/zero of={MASS_STORAGE_IMG} bs=1M count=64 2>/dev/null")
                os.system(f"mkdosfs {MASS_STORAGE_IMG} 2>/dev/null")
            except Exception:
                pass
        lun_path = os.path.join(func_path, "lun.0")
        os.makedirs(lun_path, exist_ok=True)
        _write(os.path.join(lun_path, "file"), MASS_STORAGE_IMG)
        _write(os.path.join(lun_path, "removable"), "1")
        _write(os.path.join(lun_path, "cdrom"), "0")


def _apply_profile(functions):
    _unbind_gadget()
    time.sleep(0.2)

    os.makedirs(GADGET_PATH, exist_ok=True)
    _write(os.path.join(GADGET_PATH, "idVendor"), "0x1d6b")
    _write(os.path.join(GADGET_PATH, "idProduct"), "0x0104")
    _write(os.path.join(GADGET_PATH, "bcdDevice"), "0x0100")
    _write(os.path.join(GADGET_PATH, "bcdUSB"), "0x0200")

    strings_path = os.path.join(GADGET_PATH, "strings", "0x409")
    os.makedirs(strings_path, exist_ok=True)
    _write(os.path.join(strings_path, "serialnumber"), "RJ0001")
    _write(os.path.join(strings_path, "manufacturer"), "RaspyJack")
    _write(os.path.join(strings_path, "product"), "RaspyJack USB")

    cfg_path = os.path.join(GADGET_PATH, "configs", "c.1")
    os.makedirs(cfg_path, exist_ok=True)
    cfg_strings = os.path.join(cfg_path, "strings", "0x409")
    os.makedirs(cfg_strings, exist_ok=True)
    _write(os.path.join(cfg_strings, "configuration"), "Config 1")
    _write(os.path.join(cfg_path, "MaxPower"), "250")

    for func in functions:
        _create_function(func)
        func_path = os.path.join(GADGET_PATH, "functions", func)
        link_path = os.path.join(cfg_path, func)
        if not os.path.exists(link_path):
            try:
                os.symlink(func_path, link_path)
            except Exception:
                pass

    udc = _find_udc()
    if udc:
        _write(os.path.join(GADGET_PATH, "UDC"), udc)
        return True
    return False


def _func_short(name):
    mapping = {
        FUNC_HID_KB: "KB",
        FUNC_HID_MOUSE: "Mouse",
        FUNC_ACM: "Serial",
        FUNC_RNDIS: "RNDIS",
        FUNC_ECM: "ECM",
        FUNC_MASS: "Storage",
    }
    return mapping.get(name, name.split(".")[0])


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw(view_idx, profile_sel, custom_toggles, status_msg, applying):
    image = Image.new("RGB", (WIDTH, HEIGHT), C_BG)
    draw = ScaledDraw(image)
    fn = scaled_font()
    fn_sm = scaled_font(7)

    view = VIEWS[view_idx]
    draw.rectangle([(0, 0), (WIDTH, 11)], fill=C_HEADER)
    draw.text((2, 1), f"USB Gadget [{view}]", fill=C_CYAN, font=fn)

    udc = _find_udc()
    bound = _get_bound_udc()
    active = _get_active_functions()

    if applying:
        draw.text((2, 14), "Applying...", fill=C_YELLOW, font=fn)
        LCD.LCD_ShowImage(image, 0, 0)
        return

    y = 14

    if view == "STATUS":
        draw.text((2, y), "UDC:", fill=C_MUTED, font=fn)
        draw.text((30, y), udc if udc else "none", fill=C_GREEN if udc else C_RED, font=fn)
        y += ROW_H

        draw.text((2, y), "Bound:", fill=C_MUTED, font=fn)
        draw.text((40, y), bound if bound else "unbound", fill=C_GREEN if bound else C_DIM, font=fn)
        y += ROW_H

        draw.text((2, y), "Functions:", fill=C_MUTED, font=fn)
        y += ROW_H
        if active:
            for func in active:
                draw.text((6, y), _func_short(func), fill=C_WHITE, font=fn)
                y += ROW_H
                if y > HEIGHT - 14:
                    break
        else:
            draw.text((6, y), "(none)", fill=C_DIM, font=fn)
            y += ROW_H

        if status_msg:
            draw.text((2, HEIGHT - 12), status_msg[:22], fill=C_YELLOW, font=fn_sm)

    elif view == "SELECT":
        draw.text((2, y), "Profiles:", fill=C_MUTED, font=fn_sm)
        y += 10
        total = len(PROFILES)
        start = max(0, profile_sel - (ROWS_VISIBLE - 2))
        for i in range(start, min(total, start + ROWS_VISIBLE - 1)):
            name, funcs = PROFILES[i]
            sel = i == profile_sel
            if sel:
                draw.rectangle([(0, y), (WIDTH, y + ROW_H - 1)], fill="#1a2733")
            tag = " ".join(_func_short(f) for f in funcs)
            color = C_CYAN if sel else C_WHITE
            draw.text((2, y), name[:16], fill=color, font=fn)
            draw.text((2, y + 6), tag, fill=C_DIM, font=fn_sm)
            y += ROW_H + 2
            if y > HEIGHT - 14:
                break

        draw.text((2, HEIGHT - 12), "OK=Apply  K2=Unbind", fill=C_MUTED, font=fn_sm)

    elif view == "CUSTOM":
        draw.text((2, y), "Toggle functions:", fill=C_MUTED, font=fn_sm)
        y += 10
        for idx, (func_id, label) in enumerate(ALL_FUNCTIONS):
            sel = idx == profile_sel
            enabled = custom_toggles[idx]
            if sel:
                draw.rectangle([(0, y), (WIDTH, y + ROW_H - 1)], fill="#1a2733")
            marker = "[X]" if enabled else "[ ]"
            color = C_GREEN if enabled else C_DIM
            sel_color = C_CYAN if sel else color
            draw.text((2, y), f"{marker} {label}", fill=sel_color, font=fn)
            y += ROW_H
            if y > HEIGHT - 14:
                break

        draw.text((2, HEIGHT - 12), "OK=Toggle  K2=Apply", fill=C_MUTED, font=fn_sm)

    LCD.LCD_ShowImage(image, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    view_idx = 0
    profile_sel = 0
    custom_toggles = [False] * len(ALL_FUNCTIONS)
    status_msg = ""
    applying = False

    _draw(view_idx, profile_sel, custom_toggles, status_msg, False)

    while True:
        btn = get_button(PINS, timeout=0.15)
        if btn is None:
            _draw(view_idx, profile_sel, custom_toggles, status_msg, False)
            continue

        view = VIEWS[view_idx]

        if btn == "KEY3":
            break

        elif btn == "KEY1":
            view_idx = (view_idx + 1) % len(VIEWS)
            profile_sel = 0
            status_msg = ""

        elif btn == "UP":
            if view == "SELECT":
                profile_sel = max(0, profile_sel - 1)
            elif view == "CUSTOM":
                profile_sel = max(0, profile_sel - 1)

        elif btn == "DOWN":
            if view == "SELECT":
                profile_sel = min(len(PROFILES) - 1, profile_sel + 1)
            elif view == "CUSTOM":
                profile_sel = min(len(ALL_FUNCTIONS) - 1, profile_sel + 1)

        elif btn == "LEFT":
            if view_idx > 0:
                view_idx -= 1
                profile_sel = 0

        elif btn == "OK":
            if view == "SELECT":
                _draw(view_idx, profile_sel, custom_toggles, "", True)
                name, funcs = PROFILES[profile_sel]
                ok = _apply_profile(funcs)
                status_msg = f"Applied: {name}" if ok else "No UDC available"
                applying = False
            elif view == "CUSTOM":
                custom_toggles[profile_sel] = not custom_toggles[profile_sel]
            elif view == "STATUS":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                active = _get_active_functions()
                bound = _get_bound_udc()
                path = os.path.join(LOOT_DIR, f"gadget_{ts}.txt")
                with open(path, "w") as f:
                    f.write(f"Time: {ts}\n")
                    f.write(f"UDC: {_find_udc()}\n")
                    f.write(f"Bound: {bound}\n")
                    f.write(f"Functions: {', '.join(active)}\n")
                status_msg = "Exported to loot"

        elif btn == "KEY2":
            if view == "CUSTOM":
                selected = [ALL_FUNCTIONS[i][0] for i, on in enumerate(custom_toggles) if on]
                if selected:
                    _draw(view_idx, profile_sel, custom_toggles, "", True)
                    ok = _apply_profile(selected)
                    status_msg = "Applied custom" if ok else "No UDC"
                    applying = False
                else:
                    status_msg = "No functions selected"
            else:
                _draw(view_idx, profile_sel, custom_toggles, "", True)
                _unbind_gadget()
                status_msg = "Gadget removed"
                applying = False

        _draw(view_idx, profile_sel, custom_toggles, status_msg, applying)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
