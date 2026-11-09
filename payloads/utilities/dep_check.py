#!/usr/bin/env python3
"""
RaspyJack Payload -- Dependency Checker
========================================
Author: gabecamp

Scans all payloads for required Python packages and system tools,
checks which are installed, and offers to install missing ones.

Controls
--------
  UP / DOWN   -- Scroll list
  OK          -- Install all missing / retry
  KEY1        -- Toggle pip / apt / all view
  KEY2        -- Refresh scan
  KEY3        -- Exit
"""

import os
import sys
import time
import signal
import subprocess
import threading
import importlib

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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
DEBOUNCE = 0.22
_last_btn = 0
_running = True
_installing = False
_install_log = []
_install_lock = threading.Lock()


def _cleanup(*_args):
    global _running
    _running = False


signal.signal(signal.SIGINT, _cleanup)
signal.signal(signal.SIGTERM, _cleanup)


# ---------------------------------------------------------------------------
# Dependency catalog — import_name: (pip_name, apt_name_or_None)
# pip_name=None means apt-only, apt_name=None means pip-only
# ---------------------------------------------------------------------------

PIP_DEPS = {
    "PIL":          ("Pillow", None),
    "numpy":        ("numpy", None),
    "requests":     ("requests", None),
    "serial":       ("pyserial", None),
    "smbus2":       ("smbus2", None),
    "spidev":       ("spidev", None),
    "RPi":          ("RPi.GPIO", None),
    "evdev":        ("evdev", None),
    "scapy":        ("scapy", None),
    "cv2":          ("opencv-python-headless", None),
    "qrcode":       ("qrcode", None),
    "pyzbar":       ("pyzbar", "libzbar0"),
    "bleak":        ("bleak", None),
    "nfc":          ("nfcpy", None),
    "gpsd":         ("gpsd-py3", None),
    "impacket":     ("impacket", None),
    "flask":        ("flask", None),
    "websockets":   ("websockets", None),
    "yaml":         ("pyyaml", None),
    "cryptography": ("cryptography", None),
    "paramiko":     ("paramiko", None),
    "dns":          ("dnspython", None),
    "netifaces":    ("netifaces", None),
    "psutil":       ("psutil", None),
    "pynmea2":      ("pynmea2", None),
    "esptool":      ("esptool", None),
    "yt_dlp":       ("yt-dlp", None),
    "whois":        ("python-whois", None),
    "shodan":       ("shodan", None),
    "bluepy":       ("bluepy", None),
    "aiohttp":      ("aiohttp", None),
    "pydub":        ("pydub", None),
    "whisper":      ("openai-whisper", None),
    "tqdm":         ("tqdm", None),
    "tabulate":     ("tabulate", None),
    "dbus":         ("dbus-python", "python3-dbus"),
}

# tool_binary: (apt_package, description)
APT_DEPS = {
    "nmap":         ("nmap", "Network scanner"),
    "airmon-ng":    ("aircrack-ng", "WiFi audit suite"),
    "tshark":       ("tshark", "Packet analyzer"),
    "tcpdump":      ("tcpdump", "Packet capture"),
    "ffmpeg":       ("ffmpeg", "Media processing"),
    "hostapd":      ("hostapd", "Access point daemon"),
    "dnsmasq":      ("dnsmasq", "DNS/DHCP server"),
    "hashcat":      ("hashcat", "Password cracker"),
    "john":         ("john", "Password cracker"),
    "reaver":       ("reaver", "WPS attack tool"),
    "masscan":      ("masscan", "Fast port scanner"),
    "nikto":        ("nikto", "Web scanner"),
    "kismet":       ("kismet", "Wireless sniffer"),
    "gpsd":         ("gpsd", "GPS daemon"),
    "rtl_sdr":      ("rtl-sdr", "SDR tools"),
    "rtl_433":      ("rtl-433", "SDR 433MHz decoder"),
    "bluetoothctl": ("bluez", "Bluetooth stack"),
    "hciconfig":    ("bluez", "Bluetooth stack"),
    "iw":           ("iw", "Wireless tools"),
    "nmcli":        ("network-manager", "Network manager"),
    "iptables":     ("iptables", "Firewall"),
    "ldapsearch":   ("ldap-utils", "LDAP tools"),
    "sshpass":      ("sshpass", "SSH password auth"),
    "i2cdetect":    ("i2c-tools", "I2C tools"),
    "ir-ctl":       ("v4l-utils", "Video4Linux utils"),
    "mpv":          ("mpv", "Media player"),
    "aplay":        ("alsa-utils", "Audio tools"),
    "xdotool":      ("xdotool", "X11 automation"),
    "lsusb":        ("usbutils", "USB utilities"),
    "curl":         ("curl", "HTTP client"),
    "git":          ("git", "Version control"),
    "arp-scan":     ("arp-scan", "ARP scanner"),
    "macchanger":   ("macchanger", "MAC spoofer"),
    "mdk4":         ("mdk4", "WiFi stress test"),
    "bettercap":    ("bettercap", "MITM framework"),
    "ettercap":     ("ettercap-text-only", "MITM tool"),
    "nbtscan":      ("nbtscan", "NetBIOS scanner"),
}


def _btn():
    global _last_btn
    b = get_button(PINS, GPIO)
    now = time.time()
    if b and now - _last_btn < DEBOUNCE:
        return None
    if b:
        _last_btn = now
    return b


def _check_pip(import_name):
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def _check_apt(binary):
    try:
        result = subprocess.run(
            ["which", binary], capture_output=True, timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def _scan_all():
    results = []

    for imp, (pip_name, apt_extra) in PIP_DEPS.items():
        installed = _check_pip(imp)
        results.append({
            "name": pip_name,
            "type": "pip",
            "installed": installed,
            "import": imp,
            "apt_extra": apt_extra,
        })

    seen_apt = set()
    for binary, (apt_pkg, desc) in APT_DEPS.items():
        if apt_pkg in seen_apt:
            continue
        installed = _check_apt(binary)
        seen_apt.add(apt_pkg)
        results.append({
            "name": apt_pkg,
            "type": "apt",
            "installed": installed,
            "binary": binary,
            "desc": desc,
        })

    return results


def _install_missing(deps, lcd, font_sm):
    global _installing, _install_log
    _installing = True
    _install_log = []

    pip_missing = [d for d in deps if d["type"] == "pip" and not d["installed"]]
    apt_missing = [d for d in deps if d["type"] == "apt" and not d["installed"]]

    # Collect apt extras needed by pip packages (like libzbar0)
    apt_extras = []
    for d in pip_missing:
        if d.get("apt_extra"):
            apt_extras.append(d["apt_extra"])

    total = len(pip_missing) + len(apt_missing) + len(apt_extras)
    if total == 0:
        with _install_lock:
            _install_log.append("All deps installed!")
        _installing = False
        return

    done = 0

    def _progress(msg):
        nonlocal done
        with _install_lock:
            _install_log.append(msg)
        img = Image.new("RGB", (WIDTH, HEIGHT), "black")
        d = ScaledDraw(img)
        d.rectangle((0, 0, WIDTH - 1, 14), fill="#111")
        d.text((2, 2), "INSTALLING", font=font_sm, fill="#FF9800")
        pct = done * 100 // max(1, total)
        d.text((90, 2), f"{pct}%", font=font_sm, fill="#FF9800")
        d.rectangle((4, 20, WIDTH - 5, 28), outline="#333")
        bw = max(1, int((WIDTH - 9) * done / max(1, total)))
        d.rectangle((4, 20, 4 + bw, 28), fill="#FF9800")
        y = 34
        with _install_lock:
            show = _install_log[-6:]
        for line in show:
            d.text((2, y), line[:24], font=font_sm, fill="#ccc")
            y += 12
        d.rectangle((0, HEIGHT - 12, WIDTH - 1, HEIGHT - 1), fill="#111")
        d.text((2, HEIGHT - 11), f"{done}/{total} packages", font=font_sm, fill="#666")
        lcd.LCD_ShowImage(img, 0, 0)

    # apt update first if there are apt packages
    if apt_missing or apt_extras:
        _progress("apt update...")
        try:
            subprocess.run(
                ["apt-get", "update", "-qq"],
                capture_output=True, timeout=120,
            )
        except Exception:
            pass

    # Install apt extras (libs needed by pip packages)
    for pkg in apt_extras:
        _progress(f"apt: {pkg}")
        try:
            r = subprocess.run(
                ["apt-get", "install", "-y", "-qq", pkg],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                _progress(f"  OK: {pkg}")
            else:
                _progress(f"  FAIL: {pkg}")
        except Exception as e:
            _progress(f"  ERR: {str(e)[:18]}")
        done += 1

    # Install apt packages
    for dep in apt_missing:
        pkg = dep["name"]
        _progress(f"apt: {pkg}")
        try:
            r = subprocess.run(
                ["apt-get", "install", "-y", "-qq", pkg],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode == 0:
                _progress(f"  OK: {pkg}")
                dep["installed"] = True
            else:
                err = r.stderr.strip().split("\n")[-1][:20] if r.stderr else "?"
                _progress(f"  FAIL: {err}")
        except subprocess.TimeoutExpired:
            _progress(f"  TIMEOUT: {pkg}")
        except Exception as e:
            _progress(f"  ERR: {str(e)[:18]}")
        done += 1
        _progress(f"{done}/{total}")

    # Install pip packages
    for dep in pip_missing:
        pkg = dep["name"]
        _progress(f"pip: {pkg}")
        try:
            r = subprocess.run(
                ["pip3", "install", "--break-system-packages", pkg],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode == 0:
                _progress(f"  OK: {pkg}")
                dep["installed"] = True
            else:
                err = r.stderr.strip().split("\n")[-1][:20] if r.stderr else "?"
                _progress(f"  FAIL: {err}")
        except subprocess.TimeoutExpired:
            _progress(f"  TIMEOUT: {pkg}")
        except Exception as e:
            _progress(f"  ERR: {str(e)[:18]}")
        done += 1
        _progress(f"{done}/{total}")

    _progress("Done!")
    _installing = False


def main():
    global _running

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    font = scaled_font(10)
    font_sm = scaled_font(9)

    # Splash
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((4, 50), "Scanning deps...", font=font_sm, fill="#FF9800")
    lcd.LCD_ShowImage(img, 0, 0)

    deps = _scan_all()
    scroll = 0
    view = "all"  # "all", "missing", "pip", "apt"
    views = ["all", "missing", "pip", "apt"]
    view_idx = 0

    try:
        while _running:
            btn = _btn()
            if btn == "KEY3":
                if _installing:
                    pass
                else:
                    break

            elif btn == "KEY1" and not _installing:
                view_idx = (view_idx + 1) % len(views)
                view = views[view_idx]
                scroll = 0

            elif btn == "KEY2" and not _installing:
                img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                d = ScaledDraw(img)
                d.text((4, 50), "Rescanning...", font=font_sm, fill="#FF9800")
                lcd.LCD_ShowImage(img, 0, 0)
                deps = _scan_all()
                scroll = 0

            elif btn == "OK" and not _installing:
                missing = [dp for dp in deps if not dp["installed"]]
                if missing:
                    t = threading.Thread(
                        target=_install_missing,
                        args=(deps, lcd, font_sm),
                        daemon=True,
                    )
                    t.start()
                    while _installing and _running:
                        b = _btn()
                        if b == "KEY3":
                            break
                        time.sleep(0.05)
                    time.sleep(1)
                    # Rescan after install
                    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
                    d = ScaledDraw(img)
                    d.text((4, 50), "Rescanning...", font=font_sm, fill="#FF9800")
                    lcd.LCD_ShowImage(img, 0, 0)
                    deps = _scan_all()
                    scroll = 0
                    continue

            elif btn == "UP":
                scroll = max(0, scroll - 1)
            elif btn == "DOWN":
                scroll += 1

            if _installing:
                time.sleep(0.05)
                continue

            # Filter
            if view == "missing":
                shown = [dp for dp in deps if not dp["installed"]]
            elif view == "pip":
                shown = [dp for dp in deps if dp["type"] == "pip"]
            elif view == "apt":
                shown = [dp for dp in deps if dp["type"] == "apt"]
            else:
                shown = deps

            # Sort: missing first, then alphabetical
            shown = sorted(shown, key=lambda x: (x["installed"], x["name"].lower()))

            total = len(deps)
            installed = sum(1 for dp in deps if dp["installed"])
            missing = total - installed

            max_scroll = max(0, len(shown) - 7)
            scroll = min(scroll, max_scroll)

            img = Image.new("RGB", (WIDTH, HEIGHT), "black")
            d = ScaledDraw(img)

            # Header
            d.rectangle((0, 0, WIDTH - 1, 14), fill="#111")
            d.text((2, 2), "DEP CHECK", font=font_sm, fill="#FF9800")
            view_label = view.upper()
            d.text((70, 2), view_label, font=font_sm, fill="#888")
            if missing == 0:
                d.text((100, 2), "OK", font=font_sm, fill="#00FF00")
            else:
                d.text((100, 2), f"-{missing}", font=font_sm, fill="#FF4444")

            # Summary bar
            y = 16
            d.text((2, y), f"{installed}/{total} installed", font=font_sm,
                   fill="#00FF00" if missing == 0 else "#FFAA00")
            pip_miss = sum(1 for dp in deps if dp["type"] == "pip" and not dp["installed"])
            apt_miss = sum(1 for dp in deps if dp["type"] == "apt" and not dp["installed"])
            d.text((80, y), f"P:{pip_miss} A:{apt_miss}", font=font_sm, fill="#888")
            y += 12

            # Separator
            d.line([(0, y), (WIDTH - 1, y)], fill="#222")
            y += 2

            # List
            max_rows = 7
            for i in range(scroll, min(len(shown), scroll + max_rows)):
                if y > HEIGHT - 14:
                    break
                dp = shown[i]
                name = dp["name"][:16]
                tp = "P" if dp["type"] == "pip" else "A"

                if dp["installed"]:
                    icon_col = "#00AA00"
                    icon = "+"
                    name_col = "#888"
                else:
                    icon_col = "#FF4444"
                    icon = "x"
                    name_col = "#FFAA00"

                d.text((2, y), icon, font=font_sm, fill=icon_col)
                d.text((10, y), f"[{tp}]", font=font_sm, fill="#555")
                d.text((28, y), name, font=font_sm, fill=name_col)
                y += 11

            # Scroll indicator
            if len(shown) > max_rows:
                bar_h = max(4, int(max_rows / max(1, len(shown)) * 80))
                bar_y = 30 + int(scroll / max(1, len(shown) - max_rows) * (80 - bar_h))
                d.rectangle((WIDTH - 3, bar_y, WIDTH - 1, bar_y + bar_h), fill="#333")

            # Footer
            d.rectangle((0, HEIGHT - 12, WIDTH - 1, HEIGHT - 1), fill="#111")
            if missing > 0:
                d.text((2, HEIGHT - 11), "OK:Install K1:View K3:X", font=font_sm, fill="#666")
            else:
                d.text((2, HEIGHT - 11), "All good! K1:View K3:X", font=font_sm, fill="#666")

            lcd.LCD_ShowImage(img, 0, 0)
            time.sleep(0.05)

    finally:
        try:
            lcd.LCD_Clear()
        except Exception:
            pass
        GPIO.cleanup()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
