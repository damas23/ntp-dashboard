# ticc-dash.py
from flask import Flask, abort, jsonify, render_template, render_template_string
import subprocess
from datetime import datetime
import socket
import os

app = Flask(__name__)

def _is_ipv4(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except OSError:
        return False

def _is_ipv6(addr: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except OSError:
        return False

def _parse_client_line(line: str):
    #parts = line.split()
    parts = line.split(",")
    if len(parts) < 7 or not parts[0].strip():
        raise ValueError("Incomplete chronyc client record")
    addr = parts[0]
    f = parts[1:]
    def g(i): return f[i] if i < len(f) else ""
    return {
        #"addr": addr,
        #"NTP": g(0),
        #"Drop": g(1),
        #"Int": g(2),
        #"IntL": g(3),
        #"Last": g(4),
        #"Cmd": g(5)
        "addr": parts[0],
        "NTP": parts[1],
        "Drop": parts[2],
        "Int": parts[3],
        "IntL": parts[4],
        "Last": parts[5],
        "Cmd": parts[6]
    }

def stale_threshold_seconds(row):
    # chronyc Int is an estimated request interval expressed as log2(seconds).
    # 127 means unknown. Keep a five-minute floor and allow three intervals.
    try:
        interval = int(row.get("Int", ""))
    except (TypeError, ValueError):
        return 300
    if not -20 <= interval <= 32:
        return 300
    return max(300, 3 * (2 ** interval))

def calculate_status(row):
    try:
        drop = int(row.get("Drop", ""))
    except (TypeError, ValueError):
        return "Warning"

    if drop >= 10:
        return "Critical"
    elif drop > 0:
        return "Warning"
    try:
        last = int(row.get("Last", ""))
    except (TypeError, ValueError):
        return "Warning"
    if drop < 0 or last < 0:
        return "Warning"
    if last > stale_threshold_seconds(row):
        return "Stale"
    return "OK"

def _refid_to_text(refid_hex: str, ref_addr: str) -> str:
    """Resolve a chrony reference ID to something readable.

    Stratum-1 sources use a 4-char ASCII ID (e.g. GPS, PPS). Higher strata
    use the IPv4 address of the source encoded as hex.
    """
    refid_hex = (refid_hex or "").strip()
    ref_addr = (ref_addr or "").strip()
    # Prefer a real IP when chrony gives us one
    if ref_addr and ref_addr not in ("0.0.0.0", "127.0.0.1", "::", ""):
        return ref_addr
    if len(refid_hex) == 8:
        try:
            octets = [int(refid_hex[i:i + 2], 16) for i in (0, 2, 4, 6)]
            if all(0 <= o <= 255 for o in octets):
                candidate = ".".join(str(o) for o in octets)
                # 127.127.x.x is a refclock, not a network host
                if not candidate.startswith("127.127."):
                    return candidate
        except ValueError:
            pass
        # Fall back to printable ASCII (e.g. ".GPS." / "PPS")
        try:
            ascii_txt = bytes.fromhex(refid_hex).decode("ascii", "replace")
            if ascii_txt.isprintable():
                return ascii_txt.strip()
        except ValueError:
            pass
    return refid_hex or "unknown"


def get_server_health():
    """Health of the NTP server itself (not the clients).

    Only 'tracking' and 'serverstats' are queried here; both are permitted
    for the chrony user without elevated privileges.
    """
    health = {"available": False}
    try:
        out = subprocess.check_output(
            ["chronyc", "-c", "tracking"], universal_newlines=True, timeout=5
        )
    except subprocess.TimeoutExpired:
        health["error"] = "Timeout reading chrony tracking"
        return health
    except Exception as e:
        health["error"] = "Error: %s" % e
        return health

    fields = out.strip().split(",")
    if len(fields) < 14:
        health["error"] = "Unexpected tracking output"
        return health

    def fnum(i, default=0.0):
        try:
            return float(fields[i])
        except (TypeError, ValueError):
            return default

    try:
        stratum = int(fields[2])
    except (TypeError, ValueError):
        stratum = 0

    ref_epoch = fnum(3, 0.0)
    ref_time_iso = ""
    ref_age_seconds = None
    if ref_epoch > 0:
        try:
            ref_dt = datetime.fromtimestamp(ref_epoch)
            ref_time_iso = ref_dt.strftime("%Y-%m-%d %H:%M:%S")
            ref_age_seconds = max(0, int((datetime.now() - ref_dt).total_seconds()))
        except (OverflowError, OSError, ValueError):
            pass

    health.update({
        "available": True,
        "reference_id": fields[0],
        "reference_source": _refid_to_text(fields[0], fields[1]),
        "stratum": stratum,
        "reference_time": ref_time_iso,
        "reference_age_seconds": ref_age_seconds,
        "system_offset_seconds": fnum(4),
        "last_offset_seconds": fnum(5),
        "rms_offset_seconds": fnum(6),
        "frequency_ppm": fnum(7),
        "residual_frequency_ppm": fnum(8),
        "skew_ppm": fnum(9),
        "root_delay_seconds": fnum(10),
        "root_dispersion_seconds": fnum(11),
        "update_interval_seconds": fnum(12),
        "leap_status": fields[13].strip(),
        # A stratum of 10 here is the local fallback (not synced upstream)
        "synced": 0 < stratum < 10,
    })

    try:
        stats = subprocess.check_output(
            ["chronyc", "-c", "serverstats"], universal_newlines=True, timeout=5
        ).strip().split(",")

        def sint(i):
            try:
                return int(stats[i])
            except (IndexError, TypeError, ValueError):
                return 0

        health["packets_received"] = sint(0)
        health["packets_dropped"] = sint(1)
        health["command_packets"] = sint(2)
        health["command_dropped"] = sint(3)
    except Exception:
        health["packets_received"] = None
        health["packets_dropped"] = None
        health["command_packets"] = None
        health["command_dropped"] = None

    return health


def get_chrony_clients():
    try:
        output = subprocess.check_output(["chronyc", "-c", "clients"], universal_newlines=True, timeout=5)
    except subprocess.TimeoutExpired:
        return [], 0, "Timeout (chronyc clients too slow)"
    except Exception as e:
        return [], 0, f"Error: {e}"

    lines = output.strip().split("\n")

    body = [ln for ln in lines if ln.strip()]
    hostnames, ipv4s, ipv6s = [], [], []

    for ln in body:
        parts = ln.split(",")
        if not parts:
            continue

        addr = parts[0]

        # filter local addresses
        if addr in ["127.0.0.1", "::1"]:
            continue

        if _is_ipv4(addr):
            ipv4s.append(ln)
        elif _is_ipv6(addr):
            ipv6s.append(ln)
        else:
            hostnames.append(ln)

    hostnames.sort(key=lambda x: x.split(",")[0].lower())
    ipv4s.sort(key=lambda x: tuple(map(int, x.split(",")[0].split("."))))
    ipv6s.sort(key=lambda x: x.split(",")[0])

    sorted_lines = hostnames + ipv4s + ipv6s

    parsed = []
    for ln in sorted_lines:
        try:
            row = _parse_client_line(ln)
        except ValueError:
            return [], 0, "Invalid client data returned by chronyc"

        if not row:
            continue

        row["StaleAfter"] = stale_threshold_seconds(row)
        row["Status"] = calculate_status(row)

        parsed.append(row)
    return parsed, len(parsed), ""

def get_local_time():
    return datetime.now().strftime("%d-%m-%Y, %H:%M:%S")

# ---------- chrony log reading ----------
CHRONY_LOGDIR = "/var/log/chrony"

def _read_log_tail(filename, max_lines=400):
    """Read the last N non-banner lines of a chrony log file.

    Handles the file rotating mid-read by retrying once, and tolerates a
    missing file (returns []).
    """
    path = os.path.join(CHRONY_LOGDIR, filename)
    for _attempt in range(2):
        try:
            with open(path, "r", errors="replace") as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            return []
        except OSError:
            return []
        # A chrony log may be replaced by rotation between open and read;
        # if the file we read is now gone, retry once.
        if os.path.exists(path):
            break
    # Drop banner/blank lines (banner rows start with '=' or contain headers)
    out = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("=")]
    # Skip the textual header row (starts with "Date (UTC)")
    out = [ln for ln in out if not ln.lstrip().startswith("Date (UTC)")]
    return out[-max_lines:]

def _fnum(token, default=None):
    try:
        return float(token)
    except (TypeError, ValueError):
        return default

def _inum(token, default=None):
    try:
        return int(token)
    except (TypeError, ValueError):
        return default

def parse_tracking_log(max_entries=180):
    """Parse tracking.log: server-wide sync state over time."""
    entries = []
    for ln in _read_log_tail("tracking.log"):
        p = ln.split()
        # Date Time IP St Freq Skew Offset L Co Offset_sd Rem_corr Root_delay Root_disp Max_err
        if len(p) < 13:
            continue
        entries.append({
            "ts": p[0] + " " + p[1],
            "source": p[2],
            "stratum": _inum(p[3], 0),
            "frequency_ppm": _fnum(p[4]),
            "skew_ppm": _fnum(p[5]),
            "offset": _fnum(p[6]),
            "leap": p[7],
            "root_delay": _fnum(p[10]),
            "root_dispersion": _fnum(p[11]),
        })
    return entries[-max_entries:]

def parse_statistics_log(max_entries=400):
    """Parse statistics.log: per-source estimates over time."""
    entries = []
    for ln in _read_log_tail("statistics.log"):
        p = ln.split()
        # Date Time IP Std_dev Est_offset Offset_sd Diff_freq Est_skew Stress Ns Bs Nr Asym
        if len(p) < 12:
            continue
        entries.append({
            "ts": p[0] + " " + p[1],
            "source": p[2],
            "std_dev": _fnum(p[3]),
            "est_offset": _fnum(p[4]),
            "offset_sd": _fnum(p[5]),
            "diff_freq": _fnum(p[6]),
            "est_skew": _fnum(p[7]),
            "stress": _fnum(p[8]),
            "samples": _inum(p[9], 0),
        })
    return entries[-max_entries:]

def get_log_summary():
    """Aggregate overview of the log files for the dashboard."""
    files = {}
    for name in ("tracking.log", "measurements.log", "statistics.log"):
        path = os.path.join(CHRONY_LOGDIR, name)
        try:
            st = os.stat(path)
            files[name] = {"exists": True, "size": st.st_size,
                           "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
        except OSError:
            files[name] = {"exists": False, "size": 0, "modified": None}
    return files

@app.route("/history")
def history():
    tracking = parse_tracking_log()
    statistics = parse_statistics_log()

    # Build per-source offset series from statistics.log for charting
    sources = {}
    for e in statistics:
        sources.setdefault(e["source"], []).append(e)
    source_series = []
    for src, rows in sources.items():
        # keep the most recent 60 points per source, oldest-first
        rows = rows[-60:]
        source_series.append({
            "source": src,
            "points": [{"t": r["ts"], "offset": r["est_offset"]} for r in rows],
        })
    source_series.sort(key=lambda s: s["source"])

    payload = {
        "local_time": get_local_time(),
        "files": get_log_summary(),
        "tracking": tracking,
        "statistics": statistics[-200:],
        "sources": source_series,
    }
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/data")
def data():
    parsed, count, err = get_chrony_clients()
    payload = {
        "clients_parsed": parsed,
        "count": count,
        "local_time": get_local_time(),
        "server": get_server_health(),
    }
    if err:
        payload["error"] = err
    response = jsonify(payload)
    response.status_code = 503 if err else 200
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/documentation")
def documentation():
    return render_template("documentation.html")

@app.route("/clients", defaults={"status": "All"})
@app.route("/clients/<status>")
def client_list(status):
    if status not in ("All", "OK", "Stale", "Warning", "Critical"):
        abort(404)
    return render_template("clients.html", status=status)

@app.route("/")
def dashboard():
    html = """
    <!DOCTYPE html>
    <html lang="en" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Indo Raya Tenaga NTP Server</title>

        <link rel="icon" type="image/png" href="/static/img/logo-indoraya-color.png"/>
        <link rel="icon" type="image/png" href="/static/img/favicon.png"/>

        <style>
            :root{
                --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --info:#38bdf8;
                --bg:#0b1119; --bg-grad-1:#0e1622; --bg-grad-2:#0b1119;
                --card:#141c27; --card-2:#1a2432;
                --text:#e8eef5; --text-dim:#8a97a8; --text-faint:#5f6b7c;
                --border: rgba(255,255,255,.08); --row-sep: rgba(255,255,255,.05);
                --accent:#5eead4; --accent-2:#38bdf8;
                --tile-bg: rgba(255,255,255,0.035); --detail-bg: rgba(255,255,255,0.02);
                --shadow: 0 4px 20px rgba(0,0,0,.35);
                --toolbar-bg: rgba(15,22,32,.78);
                --toolbar-border: rgba(255,255,255,.10);
            }
            html[data-bs-theme="light"]{
                --bg:#f1f5f9; --bg-grad-1:#f8fafc; --bg-grad-2:#eef2f7;
                --card:#ffffff; --card-2:#f8fafc;
                --text:#0f172a; --text-dim:#55637a; --text-faint:#8794a8;
                --border: rgba(15,23,42,.10); --row-sep: rgba(15,23,42,.06);
                --accent:#0d9488; --accent-2:#0284c7;
                --tile-bg: rgba(15,23,42,0.03); --detail-bg: rgba(15,23,42,0.02);
                --shadow: 0 4px 18px rgba(15,23,42,.08);
                --toolbar-bg: rgba(255,255,255,.88);
                --toolbar-border: rgba(15,23,42,.10);
            }

            *{ box-sizing:border-box; }
            body{
                font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
                background: linear-gradient(180deg, var(--bg-grad-1) 0%, var(--bg-grad-2) 340px);
                background-color: var(--bg);
                color: var(--text);
                min-height:100vh;
                -webkit-font-smoothing: antialiased;
                margin:0;
            }
            .page{ max-width: 1240px; margin: 0 auto; padding: 18px 20px 48px; }

            /* ---------- header ---------- */
            .brand-wrap{
                display:flex; align-items:center; justify-content:center;
                gap: 14px; margin-top: 8px;
            }
            .brand-logo{
                height: 46px; width:auto; object-fit:contain; user-select:none;
                /* The supplied logo is dark navy with a transparent background,
                   so it is placed on a light chip to stay legible in dark mode. */
                background: #ffffff; border-radius: 10px; padding: 6px 10px;
                box-shadow: 0 2px 12px rgba(0,0,0,.22);
            }
            @media (max-width: 600px){ .brand-logo{ height: 34px; padding: 5px 8px; } }
            .brand-text{ display:flex; flex-direction:column; }
            .brand-wrap .title{
                font-weight: 800; font-size: clamp(1.4rem, 0.9rem + 1.5vw, 2.15rem);
                letter-spacing: .3px; line-height:1.1;
                background: linear-gradient(92deg, var(--accent), var(--accent-2));
                -webkit-background-clip: text; background-clip: text; color: transparent;
            }
            .brand-sub{ color: var(--text-dim); font-size: .92rem; font-weight:500; letter-spacing:.2px; margin-top:2px; }
            .brand-credit{
                color: var(--text-faint); font-size: .76rem; margin-top:5px; line-height:1.5;
                max-width: 560px;
            }
            .brand-credit a{ color: var(--text-dim); text-decoration:none; border-bottom:1px dotted var(--text-faint); }
            .brand-credit a:hover{ color: var(--accent-2); }
            .brand-credit strong{ color: var(--text-dim); font-weight:600; }

            /* ---------- live status strip ---------- */
            .status-strip{
                display:flex; align-items:center; justify-content:center; gap: 18px;
                flex-wrap:wrap; margin: 16px 0 22px; color: var(--text-dim); font-size:.86rem;
            }
            .live{ display:inline-flex; align-items:center; gap:8px; font-weight:600; color: var(--text); }
            .dot{ width:9px; height:9px; border-radius:50%; background: var(--ok); box-shadow:0 0 0 0 rgba(34,197,94,.6); animation: pulse 2s infinite; }
            .dot.bad{ background: var(--bad); box-shadow:0 0 0 0 rgba(239,68,68,.6); }
            @keyframes pulse{
                0%{ box-shadow:0 0 0 0 rgba(34,197,94,.55); }
                70%{ box-shadow:0 0 0 9px rgba(34,197,94,0); }
                100%{ box-shadow:0 0 0 0 rgba(34,197,94,0); }
            }
            .sep-dot{ opacity:.35; }

            /* ---------- section titles ---------- */
            .section-title{
                display:flex; align-items:center; gap:9px;
                font-size: .82rem; font-weight:700; letter-spacing:.09em; text-transform:uppercase;
                color: var(--text-faint); margin: 0 0 12px 2px;
            }
            .section-title .line{ flex:1; height:1px; background: var(--border); }

            /* ---------- server health ---------- */
            .health-grid{
                display:grid; gap:12px; margin-bottom: 26px;
                grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            }
            .hcard{
                position:relative; background: var(--card); border:1px solid var(--border);
                border-radius: 14px; padding: 14px 16px; box-shadow: var(--shadow);
                overflow:hidden;
            }
            .hcard::before{
                content:""; position:absolute; left:0; top:0; bottom:0; width:3px;
                background: var(--accent);
            }
            .hcard.ok::before{ background: var(--ok); }
            .hcard.warn::before{ background: var(--warn); }
            .hcard.bad::before{ background: var(--bad); }
            .hcard .hlabel{
                font-size:.72rem; text-transform:uppercase; letter-spacing:.07em;
                color: var(--text-faint); font-weight:700; margin-bottom:6px;
                display:flex; align-items:center; gap:6px;
            }
            .hcard .hvalue{ font-size:1.5rem; font-weight:800; letter-spacing:.2px; line-height:1.15;
                font-variant-numeric: tabular-nums; }
            .hcard .hsub{ font-size:.78rem; color: var(--text-dim); margin-top:4px; }
            .hvalue .unit{ font-size:.85rem; font-weight:600; color: var(--text-dim); margin-left:3px; }

            /* ---------- client stat cards ---------- */
            .stat-grid{
                display:grid; gap:12px; margin-bottom: 22px;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }
            .stat{
                background: var(--card); border:1px solid var(--border); border-radius:14px;
                padding: 15px 16px; box-shadow: var(--shadow); position:relative; overflow:hidden;
                display:block; color:var(--text); text-decoration:none;
                transition:transform .15s ease, border-color .15s ease;
            }
            .stat:hover{ transform:translateY(-3px); border-color:var(--accent-2); }
            .stat:focus-visible{ outline:2px solid var(--accent-2); outline-offset:3px; }
            .stat .view-link{ display:block; margin-top:10px; font-size:.74rem; color:var(--text-dim); }
            @media (prefers-reduced-motion:reduce){ .stat{ transition:none; } .stat:hover{ transform:none; } }
            .stat .top{ display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
            .stat .name{ font-size:.78rem; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color: var(--text-dim); }
            .stat .ico{ width:30px; height:30px; border-radius:9px; display:flex; align-items:center; justify-content:center; font-size:15px; }
            .stat .num{ font-size:2.1rem; font-weight:800; line-height:1; font-variant-numeric: tabular-nums; }
            .stat .pct{ font-size:.82rem; font-weight:600; color: var(--text-dim); margin-left:7px; }
            .stat .bar{ height:5px; border-radius:99px; background: var(--tile-bg); margin-top:12px; overflow:hidden; }
            .stat .bar > i{ display:block; height:100%; border-radius:99px; transition: width .5s ease; }
            .s-ok .ico{ background: rgba(34,197,94,.14); color: var(--ok); } .s-ok .num{ color: var(--ok); } .s-ok .bar > i{ background: var(--ok); }
            .s-stale .ico{ background: rgba(56,189,248,.14); color: var(--info); } .s-stale .num{ color: var(--info); } .s-stale .bar > i{ background: var(--info); }
            .s-warn .ico{ background: rgba(245,158,11,.14); color: var(--warn); } .s-warn .num{ color: var(--warn); } .s-warn .bar > i{ background: var(--warn); }
            .s-bad .ico{ background: rgba(239,68,68,.14); color: var(--bad); } .s-bad .num{ color: var(--bad); } .s-bad .bar > i{ background: var(--bad); }
            .s-total .ico{ background: rgba(94,234,212,.14); color: var(--accent); } .s-total .num{ color: var(--accent); }

            /* ---------- toolbar ---------- */
            .toolbar{
                position: fixed; right: 18px; top: 14px; z-index: 1000;
                display:flex; align-items:center; gap:10px;
                padding: 6px 12px; border-radius: 999px;
                background: var(--toolbar-bg); border: 1px solid var(--toolbar-border);
                box-shadow: 0 8px 26px rgba(0,0,0,.30); backdrop-filter: blur(10px);
            }
            .switch{ display:flex; align-items:center; gap:8px; user-select:none; cursor:pointer; }
            .switch input{ display:none; }
            .slider{ position:relative; width:44px; height:21px; background:#64748b; border-radius:999px; transition:.25s; }
            .slider::before{ content:""; position:absolute; height:17px; width:17px; left:2px; bottom:2px; background:#fff; border-radius:50%; transition:.25s; box-shadow:0 1px 3px rgba(0,0,0,.35); }
            .switch input:checked + .slider{ background: var(--accent); }
            .switch input:checked + .slider::before{ transform: translateX(23px); }
            .ico{ width:17px; height:17px; opacity:.9; }
            .info-wrap{ position:relative; }
            .info-btn{
                width:22px; height:22px; border-radius:50%; display:flex; align-items:center; justify-content:center;
                background: var(--accent-2); color:#04141f; font-weight:800; cursor:pointer; user-select:none;
                line-height:1; font-size:.8rem;
            }
            .info-pop{
                position:absolute; right:0; top:40px; min-width:270px; max-width:330px;
                background: var(--card); border:1px solid var(--border); color: var(--text);
                border-radius:12px; padding:12px 14px; box-shadow: 0 12px 30px rgba(0,0,0,.35);
                display:none; z-index:3000; font-size:.85rem; line-height:1.5;
            }
            .info-pop a{ color: var(--accent-2); }
            .docs-btn{ display:inline-flex; align-items:center; gap:6px;
                color:var(--text); border:1px solid var(--border); border-radius:999px;
                padding:5px 10px; font-size:.78rem; font-weight:600; text-decoration:none; }
            .docs-btn:hover{ background:var(--card-2); color:var(--accent-2); }
            .docs-btn:focus-visible{ outline:2px solid var(--accent-2); outline-offset:3px; }
            .page{ padding-top:64px; }
            @media (max-width:520px){ .docs-btn span{ display:none; } }

            /* ---------- controls ---------- */
            .controls{
                display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:14px;
            }
            .controls .search-wrap{ position:relative; flex:1; min-width:220px; max-width:460px; }
            .controls .search-wrap svg{ position:absolute; left:12px; top:50%; transform:translateY(-50%); width:16px; height:16px; opacity:.5; }
            .ctrl{
                background: var(--card); border:1px solid var(--border); color: var(--text);
                border-radius:10px; padding:9px 13px; font-size:.9rem; outline:none; transition:.15s;
            }
            .ctrl:focus{ border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(56,189,248,.15); }
            input.ctrl{ padding-left:36px; width:100%; }
            select.ctrl{ cursor:pointer; }

            /* ---------- table ---------- */
            .table-wrap{ background: var(--card); border:1px solid var(--border); border-radius:16px;
                overflow:hidden; box-shadow: var(--shadow); }
            table{ width:100%; border-collapse: collapse; font-size:.92rem; }
            thead th{
                text-align:left; font-weight:700; font-size:.75rem; letter-spacing:.05em; text-transform:uppercase;
                color: var(--text-faint); padding:13px 14px; border-bottom:1px solid var(--border);
                background: var(--card-2); white-space:nowrap;
            }
            tbody td{ padding:11px 14px; border-top:1px solid var(--row-sep); }
            tbody tr.client-row{ cursor:pointer; transition: background .12s; }
            tbody tr.client-row:hover{ background: var(--tile-bg); }
            .td-num{ text-align:right; font-variant-numeric: tabular-nums; }
            .addr-cell{ font-weight:600; display:flex; align-items:center; gap:8px; }
            .mono{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
            .caret-cell{ width:34px; text-align:center; color: var(--text-faint); }
            .status-badge{
                display:inline-flex; align-items:center; gap:6px; font-size:.76rem; font-weight:700;
                padding:3px 10px; border-radius:99px; white-space:nowrap;
            }
            .status-badge::before{ content:""; width:6px; height:6px; border-radius:50%; background: currentColor; }
            .b-ok{ background: rgba(34,197,94,.13); color: var(--ok); }
            .b-stale{ background: rgba(56,189,248,.13); color: var(--info); }
            .b-warn{ background: rgba(245,158,11,.13); color: var(--warn); }
            .b-bad{ background: rgba(239,68,68,.13); color: var(--bad); }

            .sev-0{ box-shadow: inset 3px 0 0 var(--ok); }
            .sev-1{ box-shadow: inset 3px 0 0 var(--info); }
            .sev-2{ box-shadow: inset 3px 0 0 var(--warn); }
            .sev-3{ box-shadow: inset 3px 0 0 var(--bad); }

            .subnet-header-row{ cursor:pointer; }
            .subnet-header{ background: var(--card-2); padding:11px 14px !important; }
            .subnet-row{ display:flex; justify-content:space-between; align-items:center; }
            .subnet-left{ font-weight:700; font-size:.9rem; display:flex; align-items:center; gap:8px; }
            .subnet-count{ color: var(--text-faint); font-weight:500; font-size:.82rem; }
            .subnet-right{ font-weight:700; font-size:.82rem; }

            .detail-row td{ background: var(--detail-bg); padding:0 !important; }
            .metrics{ display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:10px; padding:14px; }
            @media (max-width: 900px){ .metrics{ grid-template-columns: repeat(2, minmax(0,1fr)); } }
            @media (max-width: 560px){ .metrics{ grid-template-columns: 1fr; } }
            .metric{ border-radius:11px; background: var(--tile-bg); padding:11px 13px;
                display:flex; flex-direction:column; gap:3px; }
            .metric .label{ font-size:.72rem; text-transform:uppercase; letter-spacing:.05em; color: var(--text-faint); font-weight:700; }
            .metric .value{ font-weight:700; font-size:1.02rem; font-variant-numeric: tabular-nums; }

            .alert-box{ border-radius:12px; padding:12px 15px; margin-bottom:16px; font-size:.9rem;
                border:1px solid rgba(245,158,11,.35); background: rgba(245,158,11,.10); color: var(--warn); }
            .empty-state{ text-align:center; padding:44px 20px; color: var(--text-dim); }
            /* ---------- time history ---------- */
            .hist-range{ margin-left:auto; }
            .ctrl-sm{ padding:5px 10px; font-size:.8rem; }
            .hist-note{ color: var(--text-faint); font-size:.82rem; margin:-4px 0 12px 2px; }
            .chart-grid{ display:grid; gap:12px; grid-template-columns: repeat(auto-fit, minmax(320px,1fr)); }
            .chart-card{ background: var(--card); border:1px solid var(--border); border-radius:14px;
                padding:14px 16px; box-shadow: var(--shadow); }
            .chart-head{ display:flex; align-items:baseline; justify-content:space-between; margin-bottom:10px; }
            .chart-title{ font-weight:700; font-size:.9rem; }
            .chart-sub{ color: var(--text-faint); font-size:.76rem; }
            canvas{ width:100%; display:block; }
            .hist-bad{ color: var(--bad); } .hist-warn{ color: var(--warn); }
            .hist-ok{ color: var(--ok); }
            .history-pagination{ display:flex; align-items:center; justify-content:flex-end;
                flex-wrap:wrap; gap:10px; margin-top:12px; font-size:.82rem; color:var(--text-dim); }
            .history-pagination button{ cursor:pointer; }
            .history-pagination button:disabled{ opacity:.4; cursor:default; }
            .history-pagination button:focus-visible{ outline:2px solid var(--accent-2); outline-offset:3px; }
            .footer-credit{
                text-align:center; margin-top:26px; padding-top:16px;
                border-top:1px solid var(--border); color: var(--text-faint);
                font-size:.8rem; line-height:1.7;
            }
            .footer-credit a{ color: var(--text-dim); text-decoration:none; border-bottom:1px dotted var(--text-faint); }
            .footer-credit a:hover{ color: var(--accent-2); }
            @media (max-width: 720px){
                thead th:nth-child(5), tbody td:nth-child(5),
                thead th:nth-child(6), tbody td:nth-child(6){ display:none; }
            }
        </style>
    </head>
    <body>
        <!-- Toolbar -->
        <div class="toolbar">
            <label class="switch" title="Expand / collapse all clients">
                <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="3" width="7" height="7" rx="1"></rect>
                    <rect x="14" y="3" width="7" height="7" rx="1"></rect>
                    <rect x="3" y="14" width="7" height="7" rx="1"></rect>
                </svg>
                <input type="checkbox" id="expand-toggle"><span class="slider"></span>
            </label>
            <label class="switch" title="Light / dark theme">
                <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 3v2M12 19v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M3 12h2M19 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"></path>
                    <circle cx="12" cy="12" r="5"></circle>
                </svg>
                <input type="checkbox" id="theme-toggle"><span class="slider"></span>
            </label>
            <div class="info-wrap">
                <div class="info-btn" id="infoBtn" title="Project info">i</div>
                <div class="info-pop" id="infoPop">
                    <strong>Indo Raya Tenaga NTP Server</strong><br/>
                    Time Information of Chrony Clients.<br/><br/>
                    Dashboard based on the open-source
                    <a href="https://github.com/anoniemerd/ticc-dash" target="_blank" rel="noopener">TICC-DASH</a>
                    project by <strong>Anoniemerd</strong>
                    (<a href="https://ticc-dash.org" target="_blank" rel="noopener">ticc-dash.org</a>),
                    released under the MIT License.
                </div>
            </div>
            <a class="docs-btn" id="documentationBtn" href="/documentation" target="ntpDocumentation"
               title="Documentation (opens a new window)" aria-label="Documentation (opens a new window)">
                <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <path d="M12 5v15M12 5C8 2 4 3 2 4v15c3-1 6-1 10 1 4-2 7-2 10-1V4c-2-1-6-2-10 1Z"></path>
                </svg><span>Documentation</span>
            </a>
        </div>

        <div class="page">
            <!-- Header -->
            <div class="brand-wrap">
                <img class="brand-logo" src="/static/img/logo-indoraya-color.png" alt="Indo Raya Tenaga" />
                <div class="brand-text">
                    <div class="title">Indo Raya Tenaga NTP Server</div>
                    <div class="brand-sub">Time Information of Chrony Clients</div>
                    <div class="brand-credit">
                        Dashboard based on the open-source
                        <a href="https://github.com/anoniemerd/ticc-dash" target="_blank" rel="noopener">TICC-DASH</a>
                        project by <strong>Anoniemerd</strong>
                        (<a href="https://ticc-dash.org" target="_blank" rel="noopener">ticc-dash.org</a>), MIT License.
                    </div>
                </div>
            </div>

            <!-- Live status strip -->
            <div class="status-strip">
                <span class="live"><span class="dot" id="live-dot"></span><span id="live-label">Connecting…</span></span>
                <span class="sep-dot">•</span>
                <span id="last-update">Waiting for first update…</span>
                <span class="sep-dot">•</span>
                <span class="mono" id="server-clock">--:--:--</span>
            </div>

            <div id="collection-error" class="alert-box" role="alert" hidden></div>

            <!-- Server health -->
            <div class="section-title">NTP Server Health <span class="line"></span></div>
            <div class="health-grid" id="health-grid"></div>

            <!-- Client summary -->
            <div class="section-title">Client Overview <span class="line"></span></div>
            <div class="stat-grid">
                <a class="stat s-total" href="/clients" target="ntpClients" aria-label="View all clients in a popup window">
                    <div class="top"><span class="name">Total Clients</span><span class="ico">📡</span></div>
                    <div><span class="num" id="count-total">0</span></div>
                    <div class="bar"><i style="width:100%; background:var(--accent)"></i></div>
                    <span class="view-link">View all clients ↗</span>
                </a>
                <a class="stat s-ok" href="/clients/OK" target="ntpClients" aria-label="View OK clients in a popup window">
                    <div class="top"><span class="name">OK</span><span class="ico">✓</span></div>
                    <div><span class="num" id="count-ok">0</span><span class="pct" id="pct-ok">0%</span></div>
                    <div class="bar"><i id="bar-ok" style="width:0%"></i></div>
                    <span class="view-link">View OK clients ↗</span>
                </a>
                <a class="stat s-stale" href="/clients/Stale" target="ntpClients" aria-label="View stale clients in a popup window">
                    <div class="top"><span class="name">Stale</span><span class="ico">◷</span></div>
                    <div><span class="num" id="count-stale">0</span><span class="pct" id="pct-stale">0%</span></div>
                    <div class="bar"><i id="bar-stale" style="width:0%"></i></div>
                    <span class="view-link">View stale clients ↗</span>
                </a>
                <a class="stat s-warn" href="/clients/Warning" target="ntpClients" aria-label="View warning clients in a popup window">
                    <div class="top"><span class="name">Warning</span><span class="ico">!</span></div>
                    <div><span class="num" id="count-warn">0</span><span class="pct" id="pct-warn">0%</span></div>
                    <div class="bar"><i id="bar-warn" style="width:0%"></i></div>
                    <span class="view-link">View warning clients ↗</span>
                </a>
                <a class="stat s-bad" href="/clients/Critical" target="ntpClients" aria-label="View critical clients in a popup window">
                    <div class="top"><span class="name">Critical</span><span class="ico">✕</span></div>
                    <div><span class="num" id="count-bad">0</span><span class="pct" id="pct-bad">0%</span></div>
                    <div class="bar"><i id="bar-bad" style="width:0%"></i></div>
                    <span class="view-link">View critical clients ↗</span>
                </a>
            </div>

            <!-- Controls -->
            <div class="controls">
                <div class="search-wrap">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="7"></circle><path d="M21 21l-4.3-4.3"></path>
                    </svg>
                    <input id="search" type="text" class="ctrl" placeholder="Search by address or status…"/>
                </div>
                <select id="sort-select" class="ctrl" title="Sort clients">
                    <option value="ip_order">Sort: IP address</option>
                    <option value="drop_desc">Sort: drop count (high → low)</option>
                    <option value="last_recent">Sort: last seen (recent → old)</option>
                    <option value="status_sev">Sort: severity (worst first)</option>
                </select>
            </div>

            <!-- Table -->
            <div class="table-wrap">
                <table>
                    <colgroup>
                        <col style="width:34px" />
                        <col />
                        <col style="width:130px" />
                        <col style="width:86px" />
                        <col style="width:86px" />
                        <col style="width:86px" />
                        <col style="width:104px" />
                        <col style="width:150px" />
                    </colgroup>
                    <thead>
                        <tr>
                            <th class="caret-cell"></th>
                            <th>Address</th>
                            <th>Status</th>
                            <th class="td-num">NTP</th>
                            <th class="td-num">Drop</th>
                            <th class="td-num">Cmd</th>
                            <th class="td-num" title="Estimated request interval in log2(seconds); 12 ≈ 4096 s">Interval</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody id="client-tbody"></tbody>
                </table>
                <div id="empty-state" class="empty-state" hidden>No clients match your filter.</div>
            </div>

            <!-- Time History (from chrony logs) -->
            <div class="section-title" style="margin-top:30px;">Time History <span class="line"></span>
                <span class="hist-range">
                    <select id="hist-range" class="ctrl ctrl-sm">
                        <option value="60">Last 60 samples</option>
                        <option value="180" selected>Last 180 samples</option>
                        <option value="400">Last 400 samples</option>
                    </select>
                </span>
            </div>
            <div id="hist-note" class="hist-note">Loading history…</div>

            <div class="chart-grid">
                <div class="chart-card">
                    <div class="chart-head">
                        <span class="chart-title">Clock offset</span>
                        <span class="chart-sub" id="chart-offset-sub">system offset over time</span>
                    </div>
                    <canvas id="chart-offset" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <div class="chart-head">
                        <span class="chart-title">Frequency drift</span>
                        <span class="chart-sub">ppm</span>
                    </div>
                    <canvas id="chart-freq" height="150"></canvas>
                </div>
            </div>

            <div class="table-wrap" style="margin-top:14px;">
                <table>
                    <colgroup>
                        <col style="width:180px" /><col style="width:180px" /><col style="width:150px" /><col />
                        <col style="width:120px" /><col style="width:110px" /><col style="width:110px" />
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Timestamp (UTC)</th>
                            <th>Timestamp (UTC +7)</th>
                            <th>Source</th>
                            <th>Leap</th>
                            <th class="td-num">Stratum</th>
                            <th class="td-num">Offset</th>
                            <th class="td-num">Freq (ppm)</th>
                        </tr>
                    </thead>
                    <tbody id="hist-tbody"></tbody>
                </table>
                <div id="hist-empty" class="empty-state" hidden>No history yet — chrony logging was just enabled, so entries appear over time.</div>
            </div>
            <nav class="history-pagination" aria-label="Time History pages">
                <span id="hist-page-info" role="status">Page 0 of 0 · 0 records</span>
                <button id="hist-prev" class="ctrl ctrl-sm" type="button" aria-controls="hist-tbody" disabled>← Previous</button>
                <button id="hist-next" class="ctrl ctrl-sm" type="button" aria-controls="hist-tbody" disabled>Next →</button>
            </nav>

            <div class="footer-credit">
                Dashboard based on the open-source
                <a href="https://github.com/anoniemerd/ticc-dash" target="_blank" rel="noopener">TICC-DASH</a>
                project by <strong>Anoniemerd</strong>
                (<a href="https://ticc-dash.org" target="_blank" rel="noopener">ticc-dash.org</a>), MIT License
                &nbsp;•&nbsp; Indo Raya Tenaga NTP Server
            </div>
        </div>

        <script>
            const THEME_KEY="ticc_dash_theme";
            function applyTheme(theme){
                document.documentElement.setAttribute("data-bs-theme", theme);
                const t=document.getElementById("theme-toggle"); if(t) t.checked = (theme==="dark");
            }
            const savedTheme=localStorage.getItem(THEME_KEY)||"dark"; applyTheme(savedTheme);
            document.getElementById("theme-toggle").addEventListener("change", function(){
                const t=this.checked?"dark":"light"; localStorage.setItem(THEME_KEY,t); applyTheme(t);
            });

            const infoBtn=document.getElementById("infoBtn"), infoPop=document.getElementById("infoPop");
            infoBtn.addEventListener("click",(e)=>{e.stopPropagation(); infoPop.style.display = infoPop.style.display==="block"?"none":"block";});
            document.addEventListener("click",(e)=>{ if(!infoPop.contains(e.target) && e.target!==infoBtn){ infoPop.style.display="none"; } });
            document.querySelectorAll("#documentationBtn, .stat-grid a.stat").forEach(link=>{
                link.addEventListener("click", function(e){
                    if(e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
                    const popup=window.open(this.href, this.target,
                        "popup=yes,width=980,height=780,resizable=yes,scrollbars=yes");
                    if(popup){ e.preventDefault(); popup.focus(); }
                });
            });

            function $(id){ return document.getElementById(id); }
            function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
            function toInt(v){ const n=parseInt(v,10); return isNaN(n)?0:n; }

            function lastToSeconds(raw){
                if(raw==null) return null; const s=String(raw).trim().toLowerCase();
                if (s==="-"||s==="?"||s==="") return null;
                if (/^\\d+$/.test(s)) return parseInt(s,10);
                const m=s.match(/^(\\d+(?:\\.\\d+)?)\\s*([a-z]+)$/i); if(!m) return null;
                const num=parseFloat(m[1]), unit=m[2];
                if(["s","sec","secs","second","seconds"].includes(unit)) return num;
                if(["m","min","mins","minute","minutes"].includes(unit)) return num*60;
                if(["h","hr","hrs","hour","hours"].includes(unit)) return num*3600;
                if(["d","day","days"].includes(unit)) return num*86400;
                return null;
            }
            function humanLast(raw){
                const sec=lastToSeconds(raw); if(sec===null) return raw||"-";
                if(sec<60) return Math.floor(sec)+" sec ago";
                const m=Math.floor(sec/60); if(m<60) return m+" min ago";
                const h=Math.floor(m/60); if(h<24) return h+" hr ago";
                return Math.floor(h/24)+" d ago";
            }
            function severity(r){
                if(r.Status === "Critical") return 3;
                if(r.Status === "Warning") return 2;
                if(r.Status === "Stale") return 1;
                return 0;
            }
            function statusBadge(r){
                const map={OK:"b-ok",Stale:"b-stale",Warning:"b-warn",Critical:"b-bad"};
                return '<span class="status-badge '+(map[r.Status]||"b-ok")+'">'+esc(r.Status)+'</span>';
            }
            function iconForAddr(a){
                if(/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(a)) return "🌐";
                if(/^[0-9a-fA-F:]+$/.test(a) && a.includes(":")) return "🔗";
                return "💻";
            }

            /* ---------- server health rendering ---------- */
            function fmtSeconds(s){
                if(s==null || isNaN(s)) return "-";
                const a=Math.abs(s);
                if(a < 1e-3) return (s*1e6).toFixed(0)+" µs";
                if(a < 1) return (s*1e3).toFixed(3)+" ms";
                return s.toFixed(3)+" s";
            }
            function healthCard(cls, label, value, unit, sub){
                return '<div class="hcard '+cls+'"><div class="hlabel">'+label+'</div>'+
                       '<div class="hvalue">'+value+(unit?'<span class="unit">'+unit+'</span>':'')+'</div>'+
                       (sub?'<div class="hsub">'+sub+'</div>':'')+'</div>';
            }
            function renderHealth(s){
                const g=$("health-grid");
                if(!s || !s.available){
                    g.innerHTML = healthCard("warn","Server status","Unavailable","", esc((s&&s.error)||"chronyc tracking not readable"));
                    return;
                }
                const synced=!!s.synced;
                const stratCls = synced ? (s.stratum<=3?"ok":"") : "bad";
                const leapCls = (s.leap_status==="Normal") ? "ok" : "warn";
                const offCls = Math.abs(s.system_offset_seconds) < 0.05 ? "ok" : (Math.abs(s.system_offset_seconds) < 0.5 ? "warn" : "bad");
                let ageTxt = "";
                if(s.reference_age_seconds!=null){
                    const a=s.reference_age_seconds;
                    ageTxt = a<90 ? a+"s ago" : (a<5400 ? Math.round(a/60)+" min ago" : Math.round(a/3600)+" h ago");
                }
                let packets = "-";
                if(s.packets_received!=null){
                    packets = Number(s.packets_received).toLocaleString();
                }
                g.innerHTML =
                    healthCard(synced?"ok":"bad","Sync state", synced?"Synchronized":"Not synced","",
                        synced? "Locked to upstream source" : "Serving local fallback (stratum 10)") +
                    healthCard(stratCls,"Stratum", s.stratum, "", "Distance from reference clock") +
                    healthCard("","Sync source", '<span class="mono" style="font-size:1rem">'+esc(s.reference_source)+'</span>', "",
                        "Ref ID "+esc(s.reference_id)+(ageTxt? " • "+ageTxt : "")) +
                    healthCard(offCls,"System offset", fmtSeconds(s.system_offset_seconds), "",
                        "RMS "+fmtSeconds(s.rms_offset_seconds)) +
                    healthCard(leapCls,"Leap status", esc(s.leap_status), "", "Frequency "+ (s.frequency_ppm!=null?s.frequency_ppm.toFixed(2):"-") +" ppm") +
                    healthCard("","NTP packets", packets, "",
                        s.packets_dropped!=null ? (Number(s.packets_dropped).toLocaleString()+" dropped") : "");
            }

            /* ---------- summary ---------- */
            function updateSummary(rows){
                let ok=0,w=0,b=0,st=0;
                rows.forEach(r=>{
                    const s=r.Status;
                    if(s==="OK") ok++; else if(s==="Warning") w++;
                    else if(s==="Critical") b++; else if(s==="Stale") st++;
                });
                const total=rows.length||1;
                const set=(id,n)=>{ const el=$(id); if(el) el.textContent=n; };
                const pct=n=>Math.round(n/total*100)+"%";
                set("count-total", rows.length);
                set("count-ok",ok); set("count-stale",st); set("count-warn",w); set("count-bad",b);
                set("pct-ok",pct(ok)); set("pct-stale",pct(st)); set("pct-warn",pct(w)); set("pct-bad",pct(b));
                const bar=(id,n)=>{ const el=$(id); if(el) el.style.width=pct(n); };
                bar("bar-ok",ok); bar("bar-stale",st); bar("bar-warn",w); bar("bar-bad",b);
            }

            /* ---------- detail rows ---------- */
            function metric(label,value){ return '<div class="metric"><div class="label">'+label+'</div><div class="value">'+value+'</div></div>'; }
            function detailHTML(r){
                return '<tr class="detail-row" data-detail-for="'+esc(r.addr)+'"><td></td><td colspan="7"><div class="metrics">'+
                    metric("NTP packets", esc(r.NTP||"-")) +
                    metric("Dropped", esc(r.Drop||"-")) +
                    metric("Command packets", esc(r.Cmd||"-")) +
                    metric("Interval (log₂ s)", esc(r.Int||"-")) +
                    metric("Stale after", esc(r.StaleAfter)+" sec") +
                    metric("Last seen", esc(humanLast(r.Last))) +
                '</div></td></tr>';
            }
            function rowHTML(r){
                const sev=severity(r), addr=r.addr||"", open=openSet.has(addr);
                const caret=open?"▲":"▼";
                return '<tr class="client-row sev-'+sev+'" data-addr="'+esc(addr)+'">'+
                    '<td class="caret-cell"><span class="caret">'+caret+'</span></td>'+
                    '<td class="addr-cell"><span>'+iconForAddr(addr)+'</span><span class="mono">'+esc(addr)+'</span></td>'+
                    '<td>'+statusBadge(r)+'</td>'+
                    '<td class="td-num">'+esc(r.NTP||"-")+'</td>'+
                    '<td class="td-num">'+esc(r.Drop||"-")+'</td>'+
                    '<td class="td-num">'+esc(r.Cmd||"-")+'</td>'+
                    '<td class="td-num">'+esc(r.Int||"-")+'</td>'+
                    '<td>'+esc(humanLast(r.Last))+'</td>'+
                '</tr>'+(open?detailHTML(r):"");
            }

            /* ---------- state ---------- */
            /* Client rows are deliberately NOT persisted. Every page load starts
               fully collapsed so the table stays compact; expanding rows is a
               per-session, at-will action. */
            function loadOpenSet(){ return new Set(); }
            function saveOpenSet(s){ /* intentionally not persisted */ }
            let openSet=loadOpenSet();
            // Only explicitly opened groups are expanded, including newly seen subnets.
            let expandedSubnets = new Set();
            let cache=[], lastHash="";

            function subnetFor(addr){
                return /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(addr)
                    ? addr.split(".").slice(0,3).join(".")+".x" : "Others";
            }

            function updateExpandToggleVisual(){
                const total=document.querySelectorAll("#client-tbody .client-row").length;
                const groups=[...document.querySelectorAll("#client-tbody .subnet-header-row")];
                $("expand-toggle").checked = total>0
                    && groups.every(row=>expandedSubnets.has(row.getAttribute("data-subnet")))
                    && [...document.querySelectorAll("#client-tbody .client-row")]
                        .every(row=>openSet.has(row.getAttribute("data-addr")));
            }
            function ipTuple(a){ if(!/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(a)) return null; return a.split(".").map(n=>parseInt(n,10)); }
            function sortRows(rows, mode){
                if(mode==="ip_order"){
                    rows.sort((a,b)=>{ const A=ipTuple(a.addr||""),B=ipTuple(b.addr||"");
                        if(A&&B){ for(let i=0;i<4;i++){ if(A[i]!=B[i]) return A[i]-B[i]; } return 0; }
                        if(A&&!B) return -1; if(!A&&B) return 1;
                        return (a.addr||"").toLowerCase().localeCompare((b.addr||"").toLowerCase()); });
                } else if(mode==="drop_desc"){ rows.sort((a,b)=> toInt(b.Drop)-toInt(a.Drop)); }
                else if(mode==="last_recent"){ rows.sort((a,b)=>{ const as=lastToSeconds(a.Last), bs=lastToSeconds(b.Last);
                    if(as===null&&bs===null) return 0; if(as===null) return 1; if(bs===null) return -1; return as-bs; }); }
                else if(mode==="status_sev"){ rows.sort((a,b)=> severity(b)-severity(a)); }
                return rows;
            }

            function subnetStatus(rows){ let max=0; rows.forEach(r=>{ const s=severity(r); if(s>max) max=s; }); return max; }
            function subnetLabel(s){ return s===3?"Critical":(s===2?"Warning":(s===1?"Stale":"OK")); }
            function subnetColor(s){
                if(s===3) return "color:var(--bad)";
                if(s===2) return "color:var(--warn)";
                if(s===1) return "color:var(--info)";
                return "color:var(--ok)";
            }

            function render(){
                const q = ($("search").value||"").trim().toLowerCase();
                const mode = $("sort-select").value;
                let rows = cache.filter(r => !q || JSON.stringify(r).toLowerCase().includes(q));
                rows = sortRows(rows, mode);
                updateSummary(rows);

                let grouped = {};
                rows.forEach(r => {
                    const subnet=subnetFor(r.addr||"");
                    if(!grouped[subnet]) grouped[subnet]=[];
                    grouped[subnet].push(r);
                });
                const sortedSubnets = Object.keys(grouped).sort((a,b)=>{
                    const ap=a.split(".").map(x=>parseInt(x)||0), bp=b.split(".").map(x=>parseInt(x)||0);
                    for(let i=0;i<3;i++){ if(ap[i]!==bp[i]) return ap[i]-bp[i]; } return 0;
                });

                let html="";
                sortedSubnets.forEach(subnet=>{
                    const s=subnetStatus(grouped[subnet]);
                    const isCollapsed=!expandedSubnets.has(subnet);
                    const icon=isCollapsed?"▼":"▲";
                    html += '<tr class="subnet-header-row" data-subnet="'+esc(subnet)+'"><td colspan="8" class="subnet-header">'+
                        '<div class="subnet-row"><div class="subnet-left"><span class="caret">'+icon+'</span> '+esc(subnet)+
                        ' <span class="subnet-count">'+grouped[subnet].length+' devices</span></div>'+
                        '<div class="subnet-right" style="'+subnetColor(s)+'">'+subnetLabel(s)+'</div></div></td></tr>';
                    if(!isCollapsed) html += grouped[subnet].map(rowHTML).join("");
                });
                $("client-tbody").innerHTML = html;
                $("empty-state").hidden = rows.length>0;
                bindHandlers();
                updateExpandToggleVisual();
            }

            function setCaret(row, ch){
                const c=row.querySelector(".caret"); if(c) c.textContent=ch;
            }

            function bindHandlers(){
                document.querySelectorAll("#client-tbody .client-row").forEach(row=>{
                    row.onclick = function(e){
                        if(e.target.closest("a,button,select,input,label")) return;
                        const addr=this.getAttribute("data-addr");
                        const isOpen=openSet.has(addr);
                        if(isOpen){
                            setCaret(this, "▼");
                            const d=document.querySelector('tr.detail-row[data-detail-for="'+CSS.escape(addr)+'"]');
                            if(d) d.remove();
                            openSet.delete(addr);
                        } else {
                            setCaret(this, "▲");
                            const rec=cache.find(r=>r.addr===addr);
                            if(rec) this.insertAdjacentHTML("afterend", detailHTML(rec));
                            openSet.add(addr);
                        }
                        saveOpenSet(openSet); updateExpandToggleVisual();
                    };
                });
                document.querySelectorAll("#client-tbody .subnet-header-row").forEach(row=>{
                    row.onclick = function(){
                        const subnet=this.getAttribute("data-subnet");
                        if(expandedSubnets.has(subnet)) expandedSubnets.delete(subnet);
                        else expandedSubnets.add(subnet);
                        render();
                    };
                });
            }

            $("expand-toggle").addEventListener("change", function(){
                if(this.checked){
                    cache.forEach(r=>{
                        expandedSubnets.add(subnetFor(r.addr||""));
                        openSet.add(r.addr||"");
                    });
                } else {
                    expandedSubnets.clear();
                    openSet=new Set();
                }
                render();
            });

            /* ---------- time history & charts ---------- */
            function fmtOffset(v){
                if(v==null || isNaN(v)) return "-";
                const a=Math.abs(v);
                if(a < 1e-3) return (v*1e6).toFixed(0)+" µs";
                if(a < 1) return (v*1e3).toFixed(3)+" ms";
                return v.toFixed(3)+" s";
            }

            /* Draw a simple line chart on a canvas (no external libs). */
            function drawLineChart(canvas, points, opts){
                opts = opts || {};
                const dpr = window.devicePixelRatio || 1;
                const cssW = canvas.clientWidth || 320;
                const cssH = parseInt(canvas.getAttribute("height"),10) || 150;
                canvas.width = cssW*dpr; canvas.height = cssH*dpr;
                const ctx = canvas.getContext("2d");
                ctx.setTransform(dpr,0,0,dpr,0,0);
                ctx.clearRect(0,0,cssW,cssH);

                const padL=52, padR=10, padT=10, padB=20;
                const w = cssW-padL-padR, h = cssH-padT-padB;
                const cs = getComputedStyle(document.documentElement);
                const colLine = opts.color || cs.getPropertyValue("--accent-2").trim() || "#38bdf8";
                const colGrid = cs.getPropertyValue("--border").trim() || "rgba(255,255,255,.1)";
                const colText = cs.getPropertyValue("--text-faint").trim() || "#888";

                if(!points || points.length===0){
                    ctx.fillStyle=colText; ctx.font="12px system-ui";
                    ctx.fillText("no data yet", padL, cssH/2);
                    return;
                }
                const vals = points.map(p=>p.v).filter(v=>v!=null && !isNaN(v));
                if(vals.length===0){ ctx.fillStyle=colText; ctx.font="12px system-ui"; ctx.fillText("no data yet", padL, cssH/2); return; }
                let min=Math.min(...vals), max=Math.max(...vals);
                if(min===max){ min-=1e-6; max+=1e-6; }
                const pad=(max-min)*0.12; min-=pad; max+=pad;

                const xOf = i => padL + (points.length===1 ? w/2 : (i/(points.length-1))*w);
                const yOf = v => padT + h - ((v-min)/(max-min))*h;

                // grid + y labels
                ctx.strokeStyle=colGrid; ctx.fillStyle=colText; ctx.font="10px system-ui"; ctx.lineWidth=1;
                for(let g=0; g<=4; g++){
                    const y=padT + (g/4)*h;
                    ctx.beginPath(); ctx.moveTo(padL,y); ctx.lineTo(padL+w,y); ctx.stroke();
                    const val = max - (g/4)*(max-min);
                    ctx.fillText(fmtOffset(val), 2, y+3);
                }

                // zero line if it falls inside range
                if(min<0 && max>0){
                    ctx.strokeStyle=cs.getPropertyValue("--text-faint").trim()||"#666";
                    ctx.setLineDash([3,3]);
                    ctx.beginPath(); ctx.moveTo(padL,yOf(0)); ctx.lineTo(padL+w,yOf(0)); ctx.stroke();
                    ctx.setLineDash([]);
                }

                // line
                ctx.strokeStyle=colLine; ctx.lineWidth=1.8; ctx.beginPath();
                let started=false;
                points.forEach((p,i)=>{
                    if(p.v==null || isNaN(p.v)) return;
                    const x=xOf(i), y=yOf(p.v);
                    if(!started){ ctx.moveTo(x,y); started=true; } else ctx.lineTo(x,y);
                });
                ctx.stroke();

                // last point marker
                for(let i=points.length-1;i>=0;i--){
                    if(points[i].v!=null && !isNaN(points[i].v)){
                        ctx.fillStyle=colLine;
                        ctx.beginPath(); ctx.arc(xOf(i), yOf(points[i].v), 3, 0, Math.PI*2); ctx.fill();
                        break;
                    }
                }
            }

            function timestampUtc7(timestamp){
                // Parse the log timestamp as UTC, independent of the browser's timezone.
                const utc=Date.parse(String(timestamp||"").replace(" ","T")+"Z");
                if(!Number.isFinite(utc)) return "-";
                return new Date(utc+7*60*60*1000).toISOString().slice(0,19).replace("T"," ");
            }

            const HISTORY_PAGE_SIZE=20;
            let histData=null, histPage=1;
            function renderHistory(){
                if(!histData) return;
                const range = parseInt($("hist-range").value,10) || 180;
                let tracking = histData.tracking || [];
                tracking = tracking.slice(-range);

                // charts
                drawLineChart($("chart-offset"), tracking.map(t=>({t:t.ts, v:t.offset})), {color:"#38bdf8"});
                drawLineChart($("chart-freq"), tracking.map(t=>({t:t.ts, v:t.frequency_ppm})), {color:"#a78bfa"});

                // table (most recent first)
                const rows = tracking.slice().reverse();
                const pageCount=Math.ceil(rows.length/HISTORY_PAGE_SIZE);
                histPage=Math.max(1,Math.min(histPage,pageCount||1));
                const start=(histPage-1)*HISTORY_PAGE_SIZE;
                const pageRows=rows.slice(start,start+HISTORY_PAGE_SIZE);
                const tbody=$("hist-tbody");
                tbody.innerHTML = pageRows.map(r=>{
                    const offCls = (r.offset==null) ? "" : (Math.abs(r.offset)<0.05 ? "hist-ok" : (Math.abs(r.offset)<0.5 ? "hist-warn" : "hist-bad"));
                    return '<tr>'+
                        '<td class="mono">'+esc(r.ts)+'</td>'+
                        '<td class="mono">'+esc(timestampUtc7(r.ts))+'</td>'+
                        '<td class="mono">'+esc(r.source)+'</td>'+
                        '<td>'+esc(r.leap||"-")+'</td>'+
                        '<td class="td-num">'+esc(r.stratum)+'</td>'+
                        '<td class="td-num '+offCls+'">'+fmtOffset(r.offset)+'</td>'+
                        '<td class="td-num">'+(r.frequency_ppm!=null?r.frequency_ppm.toFixed(3):"-")+'</td>'+
                    '</tr>';
                }).join("");
                $("hist-empty").hidden = rows.length>0;
                $("hist-page-info").textContent=rows.length
                    ? "Page "+histPage+" of "+pageCount+" · Records "+(start+1)+"–"+(start+pageRows.length)+" of "+rows.length
                    : "Page 0 of 0 · 0 records";
                $("hist-prev").disabled=histPage<=1;
                $("hist-next").disabled=histPage>=pageCount;

                // note about log files
                const f = histData.files || {};
                const parts=[];
                Object.keys(f).forEach(k=>{
                    if(f[k] && f[k].exists) parts.push(k.replace(".log","")+" ("+Math.round(f[k].size/1024)+" KB)");
                });
                $("hist-note").textContent = parts.length
                    ? "Reading chrony logs: " + parts.join(", ") + ". Samples accrue over time."
                    : "chrony log files not found in /var/log/chrony.";
            }

            function refreshHistory(){
                fetch("/history", {cache:"no-store"})
                  .then(r=>r.json())
                  .then(p=>{ histData=p; renderHistory(); })
                  .catch(()=>{ $("hist-note").textContent="Could not read chrony logs."; });
            }
            $("hist-range").addEventListener("change", ()=>{ histPage=1; renderHistory(); });
            $("hist-prev").addEventListener("click", ()=>{ histPage--; renderHistory(); });
            $("hist-next").addEventListener("click", ()=>{ histPage++; renderHistory(); });
            window.addEventListener("resize", ()=>{ if(histData) renderHistory(); });
            refreshHistory();

            /* ---------- polling ---------- */
            let lastSuccessfulUpdate="";
            function showCollectionError(message){
                const detail = lastSuccessfulUpdate
                    ? "Last successful update: "+lastSuccessfulUpdate+". Displayed data may be out of date."
                    : "No client data has been successfully collected yet.";
                const el=$("collection-error");
                el.textContent = "Data refresh failed: "+message+". "+detail;
                el.hidden=false;
                $("live-dot").classList.add("bad");
                $("live-label").textContent="Refresh failed";
            }
            function clearCollectionError(){
                $("collection-error").hidden=true;
                $("live-dot").classList.remove("bad");
                $("live-label").textContent="Live";
            }

            function computeHash(rows){ return rows.map(r=>[r.addr,r.NTP,r.Drop,r.Int,r.Last,r.Cmd,r.Status,r.StaleAfter].join("|")).join("~"); }

            function refresh(){
                fetch("/data", {cache:"no-store"})
                  .then(resp => resp.json().catch(()=>({error:"Invalid server response"})))
                  .then(payload => {
                    if(!payload || payload.error || !Array.isArray(payload.clients_parsed)){
                        showCollectionError((payload && payload.error) || "Invalid server response");
                        return;
                    }
                    lastSuccessfulUpdate = payload.local_time || new Date().toLocaleString();
                    clearCollectionError();
                    $("last-update").textContent = "Updated "+lastSuccessfulUpdate;
                    $("server-clock").textContent = (payload.local_time||"").split(", ")[1] || "--:--:--";
                    renderHealth(payload.server);
                    const rows=payload.clients_parsed||[], h=computeHash(rows);
                    if(h!==lastHash){ cache=rows; render(); lastHash=h; }
                  })
                  .catch(err => {
                    showCollectionError(err && err.name==="AbortError" ? "Request timed out" : "Cannot retrieve dashboard data");
                  })
                  .finally(()=> setTimeout(refresh, 5000));
            }

            $("sort-select").addEventListener("change", render);
            $("search").addEventListener("input", render);
            refresh();
            // chrony writes tracking entries roughly every 64 s, so refresh history
            // on a slower cadence than the live client data.
            setInterval(refreshHistory, 60000);
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
