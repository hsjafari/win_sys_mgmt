
from __future__ import annotations

# ------------------------------------------------------------------
# Standard library
# ------------------------------------------------------------------
import logging
import queue
import subprocess
import threading
import time
from functools import wraps
from pathlib import Path
from statistics import mean
from typing import List, Optional

# ------------------------------------------------------------------
# Third‑party
# ------------------------------------------------------------------
import psutil
import pythoncom  # COM initialisation helper (pywin32)
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)
from rich.logging import RichHandler

# Optional (fail‑soft)
try:
    import wmi  # type: ignore
except ImportError:
    wmi = None
try:
    import winrm  # type: ignore
except ImportError:
    winrm = None

# ------------------------------------------------------------------
# Logging — rotating file + colourful console
# ------------------------------------------------------------------
LOG_DIR = Path("logs"); LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y‑%m‑%d %H:%M:%S",
    handlers=[
        logging.handlers.RotatingFileHandler(
            LOG_DIR / "win_sys_mgmt.log", maxBytes=5_000_000, backupCount=5, encoding="utf‑8"
        ),
        RichHandler(rich_tracebacks=True, markup=True),
    ],
)
logger = logging.getLogger("win_sys_mgmt")


def route_log(fn):
    """Decorator to journal every HTTP call with method & endpoint."""
    @wraps(fn)
    def wrapper(*args, **kwargs):  # type: ignore[misc]
        logger.info("HTTP %s %s", request.method, request.path)
        return fn(*args, **kwargs)
    return wrapper

# ------------------------------------------------------------------
# Core Managers
# ------------------------------------------------------------------
class LocalWMIManager:
    """WMI helper (auto COM initialisation per thread)."""

    def __init__(self):
        if wmi is None:
            raise RuntimeError("Missing wmi package — pip install wmi")
        pythoncom.CoInitialize()
        self._com_initialised = True
        self._wmi = wmi.WMI()

    # ------------ Process API ------------
    def list_processes(self):
        return [
            dict(pid=p.ProcessId, name=p.Caption, cmd=p.CommandLine)
            for p in self._wmi.Win32_Process()
        ]

    def kill(self, pid: int):
        (self._wmi.Win32_Process(ProcessId=pid)[0]).Terminate()
        logger.warning("WMI kill PID %s", pid)

    def start(self, exe: str, args: str = "") -> int:
        pid, _ = self._wmi.Win32_Process.Create(CommandLine=f"{exe} {args}")
        logger.info("Started %s (PID %d)", exe, pid)
        return pid

    # ------------ Service API -----------
    def list_services(self):
        return [
            dict(name=s.Name, display=s.DisplayName, state=s.State, mode=s.StartMode)
            for s in self._wmi.Win32_Service()
        ]

    # ------------ Cleanup --------------
    def __del__(self):
        if getattr(self, "_com_initialised", False):
            pythoncom.CoUninitialize()


class RemoteWinRMManager:
    """Very small WinRM wrapper (CMD/PowerShell)."""

    def __init__(self, host: str, user: str, pwd: str, *, ssl: bool = False):
        if winrm is None:
            raise RuntimeError("Missing pywinrm — pip install pywinrm")
        proto = "https" if ssl else "http"
        self.session = winrm.Session(
            f"{proto}://{host}:5985/wsman", auth=(user, pwd), transport="ntlm"
        )

    def run_cmd(self, cmd: str) -> str:
        logger.info("WinRM %s $ %s", self.session.url, cmd)
        res = self.session.run_cmd(cmd)
        return (res.std_out or res.std_err).decode(errors="ignore")

# ------------------------------------------------------------------
# Policy Watchdog (thread)
# ------------------------------------------------------------------
class RestrictionPolicy(threading.Thread):
    """Kill rule hierarchy
    1. If *blacklist* populated → kill any process whose name is in blacklist.
    2. Else, if *whitelist* populated → kill any process **not** in whitelist.
    (Process names are compared case‑insensitively.)"""

    def __init__(self, allow: List[str], block: List[str], interval: int = 10):
        super().__init__(daemon=True)
        self.allow = {n.lower() for n in allow}
        self.block = {n.lower() for n in block}
        self.interval = interval
        self._stop = threading.Event()

    def run(self):
        logger.warning("Policy active — allow=%s | block=%s", self.allow or "*", self.block or "<empty>")
        while not self._stop.is_set():
            for p in psutil.process_iter(["pid", "name"]):
                nm = (p.info.get("name") or "").lower()
                kill = False
                if self.block and nm in self.block:
                    kill = True
                elif self.block:  # blacklist present & nm not in block
                    kill = False
                elif self.allow and nm not in self.allow:
                    kill = True
                if kill:
                    try:
                        p.kill(); logger.error("Policy kill %s PID %d", nm, p.pid)
                    except psutil.Error:
                        pass
            self._stop.wait(self.interval)
        logger.info("Policy stopped")

    def stop(self):
        """Signal the policy thread to terminate gracefully."""
        self._stop.set()

# … rest of the file remains unchanged …
# global pointer
policy: Optional[RestrictionPolicy] = None

# ------------------------------------------------------------------
# Network Load Generator
# ------------------------------------------------------------------
class NetUtils:
    @staticmethod
    def single_ping(host: str) -> float:
        """Returns latency ms (raises RuntimeError on failure)."""
        out = subprocess.run(["ping", "-n", "1", host], capture_output=True, text=True)
        for ln in out.stdout.splitlines():
            if "time=" in ln.lower():
                return float(ln.split("time=")[-1].split("ms")[0])
        raise RuntimeError("ping failed")


class NetLoadJob(threading.Thread):
    """Continuous pings to *host*; puts results in queue (None sentinel on stop)."""

    def __init__(self, host: str, delay: float = 0.3):
        super().__init__(daemon=True)
        self.host = host
        self.delay = delay
        self.q: queue.Queue[float | None] = queue.Queue()
        self._stop = threading.Event()

    def run(self):
        logger.info("Net‑Load START → %s", self.host)
        while not self._stop.is_set():
            try:
                self.q.put(NetUtils.single_ping(self.host))
            except Exception:
                self.q.put(float("nan"))
            self._stop.wait(self.delay)
        self.q.put(None)
        logger.info("Net‑Load STOP → %s", self.host)

    def stop(self):
        self._stop.set()

net_job: Optional[NetLoadJob] = None

# ------------------------------------------------------------------
# Flask UI
# ------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "supersecret"

NAV_ITEMS = [
    ("dashboard", "Dashboard"),
    ("processes", "Processes"),
    ("services", "Services"),
    ("remote", "Remote CMD"),
    ("ping_single", "Ping"),
    ("policy_page", "Policy"),
    ("netload", "Net‑Load"),
]

BASE = """<!doctype html><html lang='en'><head><meta charset='utf-8'>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>
<title>WinSysMgmt</title></head>
<body class='bg-light'>
<nav class='navbar navbar-expand-lg navbar-dark bg-primary mb-4'>
  <div class='container-fluid'>
    <a class='navbar-brand' href='/'>WinSysMgmt</a>
    <ul class='navbar-nav me-auto mb-2 mb-lg-0'>
      {% for ep, label in nav %}<li class='nav-item'><a class='nav-link' href='{{ url_for(ep) }}'>{{ label }}</a></li>{% endfor %}
    </ul>
  </div>
</nav>
<div class='container'>
  {% with msgs = get_flashed_messages() %}{% if msgs %}<div class='alert alert-info'>{{ msgs[0] }}</div>{% endif %}{% endwith %}
  {{ body|safe }}
</div>
</body></html>"""


def render(fragment_tpl: str, **ctx):
    fragment = render_template_string(fragment_tpl, **ctx)
    return render_template_string(BASE, body=fragment, nav=NAV_ITEMS)

# ---------------- Dashboard ---------------------
@app.route("/")
@route_log
def dashboard() -> Response:
    return render("<h3>Welcome to WinSysMgmt</h3><p>Choose a section from the navbar.</p>")

# ---------------- Processes ---------------------
@app.route('/processes')
@route_log
def processes():
    # --- NEW: search & sort parameters ---
    q     = request.args.get('q', '').lower()          # search query
    sort  = request.args.get('sort', 'pid')            # pid | name | cmd
    order = request.args.get('order', 'asc')           # asc | desc

    procs = LocalWMIManager().list_processes()

    # --- filter by search ---
    if q:
        procs = [
            p for p in procs
            if q in p['name'].lower() or q in str(p['cmd']).lower()   # ← fix NoneType
        ]


    # --- sort by column ---
    if sort in ('pid', 'name', 'cmd'):
        procs.sort(key=lambda x: str(x[sort]).lower(),
                   reverse=(order == 'desc'))

    # helper to build sortable headers
    def hdr(col, label):
        new_ord = 'desc' if sort == col and order == 'asc' else 'asc'
        return (f"<a href='?q={q}&sort={col}&order={new_ord}' "
                f"class='text-white'>{label}</a>")

    # HTML table rows
    rows = "".join(
        f"<tr><td>{p['pid']}</td>"
        f"<td>{p['name']}</td>"
        f"<td class='text-truncate' style='max-width:300px'>{p['cmd']}</td>"
        f"<td>"
        f"<a class='btn btn-sm btn-danger' "
        f"href='{url_for('kill_process', pid=p['pid'])}'>Kill</a>"
        f"</td></tr>"
        for p in procs
    )

    table = (
        "<table class='table table-sm table-striped'>"
        "<thead class='table-primary'>"
        "<tr>"
        f"<th>{hdr('pid',  'PID')}</th>"
        f"<th>{hdr('name', 'Name')}</th>"
        f"<th>{hdr('cmd',  'Command')}</th>"
        "<th></th>"
        "</tr></thead><tbody>"
        f"{rows}"
        "</tbody></table>"
    )

    # search box + launch form
    search_form = (
        "<form method='get' class='mb-2'>"
        "<div class='input-group'>"
        f"<input name='q' value='{q}' placeholder='Search…' class='form-control'>"
        "<button class='btn btn-outline-secondary'>Search</button>"
        "</div></form>"
    )

    launch_form = (
        f"<form class='row g-2' method='post' action='{url_for('start_process')}'>"
        "<div class='col'><input name='exe' placeholder='Executable' required class='form-control'></div>"
        "<div class='col'><input name='args' placeholder='Args' class='form-control'></div>"
        "<div class='col-auto'><button class='btn btn-success'>Start</button></div>"
        "</form>"
    )

    return render(f"<h3>Processes ({len(procs)})</h3>"
                  f"{launch_form}{search_form}{table}")

# ─── Kill process ⟶ /processes/kill/<pid> ───
@app.route('/processes/kill/<int:pid>')
@route_log
def kill_process(pid: int):
    LocalWMIManager().kill(pid)
    flash(f'Killed PID {pid}')
    return redirect(url_for('processes'))
# ----------  Launch new executable  ----------
@app.route("/processes/start", methods=["POST"], endpoint="start_process")
@route_log
def start_process():
    exe  = request.form["exe"]
    args = request.form.get("args", "")
    pid  = LocalWMIManager().start(exe, args)   # اجرا و دریافت PID
    flash(f"Started PID {pid}")
    return redirect(url_for("processes"))

# ---------------- Services ----------------------
@app.route("/services")
@route_log
def services() -> Response:
    svcs = LocalWMIManager().list_services()
    tbl = "".join(
        f"<tr><td>{s['name']}</td><td>{s['display']}</td><td>{s['state']}</td><td>{s['mode']}</td></tr>" for s in svcs
    )
    return render(
        f"<h3>Windows Services ({len(svcs)})</h3><table class='table table-sm table-striped'><thead><tr><th>Name</th><th>Display</th><th>State</th><th>Mode</th></tr></thead><tbody>{tbl}</tbody></table>"
    )

# ---------------- Remote CMD --------------------
@app.route("/remote", methods=["GET", "POST"])
@route_log
def remote() -> Response:
    output = None
    if request.method == "POST":
        host = request.form["host"]
        try:
            mgr = RemoteWinRMManager(host, request.form["user"], request.form["pwd"])
            output = mgr.run_cmd(request.form["cmd"])
        except Exception as exc:
            output = f"error: {exc}"
    form = """
<form method='post' class='row g-2'>
  <div class='col-3'><input name='host' placeholder='Host' class='form-control' required></div>
  <div class='col-2'><input name='user' placeholder='User' class='form-control' required></div>
  <div class='col-2'><input name='pwd' placeholder='Password' type='password' class='form-control' required></div>
  <div class='col-4'><input name='cmd' placeholder='Command' class='form-control' required></div>
  <div class='col-auto'><button class='btn btn-primary'>Run</button></div>
</form>
"""
    return render(form + (f"<pre class='bg-dark text-light p-2 mt-3'>{output}</pre>" if output else ""))

# ---------------- Single Ping -------------------
@app.route("/ping", methods=["GET", "POST"], endpoint="ping_single")
@route_log
def ping_single() -> Response:
    latency = None
    if request.method == "POST":
        host = request.form["host"]
        try:
            latency = f"{NetUtils.single_ping(host)} ms"
        except Exception as exc:
            latency = str(exc)
    form = """
<form method='post' class='row g-2'>
  <div class='col-4'><input name='host' placeholder='Host' class='form-control' required></div>
  <div class='col-auto'><button class='btn btn-success'>Ping</button></div>
</form>
"""
    return render(form + (f"<div class='alert alert-secondary mt-3'>{latency}</div>" if latency else ""))

# ---------------- Policy Page -------------------
@app.route("/policy", methods=["GET", "POST"], endpoint="policy_page")
@route_log
def policy_page():
    global policy
    if request.method == "POST":
        action = request.form["action"]
        if action == "start":
            allow = [l.strip() for l in request.form["allowed"].splitlines() if l.strip()]
            block = [l.strip() for l in request.form["blocked"].splitlines() if l.strip()]
            interval = int(request.form.get("interval", 10))
            if policy: policy.stop()
            policy = RestrictionPolicy(allow, block, interval)
            policy.start(); flash("Policy started")
        elif action == "stop" and policy:
            policy.stop(); policy = None; flash("Policy stopped")
        return redirect(url_for("policy_page"))
    return render(
        """
<h3>Restriction Policy</h3>
<form method='post'>
  <div class='row'>
    <div class='col-md-6'>
      <label class='form-label'>Allowed (whitelist — optional)</label>
      <textarea name='allowed' rows='6' class='form-control'>{{ allow }}</textarea>
    </div>
    <div class='col-md-6'>
      <label class='form-label'>Not‑Allowed (blacklist — optional)</label>
      <textarea name='blocked' rows='6' class='form-control'>{{ block }}</textarea>
    </div>
  </div>
  <div class='my-3'><label>Interval (sec)</label>
    <input name='interval' type='number' value='10' class='form-control' style='width:120px'>
  </div>
  {% if active %}<button name='action' value='stop' class='btn btn-danger'>Stop</button>{% endif %}
  <button name='action' value='start' class='btn btn-primary'>Start / Restart</button>
</form>
<p class='mt-3'>Status: {% if active %}<span class='text-success'>ACTIVE</span>{% else %}<span class='text-danger'>inactive</span>{% endif %}</p>
""",
        active=policy is not None,
        allow="\n".join(sorted(policy.allow)) if policy else "",
        block="\n".join(sorted(policy.block)) if policy else "",
    )
# ---------------- Net‑Load ----------------------
@app.route("/netload", methods=["GET", "POST"])
@route_log
def netload() -> Response:
    global net_job
    stats = None
    if request.method == "POST":
        act = request.form["action"]
        if act == "start":
            host = request.form["host"]
            if net_job:
                net_job.stop()
            net_job = NetLoadJob(host)
            net_job.start()
            flash(f"Net‑Load started → {host}")
        elif act == "stop" and net_job:
            net_job.stop(); net_job = None; flash("Net‑Load stopped")
        return redirect(url_for("netload"))
    # consume queue
    if net_job and not net_job.q.empty():
        vals: List[float] = []
        while not net_job.q.empty():
            r = net_job.q.get()
            if r is None:  # sentinel
                net_job = None; break
            vals.append(r)
        if vals:
            ok = [v for v in vals if v == v]  # filter nan
            stats = dict(n=len(vals), avg=round(mean(ok), 2) if ok else "nan", last=ok[-1] if ok else "nan")
    return render(
        """
<h3>Network Load</h3>
<form method='post' class='row g-2'>
  <div class='col-4'><input name='host' placeholder='Host' class='form-control' {% if job %}value='{{ job.host }}'{% endif %}></div>
  {% if not job %}<div class='col-auto'><button name='action' value='start' class='btn btn-primary'>Start</button></div>{% else %}<div class='col-auto'><button name='action' value='stop' class='btn btn-danger'>Stop</button></div>{% endif %}
</form>
{% if stats %}<div class='alert alert-secondary mt-3'>Avg: {{ stats.avg }} ms over {{ stats.n }} pings — last {{ stats.last }} ms</div>{% endif %}
""",
        job=net_job,
        stats=stats,
    )

# JSON endpoint (optional for JS chart)
@app.route("/netload/data")
@route_log
def netload_data():
    if not net_job:
        return jsonify(active=False)
    vals = []
    while not net_job.q.empty():
        v = net_job.q.get()
        if v is None:
            return jsonify(active=False)
        vals.append(v)
    return jsonify(active=True, values=vals, ts=time.time())

# ------------------------------------------------------------------
if __name__ == "__main__":
    try:
        app.run(debug=True, port=5000, threaded=False, use_reloader=False)
    finally:
        if policy:
            policy.stop()
        if net_job:
            net_job.stop()
