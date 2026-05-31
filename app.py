"""
Blue16 Exposure Scanner — Flask backend
Run with elevated privileges for full scan capabilities:
  Windows : Run terminal as Administrator, then: python app.py
  Linux   : sudo python app.py

Install dependencies:
  pip install flask flask-cors python-nmap apscheduler

Install nmap binary:
  Windows : https://nmap.org/download.html  (Windows installer, add to PATH)
  Linux   : sudo apt install nmap  /  sudo yum install nmap
  macOS   : brew install nmap
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import nmap
import threading
import uuid
import datetime
import os
import shutil
import json
import sqlite3
import urllib.request
import urllib.parse
import time
import concurrent.futures

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _APScheduler = True
except ImportError:
    _APScheduler = False
    print('  ⚠  apscheduler not installed — scheduled scans disabled.')
    print('     Run: pip install apscheduler')

app = Flask(__name__)
# The UI is served by this same app, so /api calls are same-origin and don't
# need permissive CORS. Restricting to the app's own origins prevents arbitrary
# websites in the operator's browser from reaching the token-handling proxies.
CORS(app, origins=[
    'http://localhost:5000',
    'http://127.0.0.1:5000',
])

JOBS: dict = {}              # active / recent in-memory jobs
CVE_DETAIL_CACHE: dict = {} # CVE-ID → {id, score, severity, summary}

# ── SQLite ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanner.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS scans (
                id           TEXT PRIMARY KEY,
                targets      TEXT,
                ports        TEXT,
                scan_type    TEXT,
                arguments    TEXT,
                status       TEXT DEFAULT 'queued',
                progress     TEXT DEFAULT '{}',
                created_at   TEXT,
                started_at   TEXT,
                completed_at TEXT,
                schedule_id  TEXT,
                label        TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id        TEXT NOT NULL,
                host           TEXT NOT NULL,
                input          TEXT,
                hostname       TEXT,
                state          TEXT,
                os             TEXT,
                os_accuracy    TEXT,
                open_count     INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                risk           TEXT DEFAULT 'info',
                scanned_at     TEXT,
                error          TEXT,
                new_ports      TEXT DEFAULT '[]',
                closed_ports   TEXT DEFAULT '[]',
                is_new_host    INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS ports (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id  INTEGER NOT NULL,
                scan_id  TEXT NOT NULL,
                port     INTEGER,
                proto    TEXT,
                state    TEXT,
                service  TEXT,
                product  TEXT,
                version  TEXT,
                risk     TEXT DEFAULT 'info',
                label    TEXT
            );

            CREATE TABLE IF NOT EXISTS schedules (
                id               TEXT PRIMARY KEY,
                name             TEXT,
                targets          TEXT,
                scan_type        TEXT DEFAULT 'service',
                ports            TEXT,
                custom_args      TEXT DEFAULT '-sV -T4',
                force_pn         INTEGER DEFAULT 1,
                interval_minutes INTEGER DEFAULT 60,
                enabled          INTEGER DEFAULT 1,
                created_at       TEXT,
                last_run         TEXT,
                next_run         TEXT
            );

            CREATE TABLE IF NOT EXISTS enrichment_cache (
                kind       TEXT NOT NULL,   -- 'cve' | 'internetdb' | 'geoip' | 'kev'
                key        TEXT NOT NULL,   -- CVE-ID / IP / 'catalog'
                data       TEXT NOT NULL,   -- JSON payload
                fetched_at REAL NOT NULL,   -- epoch seconds
                PRIMARY KEY (kind, key)
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_scan  ON hosts(scan_id);
            CREATE INDEX IF NOT EXISTS idx_hosts_host  ON hosts(host);
            CREATE INDEX IF NOT EXISTS idx_ports_host  ON ports(host_id);
        ''')
        # Migrate existing DBs that predate the label column
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN label TEXT DEFAULT ''")
        except Exception:
            pass  # column already exists

init_db()


# ── nmap binary detection ──────────────────────────────────────────────────
_NMAP_COMMON_PATHS = [
    r'C:\Program Files (x86)\Nmap\nmap.exe',
    r'C:\Program Files\Nmap\nmap.exe',
    r'C:\Nmap\nmap.exe',
    '/usr/bin/nmap',
    '/usr/local/bin/nmap',
    '/opt/homebrew/bin/nmap',
]

def _find_nmap() -> tuple:
    if shutil.which('nmap'):
        return ('nmap',)
    for p in _NMAP_COMMON_PATHS:
        if os.path.isfile(p):
            return (p,)
    return ('nmap',)

NMAP_PATH = _find_nmap()

def _nmap_installed() -> bool:
    if shutil.which('nmap'):
        return True
    return any(os.path.isfile(p) for p in _NMAP_COMMON_PATHS)


# ── Risk tables ────────────────────────────────────────────────────────────
PORT_RISK = {
    21:    ('FTP',             'critical'),
    22:    ('SSH',             'medium'),
    23:    ('Telnet',          'critical'),
    25:    ('SMTP',            'high'),
    53:    ('DNS',             'medium'),
    80:    ('HTTP',            'low'),
    110:   ('POP3',            'medium'),
    135:   ('MS-RPC',          'high'),
    137:   ('NetBIOS-NS',      'critical'),
    139:   ('NetBIOS-SSN',     'critical'),
    143:   ('IMAP',            'medium'),
    389:   ('LDAP',            'high'),
    443:   ('HTTPS',           'low'),
    445:   ('SMB',             'critical'),
    1433:  ('MSSQL',           'critical'),
    1521:  ('Oracle DB',       'critical'),
    2375:  ('Docker (unauth)', 'critical'),
    2376:  ('Docker TLS',      'high'),
    3306:  ('MySQL',           'critical'),
    3389:  ('RDP',             'critical'),
    4444:  ('Metasploit',      'critical'),
    5432:  ('PostgreSQL',      'critical'),
    5900:  ('VNC',             'critical'),
    5985:  ('WinRM HTTP',      'high'),
    5986:  ('WinRM HTTPS',     'high'),
    6379:  ('Redis',           'critical'),
    7001:  ('WebLogic',        'high'),
    8080:  ('HTTP-Alt',        'medium'),
    8443:  ('HTTPS-Alt',       'medium'),
    8888:  ('Jupyter',         'high'),
    9200:  ('Elasticsearch',   'critical'),
    10250: ('Kubernetes API',  'critical'),
    27017: ('MongoDB',         'critical'),
    27018: ('MongoDB Shard',   'critical'),
}

RISK_ORDER  = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
RISK_LABELS = ['info', 'low', 'medium', 'high', 'critical']

SCAN_PRESETS = {
    'ping':          '-sn -Pn -T4',
    'quick':         '-sT -F -Pn -T4',
    'remote_access': '-sV -Pn -T4',
    'service':       '-sV -Pn -T4',
    'full':          '-sV -O -Pn -T4 --version-intensity 5',
    'vuln':          '-sV -Pn -T4 --script=vuln',
    'custom':        None,
}

DEFAULT_PORTS = (
    '21,22,23,25,53,80,110,135,137,139,143,389,443,445,'
    '1433,1521,2375,2376,3306,3389,4444,5432,5900,'
    '5985,5986,6379,7001,8080,8443,8888,9200,10250,27017,27018'
)


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _now():
    return _utcnow().isoformat() + 'Z'


# nmap flags that write scan output to a file path. python-nmap already forces
# `-oX -` (and asserts -oX isn't user-supplied), but the others can still write
# arbitrary files — dangerous because the app runs elevated and the scheduler
# fires custom args unattended. We strip them along with their filename token.
_OUTPUT_FILE_FLAGS = {'-oN', '-oG', '-oS', '-oA'}

def _build_args(raw_args: str, force_pn: bool) -> str:
    """Tokenize nmap args, drop file-output flags, and normalize -Pn."""
    tokens   = (raw_args or '').split()
    cleaned  = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok == '-Pn':
            continue
        if tok in _OUTPUT_FILE_FLAGS:
            skip_next = True            # also drop the following filename token
            continue
        if tok.startswith('-oN') or tok.startswith('-oG') or \
           tok.startswith('-oS') or tok.startswith('-oA'):
            continue                    # e.g. -oNout.txt (no space)
        cleaned.append(tok)
    if force_pn:
        cleaned.insert(0, '-Pn')
    return ' '.join(cleaned)


# ── Change detection ───────────────────────────────────────────────────────
def detect_changes(host_ip: str, current_scan_id: str, open_ports: list) -> dict:
    """Compare current open ports against the most recent previous scan of this host."""
    try:
        with get_db() as conn:
            prev = conn.execute('''
                SELECT h.id FROM hosts h
                JOIN scans s ON h.scan_id = s.id
                WHERE h.host = ? AND h.scan_id != ? AND s.status = 'complete'
                ORDER BY s.completed_at DESC LIMIT 1
            ''', (host_ip, current_scan_id)).fetchone()

            if not prev:
                return {'new_ports': [], 'closed_ports': [], 'is_new_host': True}

            prev_rows = conn.execute(
                'SELECT port, proto FROM ports WHERE host_id = ? AND state = "open"',
                (prev['id'],)
            ).fetchall()

        prev_set  = {(r['port'], r['proto']) for r in prev_rows}
        curr_set  = {(p['port'], p['proto']) for p in open_ports}
        new_keys  = curr_set - prev_set
        gone_keys = prev_set - curr_set

        new_ports    = [p for p in open_ports if (p['port'], p['proto']) in new_keys]
        closed_ports = [{'port': k[0], 'proto': k[1]} for k in gone_keys]

        return {'new_ports': new_ports, 'closed_ports': closed_ports, 'is_new_host': False}
    except Exception as e:
        print(f'[change_detect] {e}')
        return {'new_ports': [], 'closed_ports': [], 'is_new_host': False}


# ── DB persistence ─────────────────────────────────────────────────────────
def persist_scan_to_db(job: dict):
    """Write a completed scan + results to SQLite."""
    try:
        with get_db() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO scans
                  (id, targets, ports, scan_type, arguments, status, progress,
                   created_at, started_at, completed_at, schedule_id, label)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                job['id'],
                json.dumps(job.get('targets', [])),
                job.get('ports', ''),
                job.get('scan_type', ''),
                job.get('arguments', ''),
                job.get('status', ''),
                json.dumps(job.get('progress', {})),
                job.get('created_at'),
                job.get('started_at'),
                job.get('completed_at'),
                job.get('schedule_id'),
                job.get('label', ''),
            ))

            for h in job.get('results', []):
                cur = conn.execute('''
                    INSERT INTO hosts
                      (scan_id, host, input, hostname, state, os, os_accuracy,
                       open_count, critical_count, risk, scanned_at, error,
                       new_ports, closed_ports, is_new_host)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ''', (
                    job['id'],
                    h.get('host', ''), h.get('input', ''), h.get('hostname', ''),
                    h.get('state', ''), h.get('os', ''), h.get('os_accuracy', ''),
                    h.get('open_count', 0), h.get('critical_count', 0),
                    h.get('risk', 'info'), h.get('scanned_at', ''),
                    h.get('error', ''),
                    json.dumps(h.get('new_ports', [])),
                    json.dumps(h.get('closed_ports', [])),
                    1 if h.get('is_new_host') else 0,
                ))
                host_id = cur.lastrowid

                for p in h.get('ports', []):
                    conn.execute('''
                        INSERT INTO ports
                          (host_id, scan_id, port, proto, state, service,
                           product, version, risk, label)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                    ''', (
                        host_id, job['id'],
                        p.get('port'), p.get('proto', ''), p.get('state', ''),
                        p.get('service', ''), p.get('product', ''), p.get('version', ''),
                        p.get('risk', 'info'), p.get('label', ''),
                    ))
    except Exception as e:
        print(f'[DB] persist error: {e}')


def _job_from_db(scan_id: str) -> dict | None:
    """Load a full scan + results from SQLite."""
    try:
        with get_db() as conn:
            scan = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
            if not scan:
                return None
            hosts = conn.execute('SELECT * FROM hosts WHERE scan_id=? ORDER BY id', (scan_id,)).fetchall()
            results = []
            for h in hosts:
                ports = conn.execute('SELECT * FROM ports WHERE host_id=? ORDER BY port', (h['id'],)).fetchall()
                results.append({
                    'host':           h['host'],
                    'input':          h['input'],
                    'hostname':       h['hostname'],
                    'state':          h['state'],
                    'os':             h['os'],
                    'os_accuracy':    h['os_accuracy'],
                    'open_count':     h['open_count'],
                    'critical_count': h['critical_count'],
                    'risk':           h['risk'],
                    'scanned_at':     h['scanned_at'],
                    'error':          h['error'],
                    'new_ports':      json.loads(h['new_ports']   or '[]'),
                    'closed_ports':   json.loads(h['closed_ports'] or '[]'),
                    'is_new_host':    bool(h['is_new_host']),
                    'ports':          [dict(p) for p in ports],
                })
            return {
                'id':           scan['id'],
                'targets':      json.loads(scan['targets']  or '[]'),
                'ports':        scan['ports'],
                'scan_type':    scan['scan_type'],
                'arguments':    scan['arguments'],
                'label':        scan['label'] if 'label' in scan.keys() else '',
                'status':       scan['status'],
                'progress':     json.loads(scan['progress'] or '{}'),
                'created_at':   scan['created_at'],
                'started_at':   scan['started_at'],
                'completed_at': scan['completed_at'],
                'schedule_id':  scan['schedule_id'],
                'results':      results,
            }
    except Exception as e:
        print(f'[DB] load error: {e}')
        return None


# ── Durable enrichment cache ─────────────────────────────────────────────────
# Enrichment (CVE details, Shodan InternetDB, GeoIP, CISA KEV) is keyed by
# CVE-ID / IP, not by scan, so it's cached in SQLite to survive restarts and
# avoid re-hitting rate-limited external APIs when historical scans are reopened.
CACHE_TTL = {
    'cve':        30 * 86400,   # CVE details rarely change
    'geoip':      30 * 86400,   # IP geolocation is fairly stable
    'internetdb':      86400,   # Shodan snapshot — refresh daily
    'kev':              3600,   # CISA KEV catalog — hourly
}

def _cache_get_many(kind: str, keys: list, ttl_seconds: float) -> dict:
    """Return {key: data} for cached, non-expired entries of the given kind."""
    if not keys:
        return {}
    out    = {}
    cutoff = time.time() - ttl_seconds
    try:
        with get_db() as conn:
            qmarks = ','.join('?' * len(keys))
            rows = conn.execute(
                f'SELECT key, data, fetched_at FROM enrichment_cache '
                f'WHERE kind=? AND key IN ({qmarks})',
                [kind, *keys]
            ).fetchall()
        for r in rows:
            if r['fetched_at'] >= cutoff:
                try:
                    out[r['key']] = json.loads(r['data'])
                except Exception:
                    pass
    except Exception as e:
        print(f'[cache] get error: {e}')
    return out


def _cache_put_many(kind: str, mapping: dict):
    """Upsert {key: data} entries for the given kind."""
    if not mapping:
        return
    now = time.time()
    try:
        with get_db() as conn:
            conn.executemany(
                'INSERT OR REPLACE INTO enrichment_cache (kind, key, data, fetched_at) '
                'VALUES (?,?,?,?)',
                [(kind, k, json.dumps(v), now) for k, v in mapping.items()]
            )
    except Exception as e:
        print(f'[cache] put error: {e}')


# ── In-memory job retention ──────────────────────────────────────────────────
# Completed/cancelled jobs are persisted to SQLite and remain reachable via the
# DB fallback in api_get_scan, so we only keep the most recent few in memory to
# avoid unbounded growth on long-running instances. Active jobs are never pruned.
MAX_FINISHED_JOBS = 50
_TERMINAL = {'complete', 'cancelled'}

def _prune_jobs():
    finished = [j for j in JOBS.values() if j.get('status') in _TERMINAL]
    if len(finished) <= MAX_FINISHED_JOBS:
        return
    finished.sort(key=lambda j: j.get('completed_at') or j.get('created_at') or '')
    for job in finished[:len(finished) - MAX_FINISHED_JOBS]:
        JOBS.pop(job['id'], None)


# ── Scan worker ────────────────────────────────────────────────────────────
# Targets are scanned concurrently with a bounded pool. nmap itself parallelizes
# within a single target; this adds host-level concurrency for large lists. Each
# worker builds its own PortScanner, so there's no shared nmap state across threads.
MAX_SCAN_WORKERS = 8

def _scan_target(target: str, ports: str, args: str, scan_type: str, job_id: str) -> list:
    """Scan a single target string and return a list of host result dicts.
    A target may be a CIDR/range, so it can yield multiple hosts."""
    out = []
    try:
        nm = nmap.PortScanner(nmap_search_path=NMAP_PATH)
        if scan_type in ('ping', 'quick'):
            nm.scan(hosts=target, arguments=args)
        else:
            nm.scan(hosts=target, ports=ports, arguments=args)

        for host in nm.all_hosts():
            h       = nm[host]
            ports_d = []

            for proto in h.all_protocols():
                for port in sorted(h[proto].keys()):
                    pi          = h[proto][port]
                    label, risk = PORT_RISK.get(port, ('', 'info'))
                    ports_d.append({
                        'port':    port,
                        'proto':   proto,
                        'state':   pi['state'],
                        'service': pi.get('name', ''),
                        'product': pi.get('product', ''),
                        'version': pi.get('version', ''),
                        'risk':    risk,
                        'label':   label,
                    })

            os_m       = h.get('osmatch', [])
            open_ports = [p for p in ports_d if p['state'] == 'open']
            host_risk  = max((RISK_ORDER.get(p['risk'], 0) for p in open_ports), default=0)

            changes = detect_changes(host, job_id, open_ports)

            out.append({
                'host':           host,
                'input':          target,
                'hostname':       h.hostname() or '—',
                'state':          h.state(),
                'os':             os_m[0]['name']     if os_m else '—',
                'os_accuracy':    os_m[0]['accuracy'] if os_m else '',
                'ports':          ports_d,
                'open_count':     len(open_ports),
                'critical_count': len([p for p in open_ports if p['risk'] == 'critical']),
                'risk':           RISK_LABELS[host_risk],
                'scanned_at':     _now(),
                'new_ports':      changes['new_ports'],
                'closed_ports':   changes['closed_ports'],
                'is_new_host':    changes['is_new_host'],
            })

    except nmap.PortScannerError:
        out.append({
            'host': target, 'input': target, 'hostname': '—',
            'state': 'error',
            'error': 'nmap not found — install from nmap.org then restart app.py',
            'os': '—', 'os_accuracy': '',
            'ports': [], 'open_count': 0, 'critical_count': 0,
            'risk': 'info', 'scanned_at': _now(),
            'new_ports': [], 'closed_ports': [], 'is_new_host': False,
        })
    except Exception as exc:
        out.append({
            'host': target, 'input': target, 'hostname': '—',
            'state': 'error', 'error': str(exc),
            'os': '—', 'os_accuracy': '',
            'ports': [], 'open_count': 0, 'critical_count': 0,
            'risk': 'info', 'scanned_at': _now(),
            'new_ports': [], 'closed_ports': [], 'is_new_host': False,
        })
    return out


def run_scan(job_id: str):
    job = JOBS[job_id]
    job['status']     = 'running'
    job['started_at'] = _now()

    targets   = job['targets']
    ports     = job['ports']
    args      = job['arguments']
    scan_type = job['scan_type']
    total     = len(targets)

    results   = []
    lock      = threading.Lock()
    completed = 0
    workers   = max(1, min(MAX_SCAN_WORKERS, total))

    job['progress'] = {'current': 0, 'total': total, 'host': '', 'pct': 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        future_map = {
            exe.submit(_scan_target, t, ports, args, scan_type, job_id): t
            for t in targets
        }
        for fut in concurrent.futures.as_completed(future_map):
            if job.get('cancelled'):
                for f in future_map:          # stop work that hasn't started yet
                    f.cancel()
            if fut.cancelled():
                continue

            target = future_map[fut]
            try:
                host_results = fut.result()
            except Exception as exc:
                host_results = [{
                    'host': target, 'input': target, 'hostname': '—',
                    'state': 'error', 'error': str(exc),
                    'os': '—', 'os_accuracy': '',
                    'ports': [], 'open_count': 0, 'critical_count': 0,
                    'risk': 'info', 'scanned_at': _now(),
                    'new_ports': [], 'closed_ports': [], 'is_new_host': False,
                }]

            with lock:
                results.extend(host_results)
                completed += 1
                job['results']  = list(results)
                job['progress'] = {
                    'current': completed, 'total': total,
                    'host': target,
                    'pct':  round(completed / total * 100) if total else 0,
                }

    if job.get('cancelled'):
        job['status'] = 'cancelled'
        _prune_jobs()
        return

    job['status']       = 'complete'
    job['completed_at'] = _now()
    job['progress']     = {'current': total, 'total': total, 'host': '', 'pct': 100}

    # Persist to SQLite
    persist_scan_to_db(job)
    _prune_jobs()


# ── Scheduler ──────────────────────────────────────────────────────────────
if _APScheduler:
    _scheduler = BackgroundScheduler(daemon=True)

    def run_scheduled_scan(schedule_id: str):
        try:
            with get_db() as conn:
                s = conn.execute(
                    'SELECT * FROM schedules WHERE id=? AND enabled=1', (schedule_id,)
                ).fetchone()
                if not s:
                    return
                now      = _now()
                next_run = (_utcnow() +
                            datetime.timedelta(minutes=s['interval_minutes'])).isoformat() + 'Z'
                conn.execute(
                    'UPDATE schedules SET last_run=?, next_run=? WHERE id=?',
                    (now, next_run, schedule_id)
                )

            targets = [t.strip() for t in
                       (s['targets'] or '').replace(',', '\n').splitlines() if t.strip()]
            if not targets:
                return

            scan_type   = s['scan_type']
            ports       = s['ports'] or DEFAULT_PORTS
            custom_args = s['custom_args'] or '-sV -T4'
            force_pn    = bool(s['force_pn'])

            args = SCAN_PRESETS.get(scan_type) or custom_args
            if scan_type == 'remote_access':
                ports = '22,3389,5985,5986'

            args = _build_args(args, force_pn)

            job_id = str(uuid.uuid4())
            JOBS[job_id] = {
                'id': job_id, 'targets': targets, 'ports': ports,
                'scan_type': scan_type, 'arguments': args,
                'status': 'queued',
                'progress': {'current': 0, 'total': len(targets), 'host': '', 'pct': 0},
                'results': [], 'created_at': _now(), 'started_at': None,
                'completed_at': None, 'schedule_id': schedule_id,
            }
            threading.Thread(target=run_scan, args=(job_id,), daemon=True).start()
            print(f'[Scheduler] Started job {job_id} for schedule {schedule_id}')
        except Exception as e:
            print(f'[Scheduler] Error running schedule {schedule_id}: {e}')

    def _add_apscheduler_job(sid: str, interval_minutes: int):
        try:
            _scheduler.remove_job(sid)
        except Exception:
            pass
        _scheduler.add_job(
            run_scheduled_scan, 'interval',
            minutes=interval_minutes,
            id=sid, args=[sid], replace_existing=True,
        )

    def _restore_schedules():
        try:
            with get_db() as conn:
                rows = conn.execute(
                    'SELECT id, interval_minutes FROM schedules WHERE enabled=1'
                ).fetchall()
            for r in rows:
                _add_apscheduler_job(r['id'], r['interval_minutes'])
            if rows:
                print(f'[Scheduler] Restored {len(rows)} schedule(s)')
        except Exception as e:
            print(f'[Scheduler] Restore error: {e}')

    _scheduler.start()
    _restore_schedules()
else:
    _scheduler = None
    def _add_apscheduler_job(sid, interval_minutes): pass
    def _restore_schedules(): pass


# ── API routes ─────────────────────────────────────────────────────────────
@app.route('/api/localip')
def api_localip():
    """Return the server's local (LAN) IP address."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = '127.0.0.1'
    return jsonify({'ip': ip})


@app.route('/api/ping')
def api_ping():
    if not _nmap_installed():
        return jsonify({
            'status':  'nmap_missing',
            'error':   'nmap binary not found',
            'detail':  'Download and install nmap from https://nmap.org/download.html, '
                       'then restart app.py. On Windows the default install path is '
                       'C:\\Program Files (x86)\\Nmap\\nmap.exe',
            'install': 'https://nmap.org/download.html',
        })
    try:
        ver = nmap.PortScanner(nmap_search_path=NMAP_PATH).nmap_version()
        return jsonify({'status': 'ok', 'nmap': '.'.join(str(v) for v in ver)})
    except nmap.PortScannerError as e:
        return jsonify({
            'status':  'nmap_missing',
            'error':   'nmap not found in PATH',
            'detail':  str(e),
            'install': 'https://nmap.org/download.html',
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/scan', methods=['POST'])
def api_start_scan():
    if not _nmap_installed():
        return jsonify({'error': 'nmap not installed — see https://nmap.org/download.html'}), 503

    data      = request.get_json(force=True)
    raw       = data.get('targets', '').strip()
    scan_type = data.get('scan_type', 'service')
    ports     = data.get('ports', DEFAULT_PORTS).strip() or DEFAULT_PORTS
    custom    = data.get('custom_args', '-sV -T4').strip()
    force_pn  = data.get('force_pn', True)
    label     = data.get('label', '').strip()

    if not raw:
        return jsonify({'error': 'No targets provided'}), 400

    targets = [t.strip() for t in raw.replace(',', '\n').splitlines() if t.strip()]
    if not targets:
        return jsonify({'error': 'No valid targets after parsing'}), 400

    args = SCAN_PRESETS.get(scan_type) or custom
    if scan_type == 'remote_access':
        ports = '22,3389,5985,5986'

    args = _build_args(args, force_pn)

    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        'id':           job_id,
        'targets':      targets,
        'ports':        ports,
        'scan_type':    scan_type,
        'arguments':    args,
        'label':        label,
        'status':       'queued',
        'progress':     {'current': 0, 'total': len(targets), 'host': '', 'pct': 0},
        'results':      [],
        'created_at':   _now(),
        'started_at':   None,
        'completed_at': None,
    }

    threading.Thread(target=run_scan, args=(job_id,), daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/api/scan/<job_id>')
def api_get_scan(job_id):
    job = JOBS.get(job_id)
    if job:
        return jsonify(job)
    # Fall back to SQLite for historical scans
    job = _job_from_db(job_id)
    if job:
        return jsonify(job)
    return jsonify({'error': 'Job not found'}), 404


@app.route('/api/scan/<job_id>/cancel', methods=['POST'])
def api_cancel_scan(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    job['cancelled'] = True
    return jsonify({'status': 'cancelling'})


@app.route('/api/jobs')
def api_list_jobs():
    # Active in-memory jobs
    active     = [{k: v for k, v in j.items() if k != 'results'} for j in JOBS.values()]
    active_ids = {j['id'] for j in active}

    # Historical from SQLite (exclude anything already in active)
    historical = []
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT * FROM scans ORDER BY created_at DESC LIMIT 200'
            ).fetchall()
        for r in rows:
            if r['id'] not in active_ids:
                historical.append({
                    'id':           r['id'],
                    'targets':      json.loads(r['targets']  or '[]'),
                    'ports':        r['ports'],
                    'scan_type':    r['scan_type'],
                    'arguments':    r['arguments'],
                    'label':        r['label'] if 'label' in r.keys() else '',
                    'status':       r['status'],
                    'progress':     json.loads(r['progress'] or '{}'),
                    'created_at':   r['created_at'],
                    'started_at':   r['started_at'],
                    'completed_at': r['completed_at'],
                    'schedule_id':  r['schedule_id'],
                })
    except Exception as e:
        print(f'[DB] list error: {e}')

    all_jobs = active + historical
    return jsonify(sorted(all_jobs, key=lambda j: j.get('created_at', ''), reverse=True))


# ── Schedule CRUD ──────────────────────────────────────────────────────────
@app.route('/api/schedules', methods=['GET'])
def api_list_schedules():
    try:
        with get_db() as conn:
            rows = conn.execute('SELECT * FROM schedules ORDER BY created_at DESC').fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/schedules', methods=['POST'])
def api_create_schedule():
    if not _APScheduler:
        return jsonify({'error': 'apscheduler not installed — run: pip install apscheduler'}), 503
    data             = request.get_json(force=True)
    sid              = str(uuid.uuid4())
    name             = data.get('name', 'Scheduled Scan').strip() or 'Scheduled Scan'
    targets          = data.get('targets', '').strip()
    scan_type        = data.get('scan_type', 'service')
    ports            = data.get('ports', DEFAULT_PORTS)
    custom_args      = data.get('custom_args', '-sV -T4')
    force_pn         = bool(data.get('force_pn', True))
    interval_minutes = max(1, int(data.get('interval_minutes', 60)))

    if not targets:
        return jsonify({'error': 'targets required'}), 400

    now      = _now()
    next_run = (_utcnow() +
                datetime.timedelta(minutes=interval_minutes)).isoformat() + 'Z'

    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO schedules
                  (id, name, targets, scan_type, ports, custom_args, force_pn,
                   interval_minutes, enabled, created_at, next_run)
                VALUES (?,?,?,?,?,?,?,?,1,?,?)
            ''', (sid, name, targets, scan_type, ports, custom_args,
                  1 if force_pn else 0, interval_minutes, now, next_run))
        _add_apscheduler_job(sid, interval_minutes)
        return jsonify({'id': sid, 'next_run': next_run})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/schedules/<sid>', methods=['DELETE'])
def api_delete_schedule(sid):
    try:
        with get_db() as conn:
            conn.execute('DELETE FROM schedules WHERE id=?', (sid,))
        if _scheduler:
            try: _scheduler.remove_job(sid)
            except Exception: pass
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/schedules/<sid>/toggle', methods=['POST'])
def api_toggle_schedule(sid):
    try:
        with get_db() as conn:
            row = conn.execute('SELECT enabled, interval_minutes FROM schedules WHERE id=?', (sid,)).fetchone()
            if not row:
                return jsonify({'error': 'Not found'}), 404
            new_enabled = 0 if row['enabled'] else 1
            conn.execute('UPDATE schedules SET enabled=? WHERE id=?', (new_enabled, sid))

        if new_enabled and _scheduler:
            _add_apscheduler_job(sid, row['interval_minutes'])
        elif _scheduler:
            try: _scheduler.remove_job(sid)
            except Exception: pass

        return jsonify({'enabled': bool(new_enabled)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/schedules/<sid>/run', methods=['POST'])
def api_run_schedule_now(sid):
    """Trigger a scheduled scan immediately."""
    if not _APScheduler:
        return jsonify({'error': 'apscheduler not installed'}), 503
    threading.Thread(target=run_scheduled_scan, args=(sid,), daemon=True).start()
    return jsonify({'status': 'triggered'})


# ── Cloud Apps proxy ───────────────────────────────────────────────────────
@app.route('/api/cloudapps/subnet', methods=['POST'])
def api_cloudapps_subnet():
    data       = request.get_json(force=True)
    portal_url = (data.get('portal_url') or '').strip().lstrip('/')
    api_token  = (data.get('api_token')  or '').strip()

    if not portal_url: return jsonify({'error': 'portal_url is required'}), 400
    if not api_token:  return jsonify({'error': 'api_token is required'}),  400

    portal_url = portal_url.replace('https://', '').replace('http://', '').strip('/')
    filters    = json.dumps({'category': {'eq': 1}})
    all_data   = []
    skip       = 0
    has_next   = True

    try:
        while has_next:
            params = urllib.parse.urlencode({'limit': 100, 'skip': skip, 'filters': filters})
            url    = f'https://{portal_url}/api/v1/subnet/?{params}'
            req    = urllib.request.Request(url, headers={'Authorization': f'Token {api_token}'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                d = json.loads(resp.read())
            all_data.extend(d.get('data', []))
            has_next = d.get('hasNext', False)
            skip    += 100
        return jsonify({'data': all_data})
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        try:   detail = json.loads(body).get('message') or json.loads(body).get('detail') or body
        except: detail = body
        return jsonify({'error': f'HTTP {e.code}: {detail}'}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# ── Defender for Endpoint proxy ────────────────────────────────────────────
@app.route('/api/mde/machines', methods=['POST'])
def api_mde_machines():
    """Return only the devices Defender flags as Internet facing.

    The 'Internet facing' classification (the tag shown in the portal's Tags column / the
    'Internet facing: Yes' filter) is NOT exposed on the Machine entity or in machineTags. The
    authoritative signal is the advanced-hunting DeviceInfo.IsInternetFacing column, so we run an
    advanced query instead of listing all machines and guessing from the public IP.

    Requires the delegated 'AdvancedQuery.Read' permission (WindowsDefenderATP). It uses the same
    api.securitycenter.microsoft.com resource as Machine.Read, so a single token carrying both
    scopes works."""
    data  = request.get_json(force=True)
    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'error': 'token is required'}), 400

    # Latest record per device, internet-facing, with a public IP we can actually scan.
    kql = (
        "DeviceInfo "
        "| where Timestamp > ago(30d) "
        "| summarize arg_max(Timestamp, *) by DeviceId "
        "| where IsInternetFacing == true "
        "| where isnotempty(PublicIP) "
        "| project id = DeviceId, computerDnsName = DeviceName, "
        "lastExternalIpAddress = PublicIP, healthStatus = SensorHealthState"
    )
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept':        'application/json',
        'Content-Type':  'application/json',
    }
    try:
        req = urllib.request.Request(
            'https://api.securitycenter.microsoft.com/api/advancedqueries/run',
            data=json.dumps({'Query': kql}).encode(),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            d = json.loads(resp.read())
        # QueryResponse → { Stats, Schema, Results }. Each Results row is keyed by our projection.
        return jsonify({'value': d.get('Results', [])})
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        try:   detail = json.loads(body).get('error', {}).get('message') or body
        except: detail = body
        if e.code in (401, 403):
            detail += (" — make sure the app registration has the delegated "
                       "'AdvancedQuery.Read' permission (WindowsDefenderATP) and that admin "
                       "consent was granted, then sign out and back in.")
        return jsonify({'error': f'MDE API {e.code}: {detail}'}), e.code
    except Exception as e:
        return jsonify({'error': str(e)}), 502


_KEV_CACHE: dict = {'data': None, 'ts': 0}

@app.route('/api/kev')
def api_kev():
    """Return the latest 30 CISA Known Exploited Vulnerabilities (1-hour cache)."""
    now = time.time()
    if _KEV_CACHE['data'] and now - _KEV_CACHE['ts'] < 3600:
        return jsonify(_KEV_CACHE['data'])

    # Warm the in-memory cache from SQLite (survives restarts within the TTL)
    db_cached = _cache_get_many('kev', ['catalog'], CACHE_TTL['kev']).get('catalog')
    if db_cached:
        _KEV_CACHE['data'] = db_cached
        _KEV_CACHE['ts']   = now
        return jsonify(db_cached)
    try:
        req = urllib.request.Request(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            headers={'User-Agent': 'nmap-scanner/1.0', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = json.loads(resp.read())
        vulns = raw.get('vulnerabilities', [])
        # Most recent first (already sorted by dateAdded desc in the feed)
        vulns.sort(key=lambda v: v.get('dateAdded', ''), reverse=True)
        result = {
            'total_count':     raw.get('count', len(vulns)),
            'catalog_version': raw.get('catalogVersion', ''),
            'vulnerabilities': vulns[:30],
        }
        _KEV_CACHE['data'] = result
        _KEV_CACHE['ts']   = now
        _cache_put_many('kev', {'catalog': result})
        return jsonify(result)
    except Exception as e:
        if _KEV_CACHE['data']:          # return stale on error
            return jsonify(_KEV_CACHE['data'])
        return jsonify({'error': str(e), 'vulnerabilities': []}), 502


@app.route('/api/myip')
def api_myip():
    """Return the server's public IP and geo location (= the user's IP since app runs locally)."""
    try:
        req = urllib.request.Request(
            'http://ip-api.com/json?fields=status,query,country,countryCode,city,lat,lon,org,isp',
            headers={'User-Agent': 'nmap-scanner/1.0'}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            return jsonify(json.loads(resp.read()))
    except Exception as e:
        return jsonify({'status': 'fail', 'error': str(e)}), 502


@app.route('/api/geoip', methods=['POST'])
def api_geoip():
    """Batch GeoIP via ip-api.com (free, no key, max 100 IPs per call)."""
    import re
    ips = request.get_json(force=True).get('ips', [])
    ip_re      = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    private_re = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)')
    valid = [ip for ip in ips
             if ip_re.match(ip) and not private_re.match(ip)][:100]
    if not valid:
        return jsonify([])

    cached   = _cache_get_many('geoip', valid, CACHE_TTL['geoip'])
    to_fetch = [ip for ip in valid if ip not in cached]
    if not to_fetch:
        return jsonify(list(cached.values()))

    try:
        body = json.dumps([
            {'query': ip, 'fields': 'query,status,country,countryCode,city,lat,lon,org,as'}
            for ip in to_fetch
        ]).encode()
        req = urllib.request.Request(
            'http://ip-api.com/batch',
            data=body,
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            fetched_list = json.loads(resp.read())
    except Exception as e:
        if cached:                       # serve what we have on upstream error
            return jsonify(list(cached.values()))
        return jsonify({'error': str(e)}), 502

    # Cache only successful lookups so failures get retried later.
    to_cache = {
        item['query']: item for item in fetched_list
        if isinstance(item, dict) and item.get('status') == 'success' and item.get('query')
    }
    _cache_put_many('geoip', to_cache)

    return jsonify(list(cached.values()) + fetched_list)


@app.route('/api/cve', methods=['POST'])
def api_cve():
    """Fetch CVE details (CVSS score + description) from CIRCL CVE API.
    Free, no API key required. Results are cached in-process."""
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ids = request.get_json(force=True).get('ids', [])
    valid = sorted({c.upper() for c in ids
                    if re.match(r'^CVE-\d{4}-\d+$', str(c), re.I)})[:40]
    if not valid:
        return jsonify({})

    results = {}
    to_fetch = []
    db_cached = _cache_get_many('cve', valid, CACHE_TTL['cve'])
    for cve_id in valid:
        if cve_id in CVE_DETAIL_CACHE:
            results[cve_id] = CVE_DETAIL_CACHE[cve_id]
        elif cve_id in db_cached:
            CVE_DETAIL_CACHE[cve_id] = db_cached[cve_id]
            results[cve_id]          = db_cached[cve_id]
        else:
            to_fetch.append(cve_id)

    def _severity(score):
        if score is None:
            return 'UNKNOWN'
        s = float(score)
        if s >= 9.0: return 'CRITICAL'
        if s >= 7.0: return 'HIGH'
        if s >= 4.0: return 'MEDIUM'
        return 'LOW'

    def fetch_one(cve_id):
        try:
            req = urllib.request.Request(
                f'https://cve.circl.lu/api/cve/{cve_id}',
                headers={'User-Agent': 'nmap-scanner/1.0', 'Accept': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                d = json.loads(resp.read())

            # CVSS v3 preferred, fall back to v2
            score = None
            if isinstance(d.get('cvss3'), dict):
                score = d['cvss3'].get('score')
            if score is None:
                score = d.get('cvss')          # v2 float
            if score is not None:
                score = round(float(score), 1)

            summary = (d.get('summary') or '').strip()
            if len(summary) > 240:
                summary = summary[:237] + '…'

            return cve_id, {
                'id':       cve_id,
                'score':    score,
                'severity': _severity(score),
                'summary':  summary,
                'published': (d.get('Published') or '')[:10],
            }
        except Exception:
            return cve_id, {
                'id': cve_id, 'score': None,
                'severity': 'UNKNOWN', 'summary': '', 'published': ''
            }

    fetched = {}
    with ThreadPoolExecutor(max_workers=10) as exe:
        futures = {exe.submit(fetch_one, c): c for c in to_fetch}
        for fut in as_completed(futures, timeout=30):
            try:
                cve_id, detail = fut.result()
                CVE_DETAIL_CACHE[cve_id] = detail
                results[cve_id]          = detail
                fetched[cve_id]          = detail
            except Exception:
                pass

    _cache_put_many('cve', fetched)
    return jsonify(results)


@app.route('/api/internetdb', methods=['POST'])
def api_internetdb():
    """Shodan InternetDB enrichment — no API key required.
    Returns {ip: {ports, vulns, tags, hostnames, cpes}} for each public IP."""
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ips = request.get_json(force=True).get('ips', [])
    ip_re      = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    private_re = re.compile(
        r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)'
    )
    valid = [ip for ip in ips
             if ip_re.match(ip) and not private_re.match(ip)][:50]
    if not valid:
        return jsonify({})

    results  = _cache_get_many('internetdb', valid, CACHE_TTL['internetdb'])
    to_fetch = [ip for ip in valid if ip not in results]

    def fetch_one(ip):
        try:
            req = urllib.request.Request(
                f'https://internetdb.shodan.io/{ip}',
                headers={'User-Agent': 'nmap-scanner/1.0'}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return ip, json.loads(resp.read())
        except Exception:
            return ip, None

    fetched = {}
    if to_fetch:
        with ThreadPoolExecutor(max_workers=12) as exe:
            futures = {exe.submit(fetch_one, ip): ip for ip in to_fetch}
            for fut in as_completed(futures, timeout=20):
                try:
                    ip, data = fut.result()
                    if data and isinstance(data, dict) and 'ip' in data:
                        results[ip] = data
                        fetched[ip] = data
                except Exception:
                    pass

    _cache_put_many('internetdb', fetched)
    return jsonify(results)


@app.route('/')
def serve_ui():
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanner.html'))


if __name__ == '__main__':
    nmap_ok = _nmap_installed()
    print('=' * 60)
    print('  Blue16 Exposure Scanner  ->  http://localhost:5000')
    print('  Run as Administrator/sudo for OS detection + SYN scans')
    print('=' * 60)
    if not nmap_ok:
        print('\n  ⚠️  nmap NOT FOUND in PATH or common locations!')
        print('  Install from: https://nmap.org/download.html')
        print('  Windows default: C:\\Program Files (x86)\\Nmap\\nmap.exe\n')
    else:
        print(f'  nmap  : {NMAP_PATH[0]}')
    print(f'  DB    : {DB_PATH}')
    print(f'  Sched : {"APScheduler active" if _APScheduler else "disabled (pip install apscheduler)"}')
    app.run(host='localhost', port=5000, debug=False, threaded=True)
