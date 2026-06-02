"""
Blue16 Exposure Scanner — Flask backend
Run with elevated privileges for full scan capabilities:
  Windows : Run terminal as Administrator, then: python app.py
  Linux   : sudo python app.py

Install dependencies:
  pip install flask flask-cors python-nmap apscheduler

Scan pipeline (masscan → nmap → nuclei):
  masscan and nuclei are OPTIONAL external binaries (not pip packages). When
  present they extend the pipeline; when absent the scanner degrades gracefully
  to nmap-only. masscan speeds up CIDR/range discovery, then nmap does service
  detection on just the discovered host:ports; nuclei then runs web vuln
  templates against discovered HTTP/HTTPS services.

Install nmap binary (required):
  Windows : https://nmap.org/download.html  (Windows installer, add to PATH)
  Linux   : sudo apt install nmap  /  sudo yum install nmap
  macOS   : brew install nmap

Install masscan (optional — fast range discovery; needs Npcap on Windows):
  Windows : build from https://github.com/robertdavidgraham/masscan, or place
            masscan.exe in PATH / C:\\masscan\\
  Linux   : sudo apt install masscan
  macOS   : brew install masscan

Install nuclei (optional — web vulnerability scanning):
  Any OS  : download the release binary from
            https://github.com/projectdiscovery/nuclei/releases (add to PATH),
            or: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
"""

from flask import Flask, request, jsonify, send_file, Response, stream_with_context
from flask_cors import CORS
import nmap
import threading
import uuid
import datetime
import os
import shutil
import json
import sqlite3
import subprocess
import tempfile
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

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id     INTEGER NOT NULL,
                scan_id     TEXT NOT NULL,
                template_id TEXT,
                name        TEXT,
                severity    TEXT,
                matched_at  TEXT,
                description TEXT,
                reference   TEXT,
                tags        TEXT
            );

            CREATE TABLE IF NOT EXISTS tls_certs (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id        INTEGER NOT NULL,
                scan_id        TEXT NOT NULL,
                port           INTEGER,
                subject        TEXT,
                issuer         TEXT,
                not_after      TEXT,
                days_left      INTEGER,
                self_signed    INTEGER,
                expired        INTEGER,
                expiring       INTEGER,
                weak_protocols TEXT,
                grade          TEXT,
                issues         TEXT,
                risk           TEXT
            );

            -- Triage: operator-suppressed items (false positive / accepted /
            -- remediated). Keyed by host so triage persists across scans.
            CREATE TABLE IF NOT EXISTS suppressions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host       TEXT NOT NULL,
                kind       TEXT NOT NULL,   -- 'port' | 'finding'
                key        TEXT NOT NULL,   -- '3389/tcp' | nuclei template-id
                state      TEXT NOT NULL,   -- 'false_positive'|'accepted_risk'|'remediated'
                note       TEXT DEFAULT '',
                created_at TEXT,
                UNIQUE(host, kind, key)
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_scan       ON hosts(scan_id);
            CREATE INDEX IF NOT EXISTS idx_hosts_host       ON hosts(host);
            CREATE INDEX IF NOT EXISTS idx_ports_host       ON ports(host_id);
            CREATE INDEX IF NOT EXISTS idx_findings_host    ON findings(host_id);
            CREATE INDEX IF NOT EXISTS idx_tls_host         ON tls_certs(host_id);
            CREATE INDEX IF NOT EXISTS idx_suppress_host    ON suppressions(host);
        ''')
        # Migrate existing DBs that predate later columns
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN label TEXT DEFAULT ''")
        except Exception:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE hosts ADD COLUMN finding_count INTEGER DEFAULT 0")
        except Exception:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE hosts ADD COLUMN nuclei_meta TEXT DEFAULT ''")
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


# ── masscan / nuclei binary detection (optional pipeline stages) ─────────────
# Both are external binaries (not pip). When absent the pipeline silently skips
# the corresponding stage, so these helpers must never raise.
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Windows masscan builds (e.g. MasscanForWindows) ship as masscan64.exe /
# masscan32.exe, so we try those names too — including dropped next to app.py.
_MASSCAN_NAMES = ['masscan', 'masscan64', 'masscan32']
_MASSCAN_COMMON_PATHS = [
    r'C:\masscan\masscan.exe',
    r'C:\masscan\masscan64.exe',
    r'C:\masscan\masscan32.exe',
    r'C:\Program Files\masscan\masscan.exe',
    '/usr/bin/masscan',
    '/usr/local/bin/masscan',
    '/opt/homebrew/bin/masscan',
]

_NUCLEI_NAMES = ['nuclei']
_NUCLEI_COMMON_PATHS = [
    os.path.expandvars(r'%USERPROFILE%\go\bin\nuclei.exe'),
    r'C:\nuclei\nuclei.exe',
    os.path.expanduser('~/go/bin/nuclei'),
    '/usr/bin/nuclei',
    '/usr/local/bin/nuclei',
    '/opt/homebrew/bin/nuclei',
]

# httpx (ProjectDiscovery) — confirms which discovered ports are live web
# services and yields the real scheme/title/tech, feeding clean URLs to nuclei.
_HTTPX_NAMES = ['httpx']
_HTTPX_COMMON_PATHS = [
    os.path.expandvars(r'%USERPROFILE%\go\bin\httpx.exe'),
    r'C:\httpx\httpx.exe',
    os.path.expanduser('~/go/bin/httpx'),
    '/usr/bin/httpx',
    '/usr/local/bin/httpx',
    '/opt/homebrew/bin/httpx',
]

# subfinder + dnsx (ProjectDiscovery) — pre-scan asset discovery: enumerate a
# domain's subdomains (passive) and resolve them to IPs to feed the scanner.
def _pd_common_paths(name: str) -> list:
    return [
        os.path.expandvars(rf'%USERPROFILE%\go\bin\{name}.exe'),
        rf'C:\{name}\{name}.exe',
        os.path.expanduser(f'~/go/bin/{name}'),
        f'/usr/bin/{name}',
        f'/usr/local/bin/{name}',
        f'/opt/homebrew/bin/{name}',
    ]
_SUBFINDER_NAMES = ['subfinder']
_DNSX_NAMES      = ['dnsx']

def _find_binary(names, common_paths: list, verify=None) -> str | None:
    """Locate an external binary by trying, in order: each candidate name on
    PATH, then explicit common install paths, then the application's own
    directory (so the binary can simply be dropped next to app.py).

    `verify` is an optional callable(path) -> bool; when given, a candidate is
    accepted only if it passes (so a same-named but wrong binary on PATH is
    skipped in favour of the real one elsewhere)."""
    if isinstance(names, str):
        names = [names]
    def ok(c):
        return verify is None or verify(c)
    for n in names:                       # 1) PATH (which appends .exe on Windows)
        found = shutil.which(n)
        if found and ok(found):
            return found
    for p in common_paths:                # 2) known install locations
        if os.path.isfile(p) and ok(p):
            return p
    for n in names:                       # 3) alongside app.py
        for ext in ('', '.exe'):
            cand = os.path.join(APP_DIR, n + ext)
            if os.path.isfile(cand) and ok(cand):
                return cand
    return None


def _verify_httpx(path: str) -> bool:
    """Tell ProjectDiscovery httpx (the web prober we want) apart from the
    unrelated Python 'httpx' HTTP-client CLI that frequently shadows it on PATH.

    PD httpx answers `-version` with a semver string; the Python CLI is a Click
    app that instead emits 'Usage: …' / 'No such option' / a traceback. Without
    this guard we'd silently run the wrong binary on every scan."""
    try:
        proc = subprocess.run([path, '-version'], capture_output=True,
                              text=True, timeout=8)
    except Exception:
        return False
    out = (proc.stdout or '') + (proc.stderr or '')
    if 'Usage:' in out or 'No such option' in out or 'Traceback' in out:
        return False
    import re
    return bool(re.search(r'v?\d+\.\d+\.\d+', out))

MASSCAN_PATH = _find_binary(_MASSCAN_NAMES, _MASSCAN_COMMON_PATHS)
NUCLEI_PATH  = _find_binary(_NUCLEI_NAMES,  _NUCLEI_COMMON_PATHS)
HTTPX_PATH   = _find_binary(_HTTPX_NAMES,   _HTTPX_COMMON_PATHS, verify=_verify_httpx)
SUBFINDER_PATH = _find_binary(_SUBFINDER_NAMES, _pd_common_paths('subfinder'))
DNSX_PATH      = _find_binary(_DNSX_NAMES,      _pd_common_paths('dnsx'))

def _masscan_installed() -> bool:
    return MASSCAN_PATH is not None

def _nuclei_installed() -> bool:
    return NUCLEI_PATH is not None

def _httpx_installed() -> bool:
    return HTTPX_PATH is not None

def _subfinder_installed() -> bool:
    return SUBFINDER_PATH is not None

def _dnsx_installed() -> bool:
    return DNSX_PATH is not None

def _binary_version(path: str | None) -> str:
    """Best-effort `<bin> --version` → short version string ('' if unavailable)."""
    if not path:
        return ''
    try:
        proc = subprocess.run([path, '--version'], capture_output=True,
                              text=True, timeout=8)
    except Exception:
        return ''
    import re
    clean = []
    for ln in ((proc.stdout or '') + '\n' + (proc.stderr or '')).splitlines():
        ln = re.sub(r'\x1b\[[0-9;]*m', '', ln)         # strip ANSI colour codes
        ln = re.sub(r'^\[[A-Z]{2,4}\]\s*', '', ln).strip()  # strip a [INF]-style tag
        if ln:
            clean.append(ln)
    if not clean:
        return ''
    # Prefer the first line carrying an actual version number — skips the ASCII
    # banners tools like httpx/subfinder print before their version line.
    for ln in clean:
        if re.search(r'\d+\.\d+', ln):
            return ln
    return clean[0]


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
    'web':           '-sV -Pn -T4',
    'service':       '-sV -Pn -T4',
    'full':          '-sV -O -Pn -T4 --version-intensity 5',
    'vuln':          '-sV -Pn -T4 --script=vuln',
    'custom':        None,
}

# Scan types that force a fixed port list regardless of the UI ports field.
PRESET_PORTS = {
    'remote_access': '22,3389,5985,5986',
    'web':           '80,443',
}

DEFAULT_PORTS = (
    '21,22,23,25,53,80,110,135,137,139,143,389,443,445,'
    '1433,1521,2375,2376,3306,3389,4444,5432,5900,'
    '5985,5986,6379,7001,8080,8443,8888,9200,10250,27017,27018'
)

# ── Pipeline tuning ──────────────────────────────────────────────────────────
MASSCAN_RATE    = 1000             # packets/sec for the masscan discovery stage
MASSCAN_TIMEOUT = 600              # seconds — hard cap on a single masscan run
NUCLEI_SEVERITY = 'medium,high,critical'
NUCLEI_TIMEOUT  = 900              # seconds — hard cap on a single nuclei run
HTTPX_TIMEOUT   = 300              # seconds — hard cap on a single httpx probe run
SUBFINDER_TIMEOUT = 180            # seconds — hard cap on a subfinder enumeration
SUBFINDER_MAX_MIN = 2              # minutes — subfinder's own -max-time (graceful partial exit)
DNSX_TIMEOUT      = 120            # seconds — hard cap on a dnsx resolution run
# Some domains (e.g. example.com) surface tens of thousands of CT-sourced
# subdomains; cap how many we resolve/return so discovery stays bounded.
MAX_DISCOVER_HOSTS = 2000

# Ports we treat as web services for the nuclei stage (in addition to any port
# whose nmap service name contains 'http').
WEB_PORTS    = {80, 443, 8080, 8443, 8000, 8888, 8081, 9443, 3000, 5000}
_HTTPS_PORTS = {443, 8443, 9443}

def _is_web(port: int, service: str) -> bool:
    return port in WEB_PORTS or 'http' in (service or '').lower()

def _url_for(host: str, port: int, service: str) -> str:
    svc = (service or '').lower()
    scheme = 'https' if port in _HTTPS_PORTS or 'https' in svc or 'ssl' in svc else 'http'
    return f'{scheme}://{host}:{port}'

def _normalize_target(target: str) -> str:
    """Drop a single-host CIDR suffix (/32 for IPv4, /128 for IPv6) so a lone IP
    isn't treated as a range and pushed through masscan needlessly."""
    t = target.strip()
    if t.endswith('/32') or t.endswith('/128'):
        return t.rsplit('/', 1)[0]
    return t

def _is_range(target: str) -> bool:
    """CIDR (10.0.0.0/24) or dash range (10.0.0.1-50) — worth a masscan sweep."""
    return '/' in target or '-' in target

# Ports/services to inspect for TLS (cert expiry + weak protocols/ciphers).
TLS_PORTS = {443, 8443, 9443, 993, 995, 465, 990, 636, 989, 992, 5061, 8883}

def _is_tls(port: int, service: str) -> bool:
    svc = (service or '').lower()
    return port in TLS_PORTS or 'https' in svc or 'ssl' in svc or 'tls' in svc


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


# ── Triage / suppression ─────────────────────────────────────────────────────
def _suppressed_keys(host: str, kind: str) -> set:
    """Return the set of suppressed keys (e.g. '3389/tcp') for a host + kind."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT key FROM suppressions WHERE host=? AND kind=?', (host, kind)
            ).fetchall()
        return {r['key'] for r in rows}
    except Exception as e:
        print(f'[suppress] lookup error: {e}')
        return set()


# ── Change detection ───────────────────────────────────────────────────────
def detect_changes(host_ip: str, current_scan_id: str, open_ports: list) -> dict:
    """Compare current open ports against the most recent previous scan of this host.
    Operator-suppressed ports are excluded from 'new', so accepted/known-good
    ports never re-alert."""
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

        suppressed = _suppressed_keys(host_ip, 'port')   # {'3389/tcp', ...}
        prev_set  = {(r['port'], r['proto']) for r in prev_rows}
        curr_set  = {(p['port'], p['proto']) for p in open_ports}
        new_keys  = curr_set - prev_set
        gone_keys = prev_set - curr_set

        new_ports    = [p for p in open_ports
                        if (p['port'], p['proto']) in new_keys
                        and f"{p['port']}/{p['proto']}" not in suppressed]
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
                       new_ports, closed_ports, is_new_host, finding_count, nuclei_meta)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
                    h.get('finding_count', 0),
                    json.dumps(h['nuclei']) if h.get('nuclei') else '',
                ))
                host_id = cur.lastrowid

                for fnd in h.get('findings', []):
                    conn.execute('''
                        INSERT INTO findings
                          (host_id, scan_id, template_id, name, severity,
                           matched_at, description, reference, tags)
                        VALUES (?,?,?,?,?,?,?,?,?)
                    ''', (
                        host_id, job['id'],
                        fnd.get('template_id', ''), fnd.get('name', ''),
                        fnd.get('severity', ''), fnd.get('matched_at', ''),
                        fnd.get('description', ''), fnd.get('reference', ''),
                        fnd.get('tags', ''),
                    ))

                for c in h.get('tls', []):
                    conn.execute('''
                        INSERT INTO tls_certs
                          (host_id, scan_id, port, subject, issuer, not_after,
                           days_left, self_signed, expired, expiring,
                           weak_protocols, grade, issues, risk)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ''', (
                        host_id, job['id'],
                        c.get('port'), c.get('subject', ''), c.get('issuer', ''),
                        c.get('not_after', ''), c.get('days_left'),
                        1 if c.get('self_signed') else 0,
                        1 if c.get('expired') else 0,
                        1 if c.get('expiring') else 0,
                        json.dumps(c.get('weak_protocols', [])),
                        c.get('grade', ''),
                        json.dumps(c.get('issues', [])),
                        c.get('risk', 'info'),
                    ))

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
                findings = conn.execute('SELECT * FROM findings WHERE host_id=? ORDER BY id', (h['id'],)).fetchall()
                tls_rows = conn.execute('SELECT * FROM tls_certs WHERE host_id=? ORDER BY port', (h['id'],)).fetchall()
                tls = [{
                    'port':           t['port'],
                    'subject':        t['subject'],
                    'issuer':         t['issuer'],
                    'not_after':      t['not_after'],
                    'days_left':      t['days_left'],
                    'self_signed':    bool(t['self_signed']),
                    'expired':        bool(t['expired']),
                    'expiring':       bool(t['expiring']),
                    'weak_protocols': json.loads(t['weak_protocols'] or '[]'),
                    'grade':          t['grade'],
                    'issues':         json.loads(t['issues'] or '[]'),
                    'risk':           t['risk'],
                } for t in tls_rows]
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
                    'finding_count':  h['finding_count'] if 'finding_count' in h.keys() else len(findings),
                    'nuclei':         (json.loads(h['nuclei_meta']) if 'nuclei_meta' in h.keys() and h['nuclei_meta'] else None),
                    'ports':          [dict(p) for p in ports],
                    'findings':       [dict(f) for f in findings],
                    'tls':            tls,
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
    'epss':            86400,   # FIRST.org EPSS — recomputed daily
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


# ── Exploit-likelihood enrichment (EPSS + KEV) ───────────────────────────────
# CVSS says how bad a flaw *could* be; EPSS (FIRST.org) estimates the probability
# it will be exploited in the next 30 days, and CISA KEV lists what *is* being
# exploited now. Together they turn a wall of CVEs into a real priority order.
_KEV_SET_CACHE: dict = {'data': None, 'ts': 0}

def _kev_cve_set() -> set:
    """Return the set of all CVE IDs in the CISA KEV catalog (cached)."""
    now = time.time()
    if _KEV_SET_CACHE['data'] is not None and now - _KEV_SET_CACHE['ts'] < CACHE_TTL['kev']:
        return _KEV_SET_CACHE['data']
    db = _cache_get_many('kev', ['cve_set'], CACHE_TTL['kev']).get('cve_set')
    if db:
        s = set(db)
        _KEV_SET_CACHE.update(data=s, ts=now)
        return s
    try:
        req = urllib.request.Request(
            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            headers={'User-Agent': 'nmap-scanner/1.0', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = json.loads(resp.read())
        s = {(v.get('cveID') or '').upper()
             for v in raw.get('vulnerabilities', []) if v.get('cveID')}
        _KEV_SET_CACHE.update(data=s, ts=now)
        _cache_put_many('kev', {'cve_set': sorted(s)})
        return s
    except Exception as e:
        print(f'[kev] cve-set fetch error: {e}')
        return _KEV_SET_CACHE['data'] or set()


def _fetch_epss(cve_ids: list) -> dict:
    """Return {CVE-ID: {epss, percentile}} from FIRST.org EPSS (cache-aware).
    CVEs with no EPSS data are simply absent from the result."""
    if not cve_ids:
        return {}
    out = dict(_cache_get_many('epss', cve_ids, CACHE_TTL['epss']))
    to_fetch = [c for c in cve_ids if c not in out]
    fetched = {}
    for i in range(0, len(to_fetch), 100):            # EPSS API accepts a CSV list
        chunk = to_fetch[i:i + 100]
        try:
            url = ('https://api.first.org/data/v1/epss?cve='
                   + urllib.parse.quote(','.join(chunk)))
            req = urllib.request.Request(
                url, headers={'User-Agent': 'nmap-scanner/1.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=12) as resp:
                d = json.loads(resp.read())
            for row in d.get('data', []):
                cid = (row.get('cve') or '').upper()
                if not cid:
                    continue
                rec = {
                    'epss':       round(float(row.get('epss') or 0), 4),
                    'percentile': round(float(row.get('percentile') or 0), 4),
                }
                out[cid] = rec
                fetched[cid] = rec
        except Exception as e:
            print(f'[epss] {e}')
    _cache_put_many('epss', fetched)
    return out


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


# ── masscan stage ────────────────────────────────────────────────────────────
def _run_masscan(target: str, ports: str) -> dict | None:
    """Fast port discovery on a CIDR/range. Returns {ip: [open_port_ints]}.

    Returns None on any failure so the caller falls back to scanning the full
    range with nmap. An empty dict means masscan ran cleanly but found nothing.
    """
    if not MASSCAN_PATH:
        return None
    cmd = [MASSCAN_PATH, target, '-p', ports,
           '--rate', str(MASSCAN_RATE), '-oJ', '-']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=MASSCAN_TIMEOUT)
    except Exception as e:
        print(f'[masscan] {target}: {e}')
        return None
    if proc.returncode != 0 and not proc.stdout.strip():
        print(f'[masscan] {target}: exit {proc.returncode} {proc.stderr.strip()[:200]}')
        return None

    # masscan -oJ emits a JSON array; trailing comma / partial lines are common,
    # so parse defensively line-by-line as well as whole-document.
    out: dict = {}
    def _ingest(records):
        for rec in records:
            ip = rec.get('ip')
            for p in rec.get('ports', []):
                if ip and p.get('status') == 'open' and p.get('port'):
                    out.setdefault(ip, [])
                    if p['port'] not in out[ip]:
                        out[ip].append(p['port'])
    try:
        _ingest(json.loads(proc.stdout))
    except Exception:
        for line in proc.stdout.splitlines():
            line = line.strip().rstrip(',')
            if not line.startswith('{'):
                continue
            try:
                _ingest([json.loads(line)])
            except Exception:
                pass
    return out


# ── httpx stage ──────────────────────────────────────────────────────────────
def _run_httpx(candidates: list) -> tuple:
    """Probe candidate ``host:port`` web services with httpx.

    Returns (per_host, live_urls, meta):
      per_host  = {host: [ {url, scheme, port, status_code, title, webserver,
                            tech:[...]} ]} keyed by the host we passed in (so it
                  lines up with the nmap host key).
      live_urls = flat list of confirmed-live URLs (for the nuclei stage).
      meta      = {status, target_count, live_count, duration, error}.

    httpx determines the real scheme (http vs https) and confirms the service is
    actually a live web server — far more reliable than guessing from the port.
    Never raises; on any failure the caller falls back to port-based URL guesses.
    """
    meta = {'status': 'skipped', 'target_count': len(candidates),
            'live_count': 0, 'duration': 0.0, 'error': ''}
    if not HTTPX_PATH:
        meta['error'] = 'httpx not installed'
        return {}, [], meta
    if not candidates:
        meta['error'] = 'no web candidates to probe'
        return {}, [], meta

    tmp_path = None
    t0 = time.time()
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as tf:
            tf.write('\n'.join(candidates))
            tmp_path = tf.name
        cmd = [HTTPX_PATH, '-l', tmp_path, '-json', '-silent', '-no-color',
               '-disable-update-check', '-title', '-status-code',
               '-tech-detect', '-web-server', '-timeout', '10']
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=HTTPX_TIMEOUT)
    except Exception as e:
        meta['duration'] = round(time.time() - t0, 1)
        meta['status']   = 'error'
        meta['error']    = str(e)
        print(f'[httpx] error after {meta["duration"]}s on {len(candidates)} target(s): {e}')
        return {}, [], meta
    finally:
        if tmp_path:
            try: os.unlink(tmp_path)
            except Exception: pass

    meta['duration'] = round(time.time() - t0, 1)

    per_host: dict = {}
    live_urls = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get('failed'):
            continue
        url = rec.get('url') or ''
        if not url:
            continue
        # Key by the host portion of the exact input we supplied so it matches
        # the nmap host key (httpx echoes `input` as e.g. "1.2.3.4:443").
        raw_in = rec.get('input') or rec.get('host') or ''
        host   = raw_in.rsplit(':', 1)[0] if ':' in raw_in and not raw_in.startswith('[') else (rec.get('host') or raw_in)
        tech   = rec.get('tech') or rec.get('technologies') or []
        if isinstance(tech, str):
            tech = [tech]
        per_host.setdefault(host, []).append({
            'url':         url,
            'scheme':      rec.get('scheme', ''),
            'port':        rec.get('port', ''),
            'status_code': rec.get('status_code') or rec.get('status-code') or 0,
            'title':       (rec.get('title') or '').strip(),
            'webserver':   rec.get('webserver') or rec.get('web_server') or '',
            'tech':        tech,
        })
        live_urls.append(url)

    meta['live_count'] = len(live_urls)
    fatal = [ln.strip() for ln in (proc.stderr or '').splitlines()
             if '[FTL]' in ln or '[ERR]' in ln]
    if fatal and not live_urls:
        import re as _re
        meta['error'] = _re.sub(r'\x1b\[[0-9;]*m', '', fatal[0])[:300]
        meta['status'] = 'error'
    else:
        meta['status'] = 'ran'
    print(f'[httpx] {meta["status"]}: {len(candidates)} candidate(s) → '
          f'{len(live_urls)} live in {meta["duration"]}s'
          + (f' — {meta["error"]}' if meta['error'] else ''))
    return per_host, live_urls, meta


# ── subfinder + dnsx (pre-scan asset discovery) ──────────────────────────────
import re as _re_disc
_DOMAIN_RE = _re_disc.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}'
                              r'(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$')

def _is_domain(name: str) -> bool:
    """A bare registrable hostname (no scheme/port/path), not an IP/CIDR/range.
    Also guards against argument injection (leading '-')."""
    name = (name or '').strip()
    if not name or name.startswith('-') or '/' in name or ' ' in name:
        return False
    # Reject anything that's purely an IPv4 address.
    if _re_disc.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', name):
        return False
    return bool(_DOMAIN_RE.match(name))


def _run_subfinder(domain: str) -> tuple:
    """Passive subdomain enumeration for a single domain.
    Returns (subdomains, error). Never raises."""
    if not SUBFINDER_PATH:
        return [], 'subfinder not installed'
    if not _is_domain(domain):
        return [], 'invalid domain'
    cmd = [SUBFINDER_PATH, '-silent', '-duc', '-d', domain,
           '-max-time', str(SUBFINDER_MAX_MIN)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=SUBFINDER_TIMEOUT)
    except Exception as e:
        print(f'[subfinder] {domain}: {e}')
        return [], str(e)
    subs = []
    for line in (proc.stdout or '').splitlines():
        s = line.strip().lower()
        if s and _is_domain(s):
            subs.append(s)
    subs = sorted(set(subs))
    print(f'[subfinder] {domain}: {len(subs)} subdomain(s)')
    return subs, ''


def _run_dnsx(hosts: list) -> tuple:
    """Resolve hostnames to A records with dnsx.
    Returns (resolved, error) where resolved = {host: [ips]}. Never raises."""
    hosts = [h for h in hosts if _is_domain(h)]
    if not DNSX_PATH:
        return {}, 'dnsx not installed'
    if not hosts:
        return {}, 'no resolvable hosts'
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as tf:
            tf.write('\n'.join(hosts))
            tmp_path = tf.name
        cmd = [DNSX_PATH, '-silent', '-duc', '-json', '-a', '-resp', '-l', tmp_path]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=DNSX_TIMEOUT)
    except Exception as e:
        print(f'[dnsx] {e}')
        return {}, str(e)
    finally:
        if tmp_path:
            try: os.unlink(tmp_path)
            except Exception: pass
    resolved: dict = {}
    for line in (proc.stdout or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rec  = json.loads(line)
        except Exception:
            continue
        host = (rec.get('host') or '').lower()
        ips  = rec.get('a') or []
        if host and ips:
            resolved.setdefault(host, [])
            for ip in ips:
                if ip not in resolved[host]:
                    resolved[host].append(ip)
    print(f'[dnsx] resolved {len(resolved)}/{len(hosts)} host(s)')
    return resolved, ''


# ── nuclei stage ─────────────────────────────────────────────────────────────
_NUCLEI_TEMPLATES_READY = False

def _ensure_nuclei_templates():
    """Install nuclei's template set once if it's missing.

    We run scans with -duc (disable update check) to avoid a network round-trip
    on every scan, but that also stops nuclei from auto-fetching templates on a
    fresh install — without templates every scan fails with 'no templates
    provided'. So on first use we proactively run -update-templates.
    """
    global _NUCLEI_TEMPLATES_READY
    if _NUCLEI_TEMPLATES_READY or not NUCLEI_PATH:
        return
    tdir = os.path.join(os.path.expanduser('~'), 'nuclei-templates')
    if os.path.isdir(tdir) and os.listdir(tdir):
        _NUCLEI_TEMPLATES_READY = True
        return
    try:
        print('[nuclei] templates missing — running one-time -update-templates '
              '(this can take a minute)…')
        subprocess.run([NUCLEI_PATH, '-update-templates'],
                       capture_output=True, text=True, timeout=600)
        _NUCLEI_TEMPLATES_READY = True
        print('[nuclei] templates installed.')
    except Exception as e:
        print(f'[nuclei] template install failed: {e}')


def _run_nuclei(urls: list, severity: str | None = None,
                tags: str | None = None) -> tuple:
    """Run nuclei web vuln templates against the given URLs.

    Returns (findings, meta):
      findings = {host: [finding dicts]} keyed by the IP/host portion of a target.
      meta     = run summary {status, target_count, finding_count, duration,
                 severity, error} so callers can show *what nuclei did* even when
                 it produced zero findings.
    Never raises.

    severity: comma-separated severities (e.g. 'medium,high,critical'); defaults
              to NUCLEI_SEVERITY if omitted or invalid.
    tags:     comma-separated nuclei template tags (e.g. 'cves,misconfigs').
    """
    import re as _re
    _VALID_SEV = {'info', 'low', 'medium', 'high', 'critical'}
    sev_parts  = [s.strip().lower() for s in (severity or '').split(',') if s.strip()]
    sev        = ','.join(s for s in sev_parts if s in _VALID_SEV) or NUCLEI_SEVERITY
    tag_parts  = [t.strip().lower() for t in (tags or '').split(',') if t.strip()]
    clean_tags = ','.join(t for t in tag_parts if _re.fullmatch(r'[a-z0-9\-]+', t)) or None
    meta = {
        'status':        'skipped',
        'target_count':  len(urls),
        'finding_count': 0,
        'duration':      0.0,
        'severity':      sev,
        'tags':          clean_tags or '',
        'error':         '',
    }
    if not NUCLEI_PATH:
        meta['error'] = 'nuclei not installed'
        return {}, meta
    if not urls:
        meta['error'] = 'no web services to probe'
        return {}, meta

    _ensure_nuclei_templates()

    tmp_path = None
    t0 = time.time()
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as tf:
            tf.write('\n'.join(urls))
            tmp_path = tf.name

        cmd = [NUCLEI_PATH, '-silent', '-jsonl', '-duc',
               '-severity', sev, '-l', tmp_path]
        if clean_tags:
            cmd += ['-tags', clean_tags]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=NUCLEI_TIMEOUT)
    except Exception as e:
        meta['duration'] = round(time.time() - t0, 1)
        meta['status']   = 'error'
        meta['error']    = str(e)
        print(f'[nuclei] error after {meta["duration"]}s on {len(urls)} target(s): {e}')
        return {}, meta
    finally:
        if tmp_path:
            try: os.unlink(tmp_path)
            except Exception: pass

    meta['duration'] = round(time.time() - t0, 1)

    # Surface fatal/error lines nuclei prints to stderr (e.g. missing templates)
    fatal = [ln.strip() for ln in (proc.stderr or '').splitlines()
             if '[FTL]' in ln or '[ERR]' in ln]
    if fatal:
        import re as _re
        meta['error'] = _re.sub(r'\x1b\[[0-9;]*m', '', fatal[0])[:300]

    findings: dict = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            rec  = json.loads(line)
            info = rec.get('info', {}) or {}
            # nuclei reports 'host' as the matched URL host; normalize to the
            # bare IP/hostname so it matches the nmap host key.
            raw_host = rec.get('host') or rec.get('matched-at') or ''
            host = urllib.parse.urlparse(
                raw_host if '://' in raw_host else f'//{raw_host}'
            ).hostname or raw_host
            ref = info.get('reference') or []
            findings.setdefault(host, []).append({
                'template_id': rec.get('template-id', ''),
                'name':        info.get('name', ''),
                'severity':    (info.get('severity') or 'info').lower(),
                'matched_at':  rec.get('matched-at', '') or rec.get('host', ''),
                'description': (info.get('description') or '').strip(),
                'reference':   ref[0] if isinstance(ref, list) and ref else (ref if isinstance(ref, str) else ''),
                'tags':        ','.join(info.get('tags', [])) if isinstance(info.get('tags'), list) else (info.get('tags') or ''),
            })
        except Exception:
            pass

    meta['finding_count'] = sum(len(v) for v in findings.values())
    meta['status']        = 'error' if (meta['error'] and not findings) else 'ran'
    print(f'[nuclei] {meta["status"]}: {len(urls)} target(s), '
          f'{meta["finding_count"]} finding(s) at {NUCLEI_SEVERITY} '
          f'in {meta["duration"]}s'
          + (f' — {meta["error"]}' if meta['error'] else ''))
    return findings, meta


# ── TLS / certificate inspection stage ───────────────────────────────────────
TLS_TIMEOUT = 120   # seconds — bound the ssl-cert/ssl-enum-ciphers scripts

def _parse_ssl_cert(text: str) -> dict:
    """Parse nmap ssl-cert script output into structured fields."""
    import re
    out = {}
    m = re.search(r'Subject:.*?commonName=([^\n/]+)', text)
    if m: out['subject'] = m.group(1).strip()
    m = re.search(r'Issuer:\s*(.+)', text)
    if m:
        iss = m.group(1).strip()
        cn  = re.search(r'commonName=([^\n/]+)', iss)
        org = re.search(r'organizationName=([^\n/]+)', iss)
        out['issuer'] = (cn.group(1).strip() if cn else
                         org.group(1).strip() if org else iss[:80])
    m = re.search(r'Not valid before:\s*([0-9T:\-]+)', text)
    if m: out['not_before'] = m.group(1).strip()
    m = re.search(r'Not valid after:\s*([0-9T:\-]+)', text)
    if m: out['not_after'] = m.group(1).strip()
    return out

def _parse_ssl_ciphers(text: str) -> dict:
    """Parse ssl-enum-ciphers output → weak protocols + least cipher grade."""
    import re
    weak = [p for p in ('SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1')
            if re.search(rf'^\s*{re.escape(p)}:', text, re.M)]
    grade = None
    grades = re.findall(r'least strength:\s*([A-F])', text)
    if grades:
        grade = sorted(grades)[-1]      # worst (F > A) across protocols
    return {'weak_protocols': weak, 'grade': grade}


def _run_tls(host: str, tls_ports: list) -> list:
    """Inspect TLS on the given ports via nmap ssl-cert + ssl-enum-ciphers.
    Returns a list of per-port cert dicts with computed issues + risk. Never
    raises (returns [] on failure or if there are no TLS ports)."""
    if not tls_ports:
        return []
    try:
        nm = nmap.PortScanner(nmap_search_path=NMAP_PATH)
        nm.scan(hosts=host, ports=','.join(str(p) for p in tls_ports),
                arguments='-Pn -sV --script ssl-cert,ssl-enum-ciphers '
                          '--script-timeout 30s')
    except Exception as e:
        print(f'[tls] {host}: {e}')
        return []

    results = []
    for h in nm.all_hosts():
        tcp = nm[h].get('tcp', {})
        for port, pinfo in tcp.items():
            scripts = pinfo.get('script', {}) or {}
            if 'ssl-cert' not in scripts and 'ssl-enum-ciphers' not in scripts:
                continue
            cert    = _parse_ssl_cert(scripts.get('ssl-cert', ''))
            ciphers = _parse_ssl_ciphers(scripts.get('ssl-enum-ciphers', ''))

            days_left = None
            na = cert.get('not_after')
            if na:
                for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                    try:
                        exp = datetime.datetime.strptime(na, fmt)
                        days_left = (exp - _utcnow()).days
                        break
                    except ValueError:
                        continue

            subj, iss = cert.get('subject', ''), cert.get('issuer', '')
            self_signed = bool(subj and iss and subj == iss)
            expired   = days_left is not None and days_left < 0
            expiring  = days_left is not None and 0 <= days_left <= 30
            weak_prot = ciphers.get('weak_protocols') or []
            grade     = ciphers.get('grade')
            weak_grade = grade in ('C', 'D', 'E', 'F')

            issues = []
            if expired:     issues.append(f'Certificate expired {abs(days_left)}d ago')
            elif expiring:  issues.append(f'Certificate expires in {days_left}d')
            if self_signed: issues.append('Self-signed certificate')
            for p in weak_prot: issues.append(f'Weak protocol: {p}')
            if weak_grade:  issues.append(f'Weak cipher grade: {grade}')

            risk = ('high' if (expired or weak_prot or grade in ('D', 'E', 'F'))
                    else 'medium' if (expiring or self_signed or grade == 'C')
                    else 'low')

            results.append({
                'port':           port,
                'subject':        subj,
                'issuer':         iss,
                'not_after':      na or '',
                'days_left':      days_left,
                'self_signed':    self_signed,
                'expired':        expired,
                'expiring':       expiring,
                'weak_protocols': weak_prot,
                'grade':          grade or '',
                'issues':         issues,
                'risk':           risk,
            })
    if results:
        print(f'[tls] {host}: inspected {len(results)} port(s), '
              f'{sum(len(r["issues"]) for r in results)} issue(s)')
    return results


# ── Scan worker ────────────────────────────────────────────────────────────
# Targets are scanned concurrently with a bounded pool. nmap itself parallelizes
# within a single target; this adds host-level concurrency for large lists. Each
# worker builds its own PortScanner, so there's no shared nmap state across threads.
MAX_SCAN_WORKERS = 8

def _set_stage(job: dict | None, lock, stage: str):
    """Record the current pipeline stage on the job for UI display (thread-safe)."""
    if job is None:
        return
    if lock is not None:
        with lock:
            job.setdefault('progress', {})['stage'] = stage
    else:
        job.setdefault('progress', {})['stage'] = stage


def _scan_target(target: str, ports: str, args: str, scan_type: str, job_id: str,
                 run_nuclei: bool = True, job: dict | None = None, lock=None,
                 run_tls: bool = True, nuclei_severity: str | None = None,
                 nuclei_tags: str | None = None) -> list:
    """Scan a single target through the masscan → nmap → nuclei → TLS pipeline.

    A target may be a CIDR/range, so it can yield multiple hosts. masscan only
    runs for port-scanning types on ranges (and only if installed); otherwise we
    go straight to nmap. nuclei runs against discovered web services and TLS
    inspection runs against discovered TLS services."""
    out = []
    try:
        nm = nmap.PortScanner(nmap_search_path=NMAP_PATH)

        # ── Stage 1: masscan discovery (ranges only) ─────────────────────────
        # For port-scanning types on a CIDR/range, let masscan find open ports
        # fast, then hand only those host:ports to nmap for service detection.
        # masscan is TCP + explicit-port only, so it's skipped for UDP scans and
        # top-ports mode (no explicit port list).
        use_masscan = (scan_type not in ('ping', 'quick')
                       and ports and '-sU' not in args
                       and _is_range(target) and _masscan_installed())
        discovered = None
        if use_masscan:
            _set_stage(job, lock, 'masscan')
            discovered = _run_masscan(target, ports)

        _set_stage(job, lock, 'nmap')
        if discovered is not None:
            # masscan ran cleanly; nothing open means no nmap work to do.
            if not discovered:
                return []
            union_ports = sorted({p for plist in discovered.values() for p in plist})
            nm.scan(hosts=' '.join(discovered.keys()),
                    ports=','.join(str(p) for p in union_ports),
                    arguments=args)
        elif scan_type in ('ping', 'quick') or not ports:
            # No explicit port list (ping/quick, or --top-ports in args)
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
                'findings':       [],
                'finding_count':  0,
                'http':           [],
                'tls':            [],
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
            'findings': [], 'finding_count': 0, 'http': [], 'tls': [],
        })
    except Exception as exc:
        out.append({
            'host': target, 'input': target, 'hostname': '—',
            'state': 'error', 'error': str(exc),
            'os': '—', 'os_accuracy': '',
            'ports': [], 'open_count': 0, 'critical_count': 0,
            'risk': 'info', 'scanned_at': _now(),
            'new_ports': [], 'closed_ports': [], 'is_new_host': False,
            'findings': [], 'finding_count': 0, 'http': [], 'tls': [],
        })

    # ── Stage 2.5: httpx web probing ─────────────────────────────────────────
    # Confirm which of nmap's open web-candidate ports are actually live HTTP/
    # HTTPS, with the real scheme/title/tech. When httpx is installed we hand the
    # *confirmed* URLs to nuclei; otherwise we fall back to guessing the scheme
    # from the port (_url_for), preserving the original behaviour.
    web_candidates = {
        h['host']: [p['port'] for p in h.get('ports', [])
                    if p.get('state') == 'open' and _is_web(p['port'], p.get('service', ''))]
        for h in out
    }
    flat_candidates = [f'{host}:{port}'
                       for host, plist in web_candidates.items() for port in plist]

    host_urls = {}
    if (_httpx_installed() and scan_type != 'ping' and flat_candidates):
        _set_stage(job, lock, 'httpx')
        per_host, _live, hx_meta = _run_httpx(flat_candidates)
        for h in out:
            probes = per_host.get(h['host'], [])
            h['http'] = probes
            if probes:
                host_urls[h['host']] = [pr['url'] for pr in probes]
    else:
        # No httpx (or ping scan): guess URLs from the open web ports.
        host_urls = {
            h['host']: [_url_for(h['host'], p['port'], p.get('service', ''))
                        for p in h.get('ports', [])
                        if p.get('state') == 'open' and _is_web(p['port'], p.get('service', ''))]
            for h in out
        }

    # ── Stage 3: nuclei web vuln scan ────────────────────────────────────────
    # Point nuclei at every confirmed (or guessed) web service, fold finding
    # severities back into each host's risk, and attach a per-host run summary
    # (h['nuclei']) so the UI can show what nuclei did even when it found nothing.
    total_urls = sum(len(v) for v in host_urls.values())

    skip_reason = None
    if scan_type == 'ping':
        skip_reason = 'ping scan — no web probing'
    elif not run_nuclei:
        skip_reason = 'disabled for this scan'
    elif not _nuclei_installed():
        skip_reason = 'nuclei not installed'

    def _nuclei_meta(status, probed, fcount, duration, error):
        return {'status': status, 'probed': probed, 'finding_count': fcount,
                'duration':  duration,
                'severity':  nuclei_severity or NUCLEI_SEVERITY,
                'tags':      nuclei_tags or '',
                'error':     error}

    if skip_reason is None and total_urls > 0:
        _set_stage(job, lock, 'nuclei')
        all_urls = [u for urls in host_urls.values() for u in urls]
        findings_map, run_meta = _run_nuclei(all_urls,
                                             severity=nuclei_severity,
                                             tags=nuclei_tags)
        for h in out:
            hu = host_urls.get(h['host'], [])
            f  = findings_map.get(h['host'], [])
            h['findings']      = f
            h['finding_count'] = len(f)
            if hu:
                h['nuclei'] = _nuclei_meta(run_meta['status'], len(hu), len(f),
                                           run_meta['duration'], run_meta['error'])
            if f:
                sev_risk = max(RISK_ORDER.get(x['severity'], 0) for x in f)
                cur      = RISK_ORDER.get(h['risk'], 0)
                h['risk'] = RISK_LABELS[max(cur, sev_risk)]
    else:
        # nuclei didn't run — record why on every host that had web services.
        for h in out:
            hu = host_urls.get(h['host'], [])
            if hu:
                h['nuclei'] = _nuclei_meta('skipped', len(hu), 0, 0.0,
                                           skip_reason or 'no web services')

    # ── Stage 4: TLS / certificate inspection ────────────────────────────────
    # Check discovered TLS services for expiring/expired/self-signed certs and
    # weak protocols/ciphers, then fold the worst into the host's risk.
    if run_tls and scan_type != 'ping':
        for h in out:
            tls_ports = sorted({p['port'] for p in h.get('ports', [])
                                if p.get('state') == 'open'
                                and _is_tls(p['port'], p.get('service', ''))})
            if not tls_ports:
                continue
            _set_stage(job, lock, 'tls')
            certs = _run_tls(h['host'], tls_ports)
            h['tls'] = certs
            if certs:
                tls_risk = max(RISK_ORDER.get(c['risk'], 0) for c in certs)
                cur      = RISK_ORDER.get(h['risk'], 0)
                h['risk'] = RISK_LABELS[max(cur, tls_risk)]

    return out


def run_scan(job_id: str):
    job = JOBS[job_id]
    job['status']     = 'running'
    job['started_at'] = _now()

    targets    = job['targets']
    ports      = job['ports']
    args       = job['arguments']
    scan_type  = job['scan_type']
    run_nuclei      = job.get('run_nuclei', True)
    run_tls         = job.get('run_tls', True)
    nuclei_severity = job.get('nuclei_severity') or None
    nuclei_tags     = job.get('nuclei_tags') or None
    total           = len(targets)

    results   = []
    lock      = threading.Lock()
    completed = 0
    workers   = max(1, min(MAX_SCAN_WORKERS, total))

    job['progress'] = {'current': 0, 'total': total, 'host': '', 'pct': 0, 'stage': ''}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        future_map = {
            exe.submit(_scan_target, t, ports, args, scan_type, job_id,
                       run_nuclei, job, lock, run_tls,
                       nuclei_severity, nuclei_tags): t
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
                    'findings': [], 'finding_count': 0,
                }]

            with lock:
                results.extend(host_results)
                completed += 1
                job['results']  = list(results)
                job['progress'] = {
                    'current': completed, 'total': total,
                    'host': target,
                    'pct':  round(completed / total * 100) if total else 0,
                    'stage': job.get('progress', {}).get('stage', ''),
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

            targets = [_normalize_target(t) for t in
                       (s['targets'] or '').replace(',', '\n').splitlines() if t.strip()]
            if not targets:
                return

            scan_type   = s['scan_type']
            ports       = s['ports'] or DEFAULT_PORTS
            custom_args = s['custom_args'] or '-sV -T4'
            force_pn    = bool(s['force_pn'])

            args = SCAN_PRESETS.get(scan_type) or custom_args
            if scan_type in PRESET_PORTS:
                ports = PRESET_PORTS[scan_type]

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
        return jsonify({
            'status': 'ok',
            'nmap':   '.'.join(str(v) for v in ver),
            'tools':  {
                'nmap':    {'installed': True,
                            'version': '.'.join(str(v) for v in ver)},
                'masscan': {'installed': _masscan_installed(),
                            'version': _binary_version(MASSCAN_PATH)},
                'httpx':   {'installed': _httpx_installed(),
                            'version': _binary_version(HTTPX_PATH)},
                'nuclei':  {'installed': _nuclei_installed(),
                            'version': _binary_version(NUCLEI_PATH)},
                'subfinder': {'installed': _subfinder_installed(),
                              'version': _binary_version(SUBFINDER_PATH)},
                'dnsx':      {'installed': _dnsx_installed(),
                              'version': _binary_version(DNSX_PATH)},
            },
        })
    except nmap.PortScannerError as e:
        return jsonify({
            'status':  'nmap_missing',
            'error':   'nmap not found in PATH',
            'detail':  str(e),
            'install': 'https://nmap.org/download.html',
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/discover', methods=['POST'])
def api_discover():
    """Pre-scan asset discovery for a single domain.

    Enumerates subdomains with subfinder (passive) and resolves every name to
    its A records with dnsx, returning the discovered hosts + unique IPs for the
    UI to merge into the target list. Both tools are optional: with neither
    installed this returns an error; with only dnsx we still resolve the apex.
    """
    data   = request.get_json(force=True)
    domain = (data.get('domain') or '').strip().lower()
    if not _is_domain(domain):
        return jsonify({'error': 'Enter a valid domain, e.g. example.com'}), 400
    if not (_subfinder_installed() or _dnsx_installed()):
        return jsonify({'error': 'subfinder/dnsx not installed — see Quick Setup Guide'}), 503

    errors = []
    subs, sub_err = _run_subfinder(domain)
    if sub_err and sub_err != 'subfinder not installed':
        errors.append(f'subfinder: {sub_err}')

    found_count = len(subs)
    names = sorted(set([domain] + subs))
    truncated = len(names) > MAX_DISCOVER_HOSTS
    if truncated:
        names = names[:MAX_DISCOVER_HOSTS]
        errors.append(f'capped to {MAX_DISCOVER_HOSTS} of {found_count} subdomains')

    resolved, dns_err = _run_dnsx(names)
    if dns_err and dns_err != 'dnsx not installed':
        errors.append(f'dnsx: {dns_err}')

    # Without dnsx we can't resolve; return the names so they can still be scanned.
    hosts = [{'host': h, 'ips': resolved.get(h, [])} for h in names]
    ips   = sorted({ip for v in resolved.values() for ip in v})
    return jsonify({
        'domain':           domain,
        'subdomains':       [n for n in names if n != domain],
        'subdomain_count':  found_count,
        'truncated':        truncated,
        'hosts':            hosts,
        'ips':              ips,
        'tools': {'subfinder': _subfinder_installed(), 'dnsx': _dnsx_installed()},
        'errors':           errors,
    })


@app.route('/api/scan', methods=['POST'])
def api_start_scan():
    if not _nmap_installed():
        return jsonify({'error': 'nmap not installed — see https://nmap.org/download.html'}), 503

    data      = request.get_json(force=True)
    raw       = data.get('targets', '').strip()
    scan_type = data.get('scan_type', 'service')
    ports     = data.get('ports', DEFAULT_PORTS).strip() or DEFAULT_PORTS
    custom     = data.get('custom_args', '-sV -T4').strip()
    force_pn   = data.get('force_pn', True)
    label      = data.get('label', '').strip()
    run_nuclei = bool(data.get('run_nuclei', True))
    run_tls    = bool(data.get('run_tls', True))
    udp        = bool(data.get('udp', False))
    # Nuclei template selector — validate all values (allowlist) before storing.
    import re as _re
    _VALID_SEV      = {'info', 'low', 'medium', 'high', 'critical'}
    raw_sev         = (data.get('nuclei_severity') or '').strip()
    sev_parts       = [s.strip().lower() for s in raw_sev.split(',') if s.strip()]
    nuclei_severity = ','.join(s for s in sev_parts if s in _VALID_SEV) or None
    raw_tags        = (data.get('nuclei_tags') or '').strip()
    tag_parts       = [t.strip().lower() for t in raw_tags.split(',') if t.strip()]
    nuclei_tags     = ','.join(t for t in tag_parts
                               if _re.fullmatch(r'[a-z0-9\-]+', t)) or None
    if not raw:
        return jsonify({'error': 'No targets provided'}), 400

    targets = [_normalize_target(t) for t in raw.replace(',', '\n').splitlines() if t.strip()]
    if not targets:
        return jsonify({'error': 'No valid targets after parsing'}), 400

    args = SCAN_PRESETS.get(scan_type) or custom
    if scan_type in PRESET_PORTS:
        ports = PRESET_PORTS[scan_type]

    # UDP adds a UDP scan plus a TCP SYN scan (both need root/Administrator).
    if udp:
        args += ' -sS -sU'

    args = _build_args(args, force_pn)

    job_id = str(uuid.uuid4())
    JOBS[job_id] = {
        'id':              job_id,
        'targets':         targets,
        'ports':           ports,
        'scan_type':       scan_type,
        'arguments':       args,
        'label':           label,
        'run_nuclei':      run_nuclei,
        'run_tls':         run_tls,
        'nuclei_severity': nuclei_severity,
        'nuclei_tags':     nuclei_tags,
        'status':          'queued',
        'progress':        {'current': 0, 'total': len(targets), 'host': '', 'pct': 0, 'stage': ''},
        'results':         [],
        'created_at':      _now(),
        'started_at':      None,
        'completed_at':    None,
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


@app.route('/api/scan/<job_id>/stream')
def api_scan_stream(job_id):
    """Server-Sent Events endpoint — streams live scan progress to the UI.

    Emits one JSON ``data:`` event per meaningful state change (progress
    counter, pipeline stage, or job status). Automatically closes when the
    job reaches a terminal state or after one hour.
    """
    def generate():
        deadline = time.time() + 3600   # hard cap: 1-hour stream
        last_key = None
        while time.time() < deadline:
            job = JOBS.get(job_id)
            if not job:
                # Job may have been pruned from memory but still exist in DB.
                db_job = _job_from_db(job_id)
                if db_job:
                    yield f'data: {json.dumps(db_job)}\n\n'
                return
            prog     = job.get('progress', {})
            curr_key = (prog.get('current'), prog.get('stage'), job.get('status'))
            if curr_key != last_key:
                last_key = curr_key
                yield f'data: {json.dumps(job)}\n\n'
            if job.get('status') in ('complete', 'cancelled', 'error'):
                return
            time.sleep(0.4)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':     'no-cache',
            'X-Accel-Buffering': 'no',   # disable nginx buffering if proxied
            'Connection':        'keep-alive',
        },
    )


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


# ── Triage / suppression CRUD ────────────────────────────────────────────────
_SUPPRESS_KINDS  = {'port', 'finding'}
_SUPPRESS_STATES = {'false_positive', 'accepted_risk', 'remediated'}

@app.route('/api/suppressions', methods=['GET'])
def api_list_suppressions():
    """All suppressions, optionally filtered by ?host=. The UI loads these to
    dim/triage matching ports and findings across every scan of a host."""
    host = request.args.get('host')
    try:
        with get_db() as conn:
            if host:
                rows = conn.execute(
                    'SELECT * FROM suppressions WHERE host=? ORDER BY created_at DESC', (host,)
                ).fetchall()
            else:
                rows = conn.execute(
                    'SELECT * FROM suppressions ORDER BY created_at DESC'
                ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/suppressions', methods=['POST'])
def api_create_suppression():
    """Create or update a suppression (upsert on host+kind+key)."""
    data  = request.get_json(force=True)
    host  = (data.get('host') or '').strip()
    kind  = (data.get('kind') or '').strip()
    key   = (data.get('key')  or '').strip()
    state = (data.get('state') or 'accepted_risk').strip()
    note  = (data.get('note') or '').strip()

    if not host or not key:
        return jsonify({'error': 'host and key are required'}), 400
    if kind not in _SUPPRESS_KINDS:
        return jsonify({'error': f'kind must be one of {sorted(_SUPPRESS_KINDS)}'}), 400
    if state not in _SUPPRESS_STATES:
        return jsonify({'error': f'state must be one of {sorted(_SUPPRESS_STATES)}'}), 400

    try:
        with get_db() as conn:
            conn.execute('''
                INSERT INTO suppressions (host, kind, key, state, note, created_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(host, kind, key)
                DO UPDATE SET state=excluded.state, note=excluded.note,
                              created_at=excluded.created_at
            ''', (host, kind, key, state, note, _now()))
            row = conn.execute(
                'SELECT * FROM suppressions WHERE host=? AND kind=? AND key=?',
                (host, kind, key)
            ).fetchone()
        return jsonify(dict(row))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/suppressions/delete', methods=['POST'])
def api_delete_suppression():
    """Remove a suppression (un-triage) by host+kind+key, or by id."""
    data = request.get_json(force=True)
    try:
        with get_db() as conn:
            if data.get('id'):
                conn.execute('DELETE FROM suppressions WHERE id=?', (data['id'],))
            else:
                conn.execute(
                    'DELETE FROM suppressions WHERE host=? AND kind=? AND key=?',
                    ((data.get('host') or '').strip(),
                     (data.get('kind') or '').strip(),
                     (data.get('key')  or '').strip())
                )
        return jsonify({'status': 'deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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

    # SSRF allowlist: only permit genuine Defender for Cloud Apps portal hostnames.
    # This prevents the proxy from being used to reach internal services.
    _MCAS_ALLOWED_SUFFIXES = (
        '.portal.cloudappsecurity.com',
        '.cloudapps.microsoft.com',
    )
    hostname = portal_url.split('/')[0].lower()
    if not any(hostname.endswith(s) for s in _MCAS_ALLOWED_SUFFIXES):
        return jsonify({
            'error': (
                'Invalid portal URL. Must be a Defender for Cloud Apps hostname '
                '(e.g. contoso.us2.portal.cloudappsecurity.com)'
            )
        }), 400

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

    # Layer exploit-likelihood signals on top of the (cached) CVSS details.
    # These have shorter TTLs than CVE details, so they're merged fresh each call.
    epss_map = _fetch_epss(valid)
    kev_set  = _kev_cve_set()
    for cid, det in results.items():
        e = epss_map.get(cid)
        det['epss']            = e['epss']       if e else None
        det['epss_percentile'] = e['percentile'] if e else None
        det['kev']             = cid in kev_set

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
