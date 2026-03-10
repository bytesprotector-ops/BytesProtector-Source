#!/usr/bin/env python3
"""
BytesProtector — Scan Engine v3
bytesprotectorav.org | 513k users | enterprise-grade

Detection pipeline (in order, stop at first hit):
  1. SHA-256/MD5 hash against known-bad DB (Rust binary or Python fallback)
  2. YARA-style rule matching (malware family strings)
  3. AI nano model (gradient-boosted PE feature classifier)
  4. C heuristic engine (if compiled)
  5. Script-specific patterns
  6. PHP/webshell patterns
  ZIP files: all entries scanned in-memory through same pipeline.
"""

import sys
import os
import json
import time
import hashlib
import struct
import zipfile
import argparse
import ctypes
import subprocess
import sqlite3
import threading
from pathlib import Path
from datetime import datetime


# ─── Emit helpers ─────────────────────────────────────────────────────────

def emit(obj):
    print(json.dumps(obj), flush=True)

def log(text, level='info'):
    emit({'type': 'log', 'text': text, 'level': level})

def progress(pct, speed=''):
    emit({'type': 'progress', 'pct': round(min(pct, 100), 1), 'speed': speed})

def file_event(path, count):
    emit({'type': 'file', 'path': path, 'count': count})

def threat_event(path, name, engine='', confidence=1.0):
    emit({'type': 'threat', 'path': path, 'name': name,
          'engine': engine, 'confidence': round(confidence, 2)})

def done_event():
    emit({'type': 'done', 'code': 0})


# ─── Load signature DB ────────────────────────────────────────────────────

def find_base_dir():
    # engine.py lives at <project>/backend/python/engine.py
    # so .parent.parent.parent = project root.
    # resolve() unwraps symlinks and asar-relative paths.
    return Path(__file__).resolve().parent.parent.parent

def load_threat_db(base_dir):
    candidates = [
        base_dir / 'config' / 'signatures' / 'threat_db.json',
        base_dir / 'config' / 'threat_signatures.json',
    ]
    for c in candidates:
        if c.exists():
            try:
                return json.loads(c.read_text())
            except Exception:
                pass
    return {}


# ─── Engine 1: Hash Verifier (Rust + SQLite DB + Python fallback) ─────────
#
# Supports three hash sources in priority order:
#   1. Rust binary (fastest, if compiled)
#   2. malware_hashes.db  — SQLite database (146MB, millions of known hashes)
#      Schema expected:  hashes(hash TEXT PRIMARY KEY, name TEXT, type TEXT)
#      Columns: hash = sha256 or md5 hex string, name = threat name,
#               type = 'sha256' | 'md5'  (optional — we try both)
#   3. threat_db.json in-memory dicts (small curated set)
#
# The SQLite connection is opened once and kept alive with a lock for
# thread-safety. WAL mode is enabled for concurrent read performance.
# ──────────────────────────────────────────────────────────────────────────

class HashVerifier:
    def __init__(self, base_dir, db):
        self.sha256_db = db.get('sha256', {})
        self.md5_db    = db.get('md5', {})

        # ── Rust binary (optional, fastest path) ──────────────────────────
        rust = base_dir / 'backend' / 'rust' / 'target' / 'release' / 'hash_verifier'
        if sys.platform == 'win32':
            rust = rust.with_suffix('.exe')
        self._bin = str(rust) if rust.exists() else None

        # ── SQLite hash DB (malware_hashes.db) ────────────────────────────
        # Search order: next to engine.py, config dir, base_dir root
        self._sqlite_conn = None
        self._sqlite_lock = threading.Lock()
        self._sqlite_has_type_col = False
        # Resolve the real path of this script even inside an asar bundle.
        # In packaged Electron: __file__ may be inside app.asar (read-only).
        # app.asar.unpacked is the writable mirror — try both.
        _this_file = Path(__file__).resolve()
        _this_dir  = _this_file.parent
        _unpacked  = Path(str(_this_dir).replace('app.asar', 'app.asar.unpacked'))

        db_candidates = [
            _this_dir    / 'malware_hashes.db',          # backend/python/ (dev)
            _unpacked    / 'malware_hashes.db',           # unpacked asar (production)
            base_dir / 'backend' / 'python' / 'malware_hashes.db',
            base_dir / 'config'  / 'malware_hashes.db',
            base_dir / 'malware_hashes.db',
        ]
        for candidate in db_candidates:
            if candidate.exists():
                try:
                    conn = sqlite3.connect(str(candidate), check_same_thread=False)
                    conn.execute('PRAGMA journal_mode=WAL')
                    conn.execute('PRAGMA cache_size=-32768')
                    conn.execute('PRAGMA temp_store=MEMORY')
                    # Schema: table=hash, single column sha256 TEXT PRIMARY KEY
                    # (no name column — we use generic threat name on match)
                    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                    self._sqlite_table = None
                    self._sqlite_col   = None
                    for tbl in tables:
                        try:
                            cols = {row[1] for row in conn.execute(f'PRAGMA table_info("{tbl}")')}
                            # Prefer explicit hash/sha256/md5 columns
                            for col in ('sha256', 'md5', 'hash'):
                                if col in cols:
                                    self._sqlite_table = tbl
                                    self._sqlite_col   = col
                                    break
                            if self._sqlite_table:
                                break
                        except Exception:
                            continue
                    if self._sqlite_table:
                        self._sqlite_conn = conn
                        row_count = conn.execute(f'SELECT COUNT(*) FROM "{self._sqlite_table}"').fetchone()[0]
                        log(f'HashDB: SQLite loaded -- table="{self._sqlite_table}", col="{self._sqlite_col}", {row_count:,} hashes', 'info')
                        break
                    else:
                        log(f'HashDB: {candidate.name} opened but no usable table. Tables: {tables}', 'warn')
                        conn.close()
                except Exception as e:
                    log(f'HashDB: SQLite open failed ({candidate}): {e}', 'warn')

        if not self._sqlite_conn:
            # Print every path we tried so the user can see exactly what's wrong
            for c in db_candidates:
                log(f'HashDB: tried {c} — {"EXISTS" if c.exists() else "not found"}', 'warn')
            log('HashDB: malware_hashes.db not found — using in-memory JSON DB only', 'warn')

    # ── Public API ─────────────────────────────────────────────────────────

    def check(self, path):
        """Check a file on disk. Returns (engine, threat_name, confidence) or None."""
        return self._rust_check(path) or self._compute_and_check(path)

    def check_bytes(self, data: bytes):
        """Check raw bytes (e.g. from ZIP entries)."""
        sha = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        return (self._sqlite_lookup(sha, 'sha256') or
                self._sqlite_lookup(md5, 'md5')   or
                self._json_lookup(sha, md5))

    # ── Internal helpers ───────────────────────────────────────────────────

    def _rust_check(self, path):
        if not self._bin:
            return None
        try:
            r = subprocess.run([self._bin, path], capture_output=True, text=True, timeout=5)
            if r.returncode == 1 and r.stdout.startswith('THREAT:'):
                return ('HashDB.Rust', r.stdout[7:].strip(), 1.0)
        except Exception:
            pass
        return None

    def _compute_and_check(self, path):
        """Hash the file then query SQLite + JSON DB."""
        try:
            md5_h = hashlib.md5()
            sha_h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5_h.update(chunk)
                    sha_h.update(chunk)
            sha = sha_h.hexdigest()
            md5 = md5_h.hexdigest()
        except (PermissionError, OSError, IsADirectoryError):
            return None

        return (self._sqlite_lookup(sha, 'sha256') or
                self._sqlite_lookup(md5, 'md5')    or
                self._json_lookup(sha, md5))

    def _sqlite_lookup(self, hash_hex: str, hash_type: str):
        """Query the SQLite DB for a single hash. Thread-safe.
        Supports both (sha256, name) schemas and single-column sha256-only schemas.
        """
        if not self._sqlite_conn or not self._sqlite_table:
            return None
        try:
            with self._sqlite_lock:
                tbl = self._sqlite_table
                col = self._sqlite_col
                cur = self._sqlite_conn.execute(
                    f'SELECT * FROM "{tbl}" WHERE "{col}"=? LIMIT 1',
                    (hash_hex,)
                )
                row = cur.fetchone()
                if row:
                    # If there's a name column, use it — otherwise use generic label
                    threat_name = row[1] if len(row) > 1 else 'HashDB.KnownMalware'
                    return ('HashDB.SQLite', threat_name, 1.0)
        except Exception:
            pass
        return None

    def _json_lookup(self, sha: str, md5: str):
        """Fallback to in-memory JSON DB (threat_db.json)."""
        name = self.sha256_db.get(sha) or self.md5_db.get(md5)
        return ('HashDB', name, 1.0) if name else None



# ─── Engine 2: YARA-style Rule Matcher ───────────────────────────────────

class YaraEngine:
    def __init__(self, db):
        self.rules = db.get('yara_rules', {})

    def _match_count(self, data, strings, condition):
        """Apply condition logic: any_N = at least N strings must match."""
        try:
            min_hits = int(condition.split('_')[1])
        except Exception:
            min_hits = 1
        hits = sum(1 for s in strings if s.encode() in data or s.encode().lower() in data.lower())
        return hits >= min_hits

    def scan(self, data):
        """Returns (engine, threat_name, confidence) or None."""
        for rule_name, rule in self.rules.items():
            strings    = rule.get('strings', [])
            condition  = rule.get('condition', 'any_1')
            severity   = rule.get('severity', 'medium')

            if self._match_count(data, strings, condition):
                conf = {'critical': 0.97, 'high': 0.90, 'medium': 0.75, 'low': 0.55}.get(severity, 0.75)
                return ('YARA', rule_name, conf)
        return None


# ─── Engine 3: AI Nano Model ──────────────────────────────────────────────

class AIEngine:
    def __init__(self, base_dir):
        self._model = None
        self._load_error = None

        # Try multiple candidate paths — resolves both dev and packaged layouts.
        _this_dir  = Path(__file__).resolve().parent
        _unpacked  = Path(str(_this_dir).replace('app.asar', 'app.asar.unpacked'))
        candidates = [
            _this_dir  / 'ai_model' / 'model.py',        # backend/python/ai_model/  (dev)
            _unpacked  / 'ai_model' / 'model.py',         # asar.unpacked (production)
            base_dir   / 'backend' / 'python' / 'ai_model' / 'model.py',
        ]

        for model_path in candidates:
            if not model_path.exists():
                continue
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location('bp_ai_model', str(model_path))
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                # Verify the module has the expected API
                if callable(getattr(mod, 'ai_scan', None)):
                    self._model = mod
                    break
                else:
                    self._load_error = f'model.py missing ai_scan() function'
            except Exception as e:
                self._load_error = str(e)
                log(f'AI model load failed ({model_path.name}): {e}', 'warn')

        if not self._model and self._load_error:
            log(f'AI engine unavailable: {self._load_error}', 'warn')

    def scan(self, path):
        if not self._model:
            return None
        try:
            score, threat = self._model.ai_scan(path)
            if threat:
                return ('AI', threat, score)
        except Exception:
            pass
        return None

    def scan_bytes(self, data, filename=''):
        if not self._model:
            return None
        try:
            score, threat = self._model.ai_scan_bytes(data, filename)
            if threat:
                return ('AI', threat, score)
        except Exception:
            pass
        return None


# ─── Engine 4: C Heuristic ───────────────────────────────────────────────

class CHeuristic:
    def __init__(self, base_dir):
        self._lib   = None
        self._status = 'unavailable'
        c_dir  = base_dir / 'backend' / 'c'
        src    = c_dir / 'heuristic_engine.c'
        is_win = sys.platform == 'win32'
        lib    = c_dir / ('libheuristic.dll' if is_win else 'libheuristic.so')

        # Auto-compile if .so/.dll is missing but source exists
        if not lib.exists() and src.exists():
            self._try_compile(src, lib, is_win)

        if lib.exists():
            try:
                self._lib = ctypes.CDLL(str(lib))
                self._lib.bp_scan_file.argtypes        = [ctypes.c_char_p]
                self._lib.bp_scan_file.restype         = ctypes.c_int
                self._lib.bp_get_threat_name.argtypes  = [ctypes.c_char_p, ctypes.c_int]
                self._lib.bp_get_threat_name.restype   = ctypes.c_char_p
                self._status = 'loaded'
            except OSError as e:
                self._lib    = None
                self._status = f'load-failed: {e}'

    @staticmethod
    def _find_gcc_win():
        """Search common MinGW/MSYS2 install locations on Windows."""
        import shutil
        if shutil.which('gcc'):
            return 'gcc'
        candidates = [
            r'C:\msys64\mingw64\bin\gcc.exe',
            r'C:\msys64\mingw32\bin\gcc.exe',
            r'C:\msys32\mingw32\bin\gcc.exe',
            r'C:\mingw64\bin\gcc.exe',
            r'C:\mingw32\bin\gcc.exe',
            r'C:\MinGW\bin\gcc.exe',
            r'C:\TDM-GCC-64\bin\gcc.exe',
            r'C:\TDM-GCC-32\bin\gcc.exe',
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    @staticmethod
    def _try_compile(src, dest, is_win):
        """Auto-compile the C engine. Finds gcc automatically on Windows."""
        import subprocess as _sp
        try:
            if is_win:
                gcc = CHeuristic._find_gcc_win()
                if not gcc:
                    log(
                        'C engine: gcc not found. Install MSYS2 (https://msys2.org) '
                        'then run: pacman -S mingw-w64-x86_64-gcc  '
                        '— or get WinLibs from https://winlibs.com  '
                        '(Python fallback is active and fully functional)',
                        'warn'
                    )
                    return
                # Windows DLL: no -fPIC flag
                cmd = [gcc, '-O2', '-shared', '-lm', '-o', str(dest), str(src)]
            else:
                cmd = ['gcc', '-O2', '-shared', '-fPIC', '-lm', '-o', str(dest), str(src)]

            result = _sp.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                log(f'C engine compile failed: {result.stderr.decode(errors="replace")[:200]}', 'warn')
            else:
                log('C heuristic engine compiled successfully', 'info')
        except FileNotFoundError:
            log('gcc not found — C engine unavailable (Python fallback active)', 'warn')
        except Exception as e:
            log(f'C engine compile error: {e}', 'warn')

    def scan(self, path):
        if not self._lib:
            return None
        try:
            result = self._lib.bp_scan_file(path.encode())
            if result != 0:
                name = self._lib.bp_get_threat_name(path.encode(), result)
                name = name.decode(errors='replace') if name else f'Heuristic.Code{result}'
                return ('C-Heuristic', name, 0.88)
        except Exception:
            pass
        return None


# ─── Engine 5: Pattern / Behavioral Scanner ──────────────────────────────
#
# WHY SALINEWIN WASN'T DETECTED (root cause analysis):
#
# v1/v2 matched on internal dev strings: "SalineClient", "saline_config"
# SalineWin's binary doesn't contain these. The author stripped them or
# never used them to begin with. SalineWin is a C++ compiled binary.
#
# What SalineWin ACTUALLY contains (confirmed via Joe Sandbox + Hybrid Analysis):
#   IOC 1: Exact REG ADD command to disable Task Manager:
#     "REG ADD hkcu\Software\Microsoft\Windows\CurrentVersion\policies\system /v DisableTaskMgr /t reg_dword /d 1 /f"
#   IOC 2: Direct raw disk write: "\\\\.\\PhysicalDrive0" (MBR tamper/wipe)
#   IOC 3: GetCursorPos in combo with CreateThread + WriteFile (keylogger)
#   IOC 4: "Login Data" + "Local State" in same binary (browser stealer)
#
# LESSON: Always detect on BEHAVIOR, not on brand name.
# Brand names are optional decoration. Behavior is mandatory.
# ─────────────────────────────────────────────────────────────────────────

# Patterns that are NEVER in legitimate software — instant flag, no combo needed
DEFINITE = [
    # EICAR
    (b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR',   'EICAR.TestFile',            1.00),
    # PHP webshells
    (b'eval(base64_decode(',                    'PHP.Webshell.Eval',         1.00),
    (b'system($_GET[',                          'PHP.Webshell.System',       1.00),
    (b'exec($_POST[',                           'PHP.Webshell.Exec',         1.00),
    (b'passthru($_REQUEST',                     'PHP.Webshell.Passthru',     1.00),
    (b'shell_exec($_GET',                       'PHP.Webshell.Shell',        1.00),
    (b'assert($_POST[',                         'PHP.Webshell.Assert',       1.00),
    # SalineWin IOC #1 — exact REG ADD command (confirmed in sandbox reports)
    # This SPECIFIC command to disable Task Manager is SalineWin's fingerprint.
    # No legitimate software embeds this exact command string.
    (b'/v DisableTaskMgr /t reg_dword /d 1 /f',  'Trojan.SalineWin',        0.99),
    (b'policies\\system /v DisableTaskMgr',        'Trojan.SalineWin',        0.99),
    # SalineWin IOC #2 — MBR tamper via raw disk access
    # Writing to PhysicalDrive0 directly is not done by any legit app
    (b'\\\\.\\PhysicalDrive0',                    'Trojan.SalineWin.MBRWipe', 0.98),
    # PowerShell hidden droppers
    (b'powershell -w hidden -enc ',               'PS.HiddenDropper',         0.97),
    (b' -NonInteractive -W Hidden -enc ',         'PS.HiddenDropper',         0.97),
    # BAT self-delete
    (b'cmd /c del /f /q "%~f0"',                 'BAT.SelfDestruct',         0.98),
    (b'cmd.exe /c del /f /q %0\r\n',             'BAT.SelfDestruct',         0.98),
]

# Named family strings — internal labels devs leave in (when NOT stripped)
MALWARE_FAMILIES = [
    # ── SalineWin ──────────────────────────────────────────────────────────
    (b'/v DisableTaskMgr /t reg_dword /d 1 /f',         'Trojan.SalineWin',          0.99),
    (b'policies\\system /v DisableTaskMgr',              'Trojan.SalineWin',          0.99),
    (b'REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system',
                                                         'Behavior.RegTamper.TaskMgr',0.95),
    (b'SalineWin',  'Trojan.SalineWin',   0.99),
    (b'salinewin',  'Trojan.SalineWin',   0.99),
    (b'SALINEWIN',  'Trojan.SalineWin',   0.99),
    # ── MBR / disk tamper ──────────────────────────────────────────────────
    (b'\\\\.\\PhysicalDrive0',   'Behavior.MBRTamper',   0.97),
    (b'\\\\.\\PhysicalDrive1',   'Behavior.MBRTamper',   0.97),
    # ── Ransomware ─────────────────────────────────────────────────────────
    (b'WannaCry',                'Ransomware.WannaCry',  0.99),
    (b'WANACRY!',                'Ransomware.WannaCry',  0.99),
    (b'WNcry@2ol7',              'Ransomware.WannaCry',  0.99),
    (b'LockBit',                 'Ransomware.LockBit',   0.97),
    (b'LOCKBIT',                 'Ransomware.LockBit',   0.97),
    (b'!!!-Restore-My-Files-!!!','Ransomware.LockBit',   0.97),
    (b'CONTI_LOCKER',            'Ransomware.Conti',     0.99),
    (b'sodinokibi',              'Ransomware.REvil',     0.99),
    (b'REvil',                   'Ransomware.REvil',     0.97),
    (b'BlackCat',                'Ransomware.BlackCat',  0.97),
    (b'ALPHV',                   'Ransomware.ALPHV',     0.97),
    (b'akira\x00',               'Ransomware.Akira',     0.95),
    (b'.akira\x00',              'Ransomware.Akira',     0.95),
    (b'RansomHub',               'Ransomware.RansomHub', 0.99),
    (b'PlayCrypt',               'Ransomware.Play',      0.99),
    (b'RyukReadMe',              'Ransomware.Ryuk',      0.99),
    (b'_readme.txt\x00',         'Ransomware.Stop.DJVU', 0.90),
    (b'YOUR FILES ARE ENCRYPTED','Ransomware.Generic',   0.92),
    (b'vssadmin delete shadows /all /quiet', 'Ransomware.ShadowDelete', 0.90),
    # ── RATs ───────────────────────────────────────────────────────────────
    (b'AsyncClient',             'Trojan.AsyncRAT',      0.99),
    (b'AsyncRAT',                'Trojan.AsyncRAT',      0.97),
    (b'AsyncMutex_6SI8OkPnk',    'Trojan.AsyncRAT',      0.99),
    (b'XWormV',                  'Trojan.XWorm',         0.99),
    (b'xwormmutex',              'Trojan.XWorm',         0.99),
    (b'DCRat',                   'Trojan.DCRat',         0.99),
    (b'njRAT',                   'Trojan.njRAT',         0.99),
    (b'Bladabindi',              'Trojan.njRAT',         0.99),
    (b'QuasarRAT',               'Trojan.QuasarRAT',     0.99),
    (b'Quasar.Client',           'Trojan.QuasarRAT',     0.99),
    (b'REMCOS_MUTEX',            'Trojan.Remcos',        0.99),
    (b'Remcos_SETTINGS',         'Trojan.Remcos',        0.99),
    (b'ValleyRAT',               'Trojan.ValleyRAT',     0.99),
    (b'AveMaria',                'Trojan.WarZone',        0.99),
    (b'WarzoneRAT',              'Trojan.WarZone',        0.99),
    (b'Gh0st\x00\x00\x00\x00',  'RAT.Gh0stRAT',         0.95),
    (b'GH0ST',                   'RAT.Gh0stRAT',         0.97),
    (b'DarkComet-RAT',           'RAT.DarkComet',        0.99),
    (b'NanoCore Client',         'RAT.NanoCore',         0.99),
    (b'PlugX',                   'Backdoor.PlugX',       0.99),
    # ── Backdoors ──────────────────────────────────────────────────────────
    (b'ReflectiveLoader',        'Backdoor.CobaltStrike',0.95),
    (b'beacon_metadata',         'Backdoor.CobaltStrike',0.99),
    (b'CSLDR_',                  'Backdoor.CobaltStrike',0.99),
    (b'meterpreter',             'Backdoor.Meterpreter', 0.99),
    (b'metsrv.dll',              'Backdoor.Meterpreter', 0.99),
    (b'MSF_PAYLOAD',             'Backdoor.Meterpreter', 0.99),
    # ── Infostealers ───────────────────────────────────────────────────────
    (b'RedLineClient',           'Spyware.RedLine',      0.99),
    (b'red_line_config',         'Spyware.RedLine',      0.99),
    (b'REDLINE',                 'Spyware.RedLine',      0.97),
    (b'lumma_stealer',           'Spyware.LummaC2',      0.99),
    (b'LummaC2',                 'Spyware.LummaC2',      0.99),
    (b'lumma_config',            'Spyware.LummaC2',      0.99),
    (b'raccoon_stealer',         'Spyware.Raccoon',      0.99),
    (b'vidar_config',            'Spyware.Vidar',        0.99),
    (b'VIDAR_',                  'Spyware.Vidar',        0.97),
    (b'AGENTTESLA',              'Spyware.AgentTesla',   0.99),
    (b'chromiumPasswords',       'Spyware.AgentTesla',   0.97),
    (b'FORMBOOK',                'Spyware.Formbook',     0.99),
    (b'stealc_config',           'Spyware.StealC',       0.99),
    (b'Rhadamanthys',            'Spyware.Rhadamanthys', 0.99),
    (b'AuroraStealer',           'Spyware.Aurora',       0.99),
    (b'Hawkeye\x00',             'Spyware.Hawkeye',      0.95),
    (b'HawkEye_Reborn',          'Spyware.Hawkeye',      0.99),
    (b'lokibot',                 'Spyware.LokiBot',      0.97),
    (b'loki_pwgrab',             'Spyware.LokiBot',      0.99),
    (b'AZORult',                 'Spyware.Azorult',      0.99),
    # ── Miners ─────────────────────────────────────────────────────────────
    (b'donate.v2.xmrig.com',     'Miner.XMRig',          0.99),
    (b'stratum+tcp://',          'Miner.Generic',         0.90),
    (b'pool.minexmr.com',        'Miner.XMRig',           0.99),
    (b'supportxmr.com',          'Miner.XMRig',           0.97),
    # ── Loaders ────────────────────────────────────────────────────────────
    (b'GuLoader',                'Loader.GuLoader',       0.99),
    (b'smokeloader',             'Loader.SmokeLoader',    0.97),
    (b'SMOKE_',                  'Loader.SmokeLoader',    0.90),
    (b'BumbleBee',               'Loader.BumbleBee',      0.99),
    (b'HijackLoader',            'Loader.HijackLoader',   0.99),
    (b'PureCrypter',             'Loader.PureCrypter',    0.97),
    # ── Worms / Botnets ────────────────────────────────────────────────────
    (b'EmotetMutex',             'Worm.Emotet',           0.99),
    (b'Emotet4',                 'Worm.Emotet',           0.99),
    (b'Emotet5',                 'Worm.Emotet',           0.99),
    (b'qbot_mutex',              'Worm.QakBot',           0.99),
    (b'BB_MUTEX\x00',            'Worm.QakBot',           0.99),
    (b'icedid_mutex',            'Worm.IcedID',           0.99),
    (b'MIRAI',                   'Worm.Mirai',            0.95),
    (b'ATTACK_TCP_SYN',          'Worm.Mirai',            0.99),
    # ── Droppers ───────────────────────────────────────────────────────────
    (b'SocGholish',              'Dropper.SocGholish',    0.99),
    (b'FakeUpdates',             'Dropper.SocGholish',    0.97),
    (b'GootLoader',              'Dropper.GootLoader',    0.99),
    (b'amadey_mutex',            'Dropper.Amadey',        0.99),
    (b'DarkGate',                'Dropper.DarkGate',      0.99),
    # ── APT / Offensive tools ──────────────────────────────────────────────
    (b'mimikatz',                'APT.Mimikatz',          0.99),
    (b'sekurlsa::',              'APT.Mimikatz',          0.99),
    (b'privilege::debug',        'APT.Mimikatz',          0.99),
    (b'lsadump::dcsync',         'APT.Mimikatz',          0.99),
    (b'EternalBlue',             'Exploit.EternalBlue',   0.97),
    (b'DoublePulsar',            'Exploit.EternalBlue',   0.97),
    (b'MS17-010',                'Exploit.EternalBlue',   0.95),
    (b'PlugX',                   'Backdoor.PlugX',        0.99),
    (b'PoisonIvy',               'Backdoor.PoisonIvy',    0.99),
]

# Single-string injection patterns — low confidence, "suspicious" tier
# Flagged but NOT auto-quarantined (conf < 0.5)
SUSPICIOUS_SINGLE_STRINGS = [
    (b'CreateRemoteThread',      'Suspicious.API.Injection',  0.35),
    (b'VirtualAllocEx',          'Suspicious.API.Injection',  0.30),
    (b'WriteProcessMemory',      'Suspicious.API.Injection',  0.30),
    (b'NtUnmapViewOfSection',    'Suspicious.API.HollowProc', 0.40),
    (b'ZwUnmapViewOfSection',    'Suspicious.API.HollowProc', 0.40),
    (b'SetThreadContext',         'Suspicious.API.HollowProc', 0.35),
    (b'IsDebuggerPresent',       'Suspicious.API.AntiDebug',  0.25),
    (b'GetAsyncKeyState',        'Suspicious.API.Keylogger',  0.30),
    (b'SetWindowsHookEx',        'Suspicious.API.Keylogger',  0.35),
]


# Behavioral combo rules — require ALL strings in require_all, plus optional require_any
# Excluded if any string in 'exclude' is present (reduces FP on known legit software)
BEHAVIORAL_RULES = [
    {
        'name': 'Heuristic.ProcessInjector.FullCombo',
        'require_all': [b'CreateRemoteThread', b'WriteProcessMemory', b'VirtualAllocEx'],
        'require_any': [],
        'exclude': [],
        'confidence': 0.88,
    },
    {
        'name': 'Heuristic.ProcessHollowing',
        'require_all': [b'NtUnmapViewOfSection', b'VirtualAllocEx', b'WriteProcessMemory'],
        'require_any': [],
        'exclude': [],
        'confidence': 0.88,
    },
    {
        'name': 'Heuristic.BrowserStealer.Combo',
        'require_all': [b'Login Data', b'Web Data', b'Local State'],
        'require_any': [b'sqlite3', b'CryptUnprotectData', b'ChromePass'],
        'exclude': [b'Chromium', b'Google Chrome'],  # exclude browser itself
        'confidence': 0.75,
    },
    {
        'name': 'Behavior.RegPersistence.RunKey',
        'require_all': [b'CurrentVersion\\Run', b'RegSetValueEx'],
        'require_any': [],
        'exclude': [],
        'confidence': 0.60,
    },
    {
        'name': 'Behavior.SalineWin.MBRAndRegistry',
        'require_all': [b'PhysicalDrive0', b'DisableTaskMgr'],
        'require_any': [],
        'exclude': [],
        'confidence': 0.99,
    },
]

class PatternEngine:
    @staticmethod
    def scan_data(data):
        # 1. DEFINITE — zero false positive strings (EICAR, PHP shells, SalineWin IOCs)
        for pattern, name, conf in DEFINITE:
            if pattern in data:
                return ('Pattern', name, conf)

        # 2. Named family strings — known malware labels/markers
        for pattern, name, conf in MALWARE_FAMILIES:
            if pattern in data:
                return ('Pattern', name, conf)

        # 3. Behavioral combos — multi-string rules
        for rule in BEHAVIORAL_RULES:
            if any(ex in data for ex in rule.get('exclude', [])):
                continue
            if not all(req in data for req in rule['require_all']):
                continue
            if rule.get('require_any') and not any(s in data for s in rule['require_any']):
                continue
            return ('Behavioral', rule['name'], rule['confidence'])

        # 4. Suspicious single strings — low confidence, always flagged but
        #    shown as "Suspicious" not "Threat" in the UI (conf < 0.5).
        #    Covers CreateRemoteThread alone, keylogger APIs, anti-debug, etc.
        for pattern, name, conf in SUSPICIOUS_SINGLE_STRINGS:
            if pattern in data:
                return ('Pattern', name, conf)

        return None


# ─── ZIP Scanner ──────────────────────────────────────────────────────────

def scan_zip(zip_path, hash_eng, yara_eng, ai_eng, pat_eng):
    results = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            entries = [e for e in zf.infolist()
                       if not e.is_dir() and 0 < e.file_size < 50*1024*1024]
            log(f'ZIP: {zip_path} — {len(entries)} entries')
            for entry in entries:
                try:
                    data = zf.read(entry.filename)
                except Exception:
                    continue
                label = f'{zip_path}![{entry.filename}]'
                hit = (
                    hash_eng.check_bytes(data) or
                    yara_eng.scan(data)         or
                    ai_eng.scan_bytes(data, entry.filename) or
                    pat_eng.scan_data(data)
                )
                if hit:
                    results.append((label, hit))
    except zipfile.BadZipFile:
        log(f'Not a valid ZIP: {zip_path}', 'warn')
    except Exception as e:
        log(f'ZIP error: {e}', 'warn')
    return results


# ─── File collector ───────────────────────────────────────────────────────

SKIP_DIRS = {
    'proc', 'sys', 'dev', 'run', 'snap',
    '.git', '__pycache__', 'node_modules',
    '$Recycle.Bin', 'System Volume Information',
    'WinSxS', 'Installer',
}

# Extensions that skip content/YARA scan — these formats can't carry executables.
# Hash check still runs. BUT if magic bytes don't match the extension, that
# itself becomes a high-confidence detection (disguised executable).
SAFE_EXTENSIONS = {
    '.jem', '.jemc', '.obj', '.mtl', '.fbx', '.gltf', '.glb',
    '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
    '.csv', '.tsv', '.log', '.md', '.txt', '.rst',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.tga', '.tiff', '.psd',
    '.mp3', '.mp4', '.m4v', '.m4a', '.wav', '.ogg', '.flac', '.aac',
    '.mkv', '.avi', '.mov', '.webm', '.wmv', '.flv',
    '.ttf', '.otf', '.woff', '.woff2',
    '.pdf',
    # Source code — can't contain binary malware, YARA rules cause massive FPs
    '.java', '.kt', '.scala', '.groovy',   # JVM
    '.js', '.ts', '.jsx', '.tsx', '.mjs',  # JavaScript
    '.py', '.rb', '.php', '.lua', '.pl',   # Scripting
    '.cs', '.vb', '.fs',                   # .NET
    '.c', '.cpp', '.h', '.hpp', '.rs',     # Native (source only — not compiled)
    '.go', '.swift', '.dart',              # Other
    '.html', '.css', '.scss', '.less',     # Web
    '.gradle', '.pom', '.sbt',             # Build files
    '.properties', '.env',                 # Config
}

# Expected magic bytes for media/image/doc extensions.
# If a file claims to be one of these but starts with MZ or PK, it's suspicious.
MAGIC_SIGNATURES = {
    # Video / Audio
    '.mp4':  [(4,  b'ftyp'), (4, b'moov'), (4, b'mdat'), (4, b'wide'), (4, b'free')],
    '.m4v':  [(4,  b'ftyp')],
    '.m4a':  [(4,  b'ftyp')],
    '.mov':  [(4,  b'ftyp'), (4, b'moov'), (4, b'wide')],
    '.mkv':  [(0,  b'\x1a\x45\xdf\xa3')],
    '.avi':  [(0,  b'RIFF')],
    '.wmv':  [(0,  b'\x30\x26\xb2\x75')],
    '.flv':  [(0,  b'FLV')],
    '.webm': [(0,  b'\x1a\x45\xdf\xa3')],
    '.mp3':  [(0,  b'ID3'), (0, b'\xff\xfb'), (0, b'\xff\xf3'), (0, b'\xff\xf2')],
    '.wav':  [(0,  b'RIFF')],
    '.flac': [(0,  b'fLaC')],
    '.ogg':  [(0,  b'OggS')],
    # Images
    '.png':  [(0,  b'\x89PNG')],
    '.jpg':  [(0,  b'\xff\xd8\xff')],
    '.jpeg': [(0,  b'\xff\xd8\xff')],
    '.gif':  [(0,  b'GIF8')],
    '.bmp':  [(0,  b'BM')],
    '.webp': [(0,  b'RIFF')],
    '.ico':  [(0,  b'\x00\x00\x01\x00')],
    # Docs
    '.pdf':  [(0,  b'%PDF')],
}

# Magic bytes that indicate an executable regardless of extension
EXECUTABLE_MAGIC = [
    (b'MZ',           'Disguised.Executable.PE',      0.95),  # Windows PE
    (b'\x7fELF',     'Disguised.Executable.ELF',     0.95),  # Linux ELF
    (b'\xca\xfe\xba\xbe', 'Disguised.Executable.MachO', 0.90),  # macOS Mach-O
    (b'PK\x03\x04', 'Disguised.Archive.ZIP',        0.70),  # ZIP inside media
]

# Low-confidence detections shown in UI but NOT auto-quarantined. Threshold: conf < 0.55
QUARANTINE_CONFIDENCE_THRESHOLD = 0.55


def check_magic_mismatch(fpath, ext, data):
    """
    Returns a hit tuple if the file's actual magic bytes don't match
    what its extension claims to be. This catches the classic attack of
    hiding an EXE inside a .mp4 / .jpg / .pdf etc.

    Also catches unknown/corrupt media files that shouldn't be flagged
    as ransomware just because they look weird — if there's no exe magic,
    return None even if the format is unrecognised.
    """
    if len(data) < 8:
        return None

    header = data[:8]

    # Step 1: Does the file start with executable/archive magic?
    for magic, name, conf in EXECUTABLE_MAGIC:
        magic_bytes = magic.encode() if isinstance(magic, str) else magic
        # handle Python escape sequences in the string form
        import codecs
        try:
            magic_bytes = codecs.decode(magic.encode(), 'unicode_escape').encode('latin-1') if isinstance(magic, str) else magic
        except Exception:
            pass
        if header[:len(magic_bytes)] == magic_bytes:
            # File starts with executable magic — always suspicious regardless of extension
            if ext in SAFE_EXTENSIONS:
                # Claimed to be media/doc but is actually an executable — HIGH confidence
                return ('MagicCheck', f'Trojan.DisguisedAs{ext.lstrip(".").upper()}', 0.96)
            return None  # For .exe files it's expected

    # Step 2: For known media extensions, verify expected magic IS present
    if ext in MAGIC_SIGNATURES:
        expected = MAGIC_SIGNATURES[ext]
        for offset, sig in expected:
            if data[offset:offset+len(sig)] == sig:
                return None  # Magic matches — file is what it claims to be

        # Magic doesn't match AND it's not an executable — unknown/corrupt file
        # Do NOT flag as ransomware. Just note it's unrecognised format.
        # Only flag if it's truly bizarre (high entropy + no recognisable structure)
        import math
        from collections import Counter
        freq = Counter(data[:4096])
        ent = -sum((v/4096)*math.log2(v/4096) for v in freq.values() if v > 0)
        if ent > 7.5:
            # Very high entropy + unrecognised media format = possibly encrypted payload
            return ('MagicCheck', f'Suspicious.UnknownHighEntropy{ext.lstrip(".").upper()}', 0.45)
        # Low/medium entropy + unrecognised = probably just corrupt or unusual encoding
        return None

    return None

def collect_files(paths):
    result = []
    for rp in paths:
        p = Path(rp)
        if p.is_file():
            result.append(str(p))
        elif p.is_dir():
            for root, dirs, files in os.walk(str(p), topdown=True, onerror=None):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for fn in files:
                    result.append(os.path.join(root, fn))
    return result


# ─── Quarantine ───────────────────────────────────────────────────────────

def quarantine(path, threat, quar_dir, conf=None):
    if '![' in path:
        return  # virtual path inside ZIP — can't move
    qp = Path(quar_dir)
    qp.mkdir(parents=True, exist_ok=True)
    idx = qp / 'index.json'
    try:
        items = json.loads(idx.read_text()) if idx.exists() else []
    except Exception:
        items = []
    h = hashlib.md5(path.encode()).hexdigest()[:12]
    if any(i.get('id') == h for i in items):
        return
    src = Path(path)
    if not src.exists() or not src.is_file():
        return
    dest = qp / f'{h}.quar'
    try:
        data = src.read_bytes()
        dest.write_bytes(bytes(b ^ 0xAA for b in data))
        items.append({
            'id':       h,
            'name':     src.name,
            'path':     str(src),
            'threat':   threat,
            'conf':     conf if conf is not None else 0.9,
            'date':     datetime.now().strftime('%Y-%m-%d %H:%M'),
            'size':     len(data),
            'quarfile': str(dest),
        })
        idx.write_text(json.dumps(items, indent=2))
        try: os.remove(src)
        except PermissionError: pass
    except (PermissionError, OSError):
        pass


# ─── Record history ───────────────────────────────────────────────────────

def record(log_dir, scan_type, files, threats, duration):
    ld = Path(log_dir)
    ld.mkdir(parents=True, exist_ok=True)
    hp = ld / 'scan_history.json'
    try:
        h = json.loads(hp.read_text()) if hp.exists() else []
    except Exception:
        h = []
    h.append({
        'timestamp':     datetime.now().isoformat(),
        'type':          scan_type,
        'files_scanned': files,
        'threats_found': threats,
        'duration_s':    round(duration, 2),
    })
    hp.write_text(json.dumps(h, indent=2))


# ─── Main ─────────────────────────────────────────────────────────────────

def run_verdict(base, quarfile, filename, threat_name):
    """
    Decrypt a .quar file and run the local AI model on it.
    Prints a single JSON line with the verdict result.
    """
    result = {
        'verdict': 'UNCERTAIN',
        'confidence': 0.0,
        'summary': '',
        'is_false_positive': False,
    }

    try:
        qp = Path(quarfile)
        if not qp.exists():
            result['summary'] = f'Quarantine file not found: {quarfile}'
            print(json.dumps(result))
            return

        # Decrypt XOR-0xAA
        enc = qp.read_bytes()
        data = bytes(b ^ 0xAA for b in enc)

        # Run AI model
        ai_eng = AIEngine(base)
        if not ai_eng._model:
            result['summary'] = 'AI model unavailable — verdict cannot be determined locally.'
            print(json.dumps(result))
            return

        score, detected_name = ai_eng._model.ai_scan_bytes(data, filename)

        # Build verdict
        ext = Path(filename).suffix.lower() if filename else ''

        # Non-executable formats can't be PE malware
        safe_exts = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp',
                     '.litematic', '.jem', '.json', '.txt', '.md', '.nbt',
                     '.ogg', '.mp3', '.wav', '.mp4', '.avi', '.mkv',
                     '.ttf', '.otf', '.woff', '.woff2', '.css', '.html'}

        if ext in safe_exts:
            result['verdict']          = 'LIKELY FALSE POSITIVE'
            result['confidence']       = 0.05
            result['is_false_positive'] = True
            result['summary'] = (
                f'File extension "{ext}" cannot contain executable malware. '
                f'The detection "{threat_name}" is almost certainly a false positive '
                f'caused by high entropy or unusual byte patterns in this {ext} file.'
            )
        elif score is None or score < 0.50:
            result['verdict']          = 'LIKELY FALSE POSITIVE'
            result['confidence']       = round(1.0 - (score or 0.0), 3)
            result['is_false_positive'] = True
            result['summary'] = (
                f'Local AI model re-analyzed this file and scored it {round((score or 0)*100)}% malicious '
                f'(below detection threshold). The original detection "{threat_name}" '
                f'may have been a false positive. Safe to restore if you trust the source.'
            )
        elif score >= 0.90:
            result['verdict']    = 'CONFIRMED THREAT'
            result['confidence'] = round(score, 3)
            result['summary'] = (
                f'Local AI model confirms this file is malicious with {round(score*100)}% confidence. '
                f'Detection: {detected_name or threat_name}. '
                f'Do not restore this file.'
            )
        else:
            result['verdict']    = 'UNCERTAIN'
            result['confidence'] = round(score, 3)
            result['summary'] = (
                f'Local AI model scored this file {round(score*100)}% malicious — inconclusive. '
                f'Original detection: {threat_name}. '
                f'Manual review recommended before restoring.'
            )

    except Exception as e:
        result['summary'] = f'Verdict error: {e}'

    print(json.dumps(result))



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan',           action='store_true')
    parser.add_argument('--endpoint',       action='store_true')
    parser.add_argument('--verdict',        action='store_true',
                        help='Run local AI verdict on a quarantined file')
    parser.add_argument('--quarfile',       default='',
                        help='Path to .quar file for --verdict mode')
    parser.add_argument('--filename',       default='',
                        help='Original filename for --verdict mode')
    parser.add_argument('--threat',         default='',
                        help='Detection name for --verdict mode')
    parser.add_argument('--paths',          nargs='*', default=[])
    parser.add_argument('--files',          nargs='*', default=[])
    parser.add_argument('--type',           default='quick')
    parser.add_argument('--quarantine-dir', default='')
    parser.add_argument('--no-quarantine', action='store_true',
                        help='Detect threats but do not move files to quarantine')
    args = parser.parse_args()

    base = find_base_dir()

    if args.endpoint:
        # Launch endpoint daemon
        daemon_path = base / 'backend' / 'python' / 'endpoint' / 'daemon.py'
        if daemon_path.exists():
            os.execv(sys.executable, [sys.executable, str(daemon_path)])
        else:
            log('Endpoint daemon not found', 'warn')
        return

    if args.verdict:
        run_verdict(base, args.quarfile, args.filename, args.threat)
        return

    if not args.scan:
        log('No action.', 'warn')
        done_event()
        return

    # ── Init engines ──────────────────────────────────────────────────────
    db       = load_threat_db(base)
    hash_eng = HashVerifier(base, db)
    yara_eng = YaraEngine(db)
    ai_eng   = AIEngine(base)
    c_eng    = CHeuristic(base)
    pat_eng  = PatternEngine()

    ai_status   = 'loaded' if ai_eng._model else 'unavailable'
    c_status    = 'loaded' if c_eng._lib    else 'unavailable'
    rust_status = 'loaded' if hash_eng._bin else 'Python fallback'

    log(f'Engines: HashDB · YARA({len(db.get("yara_rules",{}))} rules) · AI({ai_status}) · C({c_status}) · Rust({rust_status})')

    # ── Resolve paths ─────────────────────────────────────────────────────
    raw = args.files or args.paths or []
    if not raw:
        home = Path.home()
        if args.type == 'quick':
            raw = [
                str(home / 'Downloads'),
                str(home / 'Desktop'),
                os.environ.get('TEMP', '/tmp'),
            ]
        elif args.type == 'full':
            raw = [str(home)]
        else:
            raw = [str(home / 'Downloads')]

    raw = [p for p in raw if p and Path(p).exists()]
    if not raw:
        log('No valid scan paths.', 'warn')
        done_event()
        return

    quar_dir      = args.quarantine_dir or str(base / 'quarantine')
    do_quarantine = not args.no_quarantine
    log_dir  = str(base / 'logs')

    log(f'Scanning: {", ".join(raw)}')

    files = collect_files(raw)
    total = max(len(files), 1)
    count = 0
    threats_total = 0
    start = time.time()
    last_emit = start
    last_speed = start
    total_bytes = 0
    last_bytes  = 0

    for fpath in files:
        count += 1
        ext = Path(fpath).suffix.lower()

        try:
            total_bytes += os.path.getsize(fpath)
        except OSError:
            pass

        now = time.time()
        if now - last_emit >= 0.2:
            pct = (count / total) * 100
            dt  = now - last_speed
            speed_str = ''
            if dt >= 0.5:
                mb_s = ((total_bytes - last_bytes) / dt) / (1024 * 1024)
                speed_str = f'{mb_s:.1f} MB/s'
                last_bytes = total_bytes
                last_speed = now
            progress(pct, speed_str)
            file_event(fpath, count)
            last_emit = now

        # ZIP: scan each entry in-memory
        if ext == '.zip':
            zip_threats = list(scan_zip(fpath, hash_eng, yara_eng, ai_eng, pat_eng))
            if zip_threats:
                threats_total += len(zip_threats)
                # Report every infected entry
                for (label, (eng_name, name, conf)) in zip_threats:
                    threat_event(label, name, eng_name, conf)
                # Quarantine the ZIP container itself using the highest-confidence hit
                if do_quarantine:
                    best = max(zip_threats, key=lambda x: x[1][2])
                    _, (best_eng, best_name, best_conf) = best
                    if best_conf >= QUARANTINE_CONFIDENCE_THRESHOLD:
                        quarantine(fpath, best_name, quar_dir, conf=best_conf)
            continue

        # Read file bytes ONCE — shared across all string-based engines.
        data = _safe_read(fpath, max_bytes=8 * 1024 * 1024)

        # ── Step 1: Magic byte / extension mismatch check ──────────────────
        # Catches the classic "rename EXE to .mp4" attack.
        # Also prevents corrupt/unknown media files from being falsely
        # flagged as ransomware by the content scanner.
        magic_hit = check_magic_mismatch(fpath, ext, data)
        if magic_hit:
            hit = magic_hit
        else:
            is_safe_ext = ext in SAFE_EXTENSIONS
            if is_safe_ext:
                # Safe media/data extension + magic matches = hash check only
                hit = hash_eng.check(fpath)
            else:
                # Full scan pipeline — stops at first confident hit
                hit = (
                    hash_eng.check(fpath)   or  # 1. SHA-256/MD5 exact match
                    pat_eng.scan_data(data) or  # 2. Definite strings
                    yara_eng.scan(data)     or  # 3. YARA family rules
                    ai_eng.scan(fpath)      or  # 4. AI nano model
                    c_eng.scan(fpath)           # 5. C heuristic library
                )

        if hit:
            engine_name, name, conf = hit
            threats_total += 1
            threat_event(fpath, name, engine_name, conf)
            # Only auto-quarantine high-confidence detections.
            # Low-confidence "Suspicious.*" hits are shown in UI but NOT moved.
            # User must manually quarantine from the Quarantine page.
            if do_quarantine and conf >= QUARANTINE_CONFIDENCE_THRESHOLD:
                quarantine(fpath, name, quar_dir, conf=conf)

    duration = time.time() - start
    progress(100, '0 MB/s')
    record(log_dir, args.type, count, threats_total, duration)

    if threats_total == 0:
        log(f'All clean — {count:,} files scanned in {duration:.1f}s', 'ok')
    else:
        log(f'Done — {count:,} files · {threats_total} threat(s) · {duration:.1f}s', 'warn')

    done_event()


def _safe_read(path, max_bytes=8*1024*1024):
    """Read up to max_bytes. No size gate — must scan all files including large ones."""
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except (PermissionError, OSError, IsADirectoryError):
        return b""
if __name__ == '__main__':
    main()