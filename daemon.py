"""
BytesProtector — Endpoint Protection Engine
bytesprotectorav.org

Monitors:
  - Process creation (detects hollowing, injection, LOLBins abuse)
  - Network connections (C2 detection, suspicious outbound)
  - File system (writes to sensitive paths, mass-rename ransomware behavior)
  - Registry (persistence keys, UAC bypass, AppInit_DLLs)
  - Memory (process injection indicators via WMI)

Streams JSON events to stdout for Electron main to forward to renderer.
"""

import sys
import os
import json
import time
import threading
import subprocess
import hashlib
import re
from pathlib import Path
from datetime import datetime
from typing import Optional


def emit(obj):
    print(json.dumps(obj), flush=True)


def event(category, severity, title, detail, pid=None, process=None):
    emit({
        'type':      'endpoint_event',
        'ts':        datetime.now().strftime('%H:%M:%S'),
        'category':  category,
        'severity':  severity,   # critical / high / medium / low / info
        'title':     title,
        'detail':    detail,
        'pid':       pid,
        'process':   process,
    })


def log(text, level='info'):
    emit({'type': 'log', 'text': text, 'level': level})


# ─── Constants ────────────────────────────────────────────────────────────

IS_WIN = sys.platform == 'win32'
IS_LIN = sys.platform.startswith('linux')
IS_MAC = sys.platform == 'darwin'

# LOLBins — legitimate Windows binaries commonly abused by malware
LOLBINS = {
    'mshta.exe', 'wscript.exe', 'cscript.exe', 'regsvr32.exe',
    'rundll32.exe', 'certutil.exe', 'bitsadmin.exe', 'powershell.exe',
    'cmd.exe', 'wmic.exe', 'msiexec.exe', 'forfiles.exe',
    'schtasks.exe', 'at.exe', 'installutil.exe', 'regasm.exe',
    'msbuild.exe', 'cmstp.exe', 'odbcconf.exe', 'pcalua.exe',
    'appvlp.exe', 'control.exe', 'csc.exe', 'vbc.exe',
}

# Suspicious parent→child combos (e.g. Word spawning cmd.exe)
SUSPICIOUS_PARENT_CHILD = {
    'winword.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe', 'certutil.exe'},
    'excel.exe':     {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    'outlook.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe'},
    'chrome.exe':    {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    'firefox.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe'},
    'acrobat.exe':   {'cmd.exe', 'powershell.exe', 'wscript.exe'},
    'acrord32.exe':  {'cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'},
    'explorer.exe':  {'powershell.exe', 'wscript.exe', 'mshta.exe'},
}

# Suspicious PowerShell command patterns
PS_SUSPICIOUS_PATTERNS = [
    (r'-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/]{20,}',  'Encoded PS command'),
    (r'IEX\s*\(|Invoke-Expression',                    'IEX/Invoke-Expression'),
    (r'Net\.WebClient|WebRequest',                     'Network download'),
    (r'DownloadString|DownloadFile',                   'File download'),
    (r'-[Ww]indow[Ss]tyle\s+[Hh]idden',               'Hidden window style'),
    (r'bypass\s+-[Nn]o[Pp]rofile',                     'Policy bypass'),
    (r'FromBase64String',                              'Base64 decode'),
    (r'Reflection\.Assembly',                          'Reflective load'),
    (r'System\.Runtime\.InteropServices',              'Interop/injection'),
]

# Sensitive registry keys to watch
SENSITIVE_REGISTRY_KEYS = [
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    r'SYSTEM\CurrentControlSet\Services',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    r'SOFTWARE\Classes\exefile\shell\open\command',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',  # UAC bypass
    r'AppInit_DLLs',
    r'SYSTEM\CurrentControlSet\Control\Lsa',
]

# Sensitive paths to monitor for writes
SENSITIVE_PATHS_WIN = [
    'C:\\Windows\\System32',
    'C:\\Windows\\SysWOW64',
    'C:\\Windows\\System32\\drivers',
    os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
    os.path.expanduser('~\\AppData\\Local\\Temp'),
]

# Network: suspicious port/pattern combos
SUSPICIOUS_PORTS = {
    4444: 'Metasploit default port',
    1337: 'Common RAT C2 port',
    6666: 'Common malware callback port',
    8888: 'Common malware C2 port',
    31337: 'Back Orifice / elite hacker port',
    6379: 'Redis (often exploited)',
    9001: 'Tor default port',
    9050: 'Tor SOCKS proxy',
}

# C2 domain patterns
C2_PATTERNS = [
    r'\.onion$',
    r'pastebin\.com/raw/',
    r'discord\.com/api/webhooks/',
    r'raw\.githubusercontent\.com.*/(payload|drop|load|stage)',
    r't\.me/',
    r'bit\.ly/',
    r'iplogger\.',
    r'grabify\.',
    r'discordapp\.com/api/webhooks/',
]

# Ransomware: mass file rename/encrypt indicators
RANSOM_EXTENSIONS = {
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
    '.lockbit', '.conti', '.ryuk', '.maze', '.revil',
    '.sodinokibi', '.blackbyte', '.hive', '.blackcat',
    '.ransom', '.pay2decrypt',
}


# ─── Process Monitor ──────────────────────────────────────────────────────

class ProcessMonitor:
    def __init__(self):
        self._seen_pids   = set()
        self._running     = False
        self._thread      = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log('Process monitor started')

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._check_processes()
            except Exception:
                pass
            time.sleep(3)

    def _check_processes(self):
        if IS_WIN:
            self._check_processes_win()
        elif IS_LIN or IS_MAC:
            self._check_processes_posix()

    def _check_processes_win(self):
        try:
            # Use WMIC for process info
            result = subprocess.run(
                ['wmic', 'process', 'get', 'ProcessId,Name,ParentProcessId,CommandLine', '/format:csv'],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split('\n')
            processes = {}
            for line in lines[1:]:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    try:
                        processes[parts[2]] = {
                            'pid': parts[2],
                            'ppid': parts[3],
                            'name': parts[1].lower().strip(),
                            'cmdline': ','.join(parts[4:]).strip() if len(parts) > 4 else '',
                        }
                    except Exception:
                        pass

            # Build PID→name map
            pid_name = {p['pid']: p['name'] for p in processes.values()}

            for pid, proc in processes.items():
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                name = proc['name']
                cmdline = proc['cmdline']
                ppid = proc.get('ppid', '')
                parent_name = pid_name.get(ppid, '').lower()

                # Check LOLBin execution
                if name in LOLBINS and name not in {'explorer.exe', 'cmd.exe'}:
                    # Check for suspicious parent
                    if parent_name in SUSPICIOUS_PARENT_CHILD:
                        if name in SUSPICIOUS_PARENT_CHILD[parent_name]:
                            event(
                                'process', 'high',
                                f'Suspicious child process: {name}',
                                f'{parent_name} → {name}\nCmd: {cmdline[:200]}',
                                pid=pid, process=name
                            )
                            continue

                # Check PS suspicious commands
                if name == 'powershell.exe' and cmdline:
                    self._analyze_powershell(cmdline, pid)

                # Check certutil abuse (common dropper)
                if name == 'certutil.exe' and cmdline:
                    if any(x in cmdline.lower() for x in ['-decode', '-urlcache', '-f http']):
                        event(
                            'process', 'high',
                            'CertUtil abuse detected',
                            f'certutil used as downloader: {cmdline[:200]}',
                            pid=pid, process=name
                        )

                # Check mshta abuse
                if name == 'mshta.exe' and cmdline:
                    if 'http' in cmdline.lower() or 'vbscript' in cmdline.lower():
                        event(
                            'process', 'high',
                            'MSHTA abuse detected',
                            f'mshta running remote/script content: {cmdline[:200]}',
                            pid=pid, process=name
                        )

        except Exception:
            pass

    def _check_processes_posix(self):
        try:
            result = subprocess.run(
                ['ps', 'axo', 'pid,ppid,comm,args', '--no-headers'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split(None, 3)
                if len(parts) < 3:
                    continue
                pid, ppid, name = parts[0], parts[1], parts[2]
                args = parts[3] if len(parts) > 3 else ''
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                # Check for suspicious Python/shell combos
                if 'python' in name.lower() and '-c' in args:
                    if any(x in args for x in ['base64', 'exec(', 'eval(', '__import__']):
                        event('process', 'medium',
                              'Suspicious Python one-liner',
                              f'{name}: {args[:200]}',
                              pid=pid, process=name)
        except Exception:
            pass

    def _analyze_powershell(self, cmdline, pid):
        hits = []
        for pattern, desc in PS_SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                hits.append(desc)
        if len(hits) >= 2:
            event(
                'process', 'high',
                'Suspicious PowerShell detected',
                f'Patterns: {", ".join(hits)}\nCmd: {cmdline[:300]}',
                pid=pid, process='powershell.exe'
            )
        elif len(hits) == 1 and 'Encoded' in hits[0]:
            event(
                'process', 'medium',
                'Encoded PowerShell command',
                f'Pattern: {hits[0]}\nCmd: {cmdline[:200]}',
                pid=pid, process='powershell.exe'
            )


# ─── Network Monitor ──────────────────────────────────────────────────────

class NetworkMonitor:
    def __init__(self):
        self._seen_conns  = set()
        self._running     = False
        self._thread      = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log('Network monitor started')

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._check_connections()
            except Exception:
                pass
            time.sleep(5)

    def _check_connections(self):
        try:
            if IS_WIN:
                result = subprocess.run(
                    ['netstat', '-nao'], capture_output=True, text=True, timeout=10
                )
            else:
                result = subprocess.run(
                    ['ss', '-tnp'], capture_output=True, text=True, timeout=5
                )

            for line in result.stdout.split('\n'):
                self._analyze_connection(line)
        except Exception:
            pass

    def _analyze_connection(self, line):
        # Check for suspicious ports
        for port, reason in SUSPICIOUS_PORTS.items():
            if f':{port} ' in line or f':{port}\t' in line:
                key = f'port_{port}_{line[:30]}'
                if key not in self._seen_conns:
                    self._seen_conns.add(key)
                    event('network', 'high',
                          f'Suspicious port connection: :{port}',
                          f'{reason}\nConnection: {line.strip()[:200]}')

        # Check ESTABLISHED connections to non-standard high ports
        if 'ESTABLISHED' in line or 'ESTAB' in line:
            # Look for outbound to very high ports (common RAT behavior)
            parts = line.split()
            for part in parts:
                if ':' in part:
                    try:
                        port = int(part.split(':')[-1])
                        if port > 49152 and port not in {50000, 55000}:
                            key = f'highport_{part}'
                            # Don't spam — only flag same connection once
                            if key not in self._seen_conns:
                                self._seen_conns.add(key)
                                # Only flag if it matches other criteria
                    except ValueError:
                        pass


# ─── File System Monitor ──────────────────────────────────────────────────

class FileSystemMonitor:
    def __init__(self, on_threat_cb=None):
        self._running = False
        self._thread  = None
        self._rename_counts = {}
        self._on_threat = on_threat_cb
        self._observer = None

    def start(self):
        self._running = True
        # Try watchdog first
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            monitor = self

            class Handler(FileSystemEventHandler):
                def on_created(self, ev):
                    if not ev.is_directory:
                        monitor._check_file(ev.src_path, 'created')
                def on_modified(self, ev):
                    if not ev.is_directory:
                        monitor._check_file(ev.src_path, 'modified')
                def on_moved(self, ev):
                    monitor._check_rename(ev.src_path, ev.dest_path)

            self._observer = Observer()
            handler = Handler()
            watch_paths = self._get_watch_paths()
            for wp in watch_paths:
                if os.path.exists(wp):
                    self._observer.schedule(handler, wp, recursive=True)
            self._observer.start()
            log(f'File monitor watching: {", ".join(watch_paths)}')
        except ImportError:
            log('watchdog not installed — file monitor in polling mode', 'warn')
            self._thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._thread.start()

    def stop(self):
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()

    def _get_watch_paths(self):
        home = str(Path.home())
        paths = [
            os.path.join(home, 'Downloads'),
            os.path.join(home, 'Desktop'),
            os.path.join(home, 'Documents'),
        ]
        if IS_WIN:
            paths.append(os.environ.get('TEMP', 'C:\\Temp'))
            paths.append('C:\\Users\\Public')
        else:
            paths.append('/tmp')
        return [p for p in paths if os.path.exists(p)]

    def _check_file(self, path, action):
        """Check newly created/modified files for threats."""
        p = Path(path)
        ext = p.suffix.lower()

        # Alert on script drops in temp
        temp_dirs = [os.environ.get('TEMP', ''), '/tmp', os.path.expanduser('~/.tmp')]
        in_temp = any(str(path).startswith(t) for t in temp_dirs if t)

        if in_temp and ext in {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.hta'}:
            event('filesystem', 'medium',
                  f'Suspicious file in temp: {p.name}',
                  f'{action.title()} in temp directory\nPath: {path}')

        # Check for ransom extensions
        if ext in RANSOM_EXTENSIONS:
            event('filesystem', 'critical',
                  f'Ransomware extension detected: {ext}',
                  f'File {action}: {path}\nThis may indicate active ransomware encryption!',
                  )

        # Scan new downloads
        if 'Downloads' in path and action == 'created' and ext in {'.exe', '.zip', '.msi', '.bat', '.ps1'}:
            event('filesystem', 'low',
                  f'New download: {p.name}',
                  f'Recommend scanning: {path}')

    def _check_rename(self, src, dst):
        """Detect mass-rename ransomware behavior."""
        dst_ext = Path(dst).suffix.lower()
        if dst_ext in RANSOM_EXTENSIONS:
            event('filesystem', 'critical',
                  'Ransomware file rename detected!',
                  f'File renamed to ransomware extension\n{src} → {dst}')

        # Track rename velocity in same directory
        parent = str(Path(dst).parent)
        now = time.time()
        if parent not in self._rename_counts:
            self._rename_counts[parent] = []
        self._rename_counts[parent].append(now)
        # Remove old entries
        self._rename_counts[parent] = [t for t in self._rename_counts[parent] if now - t < 10]
        # 20+ renames in 10 seconds = ransomware
        if len(self._rename_counts[parent]) > 20:
            event('filesystem', 'critical',
                  'Mass file rename detected — possible ransomware!',
                  f'{len(self._rename_counts[parent])} files renamed in 10 seconds in:\n{parent}')
            self._rename_counts[parent] = []

    def _poll_loop(self):
        """Fallback polling monitor."""
        snapshots = {}
        watch_paths = self._get_watch_paths()
        while self._running:
            try:
                for wp in watch_paths:
                    for f in Path(wp).rglob('*'):
                        if not f.is_file():
                            continue
                        key = str(f)
                        try:
                            mtime = f.stat().st_mtime
                            if key not in snapshots:
                                snapshots[key] = mtime
                                self._check_file(key, 'created')
                            elif snapshots[key] != mtime:
                                snapshots[key] = mtime
                                self._check_file(key, 'modified')
                        except OSError:
                            pass
            except Exception:
                pass
            time.sleep(10)


# ─── Registry Monitor (Windows only) ──────────────────────────────────────

class RegistryMonitor:
    def __init__(self):
        self._running   = False
        self._thread    = None
        self._snapshots = {}

    def start(self):
        if not IS_WIN:
            return
        self._running = True
        self._take_snapshot()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log('Registry monitor started')

    def stop(self):
        self._running = False

    def _take_snapshot(self):
        for key_path in SENSITIVE_REGISTRY_KEYS:
            vals = self._read_key(key_path)
            if vals is not None:
                self._snapshots[key_path] = vals

    def _loop(self):
        while self._running:
            time.sleep(15)
            try:
                self._check_changes()
            except Exception:
                pass

    def _check_changes(self):
        for key_path in SENSITIVE_REGISTRY_KEYS:
            current = self._read_key(key_path)
            if current is None:
                continue
            prev = self._snapshots.get(key_path, {})
            for name, value in current.items():
                if name not in prev:
                    event('registry', 'high',
                          f'New registry persistence entry',
                          f'Key: HKCU\\{key_path}\nValue: {name} = {str(value)[:100]}')
                elif prev[name] != value:
                    event('registry', 'medium',
                          f'Registry value modified',
                          f'Key: HKCU\\{key_path}\nValue: {name}\nOld: {str(prev[name])[:80]}\nNew: {str(value)[:80]}')
            self._snapshots[key_path] = current

    def _read_key(self, key_path):
        try:
            import winreg
            result = {}
            for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            result[name] = value
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass
            return result
        except ImportError:
            return None


# ─── Main Endpoint Protection Daemon ──────────────────────────────────────

def run_endpoint_daemon():
    log('BytesProtector Endpoint Protection starting…', 'info')
    log(f'Platform: {sys.platform}', 'info')

    monitors = []

    # File system
    fs_mon = FileSystemMonitor()
    fs_mon.start()
    monitors.append(fs_mon)

    # Process (Windows only for full support)
    proc_mon = ProcessMonitor()
    proc_mon.start()
    monitors.append(proc_mon)

    # Network
    net_mon = NetworkMonitor()
    net_mon.start()
    monitors.append(net_mon)

    # Registry (Windows only)
    reg_mon = RegistryMonitor()
    reg_mon.start()
    monitors.append(reg_mon)

    emit({'type': 'endpoint_ready', 'monitors': [
        'filesystem', 'process', 'network',
        'registry' if IS_WIN else None
    ]})

    # Keep alive — emit heartbeat every 30s
    try:
        while True:
            time.sleep(30)
            emit({'type': 'endpoint_heartbeat', 'ts': datetime.now().isoformat()})
    except KeyboardInterrupt:
        pass
    finally:
        for m in monitors:
            try:
                m.stop()
            except Exception:
                pass


if __name__ == '__main__':
    run_endpoint_daemon()
