"""
BytesProtector — Endpoint Protection Test
==========================================
Simulates the exact behaviors that the endpoint daemon monitors for.
ALL actions here are SAFE and REVERSIBLE — they only demonstrate
detection, they don't do anything permanently harmful.

Usage:
  1. Open BytesProtector → Endpoint page → Start Protection
  2. Open a terminal and run: python bp_test_endpoint.py
  3. Watch the Endpoint alert feed light up

Each test is separated by a prompt so you can run them one at a time.

Tests:
  [1] Suspicious PowerShell — encoded command (process monitor)
  [2] Certutil abuse simulation (process monitor)  
  [3] File drop to Temp (filesystem monitor)
  [4] Mass file rename simulation (ransomware behavior)
  [5] Registry persistence key write (registry monitor) — CLEANED UP
  [6] Suspicious network port check (network monitor info)
  [7] LOLBin child process simulation (process monitor)
"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
import platform
from pathlib import Path

IS_WIN = platform.system() == 'Windows'
IS_LIN = platform.system() == 'Linux'

def sep(title):
    print(f"\n{'='*60}")
    print(f"  TEST: {title}")
    print('='*60)

def ask(prompt="Press ENTER to run this test (or 'q' to quit): "):
    r = input(prompt).strip().lower()
    if r == 'q':
        print("Exiting.")
        sys.exit(0)

def ok(msg):  print(f"  ✓ {msg}")
def warn(msg): print(f"  ⚠ {msg}")
def info(msg): print(f"  · {msg}")


print("\nBytesProtector Endpoint Protection Test")
print("Make sure the Endpoint Protection daemon is running first!")
print("Open BytesProtector → Endpoint → Start Protection")
print()
ask("Ready? Press ENTER to begin: ")


# ── TEST 1: Suspicious PowerShell ────────────────────────────────────────
sep("Suspicious PowerShell — Encoded Command")
info("Spawns powershell.exe with -EncodedCommand flag")
info("The command just does: Write-Host 'BP_ENDPOINT_TEST'")
info("Endpoint monitor should detect: Encoded PS command")
ask()

if IS_WIN:
    import base64
    cmd = "Write-Host 'BP_ENDPOINT_TEST_MARKER'"
    enc = base64.b64encode(cmd.encode('utf-16-le')).decode()
    try:
        proc = subprocess.Popen(
            ['powershell.exe', '-NonInteractive', '-WindowStyle', 'Hidden',
             '-EncodedCommand', enc],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        proc.wait(timeout=5)
        ok("PowerShell process spawned — check Endpoint feed for alert")
    except Exception as e:
        warn(f"Could not spawn PowerShell: {e}")
else:
    info("Not Windows — simulating via process name only")
    info("On Linux/Mac the process monitor checks for suspicious Python one-liners")
    try:
        proc = subprocess.Popen(
            [sys.executable, '-c',
             '__import__("base64").b64decode("QlBfRU5EUE9JTlRfVEVTVA==")'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        proc.wait(timeout=3)
        ok("Suspicious Python one-liner spawned — check Endpoint feed")
    except Exception as e:
        warn(f"Error: {e}")

time.sleep(1)


# ── TEST 2: File drop to Temp ──────────────────────────────────────────
sep("File Drop to Temp Directory")
info("Creates a .exe file in the system temp directory")
info("Filesystem monitor should detect: Suspicious file in temp")
ask()

tmp = tempfile.gettempdir()
test_exe = Path(tmp) / "bp_test_dropper.exe"
try:
    # Write an MZ header (PE magic bytes) — looks like an executable
    test_exe.write_bytes(
        b'MZ' + b'\x00' * 62 +           # MZ header stub
        b'\x40\x00\x00\x00' +            # e_lfanew = 0x40
        b'\x00' * 0x3C +
        b'PE\x00\x00' +                  # PE signature
        b'\x00' * 200                    # stub body
    )
    ok(f"Created fake PE in temp: {test_exe}")
    info("Check Endpoint feed for 'Suspicious file in temp' alert")
    time.sleep(2)
    test_exe.unlink()
    ok("Cleaned up test file")
except Exception as e:
    warn(f"Could not create temp file: {e}")

time.sleep(1)


# ── TEST 3: Mass file rename (ransomware simulation) ──────────────────
sep("Mass File Rename — Ransomware Behavior Simulation")
info("Creates 25 temp files then renames them all to .encrypted extension")
info("Filesystem monitor should detect: Mass file rename (potential ransomware)")
ask()

rename_dir = Path(tempfile.gettempdir()) / 'bp_ransim_test'
rename_dir.mkdir(exist_ok=True)
files_created = []

try:
    # Create test files
    for i in range(25):
        f = rename_dir / f"document_{i:03d}.txt"
        f.write_text(f"test file {i}")
        files_created.append(f)
    ok(f"Created {len(files_created)} test files in {rename_dir}")

    info("Now renaming all to .encrypted in rapid succession...")
    for f in files_created:
        dest = f.with_suffix('.encrypted')
        f.rename(dest)
    ok("Renamed 25 files → .encrypted")
    info("Check Endpoint feed for ransomware behavior alert!")

    time.sleep(2)
except Exception as e:
    warn(f"Error during rename test: {e}")
finally:
    # Cleanup
    try:
        shutil.rmtree(rename_dir)
        ok("Cleaned up rename test directory")
    except Exception:
        warn(f"Could not clean up {rename_dir} — delete manually")

time.sleep(1)


# ── TEST 4: Registry persistence key (Windows only) ──────────────────
sep("Registry Persistence Key — Run Key Write")
info("Writes a fake 'persistence' value to HKCU Run key")
info("Registry monitor should detect: New registry persistence entry")
info("THIS IS CLEANED UP IMMEDIATELY after detection")
ask()

if IS_WIN:
    REG_KEY = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    TEST_VALUE = 'BytesProtectorTest'
    TEST_DATA  = r'C:\Windows\Temp\bp_test.exe'
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_KEY,
            0, winreg.KEY_SET_VALUE | winreg.KEY_READ
        )
        winreg.SetValueEx(key, TEST_VALUE, 0, winreg.REG_SZ, TEST_DATA)
        winreg.CloseKey(key)
        ok(f"Wrote test Run key: {TEST_VALUE} = {TEST_DATA}")
        info("Waiting 20s for registry monitor to detect it...")
        time.sleep(20)

        # Immediately clean up
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_KEY,
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, TEST_VALUE)
        winreg.CloseKey(key)
        ok("Registry key cleaned up — persistence entry removed")
    except Exception as e:
        warn(f"Registry test failed: {e}")
else:
    info("Skipping registry test — not Windows")
    info("On Linux/Mac the registry monitor is not active")


# ── TEST 5: Suspicious network connection info ────────────────────────
sep("Network Monitor — Port Check")
info("Shows what ports the network monitor watches for")
info("(Not actually connecting anywhere)")
ask()

WATCHED_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common RAT C2",
    6666:  "Malware callback",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
    31337: "Back Orifice / elite port",
}
info("Network monitor watches for ESTABLISHED connections to:")
for port, desc in WATCHED_PORTS.items():
    info(f"  :{port}  — {desc}")

if IS_WIN:
    try:
        result = subprocess.run(['netstat', '-nao'], capture_output=True, text=True, timeout=5)
        suspicious = [l for l in result.stdout.split('\n')
                      if any(f':{p} ' in l for p in WATCHED_PORTS)]
        if suspicious:
            warn(f"Found {len(suspicious)} suspicious connection(s) on watched ports!")
            for l in suspicious:
                print(f"    {l.strip()}")
        else:
            ok("No active connections on watched ports — system clean")
    except Exception:
        pass
elif IS_LIN:
    try:
        result = subprocess.run(['ss', '-tnp'], capture_output=True, text=True, timeout=5)
        suspicious = [l for l in result.stdout.split('\n')
                      if any(f':{p}' in l for p in WATCHED_PORTS)]
        if suspicious:
            warn(f"Found {len(suspicious)} suspicious connection(s)!")
        else:
            ok("No active connections on watched ports")
    except Exception:
        pass


# ── TEST 6: Scan test file check ──────────────────────────────────────
sep("Bonus: Check if bp_test_scan.py is in the same folder")
scan_test = Path(__file__).parent / 'bp_test_scan.py'
if scan_test.exists():
    ok(f"Found bp_test_scan.py at: {scan_test}")
    info("Run a 'Scan Files' scan on bp_test_scan.py to test scan detection")
    info("Expected: Detected as Trojan.SalineWin + multiple other families")
else:
    warn("bp_test_scan.py not found in same directory")
    info("Download it from BytesProtector test files")


print()
print("=" * 60)
print("  Endpoint test complete!")
print("  Check the BytesProtector Endpoint page for all alerts.")
print("  If protection was running, you should see alerts for:")
if IS_WIN:
    print("    ✓ Encoded PowerShell command")
    print("    ✓ Suspicious file in temp (.exe)")
    print("    ✓ Mass file rename (ransomware behavior)")
    print("    ✓ Registry persistence key write")
else:
    print("    ✓ Suspicious Python one-liner")
    print("    ✓ Suspicious file in temp (.exe)")
    print("    ✓ Mass file rename (ransomware behavior)")
print("=" * 60)
