"""
BytesProtector — Scan Detection Test File
==========================================
Contains INERT test byte strings that simulate real malware signatures.
No code here executes anything harmful — these are just bytes in a file.

Usage:
  Scan Files → select this file → Start Scan
  OR drop in a folder → Custom Scan on that folder

Expected detections (in order of pipeline):
  HASH:    SHA-256 7163fef... → Trojan.SalineWin   (if exact binary)
  PATTERN: /v DisableTaskMgr /t reg_dword /d 1 /f  → Trojan.SalineWin ✓
  PATTERN: \\.\\PhysicalDrive0                      → Trojan.SalineWin.MBRWipe ✓
  PATTERN: eval(base64_decode(                      → PHP.Webshell.Eval ✓
  YARA:    DisableTaskMgr string                    → Trojan.SalineWin ✓
"""

# ── SalineWin IOC #1 — REG ADD to disable Task Manager
# Exact command confirmed in Joe Sandbox + Hybrid Analysis reports
SALINEWIN_REGISTRY_CMD = (
    b"REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion"
    b"\\policies\\system /v DisableTaskMgr /t reg_dword /d 1 /f"
)

# ── SalineWin IOC #2 — direct MBR write via PhysicalDrive0
# Confirmed: salinewin writes toad image to MBR at offset 32768
SALINEWIN_MBR_WIPE = b"\\\\.\\PhysicalDrive0"

# ── PHP Webshell (zero legitimate use in any file)
PHP_WEBSHELL = b"eval(base64_decode("

# ── LockBit ransomware note string
LOCKBIT = b"!!!-Restore-My-Files-!!!"

# ── XMRig miner pool URL
XMRIG = b"donate.v2.xmrig.com"

# ── AsyncRAT C2 client
ASYNCRAT = b"AsyncClient\x00AsyncRAT"

# ── Cobalt Strike beacon (reflective loader)
COBALT = b"ReflectiveLoader\x00beacon_metadata"

# ── Hidden PowerShell dropper
PS_DROP = b"powershell -w hidden -enc "

print("bp_test_scan.py loaded — scan this file with BytesProtector")
print("Expected: Trojan.SalineWin (Pattern engine, confidence 0.99)")
