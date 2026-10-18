"""Find the MCP client process that (indirectly) launched this proxy.

Taint is shared between proxies started by the same client, so the session
key is the client's PID. The direct parent is not always the client: pip's
``sluice.exe`` console-script launcher on Windows, ``uvx``, or a shell the
client spawns servers through can sit in between, and each proxy would then
get a different "parent". We walk up past such intermediaries.
"""

from __future__ import annotations

import os
import subprocess
import sys

INTERMEDIARIES = {
    "sluice", "sluice.exe", "py", "py.exe", "uv", "uv.exe", "uvx", "uvx.exe", "pipx", "pipx.exe",
    "sh", "bash", "zsh", "dash", "fish", "env", "cmd", "cmd.exe", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "conhost.exe",
}
MAX_HOPS = 4


def _windows_table() -> dict[int, tuple[int, str]]:
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return {}
    table: dict[int, tuple[int, str]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            table[entry.th32ProcessID] = (entry.th32ParentProcessID, entry.szExeFile)
            ok = kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return table


def _parent_and_name(pid: int, table: dict[int, tuple[int, str]] | None) -> tuple[int, str] | None:
    if table is not None:
        return table.get(pid)
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                stat = f.read()
            # comm is parenthesised and may contain spaces
            name = stat[stat.index("(") + 1: stat.rindex(")")]
            ppid = int(stat[stat.rindex(")") + 2:].split()[1])
            return ppid, name
        except (OSError, ValueError, IndexError):
            return None
    try:
        out = subprocess.run(["ps", "-o", "ppid=,comm=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=2).stdout.strip()
        ppid, _, comm = out.partition(" ")
        return int(ppid), os.path.basename(comm.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def client_pid() -> int:
    """PID of the nearest ancestor that is not a launcher or shell."""
    pid = os.getppid()
    try:
        table = _windows_table() if sys.platform == "win32" else None
    except Exception:
        return pid
    for _ in range(MAX_HOPS):
        info = _parent_and_name(pid, table)
        if info is None:
            return pid
        ppid, name = info
        if name.lower() not in INTERMEDIARIES or ppid <= 1:
            return pid
        pid = ppid
    return pid
