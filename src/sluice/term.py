"""Tiny ANSI styling helper (honours NO_COLOR, enables VT mode on Windows)."""

from __future__ import annotations

import os
import sys

_enabled: bool | None = None


def _detect(stream) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            return False
    return True


def color_enabled() -> bool:
    global _enabled
    if _enabled is None:
        _enabled = _detect(sys.stdout)
    return _enabled


_CODES = {
    "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "gray": "90", "bg_red": "41;97", "bg_green": "42;30", "bg_yellow": "43;30",
}


def style(text: str, *names: str) -> str:
    if not color_enabled() or not names:
        return text
    codes = ";".join(_CODES[n] for n in names)
    return f"\033[{codes}m{text}\033[0m"


SEVERITY_STYLE = {
    "critical": ("bold", "red"), "high": ("red",), "medium": ("yellow",), "low": ("cyan",), "info": ("gray",),
}
DECISION_STYLE = {
    "block": ("bg_red",), "would_block": ("bg_yellow",), "warn": ("yellow",), "allow": ("green",),
    "info": ("gray",), "redact": ("cyan",),
}


def sev(severity: str) -> str:
    return style(severity.upper(), *SEVERITY_STYLE.get(severity, ()))


def decision(d: str | None) -> str:
    d = d or "-"
    return style(f" {d.upper()} ", *DECISION_STYLE.get(d, ()))
