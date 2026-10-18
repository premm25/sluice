"""Content detectors.

Everything here is pure and side-effect free: functions take text (or a tool
definition) and return :class:`Finding` objects. The engine decides what to do
with them according to policy.

Detectors:
  * hidden Unicode (zero-width, bidi overrides, Unicode "tag" ASCII smuggling,
    variation-selector byte smuggling) -- with payload *reveal*
  * prompt-injection phrasing in tool outputs
  * tool poisoning in tool descriptions/schemas (incl. cross-tool shadowing)
  * secrets (cloud keys, tokens, private keys) with redaction
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    evidence: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def severity_rank(severity: str) -> int:
    return _RANK.get(severity, 0)


def max_severity(findings: Iterable[Finding]) -> str | None:
    best = None
    for f in findings:
        if best is None or _RANK[f.severity] > _RANK[best]:
            best = f.severity
    return best


def at_least(findings: Iterable[Finding], threshold: str) -> bool:
    top = max_severity(findings)
    return top is not None and _RANK[top] >= _RANK[threshold]


def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = text[a:b].replace("\n", " ")
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


# --------------------------------------------------------------------------
# Hidden Unicode
# --------------------------------------------------------------------------

# ZWJ (U+200D) is deliberately excluded: it is load-bearing in emoji sequences.
_ZERO_WIDTH = "​‌‎‏⁠⁡⁢⁣⁤﻿᠎­"
_BIDI = "‪‫‬‭‮⁦⁧⁨⁩"
_TAGS = "\U000e0000-\U000e007f"
_VS_SUPPLEMENT = "\U000e0100-\U000e01ef"

HIDDEN_RE = re.compile(f"[{_ZERO_WIDTH}{_BIDI}{_TAGS}{_VS_SUPPLEMENT}]")
_TAG_RE = re.compile(f"[{_TAGS}]+")
# Variation-selector smuggling encodes one byte per selector, usually riding on
# a single visible "carrier" character. Basic selectors (U+FE00-FE0F) are only
# suspicious when several appear in a row.
_VS_RUN_RE = re.compile(f"[︀-️{_VS_SUPPLEMENT}]{{2,}}")


def _vs_to_byte(ch: str) -> int:
    cp = ord(ch)
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    return cp - 0xE0100 + 16


def reveal_hidden(text: str) -> str:
    """Decode payloads smuggled via Unicode tags or variation selectors."""
    parts: list[str] = []
    for m in _TAG_RE.finditer(text):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0xE0020 <= ord(c) <= 0xE007E)
        if decoded.strip():  # a lone TAG SPACE splitting a word is filter evasion, not a payload
            parts.append(decoded)
    for m in _VS_RUN_RE.finditer(text):
        raw = bytes(_vs_to_byte(c) for c in m.group())
        decoded = raw.decode("utf-8", errors="replace")
        if decoded.strip():
            parts.append(decoded)
    return " | ".join(parts)


def find_hidden(text: str) -> list[Finding]:
    hits = HIDDEN_RE.findall(text)
    vs_runs = _VS_RUN_RE.findall(text)
    if not hits and not vs_runs:
        return []
    revealed = reveal_hidden(text)
    count = len(hits) + sum(len(r) for r in vs_runs)
    if revealed:
        return [Finding(
            "hidden_payload", "critical",
            f"text smuggles an invisible payload in {count} hidden Unicode characters",
            revealed[:300],
        )]
    kinds = sorted({f"U+{ord(c):04X}" for c in hits})[:8]
    return [Finding(
        "hidden_unicode", "medium",
        f"{count} invisible/bidi control characters present",
        ", ".join(kinds),
    )]


def strip_hidden(text: str) -> str:
    text = _VS_RUN_RE.sub("", text)
    return HIDDEN_RE.sub("", text)


# --------------------------------------------------------------------------
# Prompt injection / tool poisoning
# --------------------------------------------------------------------------

_I = re.IGNORECASE

INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("ignore_instructions", "high", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|all|any|your|the|system|safety)\b"
        r"[^.\n]{0,25}?\b(instructions?|prompts?|rules|directions|guidelines|guardrails|polic(y|ies))\b", _I),
     "attempts to override the agent's instructions"),
    ("fake_system_tag", "high", re.compile(
        r"</?\s*(system|important|instructions?|admin|assistant|developer)\s*>|\[/?(system|INST)\]|<\|im_(start|end)\|>", _I),
     "contains fake system/priority markup"),
    ("conceal_from_user", "high", re.compile(
        r"\b(do not|don't|dont|never|without)\b[^.\n]{0,30}?\b(tell|telling|inform|informing|mention|mentioning|reveal|revealing|show|showing|alert|alerting|notify|notifying|asking)\b"
        r"[^.\n]{0,20}?\b(the )?(user|human|them)\b", _I),
     "instructs the agent to hide actions from the user"),
    ("exfil_instruction", "high", re.compile(
        r"\b(send|post|upload|forward|transmit|exfiltrate|leak|email|submit|include)\b[^\n]{0,80}?\b(to|at|into)\b[^\n]{0,30}?"
        r"(https?://|wss?://|[\w.+-]+@[\w-]+\.[\w.]+)", _I),
     "instructs the agent to send data to an external destination"),
    ("role_hijack", "medium", re.compile(
        r"\byou are now\b|\bfrom now on,? you\b|\bnew (system )?instructions?\s*:|\bswitch(ing)? to (developer|admin|god) mode\b", _I),
     "attempts to reassign the agent's role"),
    ("coerced_action", "medium", re.compile(
        r"\b(you must|you need to|you should|immediately|before (answering|responding|using))\b[^.\n]{0,40}?\b(call|invoke|run|execute|use|read|fetch|open)\b", _I),
     "pressures the agent into taking an action"),
    ("sensitive_path", "medium", re.compile(
        r"[~/\\]\.(ssh|aws|gnupg|kube|docker|azure|config/gcloud)\b|\bid_(rsa|ed25519|ecdsa)\b|(^|[\s/\\'\"])\.env\b|"
        r"\bcredentials\.json\b|\.npmrc\b|\.pypirc\b|\.netrc\b|/etc/(passwd|shadow)\b|\bwallet\.dat\b|\bmcp\.json\b", _I),
     "references credential or secret file locations"),
    ("markdown_exfil", "medium", re.compile(
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)", _I),
     "markdown image with query parameters (zero-click exfiltration channel)"),
    ("secrecy", "low", re.compile(
        r"\b(secretly|covertly|silently|quietly)\b|\bthis is (a|an) (test|authorized)\b[^.\n]{0,30}\b(ignore|bypass)", _I),
     "uses secrecy language"),
]

_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
MAX_DESCRIPTION_CHARS = 2000


def scan_injection(text: str) -> list[Finding]:
    """Scan untrusted text (tool output, descriptions) for injection phrasing."""
    findings: list[Finding] = []
    for code, severity, pattern, message in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(Finding(code, severity, message, _snippet(text, m.start(), m.end())))
    findings.extend(find_hidden(text))
    return findings


def _schema_strings(node: Any) -> Iterator[str]:
    """Yield human-readable strings in a JSON schema (descriptions, titles, enum values)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("description", "title") and isinstance(value, str):
                yield value
            elif key in ("default", "examples", "enum", "const"):
                yield from (v for v in (value if isinstance(value, list) else [value]) if isinstance(v, str))
            else:
                yield from _schema_strings(value)
            if key == "properties" and isinstance(value, dict):
                yield from value
    elif isinstance(node, list):
        for item in node:
            yield from _schema_strings(item)


def tool_text(tool: dict[str, Any]) -> str:
    parts = [str(tool.get("name", "")), str(tool.get("title", "")), str(tool.get("description", ""))]
    parts.extend(_schema_strings(tool.get("inputSchema", {})))
    parts.extend(_schema_strings(tool.get("outputSchema", {})))
    ann = tool.get("annotations")
    if isinstance(ann, dict) and isinstance(ann.get("title"), str):
        parts.append(ann["title"])
    return "\n".join(p for p in parts if p)


def scan_tool(tool: dict[str, Any], other_tool_names: Iterable[str] = ()) -> list[Finding]:
    """Detect tool poisoning: injected instructions hidden in a tool's metadata."""
    text = tool_text(tool)
    name = str(tool.get("name", ""))
    findings = scan_injection(text)

    # In a description, "you must call X" style phrasing is a stronger signal
    # than in arbitrary output, and sensitive paths have no business there.
    escalate = {"sensitive_path": "high", "coerced_action": "medium"}
    findings = [
        Finding(f.code, escalate.get(f.code, f.severity), f.message, f.evidence) for f in findings
    ]

    description = str(tool.get("description", ""))
    if len(description) > MAX_DESCRIPTION_CHARS:
        findings.append(Finding(
            "oversized_description", "low",
            f"description is {len(description)} chars (> {MAX_DESCRIPTION_CHARS}); long descriptions hide instructions",
        ))
    m = _B64_BLOB_RE.search(text)
    if m:
        findings.append(Finding("encoded_blob", "medium", "metadata contains a long base64-like blob",
                                m.group()[:60] + "…"))

    # Cross-tool shadowing: a tool that talks about *another* tool is trying
    # to change how the agent uses that other tool.
    lowered = text.lower()
    for other in other_tool_names:
        if not other or other == name or len(other) < 4:
            continue
        if re.search(rf"(?<![\w-]){re.escape(other.lower())}(?![\w-])", lowered):
            findings.append(Finding(
                "tool_shadowing", "high",
                f"description references another tool '{other}' (cross-tool shadowing)",
                other,
            ))
    return findings


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("connection_string", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@[^\s]+", _I)),
]
# key = value assignments: only the value is redacted.
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?)"
    r"([^\s'\"]{8,})")


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (kind, value) pairs for every secret in ``text``."""
    out: list[tuple[str, str]] = []
    for kind, pattern in SECRET_PATTERNS:
        out.extend((kind, m.group()) for m in pattern.finditer(text))
    out.extend(("assigned_secret", m.group(2)) for m in _ASSIGNMENT_RE.finditer(text)
               if not m.group(2).startswith("[REDACTED"))
    return out


def redact_secrets(text: str) -> tuple[str, list[Finding]]:
    findings: list[Finding] = []
    for kind, pattern in SECRET_PATTERNS:
        def _sub(m: re.Match[str], kind: str = kind) -> str:
            findings.append(Finding("secret_redacted", "high", f"redacted {kind}", _mask(m.group())))
            return f"[REDACTED:{kind}]"
        text = pattern.sub(_sub, text)

    def _sub_assign(m: re.Match[str]) -> str:
        if m.group(2).startswith("[REDACTED"):
            return m.group()
        findings.append(Finding("secret_redacted", "medium", "redacted assigned secret", _mask(m.group(2))))
        return m.group(1) + "[REDACTED:assigned_secret]"
    text = _ASSIGNMENT_RE.sub(_sub_assign, text)
    return text, findings


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-2:]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# '=' ':' '/' '.' act as separators (k=v, URLs, paths) so a value matches in any context.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+]{16,}")


def high_value_tokens(text: str) -> set[str]:
    """Short, high-entropy strings (keys, tokens, IDs) worth tracking exactly.

    Winnowing fingerprints need ~35 characters of overlap; secrets are often
    shorter, so they are tracked as exact tokens instead.
    """
    tokens = {value for _, value in find_secrets(text)}
    for m in _TOKEN_RE.finditer(text):
        tok = m.group()
        has_digit = any(c.isdigit() for c in tok)
        has_alpha = any(c.isalpha() for c in tok)
        if has_digit and has_alpha and shannon_entropy(tok) >= 3.5:
            tokens.add(tok)
    return tokens
