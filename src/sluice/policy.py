"""Policy: TOML configuration that drives every Sluice decision.

See ``sluice init`` (or :data:`DEFAULT_POLICY_TOML`) for the documented format.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sluice.flow import LABELS
from sluice.labels import auto_labels
from sluice.ratelimit import RateLimiter, parse_rate


class PolicyError(ValueError):
    pass


ACTIONS3 = ("block", "warn", "off")


@dataclass
class DetectConfig:
    tool_poisoning: str = "block"      # quarantine tools whose metadata carries injection
    output_injection: str = "warn"     # block | warn | off for injection in tool results
    strip_hidden_unicode: bool = True  # remove invisible/smuggling characters everywhere
    redact_secrets: bool = True        # redact keys/tokens in tool results


@dataclass
class PinningConfig:
    enabled: bool = True
    on_change: str = "block"  # block | warn


@dataclass
class FlowConfig:
    enabled: bool = True
    exfiltration: str = "block"   # private data detected in sink arguments
    trifecta: str = "warn"        # sink called while session holds private + untrusted taint
    min_matches: int = 2          # fingerprint matches needed to call it a leak
    auto_label: bool = True
    resources_private: bool = True
    session_ttl: float = 12 * 3600
    kgram: int = 24
    window: int = 12
    split_detection: str = "block"  # private data sent in pieces across several sink calls
    split_window: float = 600       # seconds of outbound history kept per destination (memory only)
    split_max_chars: int = 20_000   # per-stream cap on that history
    # Declassification: "source_glob -> sink_glob" flows that are permitted,
    # e.g. "filesystem:* -> github:create_pull_request".
    allow_flows: list[str] = field(default_factory=list)

    def flow_allowed(self, source: tuple[str, str], sink: tuple[str, str]) -> bool:
        for rule in self.allow_flows:
            src, _, dst = (part.strip() for part in rule.partition("->"))
            if _match(src, *source) and _match(dst, *sink):
                return True
        return False


@dataclass
class RecordConfig:
    # Records tool definitions, call arguments (secrets redacted) and *fingerprints*
    # of results -- never result text -- for `sluice replay` and `sluice learn`.
    enabled: bool = True
    retain_days: float = 14


@dataclass
class ArgConstraint:
    within: list[str] = field(default_factory=list)
    deny: list[re.Pattern[str]] = field(default_factory=list)
    allow: list[re.Pattern[str]] = field(default_factory=list)
    max_length: int | None = None
    one_of: list[Any] | None = None
    required: bool = False


@dataclass
class Rule:
    index: int
    match: str
    action: str = "allow"
    reason: str = ""
    args: dict[str, ArgConstraint] = field(default_factory=dict)
    rate_limit: tuple[int, float] | None = None
    rate_spec: str = ""

    def matches(self, server: str, tool: str) -> bool:
        return _match(self.match, server, tool)

    @property
    def unconditional_deny(self) -> bool:
        return self.action == "deny" and not self.args


@dataclass
class ToolLabel:
    match: str
    labels: set[str]


@dataclass
class Violation:
    code: str
    message: str


@dataclass
class Policy:
    mode: str = "enforce"           # enforce | monitor
    default_action: str = "allow"   # allow | deny
    detect: DetectConfig = field(default_factory=DetectConfig)
    pinning: PinningConfig = field(default_factory=PinningConfig)
    flow: FlowConfig = field(default_factory=FlowConfig)
    record: RecordConfig = field(default_factory=RecordConfig)
    rules: list[Rule] = field(default_factory=list)
    tool_labels: list[ToolLabel] = field(default_factory=list)
    source: str = "<defaults>"

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    def labels_for(self, server: str, tool: str, definition: dict[str, Any] | None = None) -> set[str]:
        explicit = [tl for tl in self.tool_labels if _match(tl.match, server, tool)]
        if explicit:
            return set().union(*(tl.labels for tl in explicit))
        if self.flow.auto_label:
            return auto_labels(tool, definition)
        return set()

    def is_hidden(self, server: str, tool: str) -> bool:
        return any(r.unconditional_deny and r.matches(server, tool) for r in self.rules)

    def evaluate(self, server: str, tool: str, args: dict[str, Any],
                 limiter: RateLimiter | None = None, now: float | None = None) -> list[Violation]:
        matched = [r for r in self.rules if r.matches(server, tool)]
        if not matched:
            if self.default_action == "deny":
                return [Violation("default_deny", f"tool '{tool}' is not on the allowlist")]
            return []
        out: list[Violation] = []
        for rule in matched:
            if rule.action == "deny":
                out.append(Violation("rule_deny", rule.reason or f"denied by rule '{rule.match}'"))
                continue
            problems = _check_args(rule, args)
            out.extend(problems)
            if not problems and rule.rate_limit and limiter is not None:
                cap, period = rule.rate_limit
                if not limiter.allow((rule.index, server, tool), cap, period, now=now):
                    out.append(Violation("rate_limit", f"rate limit {rule.rate_spec} exceeded"))
        return out


def _match(pattern: str, server: str, tool: str) -> bool:
    if ":" in pattern:
        server_glob, tool_glob = pattern.split(":", 1)
        return fnmatch.fnmatchcase(server, server_glob) and fnmatch.fnmatchcase(tool, tool_glob)
    return fnmatch.fnmatchcase(tool, pattern)


# --------------------------------------------------------------------------
# Argument constraints
# --------------------------------------------------------------------------

_MISSING = object()


def _lookup(args: Any, dotted: str) -> Any:
    node = args
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return _MISSING
    return node


def _leaves(node: Any) -> Iterator[Any]:
    if isinstance(node, dict):
        for v in node.values():
            yield from _leaves(v)
    elif isinstance(node, list):
        for v in node:
            yield from _leaves(v)
    else:
        yield node


def _within(value: str, roots: list[str]) -> bool:
    if value.startswith("file://"):
        value = value[len("file://"):]
    target = os.path.normcase(os.path.realpath(os.path.expanduser(value)))
    for root in roots:
        base = os.path.normcase(os.path.realpath(os.path.expanduser(root)))
        try:
            if os.path.commonpath([target, base]) == base:
                return True
        except ValueError:  # different drives on Windows
            continue
    return False


def _check_args(rule: Rule, args: dict[str, Any]) -> list[Violation]:
    out: list[Violation] = []
    for key, c in rule.args.items():
        if key == "*":
            values = list(_leaves(args))
        else:
            v = _lookup(args, key)
            if v is _MISSING:
                if c.required:
                    out.append(Violation("arg_required", f"argument '{key}' is required by policy"))
                continue
            values = list(_leaves(v)) if isinstance(v, (dict, list)) else [v]
        for value in values:
            text = value if isinstance(value, str) else json.dumps(value)
            label = f"argument '{key}'" if key != "*" else "an argument"
            if c.one_of is not None and value not in c.one_of:
                out.append(Violation("arg_not_allowed", f"{label} must be one of {c.one_of}"))
            if c.max_length is not None and len(text) > c.max_length:
                out.append(Violation("arg_too_long", f"{label} exceeds {c.max_length} characters"))
            for pattern in c.deny:
                if pattern.search(text):
                    out.append(Violation("arg_denied", f"{label} matches forbidden pattern /{pattern.pattern}/"))
                    break
            if c.allow and not any(p.search(text) for p in c.allow):
                out.append(Violation("arg_not_allowed", f"{label} does not match any allowed pattern"))
            if c.within and not _within(text, c.within):
                out.append(Violation("path_outside", f"{label} path '{text}' is outside {c.within}"))
    return out


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def _check_keys(section: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"[{section}] unknown key(s): {', '.join(sorted(unknown))}; "
                          f"allowed: {', '.join(sorted(allowed))}")


def _choice(section: str, key: str, value: Any, choices: tuple[str, ...]) -> str:
    if value not in choices:
        raise PolicyError(f"[{section}] {key} must be one of {choices}, got {value!r}")
    return value


def _regexes(where: str, values: Any) -> list[re.Pattern[str]]:
    if isinstance(values, str):
        values = [values]
    try:
        return [re.compile(v) for v in values]
    except re.error as e:
        raise PolicyError(f"{where}: invalid regex: {e}") from e


def from_dict(data: dict[str, Any], source: str = "<dict>") -> Policy:
    _check_keys("policy", data, {"mode", "default_action", "detect", "pinning", "flow", "record", "tools", "rules"})
    p = Policy(source=source)
    p.mode = _choice("policy", "mode", data.get("mode", p.mode), ("enforce", "monitor"))
    p.default_action = _choice("policy", "default_action", data.get("default_action", p.default_action),
                               ("allow", "deny"))

    det = data.get("detect", {})
    _check_keys("detect", det, set(DetectConfig.__dataclass_fields__))
    p.detect = DetectConfig(**det)
    _choice("detect", "tool_poisoning", p.detect.tool_poisoning, ACTIONS3)
    _choice("detect", "output_injection", p.detect.output_injection, ACTIONS3)

    pin = data.get("pinning", {})
    _check_keys("pinning", pin, set(PinningConfig.__dataclass_fields__))
    p.pinning = PinningConfig(**pin)
    _choice("pinning", "on_change", p.pinning.on_change, ("block", "warn"))

    flow = data.get("flow", {})
    _check_keys("flow", flow, set(FlowConfig.__dataclass_fields__))
    p.flow = FlowConfig(**flow)
    _choice("flow", "exfiltration", p.flow.exfiltration, ACTIONS3)
    _choice("flow", "trifecta", p.flow.trifecta, ACTIONS3)
    _choice("flow", "split_detection", p.flow.split_detection, ACTIONS3)
    if p.flow.split_window <= 0 or p.flow.split_max_chars < 64:
        raise PolicyError("[flow] split_window must be > 0 and split_max_chars >= 64")
    if p.flow.min_matches < 1 or p.flow.kgram < 8 or p.flow.window < 1:
        raise PolicyError("[flow] min_matches >= 1, kgram >= 8 and window >= 1 are required")
    for rule in p.flow.allow_flows:
        if not isinstance(rule, str) or "->" not in rule:
            raise PolicyError(f"[flow] allow_flows entries look like 'source_glob -> sink_glob', got {rule!r}")

    rec = data.get("record", {})
    _check_keys("record", rec, set(RecordConfig.__dataclass_fields__))
    p.record = RecordConfig(**rec)
    if p.record.retain_days <= 0:
        raise PolicyError("[record] retain_days must be > 0")

    for i, entry in enumerate(data.get("tools", [])):
        where = f"tools[{i}]"
        _check_keys(where, entry, {"match", "labels"})
        if "match" not in entry:
            raise PolicyError(f"{where}: 'match' is required")
        labels = set(entry.get("labels", []))
        bad = labels - set(LABELS)
        if bad:
            raise PolicyError(f"{where}: unknown label(s) {sorted(bad)}; use {list(LABELS)}")
        p.tool_labels.append(ToolLabel(entry["match"], labels))

    for i, entry in enumerate(data.get("rules", [])):
        where = f"rules[{i}]"
        _check_keys(where, entry, {"match", "action", "reason", "args", "rate_limit"})
        if "match" not in entry:
            raise PolicyError(f"{where}: 'match' is required")
        rule = Rule(index=i, match=entry["match"], reason=entry.get("reason", ""))
        rule.action = _choice(where, "action", entry.get("action", "allow"), ("allow", "deny"))
        if "rate_limit" in entry:
            try:
                rule.rate_limit = parse_rate(entry["rate_limit"])
            except ValueError as e:
                raise PolicyError(f"{where}: {e}") from e
            rule.rate_spec = entry["rate_limit"]
        for arg, spec in entry.get("args", {}).items():
            aw = f"{where}.args.{arg}"
            _check_keys(aw, spec, {"within", "deny", "allow", "max_length", "one_of", "required"})
            within = spec.get("within", [])
            rule.args[arg] = ArgConstraint(
                within=[within] if isinstance(within, str) else list(within),
                deny=_regexes(aw, spec.get("deny", [])),
                allow=_regexes(aw, spec.get("allow", [])),
                max_length=spec.get("max_length"),
                one_of=spec.get("one_of"),
                required=bool(spec.get("required", False)),
            )
        p.rules.append(rule)
    return p


def load(path: str | os.PathLike[str] | None = None) -> Policy:
    """Load a policy file; with no path, use $SLUICE_POLICY, ~/.sluice/policy.toml, or defaults."""
    if path is None:
        env = os.environ.get("SLUICE_POLICY")
        if env:
            path = env
        else:
            from sluice.store import sluice_home
            candidate = sluice_home() / "policy.toml"
            if not candidate.exists():
                return Policy()
            path = candidate
    p = Path(path).expanduser()
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PolicyError(f"policy file not found: {p}") from e
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{p}: invalid TOML: {e}") from e
    return from_dict(data, source=str(p))


DEFAULT_POLICY_TOML = r'''# Sluice policy -- https://github.com/premm25/sluice
#
# Tool patterns are globs. Prefix with "server:" to scope to one server,
# e.g. "github:create_*". The server name is the --name given to `sluice run`.

mode = "enforce"          # enforce | monitor (log what *would* be blocked, change nothing)
default_action = "allow"  # allow | deny  (deny = only tools matched by an allow rule may run)

[detect]
tool_poisoning = "block"     # quarantine tools whose descriptions carry injected instructions
output_injection = "warn"    # block | warn | off  -- prompt injection inside tool results
strip_hidden_unicode = true  # remove zero-width / bidi / Unicode-tag smuggling characters
redact_secrets = true        # redact API keys, tokens and private keys in tool results

[pinning]
enabled = true
on_change = "block"   # a tool whose definition changes is quarantined until `sluice pins approve`

[flow]
enabled = true
exfiltration = "block"  # private data (even base64/hex/url-encoded) in a sink's arguments
trifecta = "warn"       # any sink call once the session saw private AND untrusted data
min_matches = 2         # fingerprint matches required to call it a leak
auto_label = true       # guess labels for tools not listed under [[tools]]
split_detection = "block"  # private data trickled out in pieces across several sink calls
split_window = 600         # seconds of outbound history kept per destination (in memory only)
# Declassification: flows you *want* to allow, as "source_glob -> sink_glob".
allow_flows = [
  # "filesystem:* -> github:create_pull_request",
]

[record]
# Keeps tool definitions, call arguments (secrets redacted) and fingerprints of
# results -- never result text -- so `sluice learn` and `sluice replay` can work.
enabled = true
retain_days = 14

# ---- Capability labels -------------------------------------------------------
# private:   returns data that must not leave (files, mail, databases)
# untrusted: returns attacker-influenceable content (web pages, issues, inbox)
# sink:      can send data off the machine (HTTP, email, chat, PRs)

[[tools]]
match = "filesystem:read_*"
labels = ["private"]

[[tools]]
match = "fetch"
labels = ["untrusted", "sink"]

[[tools]]
match = "*send_*"
labels = ["sink"]

# ---- Rules -------------------------------------------------------------------

[[rules]]
match = "*delete*"
action = "deny"
reason = "destructive tools are disabled"

[[rules]]
match = "*read_file*"
[rules.args.path]
deny = ['(^|[\\/])\.ssh([\\/]|$)', '(^|[\\/])\.aws([\\/]|$)', '(^|[\\/])\.env$', 'id_(rsa|ed25519)']

[[rules]]
match = "*run_command*"
rate_limit = "20/minute"
[rules.args.command]
deny = ['rm\s+-rf\s+/', 'curl[^|]*\|\s*(ba|z)?sh', 'Invoke-Expression', 'mkfs', ':\(\)\s*\{']
max_length = 2000
'''
