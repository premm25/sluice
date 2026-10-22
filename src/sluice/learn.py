"""``sluice learn``: generate a least-privilege policy from recorded traffic.

Run your agent behind Sluice for a while (monitor mode is fine), then
``sluice learn`` writes a policy that allows what the agent actually did and
nothing else -- the way ``audit2allow`` turns SELinux denials into rules:

* ``default_action = "deny"``: tools never used while learning are blocked
* one ``[[rules]]`` entry per used tool, with argument constraints inferred
  from observed values: ``within`` for file paths, a host allowlist for URLs,
  and (``--strict``) ``one_of`` for low-cardinality arguments
* a burst ``rate_limit`` at 3x the observed peak, to stop runaway loops
* explicit ``[[tools]]`` labels, so the guesses become reviewable config

Safety rule: learning never weakens flow control by itself. Calls that were
stopped as exfiltration, split exfiltration or quarantine are *excluded*, and
any private->sink flows seen are written as commented-out ``allow_flows``
suggestions for a human to review. An attack during the learning window must
not be turned into an allow rule.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any
from urllib.parse import urlsplit

from sluice import __version__
from sluice.policy import Policy
from sluice.recording import Event

# Violations a call may have had and still be learned from: they only say the
# old policy was stricter than what we are about to generate.
TOLERATED = {"default_deny", "rate_limit", "lethal_trifecta"}
FLOW_CODES = {"exfiltration", "split_exfiltration"}
MAX_DIRS = 6
API_HOSTS = 5       # <= this many distinct hosts looks like API use -> allowlist them
MAX_HOSTS = 30      # hard cap even in --strict
ENUM_MAX = 5


def _toml(value: str) -> str:
    # JSON string escapes are valid TOML basic-string escapes (non-ASCII kept as-is).
    return json.dumps(value, ensure_ascii=False)


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml(v) for v in values) + "]"


_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def looks_like_path(value: str) -> bool:
    if not value or len(value) > 1024 or "\n" in value or ("://" in value and not value.startswith("file://")):
        return False
    return (value.startswith(("~", "/", "./", "../", "file://", "\\\\"))
            or bool(_DRIVE_RE.match(value)))


def looks_like_url(value: str) -> bool:
    parts = urlsplit(value) if "://" in value else None
    return bool(parts and parts.scheme in ("http", "https", "ws", "wss") and parts.netloc)


def _is_ancestor(parent: str, child: str) -> bool:
    try:
        return os.path.commonpath([parent, child]) == parent
    except ValueError:
        return False


def cover_directories(paths: list[str]) -> list[str]:
    """Smallest set of directories containing every observed path (never broader than needed)."""
    dirs: dict[str, str] = {}
    for p in paths:
        if p.startswith("file://"):
            p = p[len("file://"):]
        full = os.path.abspath(os.path.expanduser(p))
        d = full if os.path.isdir(full) else os.path.dirname(full)
        dirs.setdefault(os.path.normcase(d), d)
    keys = sorted(dirs)
    minimal = [k for k in keys if not any(o != k and _is_ancestor(o, k) for o in keys)]
    if len(minimal) > MAX_DIRS:
        try:
            common = os.path.commonpath(minimal)
        except ValueError:
            common = ""
        if common and len(PurePath(common).parts) >= 3:  # never widen to "/home" or "C:\\Users"
            return [dirs.get(common, common)]
    return [dirs[k] for k in minimal]


def _arg_values(args: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Leaves addressable by the policy's dotted-path syntax (lists are not addressable)."""
    out: list[tuple[str, Any]] = []
    if isinstance(args, dict):
        for k, v in args.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.extend(_arg_values(v, path))
            elif not isinstance(v, list):
                out.append((path, v))
    return out


def peak_per_minute(timestamps: list[float]) -> int:
    ts = sorted(timestamps)
    best, start = 0, 0
    for end, t in enumerate(ts):
        while t - ts[start] > 60:
            start += 1
        best = max(best, end - start + 1)
    return best


@dataclass
class ToolPlan:
    server: str
    tool: str
    calls: list[Event] = field(default_factory=list)
    labels: set[str] = field(default_factory=set)
    args: dict[str, dict[str, Any]] = field(default_factory=dict)
    comments: dict[str, str] = field(default_factory=dict)
    rate: str = ""
    peak: int = 0


@dataclass
class LearnResult:
    toml: str
    calls: int
    sessions: int
    tools: list[ToolPlan]
    excluded: Counter[str]
    suggestions: list[str]
    unused: list[str]


def infer_args(calls: list[Event], strict: bool) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    values: dict[str, list[Any]] = defaultdict(list)
    for ev in calls:
        for key, value in _arg_values(ev.args):
            values[key].append(value)
    constraints: dict[str, dict[str, Any]] = {}
    comments: dict[str, str] = {}
    for key, vals in sorted(values.items()):
        strs = [v for v in vals if isinstance(v, str)]
        if not strs or len(strs) != len(vals):
            continue
        if all(looks_like_path(v) for v in strs):
            constraints[key] = {"within": cover_directories(strs)}
            continue
        if all(looks_like_url(v) for v in strs):
            hosts = sorted({urlsplit(v).netloc.lower() for v in strs})
            schemes = sorted({urlsplit(v).scheme.lower() for v in strs})
            if len(hosts) <= (MAX_HOSTS if strict else API_HOSTS):
                host_re = "|".join(re.escape(h) for h in hosts)
                scheme_re = schemes[0] if len(schemes) == 1 else "(" + "|".join(schemes) + ")"
                constraints[key] = {"allow": [f"^{scheme_re}://({host_re})([/?#]|$)"]}
                comments[key] = "hosts seen: " + ", ".join(hosts)
            else:
                comments[key] = (f"{len(hosts)} distinct hosts seen (general browsing?): not allowlisted"
                                 + ("" if strict else "; use --strict to allowlist them"))
            continue
        distinct = sorted(set(strs))
        if (strict and len(strs) >= 3 and len(distinct) <= ENUM_MAX and len(distinct) < len(strs)
                and all(len(v) <= 64 for v in distinct)):
            constraints[key] = {"one_of": distinct}
    return constraints, comments


_SOURCE_RE = re.compile(r"private source ([\w.\-/:, ]+?)(?: \(| is being|$)")


def learn(events: list[Event], base: Policy, *, strict: bool = False, default_action: str = "deny") -> LearnResult:
    definitions: dict[tuple[str, str], dict[str, Any]] = {}
    plans: dict[tuple[str, str], ToolPlan] = {}
    excluded: Counter[str] = Counter()
    suggestions: set[str] = set()
    sessions: set[str] = set()
    included = 0

    for ev in events:
        if ev.kind == "list":
            for t in ev.data.get("tools", []):
                if isinstance(t, dict) and t.get("name"):
                    definitions[(ev.server, str(t["name"]))] = t
            continue
        if ev.kind != "call" or not ev.tool:
            continue
        codes = set(ev.codes)
        if codes & FLOW_CODES:
            excluded["data-flow violation"] += 1
            for reason in ev.data.get("reasons", []):
                for m in _SOURCE_RE.finditer(reason):
                    for src in m.group(1).split(","):
                        server, _, tool = src.strip().partition("/")
                        if server and tool:
                            suggestions.add(f"{server}:{tool} -> {ev.server}:{ev.tool}")
            continue
        if ev.decision in ("block", "would_block") and codes - TOLERATED:
            excluded[", ".join(sorted(codes - TOLERATED))] += 1
            continue
        included += 1
        sessions.add(ev.session)
        plan = plans.setdefault((ev.server, ev.tool), ToolPlan(ev.server, ev.tool))
        plan.calls.append(ev)

    for (server, tool), plan in plans.items():
        plan.labels = base.labels_for(server, tool, definitions.get((server, tool)))
        plan.args, plan.comments = infer_args(plan.calls, strict)
        plan.peak = peak_per_minute([c.ts for c in plan.calls])
        plan.rate = f"{max(10, plan.peak * 3)}/minute"

    used = set(plans)
    unused = sorted(f"{s}:{t}" for (s, t) in definitions if (s, t) not in used)
    ordered = [plans[k] for k in sorted(plans)]
    text = _render(ordered, base, default_action, events, included, len(sessions), excluded,
                   sorted(suggestions), unused)
    return LearnResult(text, included, len(sessions), ordered, excluded, sorted(suggestions), unused)


def _render(plans: list[ToolPlan], base: Policy, default_action: str, events: list[Event], included: int,
            sessions: int, excluded: Counter[str], suggestions: list[str], unused: list[str]) -> str:
    calls = [e for e in events if e.kind == "call"]
    span = ""
    if calls:
        fmt = "%Y-%m-%d %H:%M"
        span = (f" between {dt.datetime.fromtimestamp(calls[0].ts).strftime(fmt)}"
                f" and {dt.datetime.fromtimestamp(calls[-1].ts).strftime(fmt)}")
    out = [
        f"# Generated by `sluice learn` (sluice {__version__}) on {dt.datetime.now():%Y-%m-%d %H:%M}",
        f"# from {included} tool call(s) in {sessions} session(s){span}.",
        "# Review it, then check what it would change with:  sluice replay --policy <this file>",
        "",
        'mode = "enforce"',
        f'default_action = "{default_action}"' + ("   # tools not seen while learning are blocked"
                                                    if default_action == "deny" else ""),
        "",
        "[flow]",
        f'exfiltration = "{base.flow.exfiltration}"',
        f'trifecta = "{base.flow.trifecta}"',
        f'split_detection = "{base.flow.split_detection}"',
    ]
    if base.flow.allow_flows:
        out.append(f"allow_flows = {_toml_list(base.flow.allow_flows)}")
    if suggestions:
        out += ["# Private -> sink flows were BLOCKED while learning. They are NOT allowed here.",
                "# If (and only if) they were legitimate, uncomment the ones you need:",
                "# allow_flows = ["]
        out += [f"#   {_toml(s)}," for s in suggestions]
        out.append("# ]")
    if excluded:
        out += ["", "# Calls not learned from (they were stopped for these reasons):"]
        out += [f"#   {n:>4}  {reason}" for reason, n in excluded.most_common()]
    if unused:
        shown = ", ".join(unused[:12]) + (" …" if len(unused) > 12 else "")
        out += ["", f"# Advertised but never used (denied by default_action): {shown}"]

    labelled = [p for p in plans if p.labels]
    if labelled:
        out += ["", "# ---- Capability labels (auto-detected: review these) ----"]
    for p in labelled:
        out += ["", "[[tools]]", f"match = {_toml(f'{p.server}:{p.tool}')}", f"labels = {_toml_list(sorted(p.labels))}"]

    out += ["", "# ---- Rules learned from observed calls ----"]
    for p in plans:
        out += ["", "[[rules]]",
                f"match = {_toml(f'{p.server}:{p.tool}')}   # {len(p.calls)} call(s)",
                f'rate_limit = "{p.rate}"   # observed peak {p.peak}/minute']
        for key in sorted(set(p.args) | set(p.comments)):
            spec = p.args.get(key)
            if spec is None:
                out.append(f"# {key}: {p.comments[key]}")
                continue
            out.append(f"[rules.args.{_toml(key) if not re.fullmatch(r'[A-Za-z0-9_]+', key) else key}]")
            for name, value in spec.items():
                out.append(f"{name} = {_toml_list(value)}")
            if key in p.comments:
                out.append(f"# {p.comments[key]}")
    return "\n".join(out) + "\n"
