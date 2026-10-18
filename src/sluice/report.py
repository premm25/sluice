"""Self-contained HTML report of the audit log (``sluice audit report``)."""

from __future__ import annotations

import datetime as dt
import html
import json
from collections import Counter
from typing import Any

from sluice import __version__, audit
from sluice.store import Store

_CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;
--block:#c0362c;--warn:#b7791f;--allow:#2f7d4f;--info:#6b6b66;--accent:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ececea;--muted:#9a9a94;
--line:#2e2e2b;--block:#ef6f62;--warn:#e0b04f;--allow:#5fbf86;--info:#9a9a94;--accent:#8ea2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px}h1{font-size:22px;margin:0}
.sub{color:var(--muted);margin:4px 0 24px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.card span{color:var(--muted);font-size:12px}
h2{font-size:15px;margin:28px 0 10px}.table{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}td.n{font-variant-numeric:tabular-nums;color:var(--muted);white-space:nowrap}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff;background:var(--info)}
.block{background:var(--block)}.would_block,.warn{background:var(--warn)}.allow{background:var(--allow)}
.detail{color:var(--muted);font-size:12px;max-width:520px;word-break:break-word}
.ok{color:var(--allow)}.bad{color:var(--block)}
"""


def _summary(e: dict[str, Any]) -> str:
    d = e["detail"]
    if e["event"] == "call":
        return "; ".join(d.get("reasons", [])) or d.get("reason", "") or ", ".join(d.get("labels", []))
    if "findings" in d:
        return ", ".join(f"{f['code']} ({f['severity']})" for f in d["findings"])
    if "changed" in d:
        return "changed: " + ", ".join(d["changed"])
    return json.dumps(d)[:200] if d else ""


def render(store: Store, limit: int = 500) -> str:
    rows = audit.events(store, limit=limit)
    st = audit.stats(store)
    v = audit.verify(store)
    decisions = Counter(e["decision"] for e in rows)
    blocked_tools = Counter(e["tool"] for e in rows if e["decision"] == "block" and e["tool"])
    esc = html.escape

    cards = [
        ("events", st["total"]),
        ("blocked", st["by_decision"].get("block", 0)),
        ("warnings", st["by_decision"].get("warn", 0) + st["by_decision"].get("would_block", 0)),
        ("calls inspected", st["by_event"].get("call", 0)),
        ("poisoned tools", st["by_event"].get("tool_poisoning", 0)),
        ("rug pulls", st["by_event"].get("rug_pull", 0)),
    ]
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>Sluice Audit Report</title><style>{_CSS}</style></head><body><main>",
        "<h1>Sluice audit report</h1>",
        f"<p class=sub>Generated {dt.datetime.now().strftime('%Y-%m-%d %H:%M')} · sluice {__version__} · "
        + (f"<span class=ok>hash chain intact ({v.checked} entries)</span>" if v.ok else
           f"<span class=bad>hash chain BROKEN at entry {v.broken_at}: {esc(v.reason)}</span>") + "</p>",
        "<div class=cards>" + "".join(f"<div class=card><b>{n}</b><span>{esc(label)}</span></div>"
                                      for label, n in cards) + "</div>",
    ]
    if blocked_tools:
        out.append("<h2>Most-blocked tools</h2><div class=table><table><tr><th>Tool</th><th>Blocks</th></tr>")
        out += [f"<tr><td>{esc(t)}</td><td class=n>{c}</td></tr>" for t, c in blocked_tools.most_common(10)]
        out.append("</table></div>")
    out.append(f"<h2>Recent events <span class=sub>(last {len(rows)}; "
               + ", ".join(f"{k}: {c}" for k, c in decisions.most_common()) + ")</span></h2>")
    out.append("<div class=table><table><tr><th>#</th><th>Time</th><th>Server / tool</th><th>Event</th>"
               "<th>Decision</th><th>Detail</th></tr>")
    for e in reversed(rows):
        t = dt.datetime.fromtimestamp(e["ts"]).strftime("%m-%d %H:%M:%S")
        d = e["decision"] or "-"
        out.append(
            f"<tr><td class=n>{e['id']}</td><td class=n>{t}</td>"
            f"<td>{esc(str(e['server']))}/<b>{esc(str(e['tool'] or '-'))}</b></td><td>{esc(e['event'])}</td>"
            f"<td><span class='pill {esc(d)}'>{esc(d)}</span></td>"
            f"<td class=detail>{esc(_summary(e))}</td></tr>")
    out.append("</table></div></main></body></html>")
    return "\n".join(out)
