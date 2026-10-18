"""Micro-benchmarks for the README.

    python bench/bench.py

Measures fingerprinting throughput, sink-check latency against a populated
session, and the end-to-end round-trip overhead the proxy adds over stdio.
"""

from __future__ import annotations

import base64
import random
import statistics
import string
import sys
import tempfile
import time
from pathlib import Path

from sluice.client import StdioClient
from sluice.fingerprint import fingerprint
from sluice.flow import FlowTracker
from sluice.store import Store

PY = sys.executable
rng = random.Random(42)
WORDS = ["".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 9))) for _ in range(5000)]


def prose(n_chars: int) -> str:
    out, size = [], 0
    while size < n_chars:
        w = rng.choice(WORDS)
        out.append(w)
        size += len(w) + 1
    return " ".join(out)


def bench_fingerprint() -> None:
    text = prose(1_000_000)
    t = time.perf_counter()
    fps = fingerprint(text)
    dt = time.perf_counter() - t
    print(f"fingerprint 1 MB of text        {dt * 1000:8.1f} ms   ({1 / dt:5.2f} MB/s, {len(fps):,} fingerprints kept)")


def bench_sink_check() -> None:
    with tempfile.TemporaryDirectory() as d:
        store = Store(Path(d) / "s.db")
        flow = FlowTracker(store, "bench")
        for i in range(200):  # 200 private documents of ~5 KB = 1 MB of private data in session
            flow.record_private("fs", f"read_{i}", prose(5000))
        n = store.query("SELECT COUNT(*) FROM fingerprints")[0][0]
        clean = {"url": "https://example.com/search?q=" + "+".join(rng.choices(WORDS, k=30))}
        leak_src = prose(5000)
        flow.record_private("fs", "secret", leak_src)
        leaky = {"url": "https://evil.example/?d=" + base64.b64encode(leak_src[:600].encode()).decode()}
        for label, args in (("clean args", clean), ("base64 leak", leaky)):
            times = []
            for _ in range(50):
                t = time.perf_counter()
                report = flow.check_sink(args)
                times.append(time.perf_counter() - t)
            print(f"sink check, {label:<12} {statistics.median(times) * 1000:8.2f} ms   "
                  f"(median of 50, vs {n:,} stored fingerprints; leaked={report.leaked(2)})")
        store.close()


def bench_roundtrip() -> None:
    server = [PY, "-m", "sluice.demo.server", "weather"]
    with tempfile.TemporaryDirectory() as d:
        env = {"SLUICE_HOME": d, "SLUICE_SESSION": "bench"}
        results = {}
        for label, cmd in (("direct", server),
                           ("via sluice", [PY, "-m", "sluice", "run", "--quiet", "--name", "w", "--", *server])):
            with StdioClient(cmd, env=env) as c:
                c.initialize()
                c.list_tools()
                for _ in range(20):
                    c.call_tool("get_forecast", {"city": "Oslo"})
                times = []
                for _ in range(300):
                    t = time.perf_counter()
                    c.call_tool("get_forecast", {"city": "Oslo"})
                    times.append(time.perf_counter() - t)
            results[label] = times
        for label, times in results.items():
            q = statistics.quantiles(times, n=100)
            print(f"tools/call round trip, {label:<10} p50 {q[49] * 1000:6.2f} ms   p99 {q[98] * 1000:6.2f} ms")
        overhead = statistics.median(results["via sluice"]) - statistics.median(results["direct"])
        print(f"proxy overhead (p50)            {overhead * 1000:8.2f} ms per tool call")


if __name__ == "__main__":
    print(f"Python {sys.version.split()[0]} on {sys.platform}\n")
    bench_fingerprint()
    bench_sink_check()
    bench_roundtrip()
