"""stdio transport: sit between an MCP client and a server subprocess.

    client (Claude Desktop, Cursor, ...)  <-stdin/stdout->  sluice  <-pipes->  real server

MCP's stdio transport is newline-delimited JSON-RPC. Two pump threads move
lines in each direction through the :class:`~sluice.engine.Engine`. The
server's stderr is inherited, so its logs still reach the client.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import Any, BinaryIO

from sluice.engine import Engine, Verdict, blocked_result

log = logging.getLogger("sluice")

SHUTDOWN_GRACE = 5.0


def resolve_command(cmd: list[str]) -> list[str]:
    """Resolve the executable via PATH (finds ``npx.cmd`` & co. on Windows)."""
    if not cmd:
        raise ValueError("no server command given")
    exe = shutil.which(cmd[0]) or cmd[0]
    return [exe, *cmd[1:]]


def encode(msg: Any) -> bytes:
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


class _Writer:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.lock = threading.Lock()
        self.closed = False

    def write(self, data: bytes) -> None:
        with self.lock:
            if self.closed:
                return
            try:
                self.stream.write(data)
                self.stream.flush()
            except (BrokenPipeError, OSError, ValueError):
                self.closed = True

    def close(self) -> None:
        with self.lock:
            self.closed = True
            try:
                self.stream.close()
            except OSError:
                pass


def _process_line(line: bytes, handler: Callable[[Any], Verdict], onward: _Writer,
                  back: _Writer, from_client: bool) -> None:
    raw = line.strip()
    if not raw:
        return
    try:
        msg = json.loads(raw)
    except ValueError:
        onward.write(raw + b"\n")  # not JSON-RPC: pass through untouched
        return
    try:
        verdict = handler(msg)
    except Exception:
        log.exception("sluice engine failure")
        if from_client and isinstance(msg, dict) and msg.get("method") == "tools/call" and "id" in msg:
            name = str((msg.get("params") or {}).get("name", "?"))
            back.write(encode(blocked_result(msg["id"], name, ["internal error while checking this call"])))
        else:
            onward.write(raw + b"\n")
        return
    for m in verdict.forward:
        onward.write(encode(m))
    for m in verdict.reply:
        back.write(encode(m))


def run_proxy(cmd: list[str], engine: Engine, stdin: BinaryIO | None = None,
              stdout: BinaryIO | None = None, env: dict[str, str] | None = None) -> int:
    client_in = stdin or sys.stdin.buffer
    client_out = _Writer(stdout or sys.stdout.buffer)
    proc = subprocess.Popen(
        resolve_command(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=None, env={**os.environ, **(env or {})}, bufsize=0,
    )
    assert proc.stdin is not None and proc.stdout is not None
    server_in = _Writer(proc.stdin)
    server_out = proc.stdout

    # In Sentinel enforce mode a tools/call waits for Sentinel's answer (and maybe a review), so each call is
    # checked on its own thread; everything else keeps its order on this one.
    concurrent_calls = getattr(engine.sentinel, "enforcing", False)

    def pump_client() -> None:
        try:
            for line in iter(client_in.readline, b""):
                if concurrent_calls and b'"tools/call"' in line:
                    threading.Thread(target=_process_line, name="sluice-call", daemon=True,
                                     args=(line, engine.from_client, server_in, client_out, True)).start()
                    continue
                _process_line(line, engine.from_client, server_in, client_out, from_client=True)
        finally:
            server_in.close()  # client went away: let the server shut down...
            try:
                proc.wait(timeout=SHUTDOWN_GRACE)
            except subprocess.TimeoutExpired:  # ...and make it, if it ignores EOF
                log.warning("server did not exit %ss after the client disconnected; terminating", SHUTDOWN_GRACE)
                proc.terminate()

    def pump_server() -> None:
        for line in iter(server_out.readline, b""):
            _process_line(line, engine.from_server, client_out, server_in, from_client=False)

    t_client = threading.Thread(target=pump_client, name="sluice-client", daemon=True)
    t_server = threading.Thread(target=pump_server, name="sluice-server", daemon=True)
    t_client.start()
    t_server.start()
    try:
        t_server.join()
    except KeyboardInterrupt:
        proc.terminate()
    return proc.wait()
