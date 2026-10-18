"""Minimal synchronous MCP stdio client (used by ``sluice scan``, the demo and tests)."""

from __future__ import annotations

import itertools
import json
import os
import queue
import subprocess
import threading
from typing import Any

from sluice import __version__
from sluice.proxy import encode, resolve_command

PROTOCOL_VERSION = "2025-06-18"


class McpError(RuntimeError):
    def __init__(self, error: dict[str, Any]):
        super().__init__(f"{error.get('code')}: {error.get('message')}")
        self.error = error


class StdioClient:
    def __init__(self, cmd: list[str], env: dict[str, str] | None = None, cwd: str | None = None):
        self.proc = subprocess.Popen(
            resolve_command(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, **(env or {})}, cwd=cwd, bufsize=0,
        )
        self._ids = itertools.count(1)
        self._waiting: dict[Any, queue.Queue[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self.notifications: list[dict[str, Any]] = []
        self.stderr_lines: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in iter(self.proc.stdout.readline, b""):
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and "id" in msg and "method" not in msg:
                with self._lock:
                    q = self._waiting.get(msg["id"])
                if q:
                    q.put(msg)
            elif isinstance(msg, dict) and "method" in msg and "id" in msg:
                # server->client request we don't support (sampling, roots...)
                self._send({"jsonrpc": "2.0", "id": msg["id"],
                            "error": {"code": -32601, "message": "not supported by sluice client"}})
            else:
                self.notifications.append(msg)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in iter(self.proc.stderr.readline, b""):
            self.stderr_lines.append(line.decode("utf-8", "replace").rstrip())

    def _send(self, msg: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(encode(msg))
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 15) -> Any:
        msg_id = next(self._ids)
        q: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            self._waiting[msg_id] = q
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self._send(msg)
            try:
                reply = q.get(timeout=timeout)
            except queue.Empty:
                if self.proc.poll() is not None:
                    tail = "\n".join(self.stderr_lines[-5:])
                    raise TimeoutError(f"server exited (code {self.proc.returncode}) during {method}\n{tail}") from None
                raise TimeoutError(f"timed out after {timeout}s waiting for {method}") from None
        finally:
            with self._lock:
                self._waiting.pop(msg_id, None)
        if "error" in reply:
            raise McpError(reply["error"])
        return reply.get("result")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def initialize(self, timeout: float = 15) -> Any:
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "sluice", "version": __version__},
        }, timeout=timeout)
        self.notify("notifications/initialized")
        return result

    def list_tools(self, timeout: float = 15) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = None
        for _ in range(100):
            result = self.request("tools/list", {"cursor": cursor} if cursor else {}, timeout=timeout)
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None, timeout: float = 30) -> Any:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def __enter__(self) -> StdioClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def result_text(result: Any) -> str:
    """Concatenate the text content of a tools/call result."""
    if not isinstance(result, dict):
        return ""
    return "\n".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
