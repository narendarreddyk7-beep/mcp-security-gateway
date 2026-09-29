"""Transparent MCP proxy over the stdio transport.

The agent launches the gateway as if it were the MCP server, passing the real
server command after `--`. The gateway spawns that server and pumps bytes in
both directions, recording every frame.

Two rules the rest of the project depends on:

1. Forwarding uses the original bytes. Parsing happens on a copy, for the audit
   log and (later) policy. A bug in our parser can never alter the stream.
2. Frames we cannot parse are forwarded and logged as unparsable. At this stage
   the proxy is transparent by design; refusing traffic is the policy engine's
   job, not the transport's.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Awaitable, Callable, Sequence

from gateway import decision as D
from gateway.audit.log import AuditLog
from gateway.proxy import jsonrpc
from gateway.proxy.jsonrpc import CLIENT_TO_SERVER, SERVER_TO_CLIENT, Message

# MCP payloads (file contents, page text) comfortably exceed asyncio's 64 KiB
# default line limit, which would raise LimitOverrunError mid-session.
STREAM_LIMIT = 16 * 1024 * 1024

# An interceptor sees a parsed message and returns a Decision: what to forward
# on, and what (if anything) to send back to the caller instead. A denial can
# never simply drop the frame - the agent is blocking on a JSON-RPC response
# and would hang - so the return path is part of the contract.
Interceptor = Callable[[str, Message], Awaitable["D.Decision"]]


async def passthrough(direction: str, message: Message) -> D.Decision:
    return D.allow(message.raw)


class StdioProxy:
    def __init__(
        self,
        server_cmd: Sequence[str],
        audit: AuditLog,
        session_id: str | None = None,
        interceptor: Interceptor = passthrough,
    ):
        self.server_cmd = list(server_cmd)
        self.audit = audit
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.interceptor = interceptor
        # msg_id -> method, so a response can be attributed to the request that
        # caused it. Needed to know a result belongs to tools/call.
        self._pending: dict[str, str] = {}

    async def run(self) -> int:
        proc = await asyncio.create_subprocess_exec(
            *self.server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherited: server logs pass straight through
            limit=STREAM_LIMIT,
        )
        assert proc.stdin and proc.stdout

        client_reader = await _stdin_reader()
        client_writer = await _stdout_writer()

        self.audit.append(
            session_id=self.session_id,
            direction="gateway",
            kind="session_start",
            payload={"server_cmd": self.server_cmd, "pid": proc.pid},
        )

        # Each pump gets a return path as well as a forward path, so a denied
        # client-to-server frame can be answered on the client's own channel.
        up = asyncio.create_task(
            self._pump(client_reader, proc.stdin, CLIENT_TO_SERVER, back=client_writer),
            name="c2s",
        )
        down = asyncio.create_task(
            self._pump(proc.stdout, client_writer, SERVER_TO_CLIENT, back=proc.stdin),
            name="s2c",
        )

        # Shutdown is asymmetric, and getting it wrong silently truncates
        # sessions. When the client closes its end we must close the server's
        # stdin and then drain whatever it still has to say - replies to
        # already-sent requests are in flight. Only when the server closes its
        # stdout is the session genuinely over.
        done, pending = await asyncio.wait(
            {up, down}, return_when=asyncio.FIRST_COMPLETED
        )

        if up in done and down in pending:
            if proc.stdin and not proc.stdin.is_closing():
                proc.stdin.close()
            try:
                await asyncio.wait_for(down, timeout=10)
            except asyncio.TimeoutError:
                down.cancel()
                await asyncio.gather(down, return_exceptions=True)
        else:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

        self.audit.append(
            session_id=self.session_id,
            direction="gateway",
            kind="session_end",
            payload={"returncode": proc.returncode},
        )
        return proc.returncode or 0

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer,  # asyncio.StreamWriter (to server) or _StdoutWriter (to client)
        direction: str,
        back=None,  # return path, for synthesised denials
    ) -> None:
        while True:
            try:
                line = await reader.readline()
            except (asyncio.LimitOverrunError, ValueError):
                # Frame past the stream limit. Record it: an oversized frame is
                # itself a signal, not something to swallow quietly.
                self.audit.append(
                    session_id=self.session_id,
                    direction=direction,
                    kind="oversize_frame",
                    payload={"limit": STREAM_LIMIT},
                )
                break
            if not line:
                break

            message = jsonrpc.parse(line)
            method = self._attribute(message, direction)

            started = time.perf_counter()
            decision = await self.interceptor(direction, message)
            latency_ms = (time.perf_counter() - started) * 1000

            self.audit.append(
                session_id=self.session_id,
                direction=direction,
                kind=message.kind,
                method=method,
                msg_id=message.msg_id,
                payload=message.audit_payload(),
                verdict=decision.action,
                rule_id=decision.rule_id,
                latency_ms=latency_ms,
            )

            if decision.respond is not None and back is not None:
                # The request never reaches the server. The caller gets an
                # error on the channel it was already waiting on.
                back.write(decision.respond)
                try:
                    await back.drain()
                except (BrokenPipeError, ConnectionResetError):
                    break

            if decision.forward is None:
                continue
            raw = decision.forward
            writer.write(raw if raw.endswith(b"\n") else raw + b"\n")
            try:
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                break

    def _attribute(self, message: Message, direction: str) -> str | None:
        """Carry the method name from a request onto its eventual response."""
        if message.kind == "request" and message.msg_id and message.method:
            self._pending[message.msg_id] = message.method
            return message.method
        if message.kind in ("response", "error") and message.msg_id:
            return self._pending.pop(message.msg_id, None)
        return message.method


class _StdoutWriter:
    """Writes to stdout from the event loop without touching asyncio private
    API. Earlier versions used asyncio.streams.FlowControlMixin via
    connect_write_pipe; that name is not public and moves between releases.
    Only the server-to-client pump writes here, so a single executor thread
    preserves ordering.
    """

    def __init__(self) -> None:
        self._fh = sys.stdout.buffer
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="stdout")

    def write(self, data: bytes) -> None:
        self._pending = data

    async def drain(self) -> None:
        data, self._pending = self._pending, b""
        if not data:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._pool, self._blocking_write, data)

    def _blocking_write(self, data: bytes) -> None:
        self._fh.write(data)
        self._fh.flush()

    _pending: bytes = b""


async def _stdin_reader() -> asyncio.StreamReader:
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=STREAM_LIMIT)
    await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )
    return reader


async def _stdout_writer() -> "_StdoutWriter":
    return _StdoutWriter()
