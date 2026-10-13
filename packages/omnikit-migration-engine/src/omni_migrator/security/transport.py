"""Bounded transport primitives; no response or process content in diagnostics.

HTTP compression is deliberately unsupported: byte ceilings apply to both wire and
decoded content without allocating an unbounded decompression buffer. Process
capture is supported only on POSIX, where a private process group can be reaped.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

RESPONSE_BYTES = 5 * 1024 * 1024
AGGREGATE_BYTES = 25 * 1024 * 1024
CHUNK_BYTES = 16 * 1024


class ResourceLimitError(ValueError):
    """A safe, content-free resource boundary diagnostic."""


@dataclass
class ByteBudget:
    max_bytes: int = AGGREGATE_BYTES
    consumed: int = 0
    timeout_seconds: float = 300.0
    _started: float = field(default_factory=time.monotonic, repr=False)

    def consume(self, size: int) -> None:
        if time.monotonic() - self._started > self.timeout_seconds:
            raise ResourceLimitError("Aggregate transfer elapsed-time limit exceeded")
        if size < 0 or self.max_bytes < 1:
            raise ResourceLimitError("Aggregate transfer size limit exceeded; narrow the capture")
        self.consumed += size
        if self.consumed > self.max_bytes or (size == 0 and self.consumed == self.max_bytes):
            raise ResourceLimitError("Aggregate transfer size limit exceeded; narrow the capture")

    @property
    def remaining_seconds(self) -> float:
        return self.timeout_seconds - (time.monotonic() - self._started)


@contextmanager
def _request_deadline(seconds: float):
    """Hard deadline also covers slowly trickling headers, not only yielded chunks.

The supported local runtime is POSIX/main-thread. Embedded/threaded callers or an
already active alarm fail closed rather than weaken another caller's deadline.
"""
    if os.name != "posix" or threading.current_thread() is not threading.main_thread():
        raise ResourceLimitError("Bounded HTTP execution requires the POSIX main thread")
    if any(signal.getitimer(signal.ITIMER_REAL)):
        raise ResourceLimitError("Cannot safely install the HTTP deadline while another timer is active")
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise ResourceLimitError("Response elapsed-time limit exceeded")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def check_json_structure(data: bytes | bytearray, *, max_depth: int = 64, max_items: int = 100_000) -> None:
    """Bound structural JSON work before decoding; the real parser checks syntax."""
    depth = items = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            items += 1
        elif byte in (125, 93):
            depth -= 1
        elif byte == 44:
            items += 1
        if depth > max_depth or items > max_items:
            raise ResourceLimitError("JSON structure limit exceeded; narrow the capture")


def bounded_request(
    client: httpx.Client,
    method: str,
    url: str | httpx.URL,
    *,
    budget: ByteBudget | None = None,
    max_bytes: int = RESPONSE_BYTES,
    timeout_seconds: float = 60.0,
    **request_kwargs: Any,
) -> httpx.Response:
    """Read at most the configured bytes before returning an inert buffered response.

    All statuses, including token/error/retry responses, use the same boundary.
    Content-Length is only an early-rejection hint; actual bytes are always counted.
    A main-thread POSIX timer enforces a total request deadline including headers.
    """
    if max_bytes < 1 or timeout_seconds <= 0:
        raise ValueError("Positive transport limits are required")
    if budget is not None:
        budget.consume(0)
        timeout_seconds = min(timeout_seconds, budget.remaining_seconds)
    headers = httpx.Headers(request_kwargs.pop("headers", {}))
    headers["Accept-Encoding"] = "identity"
    deadline = time.monotonic() + timeout_seconds
    request_kwargs["timeout"] = min(float(request_kwargs.get("timeout", timeout_seconds)), timeout_seconds)
    with _request_deadline(timeout_seconds), client.stream(method, url, headers=headers, **request_kwargs) as response:
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in {"", "identity"}:
            raise ResourceLimitError("Compressed responses are unsupported; no content was retained")
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                raise ResourceLimitError("Invalid response size header") from None
            if length < 0 or length > max_bytes:
                raise ResourceLimitError("Response size limit exceeded; narrow the capture")
            if budget is not None and length > budget.max_bytes - budget.consumed:
                raise ResourceLimitError("Aggregate transfer size limit exceeded; narrow the capture")
        output = bytearray()
        # Some injected test transports return already-buffered Response objects.
        # Do not set chunk_size: coalescing tiny chunks would postpone deadline
        # and byte checks while a peer slowly trickles data.
        chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
        for chunk in chunks:
            if time.monotonic() > deadline:
                raise ResourceLimitError("Response elapsed-time limit exceeded")
            if budget is not None:
                budget.consume(len(chunk))
            if len(output) + len(chunk) > max_bytes:
                raise ResourceLimitError("Response size limit exceeded; narrow the capture")
            output.extend(chunk)
        if time.monotonic() > deadline:
            raise ResourceLimitError("Response elapsed-time limit exceeded")
        check_json_structure(output)
        return httpx.Response(
            response.status_code, headers=response.headers, content=bytes(output),
            request=response.request, extensions=response.extensions,
        )


def bounded_process(
    args: list[str], *, env: dict[str, str], timeout: float = 30,
    stdout_limit: int = RESPONSE_BYTES, stderr_limit: int = 64 * 1024,
    budget: ByteBudget | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Drain both pipes concurrently, stop at byte/deadline limits, reap the group."""
    if os.name != "posix":
        raise ResourceLimitError("Bounded CLI execution requires a POSIX platform")
    if timeout <= 0 or min(stdout_limit, stderr_limit) < 1:
        raise ValueError("Positive process limits are required")
    if budget is not None:
        budget.consume(0)
        timeout = min(timeout, budget.remaining_seconds)
    process = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, close_fds=True,
    )
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                assert pipe is not None
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ResourceLimitError("CLI elapsed-time limit exceeded")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fd, CHUNK_BYTES)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output = outputs[key.data]
                    if budget is not None:
                        budget.consume(len(chunk))
                    if len(output) + len(chunk) > limits[key.data]:
                        raise ResourceLimitError("CLI output size limit exceeded")
                    output.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ResourceLimitError("CLI elapsed-time limit exceeded")
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise ResourceLimitError("CLI elapsed-time limit exceeded") from None
        return subprocess.CompletedProcess(args, returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]))
    finally:
        # Also stop descendants that outlive their parent or keep pipe handles open.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()
