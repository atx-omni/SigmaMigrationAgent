"""Synthetic transport/process boundaries: no live services or credentials."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import httpx
import pytest

from omni_migrator.security.transport import (
    ByteBudget, ResourceLimitError, bounded_process, bounded_request, check_json_structure,
)


class CountedStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks, self.reads, self.closed = chunks, 0, False

    def __iter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    def close(self):
        self.closed = True


def client_for(stream, *, headers=None, status=200):
    def respond(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(status, headers=headers or {}, stream=stream)
    return httpx.Client(transport=httpx.MockTransport(respond))


@pytest.mark.parametrize("headers", [{}, {"content-length": "1"}])
def test_stream_limit_stops_consumption_early_and_closes(headers):
    stream = CountedStream([b"a" * 16 for _ in range(100)])
    with client_for(stream, headers=headers) as client:
        with pytest.raises(ResourceLimitError, match="size limit"):
            bounded_request(client, "GET", "https://example.invalid", max_bytes=64)
    assert stream.reads < 10 and stream.closed


def test_exact_limit_is_accepted_and_declared_oversize_is_never_read():
    stream = CountedStream([b"a" * 16] * 4)
    with client_for(stream) as client:
        assert len(bounded_request(client, "GET", "https://example.invalid", max_bytes=64).content) == 64
    stream = CountedStream([b"a"])
    with client_for(stream, headers={"content-length": "65"}) as client:
        with pytest.raises(ResourceLimitError):
            bounded_request(client, "GET", "https://example.invalid", max_bytes=64)
    assert stream.reads == 0 and stream.closed


@pytest.mark.parametrize("status", [200, 401, 429, 503])
def test_all_status_bodies_share_stream_limit(status):
    stream = CountedStream([b"private-content" * 10] * 100)
    with client_for(stream, status=status) as client:
        with pytest.raises(ResourceLimitError) as error:
            bounded_request(client, "POST", "https://example.invalid/token", max_bytes=64)
    assert "private-content" not in str(error.value)
    assert stream.reads == 1 and stream.closed


def test_compression_rejected_before_any_decoding_or_reading():
    stream = CountedStream([b"synthetic-compressed-bomb"])
    with client_for(stream, headers={"content-encoding": "gzip"}) as client:
        with pytest.raises(ResourceLimitError, match="Compressed"):
            bounded_request(client, "GET", "https://example.invalid")
    assert stream.reads == 0 and stream.closed


def test_aggregate_limit_survives_multiple_calls():
    budget = ByteBudget(max_bytes=8)
    for iteration in range(2):
        stream = CountedStream([b"12345"])
        with client_for(stream) as client:
            if iteration == 0:
                bounded_request(client, "GET", "https://example.invalid", budget=budget)
            else:
                with pytest.raises(ResourceLimitError, match="Aggregate"):
                    bounded_request(client, "GET", "https://example.invalid", budget=budget)
    assert budget.consumed == 10


def test_exhausted_aggregate_budget_blocks_before_next_request():
    stream = CountedStream([b"{}"])
    with client_for(stream) as client:
        with pytest.raises(ResourceLimitError, match="Aggregate"):
            bounded_request(client, "GET", "https://example.invalid", budget=ByteBudget(max_bytes=10, consumed=10))
    assert stream.reads == 0


def test_hard_deadline_covers_slow_headers_before_response_is_yielded():
    def handler(request):
        time.sleep(1)
        return httpx.Response(200, json={})
    before = time.monotonic()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ResourceLimitError, match="elapsed"):
            bounded_request(client, "GET", "https://example.invalid", timeout_seconds=0.03)
    assert time.monotonic() - before < 0.5


def test_hard_deadline_stops_tiny_trickling_chunks():
    class Trickle(CountedStream):
        def __iter__(self):
            for item in super().__iter__():
                time.sleep(0.01)
                yield item
    stream = Trickle([b" "] * 1000)
    with client_for(stream) as client:
        with pytest.raises(ResourceLimitError, match="elapsed"):
            bounded_request(client, "GET", "https://example.invalid", timeout_seconds=0.04)
    assert stream.reads < 15 and stream.closed


def test_deadline_restores_signal_handler_and_refuses_existing_alarm():
    previous = signal.getsignal(signal.SIGALRM)
    with client_for(CountedStream([b"{}"])) as client:
        bounded_request(client, "GET", "https://example.invalid")
    assert signal.getsignal(signal.SIGALRM) == previous
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        with client_for(CountedStream([b"{}"])) as client:
            with pytest.raises(ResourceLimitError, match="another timer"):
                bounded_request(client, "GET", "https://example.invalid")
        assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def test_elapsed_and_structural_limits_fail_before_parse():
    budget = ByteBudget(timeout_seconds=0)
    with client_for(CountedStream([b"{} "])) as client:
        with pytest.raises(ResourceLimitError, match="elapsed"):
            bounded_request(client, "GET", "https://example.invalid", budget=budget)
    with pytest.raises(ResourceLimitError, match="structure"):
        check_json_structure(b"[" * 65 + b"]" * 65)
    with pytest.raises(ResourceLimitError, match="structure"):
        check_json_structure(b"[0,0,0,0]", max_items=3)
    check_json_structure(b'{"value":"[[[[,\\\"[[[["}', max_depth=2)


def test_process_drains_both_pipes_without_deadlock():
    result = bounded_process([sys.executable, "-c", "import os;os.write(1,b'a'*8192);os.write(2,b'b'*8192)"], env=dict(os.environ))
    assert result.returncode == 0 and result.stdout == b"a" * 8192 and result.stderr == b"b" * 8192


@pytest.mark.parametrize("fd", [1, 2])
def test_process_limits_stdout_and_stderr_in_bytes(fd):
    with pytest.raises(ResourceLimitError, match="size"):
        bounded_process([sys.executable, "-c", f"import os;os.write({fd},b'x'*1000000)"],
                        env=dict(os.environ), stdout_limit=1024, stderr_limit=1024)


def test_process_timeout_kills_and_reaps_group(monkeypatch):
    real_popen = subprocess.Popen
    captured = []
    def launch(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        captured.append(child)
        assert kwargs["start_new_session"] is True
        return child
    monkeypatch.setattr(subprocess, "Popen", launch)
    before = time.monotonic()
    with pytest.raises(ResourceLimitError, match="elapsed"):
        bounded_process([sys.executable, "-c", "import time;time.sleep(10)"], env=dict(os.environ), timeout=0.1)
    assert time.monotonic() - before < 3
    assert captured[0].poll() is not None


def test_process_aggregate_budget_and_binary_output():
    with pytest.raises(ResourceLimitError, match="Aggregate"):
        bounded_process([sys.executable, "-c", "import os;os.write(1,b'\\xff'*9)"],
                        env=dict(os.environ), budget=ByteBudget(max_bytes=8))
