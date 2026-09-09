"""Best-effort resource limits for the restricted bridge subprocess."""

from __future__ import annotations

import os


def _positive_int(name: str) -> int | None:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return None
    return value if value > 0 else None


def _bounded_soft_limit(current: tuple[int, int], requested: int) -> tuple[int, int]:
    soft, hard = current
    if hard >= 0:
        requested = min(requested, hard)
    if soft >= 0:
        requested = min(requested, soft)
    return requested, hard


def apply_bridge_process_limits() -> dict[str, int | bool]:
    """Constrain address space and CPU time where the operating system supports it.

    Windows and restricted containers may not expose ``resource``. The Node control
    plane still enforces wall-clock, queue, input, and output limits in those cases.
    """

    memory_mb = _positive_int("OMNIKIT_ENGINE_MEMORY_MB")
    cpu_seconds = _positive_int("OMNIKIT_ENGINE_CPU_SECONDS")
    applied: dict[str, int | bool] = {"supported": False}
    try:
        import resource
    except ImportError:
        return applied

    applied["supported"] = True
    if memory_mb:
        memory_bytes = memory_mb * 1024 * 1024
        try:
            resource.setrlimit(
                resource.RLIMIT_AS,
                _bounded_soft_limit(resource.getrlimit(resource.RLIMIT_AS), memory_bytes),
            )
            applied["memory_mb"] = memory_mb
        except (OSError, ValueError):
            applied["memory_limit_applied"] = False
    if cpu_seconds:
        try:
            resource.setrlimit(
                resource.RLIMIT_CPU,
                _bounded_soft_limit(resource.getrlimit(resource.RLIMIT_CPU), cpu_seconds),
            )
            applied["cpu_seconds"] = cpu_seconds
        except (OSError, ValueError):
            applied["cpu_limit_applied"] = False
    return applied
