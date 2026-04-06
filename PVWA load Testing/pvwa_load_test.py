#!/usr/bin/env python3
"""
pvwa_load_test.py — CyberArk PVWA API async load-testing tool for Python 3.14.

Authenticates to the CyberArk PVWA REST API using a single session (one login,
one logoff) and continuously fires parallel account-list requests to simulate
concurrent load. Requests run indefinitely until you press Ctrl+C.

Key behaviors:
  - Thread concurrency ramps from start_thread_count up to max_thread_count,
    adding one slot every ramp_up_sec seconds via asyncio.Semaphore.
  - Each request uses a random page size (between min_limit and max_limit).
  - Results are written to a rolling log file (RotatingFileHandler).
  - Individual task failures are self-healing — replacement queued immediately.
  - A single shared httpx.AsyncClient provides connection-pool reuse.

Requires: CyberArk-Common/cyberark_common.py
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import logging.handlers
import pathlib
import random
import signal
import sys
import time
from dataclasses import dataclass, field

_HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(_HERE.parent / "CyberArk-Common"))

from cyberark_common import (  # noqa: E402
    LogConfig,
    RestConfig,
    configure_logging,
    join_exception_message,
    logoff,
    logon,
    write_log,
)

import httpx  # noqa: E402


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class LoadTestConfig:
    pvwa_url: str
    username: str
    password: str
    max_log_size_mb: int = 100
    timeout_sec: int = 60
    warn_after_sec: int = 5
    start_thread_count: int = 1
    max_thread_count: int = 10
    ramp_up_sec: int = 30
    queue_depth: int = 100
    min_limit: int = 100
    max_limit: int = 1000


@dataclass(slots=True)
class RequestResult:
    thread_id: int
    success: bool
    returned: int
    total: int
    limit: int
    duration: float
    error: str | None = None


# ---------------------------------------------------------------------------
# Logging setup (separate from cyberark_common — rotating file + console)
# ---------------------------------------------------------------------------
def setup_load_test_logger(log_path: pathlib.Path, max_bytes: int) -> logging.Logger:
    """
    Set up a dedicated logger for the load tester.
    Uses RotatingFileHandler with backup_count=1 (mirrors .old archive behaviour).
    """
    logger = logging.getLogger("pvwa_load_test")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(ch)

    # Rotating file
    fh = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=1,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s : %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(fh)

    return logger


_lt_logger: logging.Logger | None = None


def _log(msg: str) -> None:
    if _lt_logger:
        _lt_logger.info(msg)


# ---------------------------------------------------------------------------
# Async request worker
# ---------------------------------------------------------------------------
async def fetch_accounts(
    client: httpx.AsyncClient,
    uri: str,
    token: str,
    thread_id: int,
    limit: int,
    timeout: float,
) -> RequestResult:
    """
    Single async GET to /Accounts?limit=N.
    Measures wall-clock duration with time.perf_counter().
    Returns RequestResult; never raises — all exceptions produce success=False.
    """
    start = time.perf_counter()
    try:
        response = await client.get(
            f"{uri}?limit={limit}",
            headers={"Authorization": token},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        duration = round(time.perf_counter() - start, 2)
        return RequestResult(
            thread_id=thread_id,
            success=True,
            returned=len(data.get("value", [])),
            total=int(data.get("count", 0)),
            limit=limit,
            duration=duration,
        )
    except Exception as exc:
        duration = round(time.perf_counter() - start, 2)
        return RequestResult(
            thread_id=thread_id,
            success=False,
            returned=0,
            total=0,
            limit=limit,
            duration=duration,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Ramp controller coroutine
# ---------------------------------------------------------------------------
async def ramp_controller(
    semaphore: asyncio.Semaphore,
    cfg: LoadTestConfig,
    *,
    done_event: asyncio.Event,
) -> None:
    """
    Coroutine that releases one additional semaphore slot every ramp_up_sec
    until max_thread_count is reached. Exits when done_event is set.
    """
    current = cfg.start_thread_count
    while current < cfg.max_thread_count and not done_event.is_set():
        await asyncio.sleep(cfg.ramp_up_sec)
        if done_event.is_set():
            break
        current += 1
        semaphore.release()  # expand capacity: increments _value and wakes waiters
        msg = f"RAMP | Thread count increased to {current}/{cfg.max_thread_count}"
        _log(msg)
        print(f"\033[33m{msg}\033[0m")


# ---------------------------------------------------------------------------
# Guarded fetch (acquires semaphore slot)
# ---------------------------------------------------------------------------
async def _guarded_fetch(
    client: httpx.AsyncClient,
    uri: str,
    token: str,
    job_id: int,
    limit: int,
    semaphore: asyncio.Semaphore,
    cfg: LoadTestConfig,
) -> RequestResult:
    async with semaphore:
        return await fetch_accounts(client, uri, token, job_id, limit, cfg.timeout_sec)


# ---------------------------------------------------------------------------
# Result logger
# ---------------------------------------------------------------------------
def _log_result(
    result: RequestResult,
    completed: int,
    queue_size: int,
    current_concurrency: int,
    cfg: LoadTestConfig,
) -> None:
    if not result.success:
        msg = (
            f"FAILURE | Thread: {result.thread_id} | Duration: {result.duration}s "
            f"| Error: {result.error}"
        )
        _log(msg)
        print(f"\033[31m{msg}\033[0m")
        return

    msg = (
        f"SUCCESS | Thread: {result.thread_id} | Limit: {result.limit} "
        f"| Returned: {result.returned} | Total: {result.total} "
        f"| Duration: {result.duration}s | Completed: {completed} "
        f"| QueueSize: {queue_size} | Concurrency: {current_concurrency}/{cfg.max_thread_count}"
    )
    _log(msg)
    print(f"\033[36m{msg}\033[0m")

    if result.duration > cfg.warn_after_sec:
        warn_msg = (
            f"WARNING | Thread: {result.thread_id} | Slow response: {result.duration}s "
            f"exceeded threshold of {cfg.warn_after_sec}s"
        )
        _log(warn_msg)
        print(f"\033[33m{warn_msg}\033[0m")


# ---------------------------------------------------------------------------
# Main async load test loop
# ---------------------------------------------------------------------------
async def run_load_test(cfg: LoadTestConfig, token: str) -> None:
    """
    Main async loop.
    - Pre-loads queue_depth tasks.
    - As each task completes, logs result and queues a replacement (self-healing).
    - Runs until asyncio.CancelledError (Ctrl+C).
    - Semaphore enforces current concurrency; ramp_controller grows it.
    - Single shared AsyncClient with connection pooling.
    """
    base_url = cfg.pvwa_url.rstrip("/") + "/API"
    account_uri = f"{base_url}/Accounts"
    semaphore = asyncio.Semaphore(cfg.start_thread_count)
    done_event = asyncio.Event()

    async with httpx.AsyncClient(
        timeout=cfg.timeout_sec,
        verify=True,
        limits=httpx.Limits(max_connections=cfg.max_thread_count + 10, max_keepalive_connections=cfg.max_thread_count),
    ) as client:
        tasks: set[asyncio.Task] = set()
        job_id = 0
        completed = 0
        current_concurrency = cfg.start_thread_count

        def spawn() -> None:
            nonlocal job_id
            job_id += 1
            limit = random.randint(cfg.min_limit, cfg.max_limit)
            task = asyncio.create_task(
                _guarded_fetch(client, account_uri, token, job_id, limit, semaphore, cfg),
                name=f"job-{job_id}",
            )
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        # Pre-load queue
        for _ in range(cfg.queue_depth):
            spawn()

        ramp_task = asyncio.create_task(
            ramp_controller(semaphore, cfg, done_event=done_event)
        )

        try:
            while True:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for future in done:
                    try:
                        result: RequestResult = future.result()
                    except Exception as exc:
                        result = RequestResult(
                            thread_id=-1, success=False, returned=0, total=0,
                            limit=0, duration=0.0, error=str(exc)
                        )
                    completed += 1
                    # Update current concurrency from semaphore state
                    current_concurrency = min(
                        cfg.max_thread_count,
                        cfg.start_thread_count + max(0, semaphore._value - cfg.start_thread_count)  # type: ignore[attr-defined]
                    )
                    _log_result(result, completed, len(tasks), current_concurrency, cfg)
                    spawn()  # self-healing: always replace

        except asyncio.CancelledError:
            done_event.set()
            ramp_task.cancel()
            for t in list(tasks):
                t.cancel()
            # Collect remaining with ExceptionGroup handling
            errors: list[Exception] = []
            for t in list(tasks):
                try:
                    await t
                except (asyncio.CancelledError, Exception) as e:
                    if not isinstance(e, asyncio.CancelledError):
                        errors.append(e)
            if errors:
                raise ExceptionGroup("load test shutdown errors", errors)
            raise


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CyberArk PVWA API load-testing tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pvwa-url", required=True,
                        help="PVWA URL including /PasswordVault (e.g. https://pvwa.lab/PasswordVault)")
    parser.add_argument("--username", required=True, help="CyberArk username")
    parser.add_argument("--password", help="Password (prompted if omitted)")
    parser.add_argument("--max-log-size-mb", type=int, default=100,
                        help="Maximum log file size in MB before rotation (default: 100)")
    parser.add_argument("--timeout-sec", type=int, default=60,
                        help="HTTP request timeout in seconds (default: 60)")
    parser.add_argument("--warn-after-sec", type=int, default=5,
                        help="Warn if response exceeds this many seconds (default: 5)")
    parser.add_argument("--start-thread-count", type=int, default=1,
                        help="Initial concurrency level (default: 1)")
    parser.add_argument("--max-thread-count", type=int, default=10,
                        help="Maximum concurrency level (default: 10)")
    parser.add_argument("--ramp-up-sec", type=int, default=30,
                        help="Seconds between each concurrency increment (default: 30)")
    parser.add_argument("--queue-depth", type=int, default=100,
                        help="Number of jobs to pre-load (default: 100)")
    parser.add_argument("--min-limit", type=int, default=100,
                        help="Minimum ?limit= value per request (default: 100)")
    parser.add_argument("--max-limit", type=int, default=1000,
                        help="Maximum ?limit= value per request (default: 1000)")
    parser.add_argument("--log-file", type=pathlib.Path,
                        default=_HERE / "CyberArk_Performance.log",
                        help="Log file path (default: CyberArk_Performance.log in script dir)")
    return parser


def main() -> None:
    global _lt_logger

    parser = _build_arg_parser()
    args = parser.parse_args()

    if not args.password:
        import getpass
        args.password = getpass.getpass(f"Password for {args.username}: ")

    if args.max_thread_count < args.start_thread_count:
        parser.error(f"--max-thread-count ({args.max_thread_count}) must be >= --start-thread-count ({args.start_thread_count})")
    if args.max_limit < args.min_limit:
        parser.error(f"--max-limit ({args.max_limit}) must be >= --min-limit ({args.min_limit})")

    # Set up logger
    _lt_logger = setup_load_test_logger(
        args.log_file,
        max_bytes=args.max_log_size_mb * 1024 * 1024,
    )

    cfg = LoadTestConfig(
        pvwa_url=args.pvwa_url,
        username=args.username,
        password=args.password,
        max_log_size_mb=args.max_log_size_mb,
        timeout_sec=args.timeout_sec,
        warn_after_sec=args.warn_after_sec,
        start_thread_count=args.start_thread_count,
        max_thread_count=args.max_thread_count,
        ramp_up_sec=args.ramp_up_sec,
        queue_depth=args.queue_depth,
        min_limit=args.min_limit,
        max_limit=args.max_limit,
    )

    # Sync logon
    rest_cfg = RestConfig(timeout=float(args.timeout_sec))
    configure_logging(LogConfig())  # minimal console logging for logon/logoff messages

    try:
        logon_header = logon(
            args.pvwa_url,
            args.username,
            args.password,
            cfg=rest_cfg,
        )
        token = logon_header["Authorization"]
    except Exception as exc:
        _log(f"FATAL | Login failed: {join_exception_message(exc)}")
        sys.exit(1)

    _log(
        f"LOGIN | User: {args.username} | StartThreads: {args.start_thread_count} "
        f"| MaxThreads: {args.max_thread_count} | RampUpSec: {args.ramp_up_sec} "
        f"| QueueDepth: {args.queue_depth}"
    )
    print(
        f"\033[32mLogged in as '{args.username}'. "
        f"Starting at {args.start_thread_count} thread(s), ramping to {args.max_thread_count} "
        f"every {args.ramp_up_sec}s. Pre-loading {args.queue_depth} jobs...\033[0m"
    )

    # Windows Ctrl+C handling for asyncio
    if sys.platform == "win32":
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        asyncio.run(run_load_test(cfg, token))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    except ExceptionGroup as eg:
        for exc in eg.exceptions:
            _log(f"FATAL | {exc}")
    except Exception as exc:
        _log(f"FATAL | {exc}")

    # Sync logoff
    try:
        logoff(args.pvwa_url, {"Authorization": token}, cfg=rest_cfg)
        _log("LOGOFF | Session closed successfully")
        print("\033[32mLogged off successfully.\033[0m")
    except Exception as exc:
        print(f"\033[33mLogoff failed: {exc}\033[0m")


if __name__ == "__main__":
    main()
