"""Shared helpers for the feed-fetch scripts.

Every fetch_*.py script writes one file to data/raw/<feed>.json using
write_raw() below. build_snapshot.py then merges those raw files (plus
the previous data/latest.json, for fallback on error) into the single
snapshot the frontend reads. Keeping this contract in one place avoids
six copies of the same "write JSON, stamp status/timestamp" logic.
"""

import contextlib
import datetime
import json
import os
import signal
import tempfile
import threading
import time
from urllib.parse import urlparse

import requests

RAW_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "raw")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_raw(feed_name, items, error=None):
    """Write data/raw/<feed_name>.json.

    status is only "error" when there is no usable data at all (items is
    empty) — a partial failure (e.g. one of several sub-lists in a feed
    failing) can still carry an `error` note while status stays "ok", so
    build_snapshot.py surfaces the warning without discarding good data.
    """
    os.makedirs(RAW_DIR, exist_ok=True)
    items = items or []
    status = "error" if (error and not items) else "ok"
    payload = {
        "status": status,
        "fetched_at": now_iso(),
        "count": len(items),
        "items": items,
    }
    if error:
        payload["error"] = str(error)
    path = os.path.join(RAW_DIR, f"{feed_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return payload


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_atomic(path, text):
    """Write `text` to `path` via a temp file in the same directory and
    os.replace(), so an interrupted run never leaves a half-written file:
    readers see either the old file or the new one."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class DeadlineExceeded(Exception):
    """A download ran past its wall-clock deadline. Deliberately not an
    OSError, so urllib3 / requests don't rewrap it as a connection error."""


def fetch_capped(url, max_bytes, deadline_s, headers=None, timeout=30, chunk_size=64 * 1024):
    """GET `url` and return the body as bytes, with limits the plain
    requests.get(url).content pattern lacks:

    - The body is streamed and abandoned once it passes `max_bytes`, so an
      oversized response never sits in memory whole. (A declared
      Content-Length over the cap is rejected before reading.)
    - `timeout` is per socket operation; `deadline_s` bounds the whole
      request, so a server trickling bytes can't stall the step. On Unix
      main threads it's enforced with SIGALRM, which also interrupts a read
      that is blocked; elsewhere it's checked between chunks.
    - The request and every redirect hop must be https.

    Raises requests exceptions, DeadlineExceeded, or ValueError.
    """

    def check_https(u):
        if urlparse(u or "").scheme != "https":
            raise ValueError(f"refusing non-https URL {u!r}")

    @contextlib.contextmanager
    def alarm():
        if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
            yield
            return

        def on_alarm(signum, frame):
            raise DeadlineExceeded(f"{url}: no complete response within {deadline_s}s")

        old = signal.signal(signal.SIGALRM, on_alarm)
        signal.setitimer(signal.ITIMER_REAL, deadline_s)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    check_https(url)
    start = time.monotonic()
    with alarm():
        resp = requests.get(url, headers=headers, timeout=timeout, stream=True)
        try:
            for hop in list(resp.history) + [resp]:
                check_https(hop.url)
            resp.raise_for_status()
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ValueError(f"{url}: Content-Length {declared} is over the {max_bytes}-byte cap")
            body = bytearray()
            for chunk in resp.iter_content(chunk_size=chunk_size):
                body += chunk
                if len(body) > max_bytes:
                    raise ValueError(f"{url}: body is over the {max_bytes}-byte cap")
                if time.monotonic() - start > deadline_s:
                    raise DeadlineExceeded(f"{url}: no complete response within {deadline_s}s")
            return bytes(body)
        finally:
            resp.close()
