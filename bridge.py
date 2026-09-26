#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# OlFacts Bridge
# Copyright (C) 2026 Mark J. Kuebel
#
"""OlFacts bridge: wss:// from the browser to Omara Scent Studio.

    olfacts.user.js worker        (detect, forward -- one scent at a time)
      -> wss://127.0.0.1:8443/    TLS, self-signed loopback cert
      -> this bridge              rate limit + window merge + bounded queues
      -> ws://127.0.0.1:8080/     Omara (wss:// if you ever put TLS on it)

Design decisions, learned the hard way:

  * ONE RATE LIMITER, HERE, IN FRONT OF OMARA. Shared across every downstream
    connection so two open tabs cannot each get their own cadence.

  * NEVER CONSUME WITH NO CONNECTION. A payload popped while the upstream socket
    is down used to vanish silently -- counted as neither sent nor failed. The
    worker refuses to dequeue until it has a live connection, and gives one
    failed scent exactly one retry slot.

  * THREADS, NOT ASYNCIO. Two sockets at a few messages a second is not a
    workload asyncio helps; what threads give is blast-radius control. Threads
    are not immunity from lockups either, so every blocking call carries an
    explicit bound set on the socket syscall and restored immediately.

  * NO UPSTREAM KEEPALIVE. Omara Scent Studio does not answer WebSocket ping
    frames, so websockets would declare a healthy connection dead at
    ping_timeout -- "sent 1011 keepalive ping timeout". Pings are off by
    default; idle drops are expected and reconnect fast instead.

  * ASK THE OBJECT, NOT THE DOCS. websockets' sync API has changed shape more
    than once and this code guessed wrong twice. Server lifecycle goes through
    getattr() guards, and handshake internals are loggable via --debug-ws, so a
    version change shows up as a log line rather than a silent refusal.

Requires: py -m pip install "websockets>=16"
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import queue
import socket as _socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass

try:
    from websockets.sync.client import connect as ws_connect
    from websockets.sync.server import serve as ws_serve
except ImportError as exc:                                   # pragma: no cover
    sys.exit(f"missing dependency ({exc}); run: py -m pip install 'websockets>=16'")

VALID_ODORS = {
    "marine", "petrichor", "kindred", "beach", "floral", "sweet", "barnyard",
    "winter", "evergreen", "terra_silva", "citrus", "desert", "savory_spice",
    "timber", "smoky", "machina",
}

QUEUE_MAX = 256
RECONNECT_START = 0.25          # first retry after a clean drop
RECONNECT_MAX = 2.0             # a nozzle should not wait ten seconds to speak

# Studio ignores ping frames, so keepalive is off: websockets would kill a
# healthy connection at ping_timeout. Idle drops are handled by reconnecting.
PING_INTERVAL_DEFAULT = 0.0
PING_TIMEOUT_DEFAULT = 5.0

LOCK = threading.Lock()               # guards Upstream.stats
STOP = threading.Event()


# ───────────────────────────────────────────────────── logging ──────────────
class Log:
    """Lock-guarded, encoding-safe output. A cp1252 terminal must not raise."""

    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self._lock = threading.Lock()

    def _write(self, msg: str, err: bool) -> None:
        try:
            print(msg, file=(sys.stderr if err else sys.stdout), flush=True)
        except Exception:
            try:
                print(msg.encode("ascii", "replace").decode("ascii"), flush=True)
            except Exception:
                pass

    def info(self, msg: str) -> None:
        if not self.quiet:
            with self._lock:
                self._write(msg, False)

    def warn(self, msg: str) -> None:
        with self._lock:
            self._write(f"[warn] {msg}", True)


def enable_websockets_logging() -> None:
    """websockets logs handshake refusals to its own logger, silent by default.

    Without this the bridge cannot say WHY it refused a browser connection --
    origin mismatch and malformed headers look identical from the outside, which
    is exactly how we lost several rounds to guessing.
    """
    logging.basicConfig(level=logging.WARNING,
                        format="%(name)s %(levelname)s %(message)s")
    for name in ("websockets.server", "websockets.client"):
        logging.getLogger(name).setLevel(logging.DEBUG)


# ─────────────────────────────────── payload validation ─────────────────────
@dataclass(frozen=True)
class Scent:
    odor: str
    intensity: float

    @property
    def wire(self) -> str:
        return json.dumps({"odor": self.odor, "intensity": self.intensity},
                          separators=(",", ":"))


def parse(raw: str | bytes) -> tuple[Scent | None, str]:
    """Return (scent, reason). scent is None when reason explains the discard."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    raw = raw.strip()[:4096]
    if not raw:
        return None, "empty"
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None, "not_json"
    if not isinstance(obj, dict):
        return None, "not_object"

    odor = obj.get("odor")
    if not isinstance(odor, str) or not (odor := odor.strip()):
        return None, "bad_odor"
    if odor not in VALID_ODORS:
        return None, f"unknown_odor:{odor}"

    try:
        val = float(obj.get("intensity"))
    except (TypeError, ValueError):
        return None, "bad_intensity"
    if not math.isfinite(val):
        return None, "non_finite"
    if val <= 0:
        return None, "zero_intensity"
    return Scent(odor=odor, intensity=round(min(val, 1.0), 4)), ""


# ─── rate limiting + window merging, shared across every downstream client ───
class RateLimiter:
    """Cooldown with a merge window. Inside the cooldown incoming scents
    collapse into one held command; on expiry the winner is emitted."""

    def __init__(self, interval_seconds: float, window_mode: str, log: Log) -> None:
        self.interval = interval_seconds
        self.window_mode = window_mode
        self.log = log
        self._lock = threading.Lock()
        self.last_emit_at: float | None = None
        self.held: Scent | None = None
        self.held_count = 0
        self.dropped_window = 0

    def submit(self, scent: Scent) -> Scent | None:
        now = time.monotonic()
        with self._lock:
            if self.interval <= 0:
                self.last_emit_at = now
                return scent
            if (self.held_count == 0 and
                    (self.last_emit_at is None or
                     now - self.last_emit_at >= self.interval)):
                self.last_emit_at = now
                return scent
            self.held_count += 1
            self.held = self._choose(self.held, scent)
        return None

    def _choose(self, current: Scent | None, incoming: Scent) -> Scent:
        if current is None:
            return incoming
        if self.window_mode == "most-recent":
            return incoming
        return incoming if incoming.intensity > current.intensity else current

    def flush_due(self) -> tuple[Scent | None, int]:
        with self._lock:
            if self.held is None:
                return None, 0
            now = time.monotonic()
            if self.last_emit_at is not None and \
               now - self.last_emit_at < self.interval:
                return None, 0
            scent, drops = self.held, max(0, self.held_count - 1)
            self.held, self.held_count = None, 0
            self.last_emit_at = now
            self.dropped_window += drops
        return scent, drops

    def flush_final(self) -> Scent | None:
        with self._lock:
            scent = self.held
            self.held, self.held_count = None, 0
        return scent

    def snapshot(self) -> dict[str, float]:
        with self._lock:
            return {"dropped_window": self.dropped_window, "window_seconds": self.interval}


# ─── websockets version tolerance across 13..16+ ────────────────────────────
def _sync_connect(url: str, **kw):
    """websockets 16 wants context managers; older builds lack legacy=True."""
    try:
        return ws_connect(url, legacy=True, **kw)
    except TypeError:
        return ws_connect(url, **kw)


def _bound_socket(conn, timeout: float | None) -> bool:
    """Put a bound on the underlying socket of a websockets sync connection."""
    for attr in ("socket", "sock"):
        sock = getattr(conn, attr, None)
        if sock is None:
            continue
        setter = getattr(sock, "settimeout", None)
        if callable(setter):
            try:
                setter(timeout)
                return True
            except Exception:
                pass
    return False


# ───────────── upstream worker: sole owner of the Omara socket ──────────────
class Upstream(threading.Thread):
    """One thread owns the upstream socket end to end, and drives cooldown
    expiry while idle so no separate timer thread is needed."""

    def __init__(self, url: str, log: Log, limiter: RateLimiter, *,
                 connect_timeout: float, send_timeout: float,
                 ssl_ctx: ssl.SSLContext | None,
                 ping_interval: float = PING_INTERVAL_DEFAULT,
                 ping_timeout: float = PING_TIMEOUT_DEFAULT) -> None:
        super().__init__(name="upstream", daemon=True)
        self.url, self.log, self.limiter = url, log, limiter
        self.connect_timeout, self.send_timeout, self.ssl = connect_timeout, send_timeout, ssl_ctx
        self.ping_interval = ping_interval or None
        self.ping_timeout = ping_timeout if self.ping_interval else None

        self.q: queue.Queue[str | None] = queue.Queue(maxsize=QUEUE_MAX)
        self.conn = None
        self._retry: str | None = None
        self._warned_unbounded = False
        # "downstream" is a gauge of live browser sockets, not a running total:
        # two copies of the userscript look identical to one busy page otherwise.
        self.stats: dict[str, int] = {
            "accepted": 0, "sent": 0, "failed": 0, "idle_drop": 0,
            "dropped_backpressure": 0, "dropped_unsent": 0, "reconnects": 0,
            "downstream": 0,
        }

    def submit(self, payload: str) -> bool:
        """Queue for sending. Returns False if backpressure dropped something."""
        try:
            self.q.put_nowait(payload)
            return True
        except queue.Full:
            pass
        try:
            self.q.get_nowait()
            self.q.put_nowait(payload)
        except (queue.Empty, queue.Full):
            pass
        with LOCK:
            self.stats["dropped_backpressure"] += 1
        return False

    def queue_size(self) -> int:
        return self.q.qsize()

    def _open(self) -> None:
        try:
            conn = _sync_connect(self.url, open_timeout=self.connect_timeout,
                                 close_timeout=0.5, ssl=self.ssl,
                                 ping_interval=self.ping_interval,
                                 ping_timeout=self.ping_timeout)
        except Exception as exc:
            self.log.warn(f"upstream connect failed: {exc}")
            return
        with LOCK:
            if self.conn is not None:
                self.stats["reconnects"] += 1
        self.conn = conn
        self.log.info(f"[up] connected {self.url}")

    def _close(self) -> None:
        conn, self.conn = self.conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _send(self, payload: str) -> bool:
        """True only when bytes actually went to Omara. Never lose a payload."""
        conn = self.conn
        if conn is None:
            return False
        bounded = _bound_socket(conn, self.send_timeout)
        if not bounded and not self._warned_unbounded:
            self._warned_unbounded = True
            self.log.warn("websockets build exposes no socket.settimeout; "
                          "sends are unbounded on this version")
        try:
            conn.send(payload)
            with LOCK:
                self.stats["sent"] += 1
            return True
        except Exception as exc:
            self.log.warn(f"upstream send failed, reconnecting: {exc}")
            self._close()
            with LOCK:
                self.stats["failed"] += 1
            return False
        finally:
            if bounded:
                try:
                    _bound_socket(conn, None)
                except Exception:
                    pass

    def _hold_retry(self, payload: str) -> None:
        """Keep one unsent scent for retry. One slot only, so a payload Omara
        actively rejects cannot loop forever and starve what is behind it."""
        if self._retry is not None:
            self.log.warn("dropping older unsent scent to hold the newer one")
            with LOCK:
                self.stats["dropped_unsent"] += 1
        self._retry = payload

    def _drain_inbound(self) -> None:
        conn = self.conn
        if conn is None:
            return
        try:
            conn.recv(timeout=0.05)
        except Exception as exc:
            if type(exc).__name__ in ("TimeoutError", "WebSocketTimeoutException"):
                return
            # Without pings, Studio closing a quiet socket is routine: log it as
            # expected instead of alarming.
            with LOCK:
                self.stats["idle_drop"] += 1
            self.log.info(f"[up] idle drop, reconnecting: {exc}")
            self._close()

    def run(self) -> None:
        backoff = RECONNECT_START
        while not STOP.is_set():
            try:
                if self.conn is None:
                    self._open()
                    if self.conn is None:
                        # Never pop with no connection: a scent with nowhere to
                        # go stays queued instead of vanishing uncounted.
                        STOP.wait(backoff)
                        backoff = min(backoff * 2.0, RECONNECT_MAX)
                        continue
                    backoff = RECONNECT_START
                    if self._retry is None:
                        continue
                    payload, self._retry = self._retry, None       # one more chance
                else:
                    try:
                        payload = self.q.get(timeout=0.25)
                    except queue.Empty:
                        scent, drops = self.limiter.flush_due()
                        if scent is not None:
                            self.log.info(f"[window] emitting held {scent.odor} "
                                          f"(merged {drops} more)")
                            if not self._send(scent.wire):
                                self._hold_retry(scent.wire)
                        else:
                            self._drain_inbound()
                        continue

                if payload is None:
                    break
                if not self._send(payload):
                    self._hold_retry(payload)
            except Exception as exc:                             # never die
                self.log.warn(f"upstream worker error (continuing): {exc}")
                self._close()
                STOP.wait(0.25)
        self._close()

    def drain(self, timeout: float = 1.5) -> None:
        """Flush queued sends. Pointless once STOP has ended the worker loop."""
        deadline = time.monotonic() + timeout
        while not self.q.empty() and time.monotonic() < deadline:
            time.sleep(0.05)


# ─── server lifecycle helpers (websockets sync API quirks) ──────────────────
def _wait_for_stop() -> None:
    while not STOP.is_set():
        time.sleep(0.25)


def start_serving(server, log: Log) -> None:
    """Accept connections. websockets' sync Server binds on construction but only
    ACCEPTS inside serve_forever(); entering the context manager alone does not,
    which is why this bridge once logged a listen line and never a client."""
    forever = getattr(server, "serve_forever", None)
    if callable(forever):
        log.info("[down] accept loop started")
        forever()
        return
    log.warn("[down] no serve_forever(); assuming serving began at construction")
    while not STOP.is_set():
        time.sleep(0.5)


def stop_server(server, log: Log) -> None:
    shutdown = getattr(server, "shutdown", None)
    if not callable(shutdown):
        return
    try:
        shutdown()
    except Exception as exc:
        log.warn(f"[down] shutdown raised {type(exc).__name__}")


# ──────────────────── downstream TLS server, one thread per client ──────────
def serve_downstream(up: Upstream, log: Log, args: argparse.Namespace) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    def handler(conn) -> None:
        peer = getattr(conn, "remote_address", None)
        origin = getattr(conn, "origin", None) or "-"
        with LOCK:
            up.stats["downstream"] += 1
            live = up.stats["downstream"]
        # Origin and the live count together answer the question that cost the
        # most time here: is this one page, or several copies of it?
        log.info(f"[down] client {peer} origin={origin} concurrent={live}")
        try:
            for raw in conn:
                scent, reason = parse(raw)
                if scent is None:
                    log.warn(f"discarded: {reason}")
                    try:
                        conn.send(json.dumps({"ok": False, "error": reason}))
                    except Exception:
                        break
                    continue

                with LOCK:
                    up.stats["accepted"] += 1
                emit_now = up.limiter.submit(scent)
                if emit_now is None:
                    log.info(f"[window] held {scent.odor} ({up.limiter.window_mode})")
                elif not up.submit(emit_now.wire):
                    log.warn(f"backpressure dropped {emit_now.odor}")

                try:
                    conn.send(json.dumps({"ok": True, "odor": scent.odor,
                                          "intensity": scent.intensity}))
                except Exception:
                    break
        except Exception as exc:
            log.info(f"[down] client gone: {type(exc).__name__}")
        finally:
            with LOCK:
                up.stats["downstream"] -= 1
            try:
                conn.close()
            except Exception:
                pass

    server = ws_serve(handler, args.listen_host, args.listen_port, ssl=ctx)
    log.info(f"[down] wss://{args.listen_host}:{args.listen_port} cert={args.cert}")
    threading.Thread(target=lambda: (_wait_for_stop(), stop_server(server, log)),
                     daemon=True).start()
    try:
        start_serving(server, log)
    finally:
        stop_server(server, log)


# ─────────────────────────── TLS context for upstream ──────────────────────
def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _upstream_ctx(args: argparse.Namespace) -> ssl.SSLContext | None:
    if not args.omara.startswith("wss://"):
        return None
    if args.upstream_insecure:
        return _unverified_ctx()
    return ssl.create_default_context(cafile=args.upstream_ca) if args.upstream_ca \
        else ssl.create_default_context()


# ─── selftest: layered, so a failure names the layer that died ──────────────
def probe_tls(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    """Plain TLS handshake with no websockets involved at all."""
    ctx = _unverified_ctx()
    try:
        raw = _socket.create_connection((host, port), timeout=timeout)
    except Exception as exc:
        return False, f"tcp {type(exc).__name__}: {exc}"
    try:
        wrapped = ctx.wrap_socket(raw, server_hostname="localhost")
        return True, f"TLS OK: {wrapped.version()} {wrapped.cipher()[0]}"
    except Exception as exc:
        return False, f"tls {type(exc).__name__}: {exc}"
    finally:
        try:
            raw.close()
        except Exception:
            pass


def _wait_for_sent(up: Upstream, timeout: float = 5.0) -> int:
    deadline = time.monotonic() + timeout
    while up.stats["sent"] == 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    return up.stats["sent"]


def selftest(args: argparse.Namespace) -> int:
    log = Log(False)
    limiter = RateLimiter(0.0, "strongest", log)
    up = Upstream(args.omara, log, limiter, connect_timeout=2.0, send_timeout=1.0,
                  ssl_ctx=_upstream_ctx(args), ping_interval=args.ping_interval,
                  ping_timeout=args.ping_timeout)
    up.start()
    threading.Thread(target=serve_downstream, daemon=True,
                     args=(up, log, args)).start()
    time.sleep(0.6)

    ok, detail = probe_tls(args.listen_host, args.listen_port)
    print(f"tls probe: {detail}")
    if not ok:
        print("FAIL: TLS layer itself is down -- cert or server problem", file=sys.stderr)
        STOP.set()
        return 1

    try:
        with _sync_connect(f"wss://{args.listen_host}:{args.listen_port}/",
                           ssl=_unverified_ctx(), open_timeout=8.0) as conn:
            print("ws handshake OK")
            conn.send(json.dumps({"odor": "sweet", "intensity": 0.85}))
            print(f"bridge replied: {conn.recv(timeout=5.0)}")
    except Exception as exc:
        print(f"FAIL ws roundtrip: {type(exc).__name__}: {exc}", file=sys.stderr)
        STOP.set()
        return 1

    sent = _wait_for_sent(up)              # deliver BEFORE pulling the plug
    up.drain()
    STOP.set()
    if up.is_alive():
        up.join(timeout=3.0)
    print(f"upstream stats: {up.stats}")
    if sent:
        print("PASS -- you should have smelled something")
        return 0
    print(f"TLS and WS are fine but nothing reached Omara (stats={up.stats})")
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description="OlFacts TLS bridge to Omara Scent Studio")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--omara", default="ws://127.0.0.1:8080/", help="ws:// or wss://")
    ap.add_argument("--upstream-ca", default=None)
    ap.add_argument("--upstream-insecure", action="store_true")
    ap.add_argument("--connect-timeout", type=float, default=3.0)
    ap.add_argument("--send-timeout", type=float, default=2.0)
    ap.add_argument("--ping-interval", type=float, default=PING_INTERVAL_DEFAULT,
                    help="upstream keepalive ping interval, 0 disables (default)")
    ap.add_argument("--ping-timeout", type=float, default=PING_TIMEOUT_DEFAULT)
    ap.add_argument("--rate-limit-seconds", type=float, default=2.0)
    ap.add_argument("--rate-limit-window", choices=("strongest", "most-recent"),
                    default="strongest")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--debug-ws", action="store_true",
                    help="log websockets handshake internals to explain refusals")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if args.debug_ws:
        enable_websockets_logging()

    if args.selftest:
        return selftest(args)

    log = Log(args.quiet)
    limiter = RateLimiter(args.rate_limit_seconds, args.rate_limit_window, log)
    up = Upstream(args.omara, log, limiter, connect_timeout=args.connect_timeout,
                  send_timeout=args.send_timeout, ssl_ctx=_upstream_ctx(args),
                  ping_interval=args.ping_interval, ping_timeout=args.ping_timeout)
    up.start()
    try:
        serve_downstream(up, log, args)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        # Drain WHILE THE WORKER IS STILL RUNNING. STOP ends its loop, so
        # draining after that waits on a queue nothing consumes -- it swallowed
        # the last scent of every session and made selftest report sent: 0.
        final = limiter.flush_final()
        if final is not None:
            log.info(f"[window] final flush {final.odor}")
            up.submit(final.wire)
        up.drain(timeout=3.0)
        STOP.set()
        if up.is_alive():
            up.join(timeout=3.0)
        log.info(f"totals {up.stats} {limiter.snapshot()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())