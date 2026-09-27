#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# OlFacts v2 Bridge
# Copyright (C) 2026 Mark J. Kuebel
"""OlFacts v2 bridge: wss:// from the browser, sniffed scents to Omara.

    olfacts.user.js            (detect answer + capture card text/images)
      -> wss://127.0.0.1:8444/  TLS, self-signed loopback cert
      -> this bridge            sniff via local model, rate limit, forward
      -> ws://127.0.0.1:8080/   Omara Scent Studio

v1 sprays a fixed scent per correct answer. v2 additionally asks a local
model server what the CARD smells like -- Maine is marine, Texas is desert.
The userscript cannot call the model itself (https page, http localhost), so
the bridge does it and fetches card images server-side; the browser only ever
sends URL strings, never pixels.

Two frame shapes arrive from the browser:

  classic  {"odor":"sweet","intensity":0.85}          -> straight to limiter
  sniff    {"sniff":true,"text":"Maine | capital Augusta",
            "images":["https://..."],                 (URLs, fetched here)
            "fallback":{"odor":"sweet","intensity":0.85}}

A sniff frame becomes: model decision when the model answers; the fallback
scent when the model is down or rambles; silence when the model deliberately
says the card has no sensory hook (abstract vocab, dates, formulas).

Design decisions inherited from v1 (see README): one rate limiter in front of
Omara shared across every tab; never consume with no connection; threads for
blast-radius control with explicit socket bounds; no upstream keepalive pings
because Studio ignores them. Requires: py -m pip install "websockets>=16"
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import math
import os
import queue as _queue
import socket as _socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sniff import Sniffer as ModelSniffer, VALID_ODORS   # same folder; local module

try:
    from websockets.sync.client import connect as ws_connect
    from websockets.sync.server import serve as ws_serve
except ImportError as exc:                                   # pragma: no cover
    sys.exit(f"missing dependency ({exc}); run: py -m pip install 'websockets>=16'")

QUEUE_MAX = 256
RECONNECT_START = 0.25          # first retry after a clean drop
RECONNECT_MAX = 2.0             # a nozzle should not wait ten seconds to speak

PING_INTERVAL_DEFAULT = 0.0
PING_TIMEOUT_DEFAULT = 5.0

IMAGE_CAP = 2                   # card images fetched per sniff frame
IMAGE_MAX_BYTES = 8 * 1024 * 1024

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
    """websockets logs handshake refusals to its own logger, silent by default."""
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


@dataclass(frozen=True)
class SniffReq:
    text: str
    images: tuple[str, ...]          # URLs; fetched by the bridge, never the browser
    fallback: Scent | None


def parse_scent(obj: dict) -> tuple[Scent | None, str]:
    """Classic v1 frame body: {odor, intensity}."""
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


def parse_frame(raw: str | bytes) -> tuple[Scent | SniffReq | None, str]:
    """Return (payload, reason). payload is Scent or SniffReq."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    raw = raw.strip()[:65536]
    if not raw:
        return None, "empty"
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None, "not_json"
    if not isinstance(obj, dict):
        return None, "not_object"

    if obj.get("sniff"):
        text = obj.get("text")
        text = text.strip()[:2000] if isinstance(text, str) else ""
        urls: list[str] = []
        imgs = obj.get("images")
        if isinstance(imgs, list):
            for u in imgs[:4]:
                if isinstance(u, str) and u.startswith(("http://", "https://", "data:")):
                    urls.append(u.strip())
        fb = None
        raw_fb = obj.get("fallback")
        if isinstance(raw_fb, dict):
            fb, _ = parse_scent(raw_fb)          # a broken fallback is just no fallback
        if not text and not urls:
            return (fb, "") if fb else (None, "empty_sniff")
        return SniffReq(text=text, images=tuple(urls[:IMAGE_CAP]), fallback=fb), ""

    return parse_scent(obj)


# ───────────────────────────── image fetching (server-side) ─────────────────
IMAGE_FETCH_TIMEOUT = 3.0         # per image; two images must not eat a sniff budget


def fetch_images(urls: tuple[str, ...], log: Log) -> list[str]:
    """Download up to IMAGE_CAP card images; return base64 strings.

    data: URLs pass through unchanged (already base64) so sniff.py --send and
    any other local client can attach image bytes without hosting them."""
    out: list[str] = []
    for url in urls[:IMAGE_CAP]:
        if url.startswith("data:"):
            _, _, b64 = url.partition(",")
            raw = b64.replace("\n", "").replace(" ", "")
            if len(raw) * 3 // 4 > IMAGE_MAX_BYTES:
                log.warn("inline image over cap, skipped")
                continue
            out.append(raw)
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "OlFacts/2.0"})
            with urllib.request.urlopen(req, timeout=IMAGE_FETCH_TIMEOUT) as r:
                ctype = (r.headers.get("Content-Type") or "").lower()
                if "html" in ctype:
                    log.warn(f"image is html, skipped: {url[:80]}")
                    continue
                blob = r.read(IMAGE_MAX_BYTES + 1)
            if not blob or len(blob) > IMAGE_MAX_BYTES:
                log.warn(f"image empty or over cap, skipped: {url[:80]}")
                continue
            out.append(base64.b64encode(blob).decode())
        except Exception as exc:
            log.warn(f"image fetch failed ({type(exc).__name__}), skipped: {url[:80]}")
    return out


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

        self.q: _queue.Queue[str | None] = _queue.Queue(maxsize=QUEUE_MAX)
        self.conn = None
        self._retry: str | None = None
        self._warned_unbounded = False
        # "downstream" is a gauge of live browser sockets, not a running total:
        # two copies of the userscript look identical to one busy page otherwise.
        self.stats: dict[str, int] = {
            "accepted": 0, "sent": 0, "failed": 0, "idle_drop": 0,
            "dropped_backpressure": 0, "dropped_unsent": 0, "reconnects": 0,
            "downstream": 0, "sniffed": 0, "sniff_fail": 0, "silence": 0,
            "http_post": 0,
        }

    def submit(self, payload: str) -> bool:
        """Queue for sending. Returns False if backpressure dropped something."""
        try:
            self.q.put_nowait(payload)
            return True
        except _queue.Full:
            pass
        try:
            self.q.get_nowait()
            self.q.put_nowait(payload)
        except (_queue.Empty, _queue.Full):
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
                    except _queue.Empty:
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
    ACCEPTS inside serve_forever(); entering the context manager alone does not."""
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
class SniffQueue(threading.Thread):
    """Serial sniff queue between the client handlers and Omara.

    WHY THIS EXISTS: a model call takes seconds (vision calls can take tens).
    Running it inline inside the websocket handler stalls every later frame from
    that same tab -- including the next answer's reply -- behind one slow
    generation, and two image downloads plus JSON retries could stack tens of
    seconds of blocking on a single socket. One worker thread also means one
    request in flight against the model server, so concurrent tabs cannot make
    it queue requests behind each other invisibly.

    The handler hands sniff frames here and moves on; this thread resolves them
    one at a time and replies on the originating connection when done. A reply
    to a dead connection is dropped quietly -- the scent decision itself is
    already counted, exactly like the upstream worker's no-loss rules.
    """

    def __init__(self, impl: ModelSniffer, up: Upstream, log: Log) -> None:
        super().__init__(name="sniffqueue", daemon=True)
        self.impl = impl
        self.up = up
        self.log = log
        self.q: _queue.Queue[tuple[SniffReq, object, object] | None] = _queue.Queue(maxsize=QUEUE_MAX)

    def submit(self, req: SniffReq, conn, send_lock) -> None:
        """Queue for resolution; the reply goes back on conn when ready.

        send_lock is the handler's own lock: websockets' sync connections are
        one-thread-per-connection by design, and here the queue thread and the
        handler can both want to write -- a classic frame may follow a sniff
        frame before the model has answered. Both sides take the lock."""
        try:
            self.q.put_nowait((req, conn, send_lock))
        except _queue.Full:
            self.log.warn("sniff queue full; frame answered with fallback now")
            self._emit_fallback(req)

    def _emit(self, scent: Scent) -> None:
        emit_now = self.up.limiter.submit(scent)
        if emit_now is None:
            self.log.info(f"[window] held {scent.odor} ({self.up.limiter.window_mode})")
        elif not self.up.submit(emit_now.wire):
            self.log.warn(f"backpressure dropped {scent.odor}")

    def _emit_fallback(self, req: SniffReq) -> None:
        if req.fallback is not None:
            self._emit(req.fallback)

    def run(self) -> None:
        while not STOP.is_set():
            try:
                item = self.q.get(timeout=0.25)
            except _queue.Empty:
                continue
            if item is None:
                break
            req, conn, send_lock = item
            try:
                scent, how = resolve(req, self.impl, self.up, self.log)
                if scent is None:
                    with send_lock:
                        conn.send(json.dumps({"ok": True, "odor": None, "how": how}))
                    continue
                self._emit(scent)
                with send_lock:
                    conn.send(json.dumps({"ok": True, "odor": scent.odor,
                                          "intensity": scent.intensity, "how": how}))
            except Exception:
                # Client gone mid-generation; the decision was already counted.
                pass


# ─── HTTP endpoint for privileged clients (Tampermonkey GM_xmlhttpRequest) ──
class HttpBridge(BaseHTTPRequestHandler):
    """Plain-HTTP twin of the wss socket on its own port.

    WHY: a page-context WebSocket lives inside Quizlet's origin, so Firefox's
    mixed-content rules apply and the TLS cert must be trusted in Firefox --
    every failure mode we kept hitting lives there. GM_xmlhttpRequest runs from
    the extension's privileged context instead: no page origin, no mixed
    content, no certificate, plain http on loopback is fine. Same bridge, same
    queue, same limiter behind both front doors.

    Classic frames answer inline; sniff frames block until the SniffQueue
    decides (the handler thread per-request, so clients never starve each
    other). Replies carry CORS headers because privileged requests still ask.
    """

    up: Upstream = None            # bound via partial subclass below
    sniffer: ModelSniffer | None = None
    queue: SniffQueue | None = None
    log: Log = None
    warned_plain = False           # one terminal warning per run, not per request

    def _cors(self, code: int, body: bytes = b"") -> None:
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_OPTIONS(self) -> None:      # preflight, though GM skips it mostly
        self._cors(204)

    def _read_body(self) -> bytes:
        """Bodies arrive as Content-Length OR chunked -- GM_xmlhttpRequest uses
        chunked with no length header, and reading nothing is how every sniff
        frame arrived 'empty'."""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out = bytearray()
            while len(out) <= 65536:
                line = self.rfile.readline(64).strip()
                try:
                    n = int(line.split(b";")[0], 16)
                except ValueError:
                    break                                 # malformed framing
                if n <= 0:
                    self.rfile.readline(4)                # trailing CRLF / trailer
                    break
                remaining, chunks = n, bytearray()
                while remaining > 0:                      # exactly n payload bytes
                    piece = self.rfile.read(remaining)
                    if not piece:
                        break
                    chunks += piece
                    remaining -= len(piece)
                out += chunks
                self.rfile.readline(4)                    # CRLF after this chunk
            return bytes(out[:65536])
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length)[:65536] if length else b""

    def do_POST(self) -> None:
        app = HttpBridge
        try:
            raw = self._read_body()
            req, reason = parse_frame(raw)
            if req is None:
                app.log.warn(f"[http] discarded: {reason}")
                self._cors(200, json.dumps({"ok": False, "error": reason}).encode())
                return
            with LOCK:
                app.up.stats["accepted"] += 1
                app.up.stats["http_post"] += 1
                if not app.warned_plain:
                    app.warned_plain = True
                    app.log.warn("[http] client is talking PLAIN HTTP, not wss -- "
                                 "TLS path failed (cert untrusted in Firefox?). Fine for "
                                 "loopback, but fix the cert to get encryption back.")
            if isinstance(req, Scent):
                scent, how = resolve(req, app.sniffer, app.up, app.log)
                self._http_emit(scent, how)
                return
            if app.queue is None:
                scent, how = resolve(req, app.sniffer, app.up, app.log)
                self._http_emit(scent, how)
                return
            box: dict | None = {}
            def deliver(payload: str, _box=box) -> None:
                if _box is not None:
                    _box.update(json.loads(payload))
            app.queue.submit(req, _HttpSink(deliver), threading.Lock())
            deadline = time.monotonic() + (app.sniffer.timeout * 2 + IMAGE_CAP * IMAGE_FETCH_TIMEOUT + 10 if app.sniffer else 15)
            while box is not None and not box:
                if time.monotonic() > deadline:
                    break
                time.sleep(0.05)
            payload = json.dumps(box or {"ok": False, "error": "sniff_timeout"}).encode()
            self._cors(200, payload)
        except Exception as exc:
            try:
                HttpBridge.log.warn(f"[http] handler error: {exc}")
                self._cors(200, json.dumps({"ok": False, "error": type(exc).__name__}).encode())
            except Exception:
                pass

    def _http_emit(self, scent: Scent | None, how: str) -> None:
        app = HttpBridge
        if scent is None:
            self._cors(200, json.dumps({"ok": True, "odor": None, "how": how}).encode())
            return
        emit_now = app.up.limiter.submit(scent)
        if emit_now is None:
            app.log.info(f"[window] held {scent.odor} ({app.up.limiter.window_mode})")
        elif not app.up.submit(emit_now.wire):
            app.log.warn(f"backpressure dropped {emit_now.odor}")
        self._cors(200, json.dumps({"ok": True, "odor": scent.odor,
                                    "intensity": scent.intensity, "how": how}).encode())

    def log_message(self, format: str, *args) -> None:   # keep the console clean
        pass


class _HttpSink:
    """Adapter so SniffQueue's conn.send() lands in the HTTP response box."""

    def __init__(self, fn) -> None:
        self._fn = fn

    def send(self, payload: str) -> None:
        self._fn(payload)


def start_http(up: Upstream, sniffer: ModelSniffer | None, queue: SniffQueue | None,
               log: Log, host: str, port: int) -> None:
    HttpBridge.up, HttpBridge.sniffer, HttpBridge.queue, HttpBridge.log = \
        up, sniffer, queue, log
    httpd = ThreadingHTTPServer((host, port), HttpBridge)
    log.info(f"[http] listening on http://{host}:{port}/ (privileged clients)")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


def resolve(req: Scent | SniffReq, sniffer: ModelSniffer | None, up: Upstream,
            log: Log) -> tuple[Scent | None, str]:
    """Turn a frame into the scent to emit (or None for deliberate silence)."""
    if isinstance(req, Scent):
        return req, "classic"
    if sniffer is None:                       # --no-sniff: sniff frames are their fallback
        return (req.fallback, "fallback") if req.fallback else (None, "sniff-disabled")
    images = fetch_images(req.images, log) if req.images else []
    t0 = time.monotonic()
    decision = sniffer.sniff(req.text, images)
    dt = time.monotonic() - t0
    if decision is None:                      # model unreachable/garbage -> fallback
        with LOCK:
            up.stats["sniff_fail"] += 1
        log.warn(f"sniff failed after {dt:.1f}s; using fallback")
        return (req.fallback, "fallback") if req.fallback else (None, "sniff-failed")
    with LOCK:
        up.stats["sniffed"] += 1
    if decision["odor"] is None:              # deliberate silence on abstract cards
        with LOCK:
            up.stats["silence"] += 1
        log.info(f"[sniff] {dt:.1f}s silence ({decision['why']})")
        return None, "silence"
    scent = Scent(odor=decision["odor"], intensity=decision["intensity"])
    log.info(f"[sniff] {dt:.1f}s {scent.odor}@{scent.intensity:.2f} "
             f"({decision['why']}) {req.text[:60]!r}")
    return scent, "sniffed"


def serve_downstream(up: Upstream, log: Log, args: argparse.Namespace,
                     sniffer: ModelSniffer | None, queue: SniffQueue | None) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    def handler(conn) -> None:
        peer = getattr(conn, "remote_address", None)
        origin = getattr(conn, "origin", None) or "-"
        send_lock = threading.Lock()   # conn is shared with the sniff queue thread
        with LOCK:
            up.stats["downstream"] += 1
            live = up.stats["downstream"]
        # Origin and the live count together answer the question that cost the
        # most time here: is this one page, or several copies of it?
        log.info(f"[down] client {peer} origin={origin} concurrent={live}")
        try:
            for raw in conn:
                req, reason = parse_frame(raw)
                if req is None:
                    log.warn(f"discarded: {reason}")
                    try:
                        with send_lock:
                            conn.send(json.dumps({"ok": False, "error": reason}))
                    except Exception:
                        break
                    continue

                with LOCK:
                    up.stats["accepted"] += 1

                # Sniff frames go to the queue thread and the handler moves on;
                # classic frames resolve inline exactly like v1 did. Replies
                # therefore arrive out of order, which the worker tolerates by
                # design -- every reply is self-describing.
                if isinstance(req, SniffReq) and queue is not None:
                    queue.submit(req, conn, send_lock)
                    continue

                scent, how = resolve(req, sniffer, up, log)
                if scent is None:
                    try:
                        with send_lock:
                            conn.send(json.dumps({"ok": True, "odor": None, "how": how}))
                    except Exception:
                        break
                    continue

                emit_now = up.limiter.submit(scent)
                if emit_now is None:
                    log.info(f"[window] held {scent.odor} ({up.limiter.window_mode})")
                elif not up.submit(emit_now.wire):
                    log.warn(f"backpressure dropped {emit_now.odor}")

                try:
                    with send_lock:
                        conn.send(json.dumps({"ok": True, "odor": scent.odor,
                                              "intensity": scent.intensity, "how": how}))
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


def make_sniffer(args: argparse.Namespace, log: Log) -> ModelSniffer | None:
    if args.no_sniff:
        log.info("[sniff] disabled; sniff frames emit their fallback scent")
        return None
    try:
        sn = ModelSniffer(args.base_url, args.model, args.palette,
                          timeout=args.sniff_timeout)
        sn.on_raw = lambda msg: log.info(f"[llm] {msg}")
        log.info(f"[sniff] model={args.model} @ {args.base_url}")
        return sn
    except Exception as exc:
        log.warn(f"sniffer init failed ({exc}); running fallback-only")
        return None


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


def selftest(args: argparse.Namespace, sniffer: ModelSniffer | None) -> int:
    log = Log(False)
    limiter = RateLimiter(0.0, "strongest", log)
    up = Upstream(args.omara, log, limiter, connect_timeout=2.0, send_timeout=1.0,
                  ssl_ctx=_upstream_ctx(args), ping_interval=args.ping_interval,
                  ping_timeout=args.ping_timeout)
    up.start()
    queue = SniffQueue(sniffer, up, log) if sniffer is not None else None
    if queue is not None:
        queue.start()
    threading.Thread(target=serve_downstream, daemon=True,
                     args=(up, log, args, sniffer, queue)).start()
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

            if sniffer is not None:
                # The sniff layer rides the same socket and now arrives out of
                # order -- queued behind the model -- so read with patience. A
                # model outage shows up as how:"fallback", never a hard failure;
                # the classic probe above already proved transport works.
                conn.send(json.dumps({
                    "sniff": True, "text": "Maine | a New England state on the Atlantic",
                    "images": [], "fallback": {"odor": "sweet", "intensity": 0.5}}))
                deadline = time.monotonic() + sniffer.timeout * 2 + IMAGE_CAP * IMAGE_FETCH_TIMEOUT + 10
                while time.monotonic() < deadline:
                    reply = conn.recv(timeout=max(1.0, deadline - time.monotonic()))
                    try:
                        if json.loads(reply).get("how") in ("sniffed", "silence",
                                                            "fallback", "sniff-failed"):
                            print(f"sniff probe: {reply}")
                            break
                    except json.JSONDecodeError:
                        pass
                else:
                    print("FAIL sniff probe: no decision before deadline", file=sys.stderr)
                    STOP.set()
                    return 1
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
    ap = argparse.ArgumentParser(description="OlFacts v2 TLS bridge with local-model sniffing")
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8444)
    ap.add_argument("--http-port", type=int, default=8445,
                    help="plain-HTTP port for privileged (GM_xmlhttpRequest) clients; 0 disables")
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
    ap.add_argument("--base-url", default="http://127.0.0.1:8888/v1",
                    help="OpenAI-compatible server; Ollama's is http://127.0.0.1:11434/v1")
    ap.add_argument("--model", default="unsloth/Qwen3.8-Flash-Next-GGUF")
    ap.add_argument("--palette", default=None, help="default: palette.txt beside this file")
    ap.add_argument("--sniff-timeout", type=float, default=25.0)
    ap.add_argument("--no-sniff", action="store_true",
                    help="skip the model; sniff frames emit their fallback scent")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--debug-ws", action="store_true",
                    help="log websockets handshake internals to explain refusals")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.palette is None:
        args.palette = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "palette.txt")

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if args.debug_ws:
        enable_websockets_logging()

    if args.selftest:
        return selftest(args, make_sniffer(args, Log(False)))

    log = Log(args.quiet)
    sniffer = make_sniffer(args, log)
    limiter = RateLimiter(args.rate_limit_seconds, args.rate_limit_window, log)
    up = Upstream(args.omara, log, limiter, connect_timeout=args.connect_timeout,
                  send_timeout=args.send_timeout, ssl_ctx=_upstream_ctx(args),
                  ping_interval=args.ping_interval, ping_timeout=args.ping_timeout)
    up.start()
    queue = SniffQueue(sniffer, up, log) if sniffer is not None else None
    if queue is not None:
        queue.start()
    if args.http_port:
        start_http(up, sniffer, queue, log, args.listen_host, args.http_port)
    try:
        serve_downstream(up, log, args, sniffer, queue)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        # Drain WHILE THE WORKER IS STILL RUNNING. STOP ends its loop, so
        # draining after that waits on a queue nothing consumes.
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
