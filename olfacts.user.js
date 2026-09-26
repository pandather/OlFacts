// ==UserScript==
// @name         OlFacts
// @namespace    https://olfacts.local/
// @version      1.0.0
// @description  Detect correct answers on Quizlet and emit a scent through Omara Scent Studio over TLS. Detection on the main thread; buffering and the socket in a worker. The bridge owns rate limiting -- this script only ever produces.
// @match        https://quizlet.com/*
// @noframes
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  /* ─── CONFIG ───────────────────────────────────────────────────────── */
  const BRIDGE_URL = "wss://127.0.0.1:8443/";
  const CORRECT    = { odor: "sweet", intensity: 0.85 };
  const WRONG      = null;              // e.g. { odor: "barnyard", intensity: 0.4 }
  const QUEUE_MAX  = 64;                // buffered answers while the socket is down

  /* Dedupe, NOT rate limiting. The API interceptor and the DOM observer can
     both see one graded answer; without this a correct answer counts twice and
     burns two slots of the bridge's cooldown window. */
  const DEDUPE_MS = 1000;

  const CONNECT_TIMEOUT_MS = 4000;      // longer than a loopback TLS handshake by enough
  const BACKOFF_START = 500, BACKOFF_MAX = 10000;
  const LOAD_BACKSTOP_MS = 5000;        // connect anyway if 'load' never fires

  /* Quizlet's obfuscated correctness classes. Stable per build, churn on
     deploy; API interception is primary and these are the fallback. */
  const CORRECT_CLASS = ["cwgw684"];
  const WRONG_CLASS   = ["i1eil3c9"];
  const CHECK_STROKE  = "#59E8B5";

  /* ─── WORKER: bounded buffer + socket. Produces, never limits. ─────── */
  const workerSource = `
"use strict";
const URL_ = ${JSON.stringify(BRIDGE_URL)};
const QUEUE_MAX = ${QUEUE_MAX};
const CONNECT_TIMEOUT_MS = ${CONNECT_TIMEOUT_MS};
const BACKOFF_START = ${BACKOFF_START}, BACKOFF_MAX = ${BACKOFF_MAX};

/* Bounded FIFO, drop-oldest: the producer can never be stalled by a dead peer. */
class Ring {
  constructor(cap) { this.buf = new Array(cap); this.cap = cap; this.head = 0; this.count = 0; }
  push(v) {
    let dropped = false;
    if (this.count === this.cap) { this.buf[this.head] = null;
      this.head = (this.head + 1) % this.cap; this.count--; dropped = true; }
    this.buf[(this.head + this.count) % this.cap] = v; this.count++;
    return dropped;
  }
  shift() {
    if (!this.count) return null;
    const v = this.buf[this.head]; this.buf[this.head] = null;
    this.head = (this.head + 1) % this.cap; this.count--;
    return v;
  }
  get size() { return this.count; }
}

const outbox = new Ring(QUEUE_MAX);
const stats = { produced: 0, sent: 0, dropped_queue: 0, rejected: 0, failed: 0, reconnects: 0 };

let ws = null, backoff = BACKOFF_START, closing = false;
let connectTimer = null, timedOut = false, started = false;

function log(m) { self.postMessage({ type: "log", m }); }
function clearTimer() { if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; } }

function scheduleReconnect() {
  if (closing) return;
  setTimeout(connect, backoff);
  backoff = Math.min(backoff * 2, BACKOFF_MAX);
}

/* ONE LOG LINE PER ATTEMPT. The old version let the timeout print its own
   message and then close, which printed a second one -- so every failure looked
   like two failures. Here the timer only flags why it is closing, and onclose
   does all the talking. */
function connect() {
  if (closing || ws) return;                  // no overlapping attempts
  clearTimer();
  timedOut = false;
  try { ws = new WebSocket(URL_); }
  catch (e) { log("socket ctor failed: " + e.message); ws = null; scheduleReconnect(); return; }

  connectTimer = setTimeout(() => {
    if (ws && ws.readyState === WebSocket.CONNECTING) {
      timedOut = true;
      try { ws.close(); } catch (_) {}        // onclose logs this attempt
    }
  }, CONNECT_TIMEOUT_MS);

  ws.onopen = () => {
    clearTimer();
    backoff = BACKOFF_START;
    if (outbox.size) stats.reconnects++;
    log("connected" + (outbox.size ? ", flushing " + outbox.size : ""));
    flush();
  };

  ws.onmessage = (e) => {
    try {
      const r = JSON.parse(e.data);
      if (!r.ok) { stats.rejected++; log("bridge rejected: " + r.error); }
    } catch (_) {}
  };

  ws.onerror = () => {};                      // onclose carries the code; stay quiet

  ws.onclose = (e) => {
    clearTimer();
    ws = null;
    if (closing) return;
    const why = timedOut ? "connect timed out after " + CONNECT_TIMEOUT_MS + "ms"
                         : "closed code=" + e.code + (e.reason ? " reason=" + e.reason : "");
    log(why + ", retry in " + backoff + "ms");
    scheduleReconnect();
  };
}

function flush() {
  while (ws && ws.readyState === WebSocket.OPEN && outbox.size) {
    const cmd = outbox.shift();
    try {
      ws.send(JSON.stringify(cmd));
      stats.sent++;
      log("sent " + cmd.odor + "@" + cmd.intensity);
    } catch (e) {
      stats.failed++; log("send failed: " + e.message);
      outbox.push(cmd);                       // put it back, don't lose it
      break;
    }
  }
}

self.onmessage = (ev) => {
  const d = ev.data;
  if (d.type === "shutdown") {
    closing = true;
    clearTimer();
    if (ws) try { ws.close(1000, "bye"); } catch (_) {}
    log("stats " + JSON.stringify(stats));
    return;
  }
  if (d.type === "start") {                   // main thread says the page settled
    if (started) return;
    started = true;
    connect();
    return;
  }
  if (d.type === "scent") {
    stats.produced++;
    if (outbox.push({ odor: d.odor, intensity: d.intensity })) stats.dropped_queue++;
    flush();
  }
  if (d.type === "stats") self.postMessage({ type: "stats", stats });
};
`;

  const blobUrl = URL.createObjectURL(new Blob([workerSource], { type: "application/javascript" }));
  const worker = new Worker(blobUrl);
  worker.onmessage = (ev) => {
    if (ev.data.type === "log") console.log("[olfacts]", ev.data.m);
    else console.log("[olfacts-stats]", JSON.stringify(ev.data.stats));
  };

  /* CONNECT AFTER THE PAGE SETTLES. Opening at document-start meant Firefox
     killed the handshake when Quizlet's SPA navigated -- "interrupted while the
     page was loading" -- and we spent rounds blaming a certificate for a race
     in our own timing. 'load' is the signal; the timer is the backstop for
     pages whose load event never arrives. */
  let booted = false;
  function boot() {
    if (booted) return;
    booted = true;
    console.log("[olfacts] active -> " + BRIDGE_URL +
                " top=" + (window === window.top) + " frames=" + window.frames.length);
    worker.postMessage({ type: "start" });
  }
  if (document.readyState === "complete") boot();
  else addEventListener("load", boot, { once: true });
  setTimeout(boot, LOAD_BACKSTOP_MS);

  addEventListener("pagehide", () => {
    worker.postMessage({ type: "shutdown" });
    URL.revokeObjectURL(blobUrl);
  });

  /* ─── DETECTION ────────────────────────────────────────────────────── */
  let lastFire = 0;

  function fire(profile, how) {
    if (!profile) return;
    const now = Date.now();
    if (now - lastFire < DEDUPE_MS) return;         // one answer, once
    lastFire = now;
    console.log("[olfacts] detected " + profile.odor + " via " + how);
    worker.postMessage({ type: "scent", odor: profile.odor, intensity: profile.intensity });
  }

  function verdict(node) {
    if (!node || typeof node !== "object") return null;
    if (typeof node.isCorrect === "boolean") return node.isCorrect;
    if (typeof node.correct === "boolean") return node.correct;
    const s = String(node.status || node.grade || "").toLowerCase();
    if (s === "correct" || s === "right") return true;
    if (s === "incorrect" || s === "wrong") return false;
    if (typeof node.score === "number" && typeof node.maxScore === "number")
      return node.maxScore > 0 ? node.score / node.maxScore >= 1 : null;
    return null;
  }

  function scan(node, depth = 0) {
    if (!node || typeof node !== "object" || depth > 6) return null;
    const v = verdict(node);
    if (v !== null) return v;
    if (Array.isArray(node)) {
      for (const item of node) { const r = scan(item, depth + 1); if (r !== null) return r; }
      return null;
    }
    for (const k of Object.keys(node)) {
      const r = scan(node[k], depth + 1);
      if (r !== null) return r;
    }
    return null;
  }

  function inspect(text) { try { return scan(JSON.parse(text)); } catch (_) { return null; } }

  // Primary: API interception. Catches correctness before any UI renders and
  // does not depend on obfuscated class names surviving a Quizlet deploy.
  const ENDPOINT = /grade|answer|submit|\/api\//i;

  const origFetch = window.fetch;
  window.fetch = async function (...args) {
    const res = await origFetch.apply(this, args);
    try {
      const url = typeof args[0] === "string" ? args[0] : (args[0]?.url || "");
      if (ENDPOINT.test(url)) {
        const body = res.clone ? await res.clone().text() : "";
        const v = inspect(body);
        if (v !== null) fire(v ? CORRECT : WRONG, "api");
      }
    } catch (_) {}
    return res;
  };

  const open = XMLHttpRequest.prototype.open, send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, url, ...rest) {
    this._olfactsUrl = url; return open.call(this, m, url, ...rest);
  };
  XMLHttpRequest.prototype.send = function (...rest) {
    if (ENDPOINT.test(this._olfactsUrl || "")) {
      this.addEventListener("load", () => {
        const v = inspect(this.responseText);
        if (v !== null) fire(v ? CORRECT : WRONG, "xhr");
      });
    }
    return send.apply(this, rest);
  };

  // Fallback: DOM class flips. Grading is async (~500ms), so this catches what
  // the API path misses. Cheap early exits keep it off the hot path.
  const observer = new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.attributeName !== "class") continue;
      const el = m.target;
      if (el.nodeType !== 1 || !el.querySelector) continue;
      const cls = String(el.className || "");
      if (CORRECT_CLASS.some((c) => cls.includes(c))) fire(CORRECT, "dom-class");
      else if (WRONG_CLASS.some((c) => cls.includes(c))) fire(WRONG, "dom-class");
      else if (el.querySelector(`svg[stroke="${CHECK_STROKE}"]`)) fire(CORRECT, "dom-check");
    }
  });

  function startObserver() {
    observer.observe(document.documentElement, {
      subtree: true, attributes: true, attributeFilter: ["class"],
    });
  }
  if (document.documentElement) startObserver();
  else addEventListener("DOMContentLoaded", startObserver);
})();