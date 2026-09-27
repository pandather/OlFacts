// ==UserScript==
// @name         OlFacts v2
// @namespace    https://olfacts.local/
// @version      2.1.0
// @description  Detect correct answers on Quizlet, capture the card's text and images, and let a local model pick the scent that matches what the card is ABOUT (Maine -> marine, Texas -> desert). Detection and capture on the main thread; buffering and the socket in a worker. The bridge owns rate limiting and the model call -- this script only ever produces.
// @match        https://quizlet.com/*
// @noframes
// @run-at       document-start
// @grant        GM_xmlhttpRequest
// @connect      127.0.0.1
// @connect      localhost
// ==/UserScript==

(function () {
  "use strict";

  /* ─── CONFIG ───────────────────────────────────────────────────────── */
  const BRIDGE_URL = "wss://127.0.0.1:8444/";   // v2 bridge (v1 used 8443)
  const TRANSPORT  = "auto";    // "ws" socket only | "http" privileged only | "auto" ws then http
  const HTTP_URL   = "http://127.0.0.1:8445/";  // bridge's plain-HTTP port (--http-port, default 8445)
  const CORRECT    = { odor: "sweet", intensity: 0.85 };   // fallback scent when the model is off/unreachable
  const WRONG      = null;              // e.g. { odor: "barnyard", intensity: 0.4 }
  const QUEUE_MAX  = 64;                // buffered answers while the socket is down
  const MAX_IMAGES = 3;                 // card image URLs forwarded per answer (bridge fetches them)

  /* Dedupe, NOT rate limiting. The API interceptor and the DOM observer can
     both see one graded answer; without this a correct answer counts twice and
     burns two slots of the bridge's cooldown window. */
  const DEDUPE_MS = 1000;

  const CONNECT_TIMEOUT_MS = 4000;      // longer than a loopback TLS handshake by enough
  const BACKOFF_START = 500, BACKOFF_MAX = 10000;
  const LOAD_BACKSTOP_MS = 5000;        // connect anyway if 'load' event never fires

  /* Quizlet's obfuscated correctness classes. Stable per build, churn on
     deploy; API interception is primary and these are the fallback. */
  const CORRECT_CLASS = ["cwgw684"];
  const WRONG_CLASS   = ["i1eil3c9"];
  const CHECK_STROKE  = "#59E8B5";

  /* ─── WORKER: bounded buffer + socket. Produces, never limits. ─────── */
  const workerSource = `
"use strict";
const URL_ = ${JSON.stringify(BRIDGE_URL)};
const URL_HTTP_ = ${JSON.stringify(HTTP_URL)};
const TRANSPORT = ${JSON.stringify(TRANSPORT)};
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
let fails = 0, hinted = false, mode = "ws";       // ws | http (privileged main-thread relay)
const pendingHttp = new Map();                    // id -> frame, awaiting relay result

function log(m) { self.postMessage({ type: "log", m }); }
function clearTimer() { if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; } }

function scheduleReconnect() {
  if (closing || mode !== "ws") return;
  setTimeout(connect, backoff);
  backoff = Math.min(backoff * 2, BACKOFF_MAX);
}

/* ONE LOG LINE PER ATTEMPT. The timer only flags why it is closing, and onclose
   does all the talking -- two lines per failure once read as two failures. */
function connect() {
  if (closing || ws || mode !== "ws") return;     // no overlapping attempts
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
    fails = 0; hinted = false;
    if (outbox.size) stats.reconnects++;
    log("connected" + (outbox.size ? ", flushing " + outbox.size : ""));
    flush();
  };

  ws.onmessage = (e) => {
    try {
      const r = JSON.parse(e.data);
      if (!r.ok) { stats.rejected++; log("bridge rejected: " + r.error); }
      else if (r.how === "sniffed") log("sniff -> " + r.odor + "@" + r.intensity);
      else if (r.odor === null) log("model says this card has no scent");
    } catch (_) {}
  };

  ws.onerror = () => {};                      // onclose carries the code; stay quiet

  ws.onclose = (e) => {
    clearTimer();
    ws = null;
    if (closing || mode !== "ws") return;
    const why = timedOut ? "connect timed out after " + CONNECT_TIMEOUT_MS + "ms"
                         : "closed code=" + e.code + (e.reason ? " reason=" + e.reason : "");
    fails++;
    let hint = "";
    if (!hinted && fails === 3) {
      hinted = true;
      hint = " | after 3 failures check: bridge running on 8444? cert v2\\\\certs\\\\bridge-cert.pem imported in Firefox with 'Identifying websites' ticked? (v1's trust does NOT cover a different keypair unless the files are identical)";
    }
    log(why + ", retry in " + backoff + "ms" + hint);
    /* AUTO FALLBACK: after repeated TLS failures, hand frames to the main
       thread's GM_xmlhttpRequest relay. Privileged requests bypass Firefox's
       mixed-content rules AND certificate trust entirely -- plain http to the
       bridge's HTTP port works even when wss never will. */
    if (TRANSPORT === "auto" && fails >= 3) { useHttp("after " + fails + " TLS failures"); return; }
    scheduleReconnect();
  };
}

function useHttp(why) {
  mode = "http";
  clearTimer();
  if (ws) { try { ws.close(); } catch (_) {} ws = null; }
  log("switching to privileged HTTP (" + why + ") -- no cert, no mixed content");
  self.postMessage({ type: "warn", m: "running WITHOUT TLS: wss://127.0.0.1:8444 failed " + why +
                  ". Likely cause: v2\\certs\\bridge-cert.pem not imported in Firefox with " +
                  "'Identifying websites' ticked (v1's trust only covers v2 if the cert files are identical). " +
                  "HTTP mode works but skips TLS -- fix the cert to get wss back." });
  flush();
}

let httpSeq = 0;
function sendHttp(frame) {
  const id = ++httpSeq;
  pendingHttp.set(id, frame);
  stats.sent++;                                 // v1 semantics: sent means "left us"
  self.postMessage({ type: "gm", id: id, url: URL_HTTP_, body: JSON.stringify(frame) });
}

/* HTTP mode is serial and shallow: ONE request in flight, at most ONE waiting.
   Sniff requests block server-side until the model answers (seconds), so a fast
   clicker would otherwise stack a queue of stale cards whose scents arrive long
   after they were relevant. Newest wins for the waiting slot; evictions count
   as dropped_queue. The Ring stays for ws mode, which needs its deeper buffer
   because TLS sockets do not block on the model. */
let nextFrame = null;

function queueHttp(frame) {
  if (pendingHttp.size === 0) { sendHttp(frame); return; }
  if (nextFrame !== null) { stats.dropped_queue++; log("dropping superseded card (1 waiting max)"); }
  nextFrame = frame;
}

function pumpHttp() {
  /* Called whenever the in-flight lane frees: promote the waiting card, else
     drain anything left in the ws-mode Ring from before a mode switch. */
  if (pendingHttp.size !== 0) return;
  if (nextFrame !== null) { const f = nextFrame; nextFrame = null; sendHttp(f); return; }
  while (outbox.size) queueHttp(outbox.shift());
}

function flush() {
  if (mode === "ws") {
    while (ws && ws.readyState === WebSocket.OPEN && outbox.size) {
      const cmd = outbox.shift();
      try {
        ws.send(JSON.stringify(cmd));
        stats.sent++;
        log("sent " + cmd.text.slice(0, 40) + " (" + cmd.images.length + " img)");
      } catch (e) {
        stats.failed++; log("send failed: " + e.message);
        outbox.push(cmd);                       // put it back, don't lose it
        break;
      }
    }
    return;
  }
  pumpHttp();
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
    if (TRANSPORT === "http") useHttp("config TRANSPORT=http");
    else connect();
    return;
  }
  if (d.type === "gm-result") {               // privileged relay answered for us
    pendingHttp.delete(d.id);
    try {
      const r = JSON.parse(d.body);
      if (!r.ok) { stats.rejected++; log("bridge rejected: " + r.error); }
      else if (r.how === "sniffed") log("sniff -> " + r.odor + "@" + r.intensity);
      else if (r.odor === null) log("model says this card has no scent");
    } catch (_) { stats.failed++; }
    pumpHttp();                               // free lane: next waiting card goes now
    return;
  }
  if (d.type === "scent") {                   // sniff frame: text + image URLs + fallback
    stats.produced++;
    if (mode === "http") { queueHttp(d.frame); return; }
    if (outbox.push(d.frame)) stats.dropped_queue++;
    flush();
  }
  if (d.type === "stats") self.postMessage({ type: "stats", stats });
};
`;

  const blobUrl = URL.createObjectURL(new Blob([workerSource], { type: "application/javascript" }));
  const worker = new Worker(blobUrl);
  worker.onmessage = (ev) => {
    const d = ev.data;
    if (d.type === "log") console.log("[olfacts]", d.m);
    else if (d.type === "warn") console.warn("[olfacts] " + d.m);
    else if (d.type === "stats") console.log("[olfacts-stats]", JSON.stringify(d.stats));
    else if (d.type === "gm") relayGm(d);
  };

  /* PRIVILEGED RELAY. GM_xmlhttpRequest leaves the extension, not the page:
     no origin check against quizlet.com, no mixed-content rule, no certificate
     at all. This is what makes plain http://127.0.0.1:8445 work when wss never
     will -- and why @grant GM_xmlhttpRequest + @connect 127.0.0.1 replaced
     @grant none. Timeouts generous: sniff requests block until the model answers. */
  function relayGm(d) {
    try {
      GM_xmlhttpRequest({
        method: "POST", url: d.url, headers: { "Content-Type": "application/json" },
        data: d.body,                              // THE body -- its absence was the 'empty' bug
        timeout: 120000,
        onload: (resp) => worker.postMessage({ type: "gm-result", id: d.id, body: resp.responseText || "" }),
        onerror: () => { worker.postMessage({ type: "gm-result", id: d.id, body: '{"ok":false,"error":"relay_failed"}' });
                         console.log("[olfacts] HTTP relay failed -- is the bridge up with --http-port?"); },
        ontimeout: () => worker.postMessage({ type: "gm-result", id: d.id, body: '{"ok":false,"error":"relay_timeout"}' }),
      });
    } catch (e) {
      worker.postMessage({ type: "gm-result", id: d.id, body: '{"ok":false,"error":"relay_ctor"}' });
    }
  }

  /* CONNECT AFTER THE PAGE SETTLES. Opening at document-start meant Firefox
     killed the handshake when Quizlet's SPA navigated -- "interrupted while the
     page was loading". 'load' is the signal; the timer is the backstop. */
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

  /* ─── DETECTION + CARD CAPTURE ─────────────────────────────────────── */
  let lastFire = 0;

  function fire(profile, node, how) {
    if (!profile) return;
    const now = Date.now();
    if (now - lastFire < DEDUPE_MS) return;         // one answer, once
    lastFire = now;
    const frame = buildFrame(node, profile);
    console.log("[olfacts] answer detected via " + how +
                " (fallback=" + profile.odor + ") text=" + JSON.stringify(frame.text.slice(0, 60)) +
                " images=" + frame.images.length);
    worker.postMessage({ type: "scent", frame });
  }

  /* The graded API node, when we have one, is the best card source: Quizlet's
     own grading payload carries term/definition. DOM fills in when the API
     gave us only a bare word -- "california" alone tells the model less than
     "California | capital: Sacramento", and terse cards drift toward silence. */
  function buildFrame(node, profile) {
    let text = "";
    if (node && typeof node === "object") text = harvestText(node);
    const dom = domCardText();
    if (!text) text = dom;
    else if (dom && text.length < 16 && !dom.toLowerCase().includes(text.toLowerCase()))
      text = text + " | " + dom;
    const images = domCardImages();
    return { sniff: true, text: text.slice(0, 2000), images,
             fallback: { odor: profile.odor, intensity: profile.intensity } };
  }

  function harvestText(node, depth = 0) {
    if (!node || typeof node !== "object" || depth > 5) return "";
    const pick = (v) => typeof v === "string" && v.trim() ? v.trim() : null;
    const term = pick(node.term) || pick(node.question) || pick(node.front);
    const def = pick(node.definition) || pick(node.answer) || pick(node.back);
    if (term && def) return term + " | " + def;
    if (Array.isArray(node)) {
      for (const item of node) { const r = harvestText(item, depth + 1); if (r) return r; }
      return "";
    }
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (v && typeof v === "object") { const r = harvestText(v, depth + 1); if (r) return r; }
    }
    return term || "";
  }

  function textOf(selectors) {
    const parts = [];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el && el.textContent.trim()) parts.push(el.textContent.trim());
      if (parts.length >= 2) break;                 // term + definition is enough
    }
    return parts.join(" | ");
  }

  function domCardText() {
    // Quizlet ships data-testid hooks on the study card; classes churn, ids rarely do.
    let t = textOf(['[data-testid="LearnContent"]', '[data-testid="QuestionText"]',
                    '[data-testid="answer-text"]',
                    ".is-question-answer", ".QuestionAnswer"]);
    if (t) return t;
    // Last resort: whatever the correct/incorrect element sits inside.
    const marked = document.querySelector(
      CORRECT_CLASS.map((c) => "." + c).concat(WRONG_CLASS.map((c) => "." + c)).join(","));
    const box = marked && marked.closest("[data-testid], section, article");
    return box ? box.textContent.replace(/\s+/g, " ").trim().slice(0, 400) : "";
  }

  function domCardImages() {
    const out = new Set();
    const marked = document.querySelector(
      CORRECT_CLASS.map((c) => "." + c).concat(WRONG_CLASS.map((c) => "." + c)).join(","));
    const box = (marked && marked.closest("[data-testid], section, article")) || document;
    for (const img of box.querySelectorAll("img")) {
      const src = img.currentSrc || img.src;
      if (!src || !/^https?:/.test(src)) continue;   // skip data:/blob: -- bridge fetches URLs
      if (/avatar|icon|logo|sprite/i.test(src)) continue;
      out.add(src);                                   // loading state is irrelevant: the bridge downloads by URL
      if (out.size >= MAX_IMAGES) break;
    }
    return Array.from(out);
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
    if (v !== null) return { v, node };
    if (Array.isArray(node)) {
      for (const item of node) { const r = scan(item, depth + 1); if (r) return r; }
      return null;
    }
    for (const k of Object.keys(node)) {
      const r = scan(node[k], depth + 1);
      if (r) return r;
    }
    return null;
  }

  function inspect(text) {
    try { return scan(JSON.parse(text)); } catch (_) { return null; }
  }

  // Primary: API interception. Catches correctness before any UI renders and
  // hands us the graded node itself -- the richest card source we can get.
  const ENDPOINT = /grade|answer|submit|\/api\//i;

  const origFetch = window.fetch;
  window.fetch = async function (...args) {
    const res = await origFetch.apply(this, args);
    try {
      const url = typeof args[0] === "string" ? args[0] : (args[0]?.url || "");
      if (ENDPOINT.test(url)) {
        const body = res.clone ? await res.clone().text() : "";
        const hit = inspect(body);
        if (hit) fire(hit.v ? CORRECT : WRONG, hit.node, "api");
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
        // Binary responses throw on .responseText -- and the exception lands in
        // Quizlet's call stack, not ours. Only text bodies are inspectable.
        const rt = this.responseType;
        if (rt && rt !== "text") return;
        const hit = inspect(this.responseText);
        if (hit) fire(hit.v ? CORRECT : WRONG, hit.node, "xhr");
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
      if (CORRECT_CLASS.some((c) => cls.includes(c))) fire(CORRECT, null, "dom-class");
      else if (WRONG_CLASS.some((c) => cls.includes(c))) fire(WRONG, null, "dom-class");
      else if (el.querySelector(`svg[stroke="${CHECK_STROKE}"]`)) fire(CORRECT, null, "dom-check");
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
