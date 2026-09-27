# OlFacts

BUSL-1.1, see `LICENSE`.

Detects a correct answer on Quizlet and triggers a scent on an Omara Scent
Studio device. Wrong answers can carry their own scent if you want the feedback.

## Quick start

    run.bat

That is the whole flow. On first run it checks Python, installs `websockets` if
missing, generates certificates, runs a self-test, and starts serving. Every run
after that skips straight to serving. Double-clicking works too.

Read the certificate trust step below before concluding anything is broken — an
untrusted cert looks identical to a dead server in Firefox.

## Why it is shaped like this

Quizlet is an HTTPS site that issues its own redirect to TLS. Firefox refuses an
insecure `ws://` socket from a secure page (mixed content) and offers no
per-origin loopback exception, so the browser cannot talk to Omara's plain-text
port directly. The bridge terminates TLS locally and speaks plaintext upstream.

Rate limiting exists in exactly one place: the bridge, in front of Omara. It is
shared across every downstream connection, so two open tabs cannot each get
their own cadence. The userscript buffers and forwards only.

Threads, not asyncio. Two sockets at a few messages a second is not a workload
asyncio helps; what threads give is blast-radius control — a stalled socket
freezes one role instead of the whole process. Threads are not immunity from
lockups, so every blocking call carries an explicit bound on the socket syscall
itself, and the worker never pops from the queue while its connection is down.

## Data flow

    olfacts.user.js  (main thread: detection)
      -> worker       (bounded outbox only -- never limits)
      -> wss://127.0.0.1:8443/   bridge.py: rate limit, merge window, forward
      -> ws://127.0.0.1:8080/    Omara Scent Studio

Nothing sprays on connection — the first scent you should ever smell without
answering something is the self-test (`run.bat selftest`), which proves every
wire between the bridge and the nozzle without a browser at all.

## Setup

### 1. Certificates

Automatic via `run.bat`. By hand, or with a CA instead of a self-signed leaf:

    make-cert.bat selfsigned        single leaf (default choice for loopback)
    make-cert.bat                   tiny CA + leaf, better if you add hosts later
    make-cert.bat selfsigned 825    explicit validity in days

Firefox rejects certificates without a SAN since 82/101. The script always emits
one; do not regenerate by hand with only `-subj /CN=localhost`. OpenSSL's `-subj`
also needs the **leading slash** — `/CN=localhost`, never `CN=localhost`.

### 2. Trust it in Firefox

**about:preferences → Certificates → View Certificates → Authorities → Import**,
pick `bridge-cert.pem` (or `ca-cert.pem` for the CA flavour) and tick
***Identifying websites***. Without that checkbox Firefox refuses the connection
and the console message it gives you looks like a server problem.

### 3. Self-test

    run.bat selftest

Proves TLS handshake, websocket roundtrip **and actual delivery to Omara**
without opening a browser. Runs automatically once on first install.

| Output | Meaning |
|---|---|
| `PASS -- you should have smelled something` | End to end works |
| `tls probe: tcp ...` | Port not listening; bridge already running or port clash |
| `tls probe: tls ...` | Cert or TLS stack problem, nothing to do with websockets |
| `FAIL ws roundtrip` | Websocket layer failing after TLS succeeded |
| `nothing reached Omara` | Everything local is fine; Studio is not accepting |

The self-test runs its own client with verification disabled, so **it cannot
detect a missing Firefox trust entry**. That failure only appears in the browser.

### 4. Run

    run.bat

Leave the window open. It reconnects upstream on its own and survives clients
coming and going.

Do not leave `--debug-ws` on for normal use. It logs every keepalive PING/PONG,
which buries the two lines worth reading: `[down] client` and any upstream loss
warning.

### 5. Install the userscript

Tampermonkey → Dashboard → Utilities → *Install from file*, or paste into a new
script. `@grant none` runs it in page context; nothing else is needed because the
socket is TLS.

**One copy of the script, in one manager.** Two managers both enabled means two
sockets per page and every answer can spray twice. Confirm with the bridge log:
a clean reload should produce exactly one `[down] client ... concurrent=1`.

## Verifying by hand

Reload Quizlet with DevTools open. Expected within about a second of load, with
nothing typed into the console:

```
[olfacts] active -> wss://127.0.0.1:8443/ top=true frames=0
[olfacts] connected
```

Nothing should spray at this point — `connected` is the whole confirmation.
Grade an answer and you should then see `[olfacts] sent sweet@0.85`.

and in the bridge window:

```
[down] client ('127.0.0.1', N) origin=https://quizlet.com concurrent=1
```

If connection succeeds from the console but never from the script, the two are
not running in the same context and one of them is a duplicate frame — check
`concurrent=` before believing anything else.

## Configuration

At the top of `olfacts.user.js`:

| Key | Default | Notes |
|---|---|---|
| `BRIDGE_URL` | `wss://127.0.0.1:8443/` | must match the bridge listen port |
| `CORRECT` | `sweet @ 0.85` | scent on a correct answer |
| `WRONG` | `null` | set to emit on wrong answers; must be a valid cartridge |
| `QUEUE_MAX` | `64` | answers buffered while the socket is down |
| `DEDUPE_MS` | `1000` | one graded answer counts once, not twice. **Not** a rate limit |
| `CONNECT_TIMEOUT_MS` | `4000` | how long to wait for the handshake before retrying |
| `LOAD_BACKSTOP_MS` | `5000` | connect even if the page's `load` event never arrives |

The script is `@noframes`: it runs in the top frame only, so one page equals one
socket. If Quizlet ever renders its Learn UI inside an iframe, detection goes
silent and this line must come out.

Bridge flags:

| Flag | Default | Notes |
|---|---|---|
| `--rate-limit-seconds` | `2.0` | minimum gap between Omara commands; `0` disables |
| `--rate-limit-window` | `strongest` | who wins inside a cooldown: `strongest` or `most-recent` |
| `--ping-interval` | `0` | upstream keepalive, in seconds. **Leave it at 0** — see below |
| `--ping-timeout` | `5` | how long to wait for a pong before declaring the peer dead |

Omara Scent Studio does not answer WebSocket ping frames. Turn pings on and
websockets kills a perfectly healthy connection at `ping_timeout`, which is where
`sent 1011 keepalive ping timeout` came from. With pings off, Studio still closes
quiet sockets every 20–30 seconds; that is expected, costs nothing, and the
worker reconnects in under a second.

Cartridge names accepted by the bridge: `marine`, `petrichor`, `kindred`,
`beach`, `floral`, `sweet`, `barnyard`, `winter`, `evergreen`, `terra_silva`,
`citrus`, `desert`, `savory_spice`, `timber`, `smoky`, `machina`. Anything else
is discarded with a `[warn] discarded: unknown_odor:...` line.

## Reading the stats

| Counter | Meaning |
|---|---|
| `accepted` | frames the bridge parsed and passed to the limiter |
| `sent` | bytes actually written to Omara's socket — **the only number that means "it sprayed"** |
| `failed` | send raised; worker reconnecting |
| `idle_drop` | Studio closed a quiet upstream socket; expected with pings off |
| `dropped_backpressure` | upstream queue was full, oldest scent evicted |
| `dropped_unsent` | two scents failed in a row; the older one gave up its retry slot |
| `reconnects` | upstream reconnects since start |
| `downstream` | browser sockets open right now — should be 1 |
| `dropped_window` | scents merged away inside cooldown windows |

`accepted` climbing while `sent` stays at zero means Omara is not accepting, not
that the browser is broken.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Firefox can't establish a connection`, self-test passes | cert not trusted for websites | re-import, tick *Identifying websites* |
| Connection works from the DevTools console but not from the script | more than one copy of the script running, or a stale context | check `concurrent=`; disable every manager but one |
| Two `[down] client` lines per reload | two userscript managers enabled, or the script in an iframe | keep one manager enabled; `@noframes` covers frames |
| Reconnect every ~20–30 seconds, `idle drop` | Studio closes quiet sockets | expected with `--ping-interval 0`; nothing is lost |
| `keepalive ping timeout`, steady rhythm | pings enabled and Studio ignores them | `--ping-interval 0` (the default) |
| `ERROR: openssl not on PATH` | no OpenSSL installed | install Git for Windows (bundles it) or add to PATH |
| Bridge window closes instantly with an error | bad cert path or port in use | run from a terminal; `run.bat` pauses on failure |
| `[Errno 10048] Only one usage of each socket address` | bridge already running | close the other window, or change `--listen-port` |
| `unknown_odor` in bridge log | name not in Omara's cartridge list | use one of the sixteen valid names |
| Answer counted twice | API and DOM signals both landed | `DEDUPE_MS` covers it; raise it if you see triples |
| No scent after a Quizlet deploy | obfuscated classes changed | update `CORRECT_CLASS` / `WRONG_CLASS`; the API path should still work alone |
| `websockets build exposes no socket.settimeout` | version drift in the sync client | sends are unbounded; upgrade websockets or scents may stall on a half-dead Omara |
| CORS error on `el.quizlet.com` | Quizlet telemetry blocked by your ad-blocker | unrelated noise, ignore |

## Files

| File | Role |
|---|---|
| `run.bat` | entry point: deps, certs, self-test, serve |
| `make-cert.bat` | loopback certificate generation |
| `olfacts.user.js` | detection + worker (buffer, socket; never limits) |
| `bridge.py` | TLS front end, rate limiting, bounded forwarding to Omara |
| `requirements.txt` | Python dependencies |

Keep `test.py` out of the repo. Its test C enters `serve()`'s context manager
without calling `serve_forever()`, so it reports a bind-then-timeout forever and
will tell you the bridge is broken when it isn't.
