# OlFacts v2 — cards that smell like what they're about

**Mark J. Kuebel** — BUSL-1.1, see `LICENSE`.

v1 sprayed one fixed scent per correct answer. v2 asks a local model what the
**card itself** smells like: Maine is marine, Texas is desert, a volcano is
smoky, and abstract vocabulary gets silence. The answer-detection pipeline from
v1 is unchanged; sniffing rides on top of it.

## Why the userscript does not call the model directly

Same reason v1 needed a bridge at all: Quizlet is an HTTPS page, and a browser
will not let it reach plain `http://127.0.0.1` — mixed content, no per-origin
loopback exception. So the script sends card **text and image URLs** to the
bridge over the TLS socket, and the bridge does the model call plus the image
downloads server-side. The browser never fetches or ships pixels.

This is not SniffMe: nothing ever sees your desktop. The model receives exactly
the card's text and the images on the card — no screenshots, no window lists,
no screen capture. (SniffMe's `sniffme.py` lives in its own project; v2 never
imports or runs it.)

## Data flow

    olfacts.user.js  (detect answer; capture term/definition + card image URLs)
      -> worker        (bounded outbox only -- never limits)
      -> wss://127.0.0.1:8444/   bridge.py: sniff, rate limit, merge window, forward
           |               |-> fetch card images (up to 2, http(s) only, 8 MB cap)
           |               |-> POST /chat/completions on your local model server
           |                        (JSON-schema-constrained {odor,intensity,why})
      -> ws://127.0.0.1:8080/    Omara Scent Studio

A sniff frame answers in one of three ways:

| Outcome | Meaning |
|---|---|
| `{ok:true, odor:"marine", how:"sniffed"}` | model matched the card's subject |
| `{ok:true, odor:null, how:"silence"}` | model says no cartridge fits (abstract card) |
| `how:"fallback"` | model unreachable or rambled; fixed CORRECT scent used instead |

Silence is a feature: vocabulary drills and date cards should not smell like anything.

## The raw model answer in the terminal

Every model call prints its raw JSON reply as `[llm] {...}` in the bridge
window, followed by the parsed decision line `[sniff] 1.6s marine@0.80 ...`.
That is your tuning feed: if a card gets a scent you disagree with, the `why`
field says which palette hook the model used. The raw print also exposes
malformed answers that the fallback path would otherwise hide.

## Sniff queue (why replies can arrive out of order)

Model calls take seconds; vision calls can take tens. Sniff frames therefore
go to a dedicated queue thread instead of running inside the websocket handler,
so a slow generation never blocks your next answer's frame — verified: a
classic frame sent right after a sniff gets its reply in milliseconds while the
model is still thinking. The consequence is that **replies arrive out of
order**; every reply carries `how` and the scent name so the worker log stays
readable regardless of sequence. One queue also means one request in flight at
the model server, even with several tabs open.

## Model server

One OpenAI-compatible `/chat/completions` endpoint, so both work out of the box:

- Unsloth Studio llama.cpp server: `http://127.0.0.1:8888/v1` (default)
- Ollama's OpenAI layer: `--base-url http://127.0.0.1:11434/v1 --model <your-model>`

Auth is optional and never printed: `OLFACTS_API_KEY` env var, else Unsloth
Studio's minted agent key file is picked up automatically; Ollama needs neither.
The default model must be vision-capable for card images to matter — text-only
cards work on any instruct model.

## Quick start

    run.bat

Checks Python, installs `websockets` if missing, generates certificates, runs a
self-test once on first install (including a sniff probe), and serves on 8444.
v1 lives on 8443, so both bridges can run side by side. Certificate trust in
Firefox works exactly as in v1 — import `v2\certs\bridge-cert.pem` with
*Identifying websites* ticked.

Install `v2\olfacts.user.js` in **one** manager and disable the v1 script; two
scripts mean two sockets and double decisions. The bridge log's `concurrent=`
count is the ground truth, as ever.

## Certificates: one trusted keypair, both bridges

Firefox trusts certificates, not folders. v1 imported `certs\bridge-cert.pem`;
that trust covers **any** bridge serving that exact certificate — including v2
on 8444 — which is why copying v1's cert files into `v2\certs\` makes v2 work
with no second import (verify they match: both must fingerprint the same). If
you regenerate certs in either folder, Firefox refuses again until you re-import
the new one. The userscript helps: after three failed connects it prints a hint
naming the exact file and the "Identifying websites" checkbox.

## Testing the sniff layer alone

    py sniff.py --text "Maine | a New England state on the Atlantic coast"
    py sniff.py --text "Texas | largest contiguous US state, arid panhandle" --image card.jpg

Prints `marine @ 0.90 (coastal New England...)` style lines with timings. This
is the fastest way to tune the palette: edit `palette.txt`, rerun, no restart
anywhere — the bridge hot-reloads it on edit too.

## Configuration

Bridge sniff flags:

| Flag | Default | Notes |
|---|---|---|
| `--base-url` | `http://127.0.0.1:8888/v1` | OpenAI-compat server; Ollama is `/v1` too |
| `--model` | `unsloth/Qwen3.8-Flash-Next-GGUF` | must be vision-capable for images |
| `--palette` | `palette.txt` beside bridge.py | hot-reloads on edit |
| `--sniff-timeout` | `25` | per-call HTTP timeout, seconds |
| `--no-sniff` | off | skip the model; sniff frames emit their fallback scent |

Userscript config (top of `olfacts.user.js`): same keys as v1 plus
`MAX_IMAGES` (card image URLs forwarded per answer, default 3). `CORRECT` /
`WRONG` are now **fallbacks**: used when the bridge runs with `--no-sniff` or
the model is down. `BRIDGE_URL` points at **8444**.

## Sniff stats (bridge)

v1 counters unchanged; v2 adds:

| Counter | Meaning |
|---|---|
| `sniffed` | cards the model answered with a scent or deliberate silence |
| `sniff_fail` | model unreachable/garbage; fallback used |
| `silence` | model decided the card has no sensory hook |

Sniff decisions cache by text+images (128 entries), so re-drilling the same
card set costs one model call each, ever.

## Tuning the palette

`palette.txt` is the SniffMe mechanic: each cartridge has a `SMELLS LIKE` line
(the actual scent) and a `USE IN STUDY` line (what card subjects should pick
it). The USE lines are the tuning surface — if the model keeps choosing beach
for island cards when you want marine, say so there and save. Hot-reloads per
call; no restart, no re-spraying anything.

## Files

| File | Role |
|---|---|
| `run.bat` | entry point: deps, certs, self-test, serve on 8444 |
| `make-cert.bat` | loopback certificate generation (v2\certs\) |
| `olfacts.user.js` | detection + card capture + worker (buffer, socket) |
| `bridge.py` | TLS front end, sniff orchestration, rate limiting, Omara |
| `sniff.py` | the model call itself; standalone CLI for palette tuning |
| `palette.txt` | cartridge descriptions and study-use guidance (hot-reload) |
| `requirements.txt` | Python dependencies |

## Troubleshooting

Everything in v1's README applies unchanged (cert trust, concurrent clients,
idle drops, ports). v2-specific:

| Symptom | Cause | Fix |
|---|---|---|
| `[olfacts] closed code=1015` or "Firefox can't establish a connection" with the bridge clearly running | cert not trusted — Firefox refuses the TLS handshake before the bridge ever sees it, so no `[down] client` line appears | import `v2\certs\bridge-cert.pem` (or copy v1's identical files in); see the certificate section above |
| every answer logs `sniff failed ... using fallback` | model server down or wrong `--base-url`/`--model` | `py sniff.py --text "test card"` to isolate; check the server is up |
| `json_schema rejected (4xx); retrying plain json` once, then works | server without grammar-constrained decoding | expected; the plain-JSON retry handles it |
| images never influence choice | model has no vision, or card images blocked from fetching (`image fetch failed` warns) | use a vision model; check the warn lines |
| abstract cards spray anyway | palette USE line too broad | tighten `USE IN STUDY`, hot-reload picks it up |
| v1 and v2 scripts both active | two sockets, double decisions | keep one enabled; confirm with `concurrent=1` |
