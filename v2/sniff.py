#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# OlFacts v2 sniffer
# Copyright (C) 2026 Mark J. Kuebel
"""Pick an Omara cartridge for flashcard content using a local model server.

    bridge.py handler   -> Sniffer.sniff(text, images) -> {odor, intensity, why}
    py sniff.py --text "Maine" --image card.jpg     (standalone test)

One JSON-schema-constrained call per card, like SniffMe does for game scenes:
the model returns {odor, intensity, why}; code validates and clamps. The
palette file is hot-reloaded on edit so tuning never needs a restart.

Speaks the OpenAI-compatible /chat/completions API. That covers Unsloth
Studio's llama.cpp server (http://127.0.0.1:8888/v1) and Ollama's own
OpenAI layer (http://127.0.0.1:11434/v1) with one code path. Images are sent
as data URLs; the model must be a vision-capable one for them to matter.

Auth is optional: OLFACTS_API_KEY or Unsloth Studio's minted agent key file
are used when present, and Ollama needs neither. No token is ever printed.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

log = logging.getLogger("olfacts.sniff")

VALID_ODORS = [
    "marine", "petrichor", "kindred", "beach", "floral", "sweet", "barnyard",
    "winter", "evergreen", "terra_silva", "citrus", "desert", "savory_spice",
    "timber", "smoky", "machina",
]

DEFAULT_BASE_URL = "http://127.0.0.1:8888/v1"   # Studio; Ollama's OpenAI API is /v1 too
STUDIO_KEY_FILE = os.path.expandvars(
    r"C:\Users\%USERNAME%\.unsloth\studio\auth\agent_api_key.json")

DISPLAY_TO_KEY = {
    "winter": "winter", "barnyard": "barnyard", "sweet": "sweet",
    "floral": "floral", "beach": "beach", "kindred": "kindred",
    "petrichor": "petrichor", "marine": "marine", "evergreen": "evergreen",
    "terra silva": "terra_silva", "citrus": "citrus", "desert": "desert",
    "savory spice": "savory_spice", "timber": "timber", "smoky": "smoky",
    "machina": "machina",
}

SNIFF_SCHEMA = {
    "name": "card_scent",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "odor": {"enum": VALID_ODORS + [None]},
            "intensity": {"type": "number"},
            "why": {"type": "string"},
        },
        "required": ["odor", "intensity", "why"],
        "additionalProperties": False,
    },
}

PROMPT_HEADER = """\
You assign ONE Omara scent cartridge to a flashcard so the smell reinforces \
the memory of what the card is ABOUT. You may only choose from these {n} \
cartridges: {odors}.

CARTRIDGE PALETTE (what each smells like; USE IN STUDY is authoritative):
{palette}

Rules:
- Smell the SUBJECT of the card, not its grammar. A state, animal, place, \
food, plant, material or weather topic should smell like being there: \
"Maine / capital: Augusta" -> marine (coastal New England), \
"Texas / arid panhandle" -> desert (Southwest heat and sand).
- Places are never abstract. For a state, province, city or country, choose \
the cartridge for its climate and terrain even when the card only names it: \
coastal or ocean-facing -> marine; hot and arid -> desert; deep forest -> \
evergreen; rich farm country -> terra_silva or barnyard; Mediterranean fruit \
country -> citrus; polar -> winter.
- Abstract cards with no sensory hook (vocab drills, dates, formulas) get \
odor null. Silence beats a forced fit; never invent a smell to seem helpful.
- intensity in (0, 1] measures how strongly the subject pulls at the nose: \
faint topic ~0.2-0.4, clear match ~0.5-0.7, you-could-be-there ~0.8-1.
- why: max 8 words naming the hook you used (or "abstract").

Card text:
{text}
{images_note}
Answer with the structured object only.
"""


def load_token() -> str | None:
    env = os.environ.get("OLFACTS_API_KEY")
    if env and env.strip():
        return env.strip()
    try:
        with open(STUDIO_KEY_FILE, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        server = doc["servers"]["http://127.0.0.1:8888"]
        toks = server.get("minted") or server.get("saved") or []
        return toks[-1] if toks else None
    except Exception:
        return None


def load_palette(path: str) -> dict[str, str]:
    """Parse 'Name / SMELLS LIKE / USE IN ...' blocks into {key: text}."""
    palette: dict[str, str] = {}
    cur_key: str | None = None
    cur_lines: list[str] = []

    def close() -> None:
        nonlocal cur_key, cur_lines
        if cur_key is not None:
            joined = " ".join(cur_lines)
            palette[cur_key] = " ".join(joined.split())
        cur_key, cur_lines = None, []

    with open(path, "r", encoding="utf-8-sig") as fh:
        for raw in fh.read().splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            key = DISPLAY_TO_KEY.get(low)
            if key and not low.startswith(("smells", "use")):
                close()
                cur_key = key
                continue
            if cur_key is not None:
                cur_lines.append(line)
    close()
    missing = set(VALID_ODORS) - set(palette)
    if missing:
        raise RuntimeError(f"palette {path} missing cartridges: {sorted(missing)}")
    return palette


def build_prompt(palette: dict[str, str], text: str, n_images: int) -> str:
    lines = [f"- {k}: {palette[k]}" for k in sorted(palette)]
    note = ("A card image is attached; weigh it with the text."
            if n_images else "No image attached.")
    return PROMPT_HEADER.format(n=len(VALID_ODORS),
                                odors=", ".join(sorted(VALID_ODORS)),
                                palette="\n".join(lines),
                                text=text, images_note=note)


def parse_model_json(msg: str) -> dict | None:
    """Model answers arrive as JSON, sometimes quoted or fenced. Dig it out."""
    msg = msg.strip()
    if not msg:
        return None
    if msg.startswith("'") and msg.endswith("'"):
        msg = msg[1:-1]                     # grammar quote artifacts (Studio)
    try:
        obj = json.loads(msg)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", msg, re.S)
    if m:
        try:
            obj = json.loads(m.group(1))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{.*\}", msg, re.S)      # last resort: first {...} blob
    if m:
        try:
            obj = json.loads(m.group(0))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            pass
    return None


def clamp_decision(raw: dict | None) -> dict | None:
    """Normalize a schema answer. Returns None only for garbage outside the enum."""
    if not raw:
        return None
    odor = raw.get("odor")
    odor = odor.strip().lower() if isinstance(odor, str) else None
    if odor in ("none", "null", ""):
        odor = None
    why = (raw.get("why") or "").strip()[:60]
    try:
        intensity = float(raw.get("intensity"))
    except (TypeError, ValueError):
        intensity = 0.4
    if odor is None:
        return {"odor": None, "intensity": 0.0, "why": why or "abstract"}
    if odor not in VALID_ODORS:
        return None                          # outside the enum: unusable
    return {"odor": odor,
            "intensity": min(1.0, max(0.02, round(intensity, 3))),
            "why": why}


class Sniffer:
    """One-shot card->scent calls against a local OpenAI-compatible server."""

    def __init__(self, base_url: str, model: str, palette_path: str, *,
                 timeout: float = 25.0, max_tokens: int = 160) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.palette_path = palette_path
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.on_raw: Callable[[str], None] | None = None   # callback(raw_answer_text)
        self.token = load_token()
        self._mtime = 0.0
        self._palette: dict[str, str] = {}
        self.reload_palette(force=True)
        self.cache: dict[int, dict] = {}    # successes only; redrills cost nothing

    def reload_palette(self, force: bool = False) -> None:
        try:
            mtime = os.path.getmtime(self.palette_path)
            if force or mtime != self._mtime:
                self._palette = load_palette(self.palette_path)
                self._mtime = mtime
                if not force:
                    print("[sniff] palette reloaded after edit", flush=True)
        except Exception as exc:
            if not self._palette:
                raise
            log.warning("palette reload failed, keeping previous: %s", exc)

    # -- HTTP -----------------------------------------------------------------
    def _post(self, payload: dict) -> dict:
        url = f"{self.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def _ask(self, text: str, images: list[str], schema: bool):
        content = [{"type": "text",
                    "text": build_prompt(self._palette, text, len(images))}]
        for b64 in images:
            content.append({"type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{b64}"}})
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": content}],
            "temperature": 0.0,
            "max_tokens": self.max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if schema:
            payload["response_format"] = {"type": "json_schema",
                                          "json_schema": SNIFF_SCHEMA}
        else:
            payload["response_format"] = {"type": "json_object"}
        out = self._post(payload)
        msg = (out["choices"][0]["message"].get("content") or "").strip()
        if self.on_raw:
            try:
                self.on_raw(msg)
            except Exception:
                pass
        return msg

    # -- public ------------------------------------------------------------------
    def sniff(self, text: str, images: list[str] | None = None) -> dict | None:
        """Return {odor, intensity, why}; odor None means 'no scent fits'.
        None (the whole result) means the model could not be reached."""
        text = (text or "").strip()[:2000]
        if not text and not images:
            return {"odor": None, "intensity": 0.0, "why": "empty card"}
        self.reload_palette()
        images = list(images or [])[:2]
        key = hash((text, tuple(images)))
        hit = self.cache.get(key)
        if hit is not None:
            log.debug("sniff cache hit")
            return dict(hit)

        last_exc: Exception | None = None
        for schema in (True, False):        # strict grammar, then plain json
            try:
                msg = self._ask(text, images, schema)
                decision = clamp_decision(parse_model_json(msg))
                if decision is not None:
                    if len(self.cache) >= 128:
                        self.cache.clear()
                    self.cache[key] = decision
                    return dict(decision)
                log.warning("model answer unusable despite format=%s: %r",
                            "schema" if schema else "json", msg[:120])
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode(errors="replace")[:200]
                except Exception:
                    pass
                last_exc = exc
                # A server without grammar support answers 4xx on json_schema;
                # fall through to the plain-json retry. Anything else is fatal.
                if exc.code < 500 and schema:
                    log.warning("json_schema rejected (%s: %s); retrying plain json",
                                exc.code, body)
                    continue
                log.error("sniff HTTP %s: %s", exc.code, body)
                return None
            except Exception as exc:
                last_exc = exc
                log.error("sniff call failed: %s", exc)
                return None
        del last_exc
        return None


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def post_to_bridge(url: str, frame: dict, timeout: float) -> dict:
    """Send one sniff frame to a running bridge's HTTP port and await its reply.

    This is --send mode: the bridge does the model call, the rate limiting and
    the spray, exactly as it does for the browser. Using it means your test card
    really sprays -- Omara fires if it is up. Replies arrive once the model has
    answered, so the timeout should cover a full generation."""
    req = urllib.request.Request(
        url, data=json.dumps(frame).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Sniff one card for its scent (standalone test of the model link)")
    ap.add_argument("--text", required=True, help="card term + definition")
    ap.add_argument("--image", action="append", default=[], metavar="FILE",
                    help="attach an image file (repeatable, max 2 used)")
    ap.add_argument("--model", default="unsloth/Qwen3.8-Flash-Next-GGUF")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--palette", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "palette.txt"))
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--send", metavar="URL", nargs="?", const="http://127.0.0.1:8445/",
                    help="post the card to a running bridge instead of calling the "
                         "model directly (default http://127.0.0.1:8445/). The bridge "
                         "sniffs, rate limits and SPRAYS -- Omara fires if it is up.")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(name)s %(levelname)s %(message)s")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    images: list[str] = []
    for path in args.image[:2]:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
            if not blob:
                raise OSError("empty file")
            images.append(base64.b64encode(blob).decode())
        except Exception as exc:
            print(f"image {path!r} unusable: {exc}", file=sys.stderr)

    # --send: hand the card to the bridge, which owns model + rate limit + spray.
    if args.send:
        frame = {"sniff": True, "text": args.text.strip()[:2000],
                 "images": [f"data:image/jpeg;base64,{b}" for b in images]}
        t0 = time.monotonic()
        try:
            reply = post_to_bridge(args.send, frame, timeout=args.timeout * 2 + 30)
        except Exception as exc:
            print(f"FAIL bridge unreachable at {args.send}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 1
        dt = time.monotonic() - t0
        odor = reply.get("odor") or "SILENCE"
        how = reply.get("how", "?")
        if not reply.get("ok"):
            print(f"[{dt:.1f}s] bridge rejected: {reply.get('error')}", file=sys.stderr)
            return 1
        print(f"[{dt:.1f}s] via bridge {how}: {odor}"
              + (f" @ {reply['intensity']:.2f}" if reply.get("odor") else ""))
        print("(the bridge did the model call and sprayed -- check its window for "
              "the [llm]/[sniff] lines)")
        return 0

    sn = Sniffer(args.base_url, args.model, args.palette, timeout=args.timeout)
    t0 = time.monotonic()
    decision = sn.sniff(args.text, images)
    dt = time.monotonic() - t0
    if decision is None:
        print(f"FAIL: no usable answer after {dt:.1f}s", file=sys.stderr)
        return 1
    odor = decision["odor"] or "SILENCE"
    print(f"[{dt:.1f}s] {odor}"
          + (f" @ {decision['intensity']:.2f}" if decision["odor"] else "")
          + (f"  ({decision['why']})" if decision["why"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
