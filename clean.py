#!/usr/bin/env python3
"""
Cleans the private dashboard before it goes on the public site.

Usage:  python clean.py <input.html> <output.html>

What it does:
  1. Opens the data block inside the page (the line starting "const D = ").
  2. Applies the settings below (random names, hidden online times, etc).
  3. Runs a safety scan. If anything that looks like a key, token, password,
     server address, or (when names are hidden) a real gamertag is still in
     the page, it STOPS and nothing gets published.
"""
import hashlib
import hmac
import json
import os
import re
import sys

# ------------------------------------------------------------------ settings
# True  = every player gets a random fun name, like "Sneaky Axolotl".
# False = real gamertags are shown.  Flip this whenever you want.
HIDE_REAL_NAMES = True

# The "Every hour" chart lists who was online each hour, which shows when
# each person plays. True = keep the player counts, drop the names.
HIDE_WHO_WAS_ONLINE = True

# The recent deaths list ("X was slain by Y"). True = remove it.
HIDE_DEATH_FEED = False

# Give specific players a chosen public name (used when HIDE_REAL_NAMES is
# False, or to override someone's random name).  {"RealGamertag": "Name"}
RENAME = {}

# Page title. None = keep the title from the private dashboard.
TITLE = None
# ---------------------------------------------------------------------------

MARKER = "const D = "

ADJ = ["Sneaky", "Sleepy", "Brave", "Grumpy", "Lucky", "Shiny", "Mossy", "Dusty",
       "Fuzzy", "Jolly", "Spicy", "Quiet", "Rusty", "Swift", "Wobbly", "Cosmic",
       "Frosty", "Golden", "Hungry", "Mighty", "Noble", "Silly", "Stormy", "Tiny"]
NOUN = ["Axolotl", "Creeper", "Golem", "Pikachu", "Eevee", "Snorlax", "Piglin",
        "Strider", "Allay", "Warden", "Sniffer", "Magikarp", "Ditto", "Gengar",
        "Bulbasaur", "Enderman", "Blaze", "Phantom", "Wooloo", "Mareep", "Fox",
        "Panda", "Bee", "Goat"]

# Things that must never appear on the public page.
SECRET_PATTERNS = [
    (r"ptl[ac]_[A-Za-z0-9]{10,}", "Pterodactyl / CloudNord API key"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub token"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY", "private key"),
    (r"Bearer\s+[A-Za-z0-9._-]{20,}", "auth header"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", "server IP and port"),
    (r"(?i)(?:api[_-]?key|password|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9._-]{12,}", "key or password"),
]


def random_names(names, salt):
    """Same player always gets the same random name (so charts stay consistent
    hour to hour), but without the secret salt nobody can work out who is who."""
    out, used = {}, set()
    for n in sorted(names, key=str.lower):
        h = hmac.new(salt.encode(), n.lower().encode(), hashlib.sha256).digest()
        i = int.from_bytes(h[:8], "big")
        alias = f"{ADJ[i % len(ADJ)]} {NOUN[(i // len(ADJ)) % len(NOUN)]}"
        base, k = alias, 2
        while alias in used:
            alias, k = f"{base} {k}", k + 1
        used.add(alias)
        out[n] = alias
    return out


def collect_names(data):
    names = {p["name"] for p in data.get("players", [])}
    names |= {t["name"] for t in data.get("trainers", [])}
    names |= set(data.get("daily", {}))
    names |= set((data.get("ot") or {}).get("players", []))
    for day in data.get("day_players", []):
        names |= set(day)
    for h in data.get("hourly", []):
        names |= set(h.get("who", []))
    return {n for n in names if n}


def main(src, dst):
    html = open(src, encoding="utf-8").read()
    start = html.index(MARKER) + len(MARKER)
    data, length = json.JSONDecoder().raw_decode(html[start:])
    real = collect_names(data)

    if HIDE_REAL_NAMES:
        salt = os.environ.get("ALIAS_SALT", "")
        if len(salt) < 12:
            sys.exit("ALIAS_SALT secret is missing or too short. Add it in "
                     "Settings > Secrets and variables > Actions.")
        mapping = random_names(real, salt)
        mapping.update(RENAME)
    else:
        mapping = dict(RENAME)

    if HIDE_WHO_WAS_ONLINE:
        for h in data.get("hourly", []):
            h["who"] = []
    if HIDE_DEATH_FEED:
        data["deaths_feed"] = []
    if TITLE:
        data["title"] = TITLE

    if mapping:
        pattern = re.compile(r"(?<![\w])(" + "|".join(
            re.escape(n) for n in sorted(mapping, key=len, reverse=True)) + r")(?![\w])",
            re.IGNORECASE)
        lower = {k.lower(): v for k, v in mapping.items()}
        swap = lambda s: pattern.sub(lambda m: lower[m.group(1).lower()], s)

        def walk(x):
            if isinstance(x, dict):
                return {swap(k): walk(v) for k, v in x.items()}
            if isinstance(x, list):
                return [walk(v) for v in x]
            if isinstance(x, str):
                return swap(x)
            return x
        data = walk(data)

    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    html = html[:start] + blob + html[start + length:]
    if TITLE:
        html = re.sub(r"<title>.*?</title>", f"<title>{TITLE}</title>", html, count=1)
    # keep it out of Google
    html = html.replace("<head>", '<head>\n<meta name="robots" content="noindex, nofollow">', 1)

    # ---------------------------------------------------------------- safety scan
    problems = []
    for pat, what in SECRET_PATTERNS:
        for m in re.finditer(pat, html):
            problems.append(f"{what}: {m.group(0)[:12]}...")
    if HIDE_REAL_NAMES:
        for n in real:
            if n in RENAME and RENAME[n] == n:
                continue
            if len(n) >= 4 and re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", html, re.IGNORECASE):
                problems.append(f"real gamertag still on page: {n[:2]}***")
    if problems:
        print("SAFETY CHECK FAILED, nothing was published:")
        for p in problems:
            print("  -", p)
        sys.exit(1)

    open(dst, "w", encoding="utf-8").write(html)
    print(f"cleaned: {len(real)} players, names {'random' if HIDE_REAL_NAMES else 'real'}, "
          f"online names {'hidden' if HIDE_WHO_WAS_ONLINE else 'kept'}, "
          f"death feed {'hidden' if HIDE_DEATH_FEED else 'kept'}. Safety check passed.")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
