#!/usr/bin/env python3
"""sitecheck.py - small, stdlib-only checks for the static site. Needs Python 3.9+.

Checks, per *.html file under the root:
  - every local href/src/srcset target exists AND stays inside the root (no ../../.. escapes)
  - <a href="javascript:..."> and similar script URLs are flagged
  - <img> has an alt attribute
  - anything the page LOADS (script, link, img, iframe, source, video, audio, embed, object, track, srcset,
    CSS url()/@import) may only come from ALLOWED_HOSTS; plain outbound <a href> links are fine
  - external <script src> must carry an integrity= attribute (a pinned, hash-checked file);
    external stylesheets from fonts.googleapis.com are exempt (Google serves them per browser, no hash possible)
  - banned phrases: plain case-insensitive substring match, so a sentence that merely NEGATES a banned word
    (for example "nothing here is guaranteed") is flagged too: reword it, or add the exact sentence to
    BANNED_OK below. Keep both lists GENERIC: the private list stays on the owner's PC.
Exit 0 clean, 1 problems.
"""
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse, unquote

ALLOWED_HOSTS = {"fonts.googleapis.com", "fonts.gstatic.com", "hearthward.ai"}   # own domain + allowed CDNs; nothing else
SRI_EXEMPT_HOSTS = {"fonts.googleapis.com"}
BANNED = ["guaranteed", "100% safe", "prevents all", "never leaves your"]   # public-claim rules; edit freely
BANNED_OK: list[str] = []          # exact sentences (case-insensitive) allowed to contain a banned phrase
LOADING_TAGS = {"script", "link", "img", "iframe", "source", "video", "audio", "embed", "object", "track", "input"}
CSS_EXT = re.compile(r"(?:url\(\s*['\"]?|@import\s+['\"]?)((?:https?:)?//[^'\")\s]+)", re.I)


class P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs, self.imgs_no_alt, self.css = [], 0, []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        for k in ("href", "src", "data", "poster"):
            if a.get(k):
                self.refs.append((tag, a[k], a))
        for k in ("srcset", "imagesrcset"):
            if a.get(k):
                self.refs += [(tag, s.split()[0], a) for s in a[k].split(",") if s.strip()]
        if tag == "img" and "alt" not in a:
            self.imgs_no_alt += 1
        if tag == "style":
            self._in_style = True
        if a.get("style"):
            self.css.append(a["style"])

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.css.append(data)


def main(root: str) -> int:
    base = Path(root).resolve()
    problems = []
    for f in sorted(base.rglob("*.html")):
        if ".git" in f.parts:
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        p = P()
        p.feed(text)
        rel = f.relative_to(base)
        if p.imgs_no_alt:
            problems.append(f"{rel}: {p.imgs_no_alt} <img> without alt")
        for css in p.css:
            for m in CSS_EXT.finditer(css):
                host = urlparse(m.group(1) if not m.group(1).startswith("//") else "https:" + m.group(1)).hostname
                if host not in ALLOWED_HOSTS:
                    problems.append(f"{rel}: CSS loads from {host} which is not allowed")
        for tag, ref, a in p.refs:
            ref = ref.strip()
            u = urlparse(ref)
            if u.scheme in ("javascript", "vbscript") or ref.lower().startswith(("javascript:", "vbscript:")):
                problems.append(f"{rel}: <{tag}> uses a script URL ({u.scheme}:)")
                continue
            if u.scheme in ("mailto", "tel") or ref.startswith("#"):
                continue
            if u.scheme == "data":
                if tag in ("script", "iframe", "embed", "object"):
                    problems.append(f"{rel}: <{tag}> loads a data: URL")
                continue
            if u.scheme in ("http", "https") or ref.startswith("//"):
                host = urlparse(ref if u.scheme else "https:" + ref).hostname
                if tag in LOADING_TAGS and host not in ALLOWED_HOSTS:
                    problems.append(f"{rel}: external {tag} from {host} is not allowed")
                elif tag == "script" and not a.get("integrity"):
                    problems.append(f"{rel}: external script from {host} has no integrity= (pinned hash)")
                elif tag == "link" and a.get("rel", "").lower() == "stylesheet" and host not in SRI_EXEMPT_HOSTS \
                        and not a.get("integrity"):
                    problems.append(f"{rel}: external stylesheet from {host} has no integrity=")
                continue
            target = (base / unquote(u.path.lstrip("/"))) if u.path.startswith("/") else (f.parent / unquote(u.path))
            if not u.path:
                continue
            try:
                inside = target.resolve().is_relative_to(base)
            except (OSError, ValueError):
                inside = False
            if not inside:
                problems.append(f"{rel}: local target {ref} points outside the site folder")
            elif not (target.exists() or (target / "index.html").exists()):
                problems.append(f"{rel}: missing local target {ref}")
        scan = text
        for ok in BANNED_OK:
            scan = re.sub(re.escape(ok), "", scan, flags=re.I)
        for w in BANNED:
            if re.search(re.escape(w), scan, re.I):
                problems.append(f"{rel}: banned phrase {w!r}")
    for m in problems:
        print(m)
    print(f"sitecheck: {len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
