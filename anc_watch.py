#!/usr/bin/env python3
"""
ANC citizenship-case watcher for cetatenie.just.ro.

Monitors a single dossier (default 10225/RD/2023, art. 11 "redobandire") and
e-mails the result. The whole domain sits behind a JavaScript anti-bot wall that
returns HTTP 503 + a SHA1 proof-of-work challenge; this script solves that PoW in
pure Python (no browser needed), then:

  1. loads /stadiu-dosar/, finds the *current* Art-<art>-<year>-Update-*.pdf link
     dynamically (the date in the file name changes ~weekly),
  2. downloads + parses that PDF, locates the dossier row and reads the SOLUTIE
     column (an order number "<n>/P/<year>" means the case is solved),
  3. cross-checks the orders list /ordine-articolul-1-1/ to attach the order PDF,
  4. keeps a state file so the "solved!" alert is sent exactly once.

Designed to run unattended in Docker (see Dockerfile / docker-compose.yml).
Only dependency: pypdf.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import logging
import os
import re
import smtplib
import ssl
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from pypdf import PdfReader

# --------------------------------------------------------------------------- #
# Configuration (all overridable via environment / docker .env)
# --------------------------------------------------------------------------- #
BASE_URL = os.environ.get("ANC_BASE_URL", "https://cetatenie.just.ro").rstrip("/")
STADIU_URL = f"{BASE_URL}/stadiu-dosar/"
ORDERS_URL = f"{BASE_URL}/ordine-articolul-1-1/"

DOSSIER = os.environ.get("ANC_DOSSIER", "10225/RD/2023").strip()
ARTICLE = os.environ.get("ANC_ARTICLE", "11").strip()
YEAR = os.environ.get("ANC_YEAR", "2023").strip()

USER_AGENT = os.environ.get(
    "ANC_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
)

STATE_FILE = Path(os.environ.get("STATE_FILE", "/data/state.json"))
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "86400"))  # seconds (loop mode)

HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
HTTP_RETRIES = int(os.environ.get("HTTP_RETRIES", "4"))
SOLVE_ATTEMPTS = int(os.environ.get("SOLVE_ATTEMPTS", "4"))
ERROR_THRESHOLD = int(os.environ.get("ERROR_THRESHOLD", "3"))  # consecutive fails before error mail

# --- e-mail / SMTP ---
ALERT_TO = os.environ.get("ALERT_TO", "filinvadim@pm.me").strip()
ALERT_FROM = os.environ.get("ALERT_FROM", "").strip()
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_SECURITY = os.environ.get("SMTP_SECURITY", "starttls").strip().lower()  # starttls|ssl|none
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASS = os.environ.get("SMTP_PASS", "")

NOTIFY_ON_START = os.environ.get("NOTIFY_ON_START", "1") not in ("0", "false", "False", "")
ALWAYS_NOTIFY = os.environ.get("ALWAYS_NOTIFY", "0") not in ("0", "false", "False", "")
NOTIFY_ON_ERROR = os.environ.get("NOTIFY_ON_ERROR", "1") not in ("0", "false", "False", "")

CHALLENGE_MARKERS = (b"Verifying your browser", b"Activati JavaScript")

log = logging.getLogger("anc-watch")


# --------------------------------------------------------------------------- #
# Anti-bot wall: SHA1 proof-of-work solver + cookie-bearing HTTP client
# --------------------------------------------------------------------------- #
class Wall:
    """HTTP client that transparently solves the cetatenie.just.ro PoW challenge.

    The challenge page embeds a 40-hex-char token ``c``; with ``n1 = int(c[0],16)``
    you brute-force ``i = 0,1,2,...`` until ``sha1(c+i)`` has byte[n1]==0xB0 and
    byte[n1+1]==0x0B, then present cookie ``res=<c><i>``. Validation is stateless,
    so one solved cookie unlocks every path on the domain until it rotates.
    """

    TOKEN_RE = re.compile(r"['\"]([0-9A-Fa-f]{40})['\"]")

    def __init__(self) -> None:
        self.cookie: str | None = None

    @staticmethod
    def _is_challenge(body: bytes) -> bool:
        if body[:4] == b"%PDF":
            return False
        head = body[:8192]
        return any(m in head for m in CHALLENGE_MARKERS)

    @classmethod
    def solve(cls, html: str) -> str:
        m = cls.TOKEN_RE.search(html)
        if not m:
            raise RuntimeError("anti-bot challenge present but no 40-hex token found")
        c = m.group(1)
        n1 = int(c[0], 16)
        if n1 + 1 >= 20:  # sha1 digest is 20 bytes; guard impossible index
            raise RuntimeError(f"unexpected token first char -> n1={n1} out of range")
        i = 0
        while True:
            d = hashlib.sha1(f"{c}{i}".encode()).digest()
            if d[n1] == 0xB0 and d[n1 + 1] == 0x0B:
                log.info("PoW solved: token=%s n1=%d nonce=%d sha1=%s", c, n1, i, d.hex())
                return f"res={c}{i}"
            i += 1
            if i > 5_000_000:  # ~1/65536 hit rate; this never happens, just a safety net
                raise RuntimeError("PoW solver exceeded iteration budget")

    def _raw_get(self, url: str) -> bytes:
        last_err: Exception | None = None
        for attempt in range(1, HTTP_RETRIES + 1):
            req = urllib.request.Request(url)
            req.add_header("User-Agent", USER_AGENT)
            req.add_header("Accept-Language", "en-US,en;q=0.9,ro;q=0.8")
            req.add_header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,*/*;q=0.8",
            )
            if self.cookie:
                req.add_header("Cookie", self.cookie)
            try:
                with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                # 503 carries the challenge body, which we *want* to read and solve.
                body = e.read()
                if e.code == 503 or self._is_challenge(body):
                    return body
                last_err = e
                log.warning("HTTP %s for %s (attempt %d/%d)", e.code, url, attempt, HTTP_RETRIES)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e
                log.warning("network error for %s (attempt %d/%d): %s", url, attempt, HTTP_RETRIES, e)
            time.sleep(min(2 ** attempt, 20))
        raise RuntimeError(f"GET failed after {HTTP_RETRIES} attempts: {url}: {last_err}")

    def get(self, url: str) -> bytes:
        """GET url, transparently solving / refreshing the anti-bot cookie."""
        for attempt in range(SOLVE_ATTEMPTS):
            body = self._raw_get(url)
            if not self._is_challenge(body):
                return body
            log.info("anti-bot wall hit on %s -> solving (attempt %d)", url, attempt + 1)
            self.cookie = self.solve(body.decode("utf-8", "replace"))
        raise RuntimeError(f"could not pass anti-bot wall after {SOLVE_ATTEMPTS} solves: {url}")

    def get_text(self, url: str) -> str:
        return self.get(url).decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Scraping / parsing
# --------------------------------------------------------------------------- #
def find_pdf_url(stadiu_html: str, article: str, year: str) -> str:
    """Return the newest Art-<article>-<year>-Update-<date>.pdf link on the page."""
    pat = re.compile(
        r"https?://[^\s\"'<>]+/Art-%s-%s-Update-[^\s\"'<>]+\.pdf" % (re.escape(article), re.escape(year)),
        re.IGNORECASE,
    )
    urls = list(dict.fromkeys(pat.findall(stadiu_html)))  # dedup, keep order
    if not urls:
        raise RuntimeError(f"no Art-{article}-{year}-Update-*.pdf link found on {STADIU_URL}")

    date_re = re.compile(r"Update-(\d{2})[._-](\d{2})[._-](\d{4})", re.IGNORECASE)

    def keyfn(u: str):
        m = date_re.search(u)
        if not m:
            return dt.date.min
        d, mo, y = (int(x) for x in m.groups())
        try:
            return dt.date(y, mo, d)
        except ValueError:
            return dt.date.min

    urls.sort(key=keyfn)
    chosen = urls[-1]
    if len(urls) > 1:
        log.info("multiple PDFs found, picked newest by filename date: %s", chosen)
    return chosen


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s)


def parse_status(pdf_bytes: bytes, dossier: str) -> dict:
    """Locate `dossier` in the PDF table and read its columns.

    Returns dict with: found, page, raw_line, data_inreg, termen, solutie, resolved.
    `resolved` is True only when an order signature "<n>/P/<year>" sits in the row,
    which is exactly the SOLUTIE-filled signal.
    """
    if pdf_bytes[:4] != b"%PDF":
        raise RuntimeError("downloaded file is not a PDF (anti-bot or 404 page?)")

    target = _norm(dossier)
    our_num = dossier.split("/", 1)[0].strip()                 # "10225"
    code_m = re.search(r"/([A-Za-z]{1,4})/", dossier)
    code = code_m.group(1) if code_m else "RD"                 # dossier reg-code, e.g. RD
    # row start = "<num>/RD/" — the (?<!\d) stops 10225 matching inside 110225.
    our_start_re = re.compile(r"(?<!\d)%s\s*/\s*%s\s*/" % (re.escape(our_num), re.escape(code)), re.I)
    row_start_re = re.compile(r"(?<!\d)\d{3,6}\s*/\s*%s\s*/" % re.escape(code), re.I)
    # Parse on the ORIGINAL (space-separated) line: fields stay separated there, so the
    # order number "1607/P/2025" doesn't glue onto the preceding date.
    date_re = re.compile(r"\d{2}\.\d{2}\.\d{4}")
    order_re = re.compile(r"(\d+)\s*/\s*P\s*/\s*(\d{4})", re.I)  # SOLUTIE = order signature

    reader = PdfReader(io.BytesIO(pdf_bytes))
    log.info("PDF parsed: %d pages, scanning for %s", len(reader.pages), dossier)

    for pidx, page in enumerate(reader.pages):
        try:
            txt = page.extract_text() or ""
        except Exception as e:  # one bad page must not kill the scan
            log.debug("page %d extract failed: %s", pidx, e)
            continue
        if target not in _norm(txt):
            continue
        for line in txt.splitlines():
            ms = our_start_re.search(line)
            if not ms:
                continue
            start = ms.start()
            # isolate our row if pypdf merged the next dossier onto the same line
            nxt = next((m.start() for m in row_start_re.finditer(line) if m.start() > start), None)
            seg = line[start:nxt] if nxt else line[start:]
            dates = date_re.findall(seg)
            order = order_re.search(seg)
            return {
                "found": True,
                "page": pidx,
                "raw_line": line.strip(),
                "data_inreg": dates[0] if dates else None,
                "termen": dates[1] if len(dates) > 1 else None,
                "solutie": re.sub(r"\s+", "", order.group(0)) if order else None,
                "resolved": bool(order),
            }
    return {"found": False, "page": None, "raw_line": None,
            "data_inreg": None, "termen": None, "solutie": None, "resolved": False}


def find_order_link(orders_html: str, solutie: str) -> str | None:
    """Best-effort: given SOLUTIE '1607/P/2025', find the matching order PDF link."""
    m = re.match(r"(\d+)/P/", solutie or "", re.IGNORECASE)
    if not m:
        return None
    num = m.group(1)
    links = re.findall(r"https?://[^\s\"'<>]+\.pdf", orders_html)
    needle = re.compile(r"(?<!\d)%sP" % re.escape(num), re.IGNORECASE)  # "1607P" in file name
    for link in links:
        if needle.search(link.replace("-", "").replace("_", "").replace(".", "")):
            return link
    return None


def termen_note(termen: str | None) -> str:
    if not termen:
        return ""
    try:
        d, mo, y = (int(x) for x in termen.split("."))
        t = dt.date(y, mo, d)
    except (ValueError, AttributeError):
        return ""
    today = dt.date.today()
    if t < today:
        return f" (просрочен на {(today - t).days} дн.)"
    return f" (через {(t - today).days} дн.)"


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except Exception as e:
        log.warning("state file unreadable (%s) — starting fresh", e)
        return {}


def save_state(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(STATE_FILE)  # atomic
    except Exception as e:
        log.error("could not persist state to %s: %s", STATE_FILE, e)


# --------------------------------------------------------------------------- #
# E-mail
# --------------------------------------------------------------------------- #
def send_email(subject: str, body: str, dry_run: bool = False) -> bool:
    recipients = [a.strip() for a in ALERT_TO.split(",") if a.strip()]
    if dry_run or not SMTP_HOST:
        log.info("[DRY-RUN email] -> %s\nSubject: %s\n%s\n%s", recipients, subject, "-" * 60, body)
        return True

    msg = EmailMessage()
    msg["From"] = ALERT_FROM or SMTP_USER or "anc-watch@localhost"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="anc-watch")
    msg.set_content(body)

    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            ctx = ssl.create_default_context()
            if SMTP_SECURITY == "ssl":
                srv = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30, context=ctx)
            else:
                srv = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
            with srv:
                srv.ehlo()
                if SMTP_SECURITY == "starttls":
                    srv.starttls(context=ctx)
                    srv.ehlo()
                if SMTP_USER:
                    srv.login(SMTP_USER, SMTP_PASS)
                srv.send_message(msg, to_addrs=recipients)
            log.info("e-mail sent to %s (subject: %s)", recipients, subject)
            return True
        except Exception as e:
            last_err = e
            log.warning("e-mail attempt %d/3 failed: %s", attempt, e)
            time.sleep(3 * attempt)
    log.error("e-mail FAILED after retries: %s", last_err)
    return False


def build_report(st: dict, pdf_url: str, order_link: str | None, when: dt.datetime) -> tuple[str, str]:
    ts = when.strftime("%Y-%m-%d %H:%M UTC")
    if not st["found"]:
        subj = f"⚠️ ANC {DOSSIER}: дело НЕ найдено в списке"
        body = (f"Проверка {ts}\n\nДосье {DOSSIER} не найдено в {pdf_url}\n"
                f"Возможно изменился формат файла/таблицы — стоит проверить вручную.\n")
        return subj, body

    if st["resolved"]:
        subj = f"✅ ANC {DOSSIER}: ОРДИН {st['solutie']} — дело решено!"
        lines = [
            f"🎉 По досье {DOSSIER} издан приказ (SOLUTIE заполнен).",
            "",
            f"  Дело:      {DOSSIER}",
            f"  SOLUTIE:   {st['solutie']}   <-- номер приказа",
            f"  Подан:     {st['data_inreg'] or '—'}",
            f"  Стр. PDF:  {st['page']}",
            f"  Строка:    {st['raw_line']}",
            "",
            f"  Источник:  {pdf_url}",
        ]
        if order_link:
            lines.append(f"  Приказ PDF: {order_link}")
        lines.append(f"  Список приказов: {ORDERS_URL}")
        lines += ["", f"Проверено: {ts}",
                  "Следующий шаг: присяга (juramant) — отслеживается по номеру дела на сайте ANC."]
        return subj, "\n".join(lines)

    subj = f"ANC {DOSSIER}: без изменений — в работе (termen {st['termen'] or '—'})"
    body = "\n".join([
        f"Статус досье {DOSSIER} — БЕЗ ИЗМЕНЕНИЙ: дело ещё в работе, приказа нет.",
        "",
        f"  Дело:      {DOSSIER}",
        f"  SOLUTIE:   (пусто)",
        f"  Подан:     {st['data_inreg'] or '—'}",
        f"  TERMEN:    {st['termen'] or '—'}{termen_note(st['termen'])}",
        f"  Стр. PDF:  {st['page']}",
        f"  Строка:    {st['raw_line']}",
        "",
        f"  Источник:  {pdf_url}",
        "",
        f"Проверено: {ts}. Письмо придёт снова, когда SOLUTIE заполнится.",
    ])
    return subj, body


# --------------------------------------------------------------------------- #
# One check cycle
# --------------------------------------------------------------------------- #
def run_once(dry_run: bool = False) -> bool:
    """Perform one full check. Returns True on success (no exception)."""
    now = dt.datetime.now(dt.timezone.utc)
    state = load_state()
    rec = state.get(DOSSIER, {})

    wall = Wall()
    stadiu_html = wall.get_text(STADIU_URL)
    pdf_url = find_pdf_url(stadiu_html, ARTICLE, YEAR)
    log.info("current PDF: %s", pdf_url)
    pdf_bytes = wall.get(pdf_url)
    st = parse_status(pdf_bytes, DOSSIER)

    order_link = None
    if st["resolved"] and st["solutie"]:
        try:
            order_link = find_order_link(wall.get_text(ORDERS_URL), st["solutie"])
        except Exception as e:
            log.warning("orders-list lookup failed (non-fatal): %s", e)

    log.info("RESULT %s: found=%s resolved=%s solutie=%s termen=%s",
             DOSSIER, st["found"], st["resolved"], st["solutie"], st["termen"])

    first_run = DOSSIER not in state
    already_alerted = rec.get("alerted", False)

    send = False
    if st["resolved"] and not already_alerted:
        send = True
    elif first_run and NOTIFY_ON_START:
        send = True
    elif ALWAYS_NOTIFY:
        send = True

    new_rec = {
        "found": st["found"],
        "resolved": st["resolved"],
        "solutie": st["solutie"],
        "termen": st["termen"],
        "pdf_url": pdf_url,
        "last_checked": now.isoformat(),
        "alerted": already_alerted,
        "consecutive_failures": 0,
        "error_notified": False,
    }

    if send:
        subj, body = build_report(st, pdf_url, order_link, now)
        ok = send_email(subj, body, dry_run=dry_run)
        if ok and st["resolved"]:
            new_rec["alerted"] = True  # mark only after a successful "solved" mail
    else:
        log.info("no e-mail this run (resolved=%s already_alerted=%s)", st["resolved"], already_alerted)

    state[DOSSIER] = new_rec
    save_state(state)
    return True


def record_failure(err: Exception, dry_run: bool = False) -> None:
    state = load_state()
    rec = state.get(DOSSIER, {})
    fails = int(rec.get("consecutive_failures", 0)) + 1
    rec["consecutive_failures"] = fails
    rec["last_error"] = f"{type(err).__name__}: {err}"
    rec["last_checked"] = dt.datetime.now(dt.timezone.utc).isoformat()
    if NOTIFY_ON_ERROR and fails >= ERROR_THRESHOLD and not rec.get("error_notified"):
        ok = send_email(
            f"⚠️ ANC {DOSSIER}: монитор не может прочитать сайт ({fails} раз подряд)",
            f"Ошибка при проверке {DOSSIER}:\n\n{type(err).__name__}: {err}\n\n"
            f"Сайт мог изменить анти-бот стену/формат. Нужна ручная проверка:\n{STADIU_URL}\n",
            dry_run=dry_run,
        )
        if ok:
            rec["error_notified"] = True
    state[DOSSIER] = rec
    save_state(state)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Monitor an ANC citizenship dossier and e-mail the result.")
    ap.add_argument("--once", action="store_true", help="run a single check and exit")
    ap.add_argument("--loop", action="store_true", help="run forever, every CHECK_INTERVAL seconds")
    ap.add_argument("--dry-run", action="store_true", help="print the e-mail instead of sending it")
    args = ap.parse_args()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    dry = args.dry_run or not SMTP_HOST
    if dry and not args.dry_run:
        log.warning("SMTP_HOST not set — running in DRY-RUN mode (e-mails will only be logged)")

    def cycle() -> None:
        try:
            run_once(dry_run=dry)
        except Exception as e:
            log.exception("check cycle failed: %s", e)
            try:
                record_failure(e, dry_run=dry)
            except Exception:
                log.exception("could not record failure")

    if args.loop or (not args.once):  # default is loop (Docker long-running service)
        log.info("watcher started: dossier=%s art=%s year=%s interval=%ds to=%s",
                 DOSSIER, ARTICLE, YEAR, CHECK_INTERVAL, ALERT_TO)
        while True:
            cycle()
            log.info("sleeping %d s until next check", CHECK_INTERVAL)
            time.sleep(CHECK_INTERVAL)
    else:
        cycle()
    return 0


if __name__ == "__main__":
    sys.exit(main())
