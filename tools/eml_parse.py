#!/usr/bin/env python3
"""Generic .eml parser for phishing-analysis triage.

Extracts key headers, Received chain, authentication results, body text,
all href/src URLs and MIME parts from one or more .eml files.

Usage:
    python3 eml_parse.py file1.eml [file2.eml ...]

Output is printed to stdout (plain text, no HTML rendering).
This tool contains no case data or PII - feed it your own samples.
"""

import email
import email.policy
import hashlib
import re
import sys
from email.header import decode_header, make_header

HEADERS = [
    "From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To",
    "Return-Path", "Sender", "X-Mailer", "User-Agent", "MIME-Version",
    "Content-Type", "Delivered-To", "Received-SPF", "Authentication-Results",
    "DKIM-Signature", "ARC-Authentication-Results", "List-Unsubscribe",
    "X-Google-Smtp-Source", "X-Originating-IP",
]


def dec(s):
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def parse(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    print("=" * 90)
    print("FILE:", path)
    print("SHA256:", hashlib.sha256(raw).hexdigest())
    print("=" * 90)

    for h in HEADERS:
        for v in msg.get_all(h, []):
            print(f"{h}: {dec(v)[:600]}")

    print("RECEIVED CHAIN:")
    for r in msg.get_all("Received", []):
        print("  ->", dec(r)[:400].replace("\n", " "))

    for part in msg.walk():
        ct = part.get_content_type()
        if part.is_multipart():
            continue
        fn = part.get_filename()
        cd = part.get_content_disposition()
        if ct not in ("text/plain", "text/html"):
            print(f"[PART] type={ct} disposition={cd} filename={fn}")
            continue
        try:
            body = part.get_content()
        except Exception as e:
            print(f"[PART decode error] {e}")
            continue
        if ct == "text/plain":
            print("--- TEXT BODY ---")
            print(body[:4000])
        else:
            links = re.findall(r'href=["\']([^"\']+)["\']', body, re.I)
            imgs = re.findall(r'src=["\']([^"\']+)["\']', body, re.I)
            print("--- HTML LINKS ---")
            for u in dict.fromkeys(links):
                print(u)
            print("--- HTML IMAGES ---")
            for u in dict.fromkeys(imgs):
                print(u)
            text = re.sub(r"<[^>]+>", " ", body)
            text = re.sub(r"\s+", " ", text)
            print("--- VISIBLE TEXT ---")
            print(text[:2500])
    print()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    for path in argv[1:]:
        try:
            parse(path)
        except FileNotFoundError:
            print(f"[!] not found: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
