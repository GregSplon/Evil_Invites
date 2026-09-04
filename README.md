# "Special Invitation" Phishing + ScreenConnect RAT Campaign — Threat Intelligence Pack

> **Classification:** Phishing / AiTM credential theft + Remote Access Trojan (RAT) delivery via abuse of a legitimate signed RMM product
> **Coverage period:** 2026-08-13 → 2026-09-04 (ongoing)
> **Severity:** High · **Status:** Active at time of writing · **TLP:** CLEAR (sanitized)

## Overview

Defensive analysis of an unsolicited, multi-wave email campaign. The campaign impersonates **Evite** and **Punchbowl** invitation brands using **cloned transactional templates** and delivers one of two payloads:

1. **Credential phishing (AiTM)** — cloned Evite/Punchbowl emails pointing to attacker domains serving a Cloudflare-backed phish kit (`/akk` path pattern) that harvests email + password + MFA codes via an operator-in-the-loop relay.
2. **RAT delivery** — cloned Evite/Punchbowl emails whose call-to-action links download a **genuine, digitally signed ConnectWise ScreenConnect client installer** configured for **unattended, persistent, guest (no-authentication) access** to the victim's computer (`?e=Access&y=Guest`).

All observed mail passes SPF/DKIM/DMARC/ARC because it was sent through legitimate webmail accounts assessed as compromised or abused — authentication-pass is *not* a benign signal for this campaign.

## Key findings

- **≥3 sender personas using legitimate webmail accounts**, one confirmed account takeover (`sender-a@example.invalid`); repeated clone structure and shared infrastructure are consistent with one coordinated campaign. Operator attribution remains unconfirmed.
- **2 parallel ScreenConnect SaaS tenants** (ConnectWise-hosted, OVH) serving the same build (26.5.3.9691); embedded relay hosts and RSA tenant keys differ per tenant → tenant-pair fingerprinting works, hash-per-tenant blocking works.
- **Evite clone preserves genuine `evite.com/_ct/` transactional tool links** while rewriting CTAs → clone sourced from a genuine Evite notification or equivalent template source.
- **Punchbowl lure assets are reused verbatim across personas/dates**, including a live tracking pixel → strong campaign pivot/correlation anchor.
- **Community/faith-themed persona content was observed**, but the available samples do **not** establish that the campaign specifically targeted a local community.
- Campaign progression observed: credential phish (08-13) → AiTM (08-21) → RAT delivery (08-24) → additional personas + second tenant (09-04).

## Repository structure

```
├── README.md                  <- this file
├── LICENSE
├── analysis/                  <- per-sample breakdowns (sanitized), template comparisons
├── indicators/
│   ├── iocs.csv               <- machine-readable IOC list with confidence/role metadata
│   ├── yara/                  <- YARA rules (tenant + generic ScreenConnect abuse)
│   └── sigma/                 <- Sigma rules (process / service / network)
├── detection/                 <- hunt queries & SIEM guidance (KQL, Splunk)
├── infrastructure/            <- validated DNS/TLS/hash evidence, network map
├── reporting/                 <- current fingerprint, historical versions, abuse package
└── tools/                     <- generic parsing utilities used in the analysis
```

## Scope & ethics notice

- This repository is **defensive threat-intel research** produced from email the researcher received directly (unsolicited phishing).
- All victim PII, real-name recipients, and any content identifying affected individuals/communities have been **removed or genericized**.
- No attacker infrastructure was accessed beyond passive/OSINT checks (DNS, TLS, public HTTP responses, download of the public installer for hashing).
- The ScreenConnect client installer is a **legitimate signed product**; the abuse is contextual (attacker-controlled tenant + guest-access parameters). Rules here are tuned to detect *abuse indicators* and will false-positive on legitimate MSP remote-support use if applied generically — allowlist sanctioned tenants/hosts where appropriate.
- Do not use this content to attack any party. Reporting and takedown guidance is in `reporting/FINGERPRINT_v5_2026-09-04.md` and `reporting/ABUSE_REPORT.md`.

## License

Content is provided under CC BY 4.0 (attribution appreciated). Indicator data is derived from observed attacks; verify before blocking in production.
