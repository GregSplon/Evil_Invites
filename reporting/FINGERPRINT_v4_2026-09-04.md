# Campaign Fingerprint — v4 (consolidated)
## "Special / Distinguished Invitation" Phishing + ScreenConnect RAT Campaign
**Updated:** 2026-09-04 (supersedes v3 of 2026-08-24) · **Severity: High** · **Payloads:** AiTM credential phishing + remote-access (ScreenConnect RAT) delivery

---

## 1. What changed since v3

1. **Confirmed single coordinated campaign, multi-persona.** Same payload pattern now flows through ≥3 sender personas using different compromised accounts. New persona: **"Persona C"** `<sender-c@example.invalid>` with a fabricated faith-community signature — targeted social engineering, likely aimed at a local community.
2. **Second ScreenConnect tenant discovered (parallel, not rotated):** `ieee2.screenconnect.com`. The 08-24 tenant `jeanies-journeys.screenconnect.com` is **still live** — both serve installers concurrently. Two web/relay pairs, same ScreenConnect build (26.5.3.9691), same 12,809,272-byte installer shape.
3. **Evite-branded templates now ALSO deliver the RAT**, not just credential phish. 09-04 "Eva's Party For Screen!" clone preserves **real** `evite.com/_ct/...` transactional tool links (token `2219ac970807acf42695103f304ff42729ac67fe`) while rewriting every CTA to the ScreenConnect installer — evidence the template was cloned from a genuine Evite reminder email.
4. **New credential-phish domain:** `fbends.icu/akk` (registered 08-25, the gap day between the 08-24 RAT wave and the 08-27 "Join Us!" wave). Same `.icu` + `/akk` pattern, PDR registrar, new Cloudflare NS pair (`pola/tate`).
5. **New hosting element:** Cloudflare R2 bucket `pub-58388a1519064228b441a5517c701114.r2.dev` serving lure artwork.
6. **Punchbowl lure assets are reused verbatim** across personas and dates (same invitation images + live tracking pixel `4cbe4dcc60c6751f`) — a strong campaign-level pivot/attribution anchor.

---

## 2. Consolidated fingerprint (v4)

### 2.1 Personas (all legitimate accounts — SPF/DKIM/DMARC/ARC pass = compromised senders)

| Persona | Account | Dates observed | Payloads delivered |
|---|---|---|---|
| "Persona A" | `sender-a@example.invalid` (confirmed ATO) | 08-13 → 08-24 | Evite cred-phish → Punchbowl+ScreenConnect RAT |
| "Persona B" | `sender-b@example.invalid` | 08-21 → 09-04 | Evite cred-phish → Evite+ScreenConnect RAT |
| "Persona C" | `sender-c@example.invalid` | 08-27 → 09-04 | Punchbowl cred-phish (`fbends.icu/akk`) → Punchbowl+ScreenConnect RAT |
| Forwarders/re-senders | `forwarder-a@example.invalid`, `forwarder-b@example.invalid` (webmail clients) | 08-24 | Re:/Fw: of Persona A RAT lure (social spread) |

### 2.2 Payload families

| | **Credential phish (AiTM)** | **RAT delivery** |
|---|---|---|
| **Landing / link** | `https://acodcadohappiness.icu/akk/`, `http://fbends.icu/akk` (all CTAs rewritten) | `*.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest` |
| **Brand template** | Evite (08-13/08-21), Punchbowl-logo (08-27) | Punchbowl (08-24, 09-04), Evite (09-04) |
| **Event hooks** | "Save the Date", "You're invited", "Come celebrate… Event Host" | "ACCESS THE FULL INVITATION ON YOUR PC", "A Party Invitation", 3-step open-install-Yes |
| **State** | Live behind Cloudflare managed challenge (403 to bots) on both domains as of 09-04 | Both SC tenants live as of 09-04 |

### 2.3 ScreenConnect RAT infrastructure (ConnectWise SaaS on OVH)

| Tenant | Web / installer | Relay (embedded in installer) | Region |
|---|---|---|---|
| `jeanies-journeys.screenconnect.com` (since 08-24) | `server-ovh60020004-web…` → **148.113.219.237** | `instance-s7gewk-relay…` → **15.235.110.92** | OVH CA |
| `ieee2.screenconnect.com` (since 09-04) | `server-ovh30010021-web…` → **40.160.1.134** | `instance-ifkw0e-relay…` → **15.204.129.194** | OVH US |

- Build: ScreenConnect **26.5.3.9691**; installer size **12,809,272 B**; PE metadata: File/Product version 26.5.3.9691, "ScreenConnect", signed by ConnectWise chain (wildcard `*.screenconnect.com`, DigiCert).
- Installer SHA-256: `jeanies-journeys` = `c68c432515df92ebe29b9eb3dab6a2d2cf1dea292eae3d5f5e081b05ae86f422`; `ieee2` = `5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e`.
- `e=Access` = unattended persistent install (service, reboot survival); `y=Guest` = enrolls into attacker tenant with **no victim-side authentication**. Interactive remote control + further payload deployment from the tenant console.

### 2.4 Credential-phish infrastructure

| Domain | Registrar | Created | NS (Cloudflare) | Purpose |
|---|---|---|---|---|
| `acodcadohappiness.icu` | PDR Ltd | 2026-07-30 | sevki/elly | `/akk/` cred phish (since 08-21) |
| `fbends.icu` | PDR Ltd | 2026-08-25 | pola/tate | `/akk` cred phish (since 08-27) |

- Cloudflare-proxied, managed challenge ("Just a moment…") on all paths — bot blocking; interactive browsers pass and see the kit.
- Supporting infra: Cloudflare R2 `pub-58388a1519064228b441a5517c701114.r2.dev` (lure art), tracking pixel `nav-adv0cati0n.im/invitesz/` (registered; no NS currently), backend Cloudflare Worker relay `/server/relay` → operator Telegram; prior origin/C2 `66.163.122.218` (GTHost) with Overlord 2.5.9 panel `burt-drop.mom`.

### 2.5 Campaign timeline (validated)

| Date | Sender | Template | Payload target |
|---|---|---|---|
| 08-13 | Persona A | Evite "Save the Date" | cred-phish domain (burned) |
| 08-21 | Persona B | Evite "Save the Date" | `acodcadohappiness.icu/akk` |
| 08-24 (08:52→22:32) | Persona A (+Re:/Fw:) | Punchbowl "Event Host" | SC RAT `jeanies-journeys` |
| 08-25 | — | — | `fbends.icu` registered |
| 08-27 | Persona C | Punchbowl-logo "Join Us!" | `fbends.icu/akk` |
| 09-04 | Persona B | Evite "A Party Invitation" | SC RAT `ieee2` |
| 09-04 | Persona C | Punchbowl "Event Host" | SC RAT `ieee2` |

---

## 3. Detection & hunt rules (additions to v3)

- **New domains to block:** `fbends.icu` (and any `/akk`), `ieee2.screenconnect.com`, `instance-ifkw0e-relay.screenconnect.com`.
- **New file hash to block:** `5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e`.
- **New IPs to watch egress:** `40.160.1.134`, `15.204.129.194` (plus v3: `148.113.219.237`, `15.235.110.92`).
- **Alert signature:** inbound mail whose CTA links point to `*.screenconnect.com/Bin/ScreenConnect.ClientSetup.{exe,msi}?e=Access&y=Guest` OR to an `/akk` path on a non-CF-bypassed `.icu` domain; subject regexes incl. `A DISTINGUISHED INVITATION`, `SPECIAL INVITATION FROM`, `JOIN US`.
- **Endpoint:** same as v3 (ScreenConnect client service/process/network); now check **both** tenant web/relay IPs. Any non-sanctioned endpoint reaching either pair = indicator.
- **Template-pivot detection:** Evite/Punchbowl emails whose ancillary links are real (`evite.com/_ct/*`, `evitecdn.com`, `static.punchbowl.com`) but whose **CTAs differ from the brand's own RSVP domain** — a clone that reuses genuine transactional links to defeat naive brand-URL checks.

## 4. Next steps (unchanged from v3, plus)

- **ConnectWise abuse reporting for BOTH tenants** (`jeanies-journeys`, `ieee2` + relays `instance-s7gewk`, `instance-ifkw0e`) — ToS suspension removes the RAT delivery channel.
- **Provider:** report the three sender accounts as compromised and used for phishing; continue recovery for all affected accounts.
- **PDR Ltd abuse** for `fbends.icu` (and `acodcadohappiness.icu`); monitor new PDR + any-Cloudflare-NS + `.icu/.cfd/.lat/.mom/.sbs/.top/.im` registrations weekly.
- **Community intel:** submit new installer hash + both SC tenant URLs + `fbends.icu` to URLhaus/VT/PhishTank; share the R2 bucket path as an abuse contact for Cloudflare.
- **Community warning:** given the fabricated faith-community persona, warn the affected community that "invitation" emails mentioning local figures are forged; verify by phone.

---

## 5. IOC block list (all known, consolidated)

**URLs:** `https://jeanies-journeys.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest`, `https://ieee2.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest`, `https://acodcadohappiness.icu/akk/`, `http://fbends.icu/akk`

**Domains:** `jeanies-journeys.screenconnect.com`, `instance-s7gewk-relay.screenconnect.com`, `ieee2.screenconnect.com`, `instance-ifkw0e-relay.screenconnect.com`, `acodcadohappiness.icu`, `fbends.icu`, `nav-adv0cati0n.im`, `pub-58388a1519064228b441a5517c701114.r2.dev`, `burt-drop.mom`

**IPs:** `148.113.219.237`, `15.235.110.92`, `40.160.1.134`, `15.204.129.194`, `66.163.122.218`

**Files (SHA-256):** `c68c432515df92ebe29b9eb3dab6a2d2cf1dea292eae3d5f5e081b05ae86f422`, `5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e` (ScreenConnect.ClientSetup.exe, 26.5.3.9691, 12,809,272 B)

**Senders:** `sender-a@example.invalid`, `sender-b@example.invalid`, `sender-c@example.invalid`, `forwarder-a@example.invalid`, `forwarder-b@example.invalid`

**Subject regex:** `(PLEASE KINDLY OPEN AND DOWNLOAD YOUR SPECIAL INVITE|INVITATION EXTENDED (EXCLUSIVELY )?FROM|A DISTINGUISHED INVITATION|SPECIAL INVITATION FROM|SAVE THE DATE|JOIN US)`

**Email sample hashes (this batch):** `174fb277…c0a48d` (Eva 09-04), `f8246227…61b33` (Zavior 09-04), `d23e2367…3eff6` (Eva 08-21 dup), `802759fc…d8b39` (Zavior 08-27)

---

*Sources: analysis of 8 .eml samples (08-21 → 09-04); live DNS/TLS/HTTP + installer-hash validation on 08-24 and 09-04; prior project findings (Evite/PostNote kit, Overlord C2, Cloudflare Worker relay); public reporting on `e=Access&y=Guest` ScreenConnect abuse. All timestamps UTC unless noted.*
