# Email Sample Analysis (sanitized)

Per-sample breakdowns. Recipient addresses and any content identifying affected individuals are **removed** (this is a deliberate sanitization; source .eml files are not redistributed).

| # | Date (UTC) | Sender account | Persona | Subject | Template | Payload target | Sample SHA-256 |
|---|---|---|---|---|---|---|---|
| 1 | 2026-08-13 | search4cm@gmail.com | "Dori Picard" | SAVE THE DATE- INVITATION EXTENDED TO YOU FROM Dori Picard | Evite | credential phish (burned domain) | *(prior sample)* |
| 2 | 2026-08-21 15:19 | ndbisongirl@gmail.com | "Eva Lahlum" | SAVE THE DATE: INVITATION EXTENDED EXCLUSIVELY FROM Eva Lahlum | Evite | `acodcadohappiness.icu/akk/` | d23e23674999516f34988e8259e3d0dcb2a945b6bcb6e8f942c37d8e9f03eff6 |
| 3 | 2026-08-24 15:53 | search4cm@gmail.com | "Dori Picard" | PLEASE KINDLY OPEN AND DOWNLOAD YOUR SPECIAL INVITE FROM DORI PICARD | Punchbowl ("Chip Nesser") | SC RAT tenant A | *(embedded in 5/6)* |
| 4 | 2026-08-24 17:46 | littleann.schweitz06@gmail.com | "Annie Norberg" (Re:) | Re: PLEASE KINDLY OPEN AND DOWNLOAD… | Punchbowl | SC RAT tenant A | 37dc2352103abe32b1ba41061606d3fc5462a9aa89a56af7899a1e9bd8bc2c6e |
| 5 | 2026-08-24 22:32 | jacinta58103@yahoo.com | "Jacinta Splonskowski" (Fw:) | Fw: PLEASE KINDLY OPEN AND DOWNLOAD… | Punchbowl | SC RAT tenant A | 81c86acaf1c4eca275377a7a29a8d856adf472078a23d9f48971290aa013b46f |
| 6 | 2026-08-27 13:03 | zavfranck@gmail.com | "Zavior Franck" | Join Us! | Punchbowl-logo | `fbends.icu/akk` | 802759fc0c18dbf9afbba5ded595c0a678e4809272a1b0f736b88e78cc3d8b39 |
| 7 | 2026-09-04 13:39 | ndbisongirl@gmail.com | "Eva Lahlum" | A Distinguished Invitation From Eva Lahlum | Evite ("Eva's Party For Screen!") | SC RAT tenant B | 174fb27780a8c3989629eb78f309321c6b2b935a51e85980b31777c619c0a48d |
| 8 | 2026-09-04 15:55 | zavfranck@gmail.com | "Zavior Franck" | SPECIAL INVITATION FROM ZAVIOR FRANCK | Punchbowl ("Chip Nesser") | SC RAT tenant B | f8246227127be5357ea2d113e8f041d0596df18dfb02977adbf9017ec6161b33 |

## Structural observations

### Email-level fingerprints
- All Gmail senders: `Message-ID: <…@mail.gmail.com>`, DKIM `d=gmail.com s=20251104`, SPF/DKIM/DMARC/ARC **all pass**; from a **compromised** account, not an attacker SMTP.
- Yahoo forward (#5): `X-Mailer: WebService/1.1.26380 YahooMailIosMobile`, DMARC `p=REJECT` on yahoo.com still passes (real account).
- `To: undisclosed-recipients:;` for broadcast waves (#2, #6–#8); direct `To:` for the family re-sends (#4, #5).
- Plain-text part present in every sample (HTML + text multipart/alternative) — kit-generated.

### Clone-template fingerprints
- **Punchbowl clones** (#3–#6, #8): identical hotlinks to `static.punchbowl.com` assets incl. invitation `…/1794f7f27962a5c27f8f/envelope/6a295f6c…jpg` and **live tracking pixel** `www.punchbowl.com/invitation/4cbe4dcc60c6751f/t.gif` — same invitation reused across personas/dates.
- **Evite clones** (#2, #7): hotlink `g0.evitecdn.com` icon sets; **#7 preserves genuine `evite.com/_ct/2219ac970807acf42695103f304ff42729ac67fe/…` transactional tool links** (change RSVP / review details / send message / notification settings) while all CTAs are rewritten → template cloned from a real Evite notification.
- All CTAs + many footer links point to the single payload destination (all-anchor rewriting).
- **RAT variant social engineering:** "ACCESS THE FULL INVITATION ON YOUR PC — click 'Open Invitation' to download the file → open the downloaded invitation Card → when prompted select 'Yes'" (UAC click-through).
- **Persona detail (#6, #8):** fabricated signature "Seminarian, Diocese of Duluth / Pontifical North American College / Pax Christi" — plausibly targeting a Catholic community.

### Header auth caveat
Passing SPF/DKIM/DMARC/ARC here is **not** a trust signal — it reflects account compromise of real webmail users, not sender legitimacy.
