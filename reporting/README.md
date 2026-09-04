# Reporting

| File | Version | Date | Contents |
|---|---|---|---|
| `FINGERPRINT_v4_2026-09-04.md` | v4 (current) | 2026-09-04 | Consolidated fingerprint + company advisory: payload families, personas, ScreenConnect tenants, credential-phish domains, timeline, detection/hunt rules, incident response and takedown steps, consolidated IOC list |

v3 (2026-08-24) is fully superseded by v4; its content is summarized inside v4's "What changed since v3" section.

## Suggested report flow for a company advisory

1. **Executive summary** (1 paragraph: brand-impersonation campaign delivering both credential phish and signed-RAT installers via compromised legitimate senders).
2. **Fingerprint tables** (personas, payload families, infra, timeline).
3. **Why controls fail** (auth-pass senders, hotlinked brand CDN assets, legit signed binary, all-anchor rewriting).
4. **Hunt/block rules** (IOC table + detection queries in `../detection/`).
5. **Response playbook** (clicked the link? ran the installer? → isolate, collect, remove client, treat as full account compromise, search all mailboxes for the subject regexes).
6. **Takedown channels** (ConnectWise abuse, Google recovery, registrar abuse, URLhaus/VT submissions, national CERT/IC3 as applicable).
