# Campaign Fingerprint — v5 (consolidated)
## "Special / Distinguished Invitation" Phishing + ScreenConnect RAT Campaign
**Updated:** 2026-09-04 · **Severity:** High · **TLP:** CLEAR

---

## 1. What changed since v4

1. **Targeting claim corrected.** Community/faith-themed persona content was observed, but the available evidence does not establish deliberate targeting of a specific local community. Treat targeted-social-engineering as an unproven hypothesis.
2. **Attribution language tightened.** Repeated clone structure, shared lure assets, payload patterns, and infrastructure support a single coordinated campaign assessment, but operator identity remains unconfirmed.
3. **Detection logic corrected.** Network detection no longer suppresses connections simply because the initiating binary runs from a legitimate ScreenConnect path. The campaign abuses the legitimate client; allowlisting must be tenant-specific.
4. **Generic YARA tightened.** The generic ScreenConnect guest-access rule now requires both `e=Access` and `y=Guest` indicators in addition to ScreenConnect configuration/relay strings.
5. **Defender KQL made directly runnable.** Email URL correlation now uses an explicit `EmailUrlInfo` join on `NetworkMessageId`.
6. **IOC schema expanded.** Indicators now include role, confidence, provenance, status, TLP, and shareability.
7. **Provider-ready abuse package added.** See `ABUSE_REPORT.md`.

---

## 2. Executive assessment

This is an active, multi-wave phishing campaign impersonating invitation brands including Evite and Punchbowl. Observed samples use legitimate webmail accounts and therefore may pass SPF/DKIM/DMARC/ARC. Payload delivery falls into two families:

- **Credential phishing / AiTM:** attacker-controlled `/akk` paths behind Cloudflare infrastructure.
- **Remote-access delivery:** legitimate signed ConnectWise ScreenConnect installers configured to enroll a victim into attacker-controlled unattended guest-access tenants.

The strongest defensive leverage is not individual disposable phishing domains. It is the combination of ScreenConnect tenant identities, tenant-specific relay configuration, installer hashes, repeated invitation-template artifacts, CTA-rewrite behavior, and account-abuse patterns.

---

## 3. Observed campaign structure

### Sender/persona assessment

| Persona | Account | Dates observed | Payloads | Assessment |
|---|---|---|---|---|
| Persona A | `sender-a@example.invalid` | 08-13 → 08-24 | credential phish → ScreenConnect | Confirmed ATO in source investigation |
| Persona B | `sender-b@example.invalid` | 08-21 → 09-04 | credential phish → ScreenConnect | Legitimate account observed in campaign; compromise assessed from behavior |
| Persona C | `sender-c@example.invalid` | 08-27 → 09-04 | credential phish → ScreenConnect | Legitimate account observed in campaign; compromise assessed from behavior |
| Forwarders/re-senders | sanitized placeholders | 08-24 | re/fw of lure | Secondary spread; intent/compromise state not assumed |

### Credential-phish infrastructure

| Domain | Created | Path | Role | Status at 09-04 |
|---|---|---|---|---|
| `acodcadohappiness.icu` | 2026-07-30 | `/akk/` | credential phish | live behind Cloudflare managed challenge |
| `fbends.icu` | 2026-08-25 | `/akk` | credential phish | live behind Cloudflare managed challenge |

Supporting observed infrastructure includes Cloudflare R2 lure hosting and campaign tracking artifacts. Historical linked infrastructure should remain clearly separated from current active delivery infrastructure.

### ScreenConnect delivery infrastructure

| Tenant | Relay | Web IP | Relay IP | SHA-256 |
|---|---|---:|---:|---|
| `jeanies-journeys.screenconnect.com` | `instance-s7gewk-relay.screenconnect.com` | `148.113.219.237` | `15.235.110.92` | `c68c432515df92ebe29b9eb3dab6a2d2cf1dea292eae3d5f5e081b05ae86f422` |
| `ieee2.screenconnect.com` | `instance-ifkw0e-relay.screenconnect.com` | `40.160.1.134` | `15.204.129.194` | `5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e` |

Both observed installers were ScreenConnect version `26.5.3.9691`, size `12,809,272` bytes. Tenant-specific relay/key material causes hashes to differ even when the stock application build is the same.

---

## 4. High-value campaign pivots

Defenders should prioritize correlation on:

- Exact observed ScreenConnect tenant and relay hostnames.
- Tenant-specific installer SHA-256 values.
- `ScreenConnect.ClientSetup` delivery through unsolicited invitation-themed email.
- CTA paths containing `e=Access&y=Guest`.
- Evite/Punchbowl-branded messages that retain legitimate brand assets or ancillary links while rewriting the primary CTA to third-party infrastructure.
- Reused Punchbowl invitation/tracking artifacts across separate personas and dates.
- `/akk` credential-phish paths combined with newly registered domains and Cloudflare fronting.
- Authenticated mail from legitimate consumer webmail accounts where message content matches the campaign family.

Do not treat signer legitimacy, SPF/DKIM/DMARC pass, or a normal ScreenConnect installation path as benign by themselves.

---

## 5. Detection guidance

See `../detection/` and `../indicators/` for runnable KQL, Splunk, Sigma, and YARA content.

Important implementation notes:

- Known observed tenant/relay matches should be considered high confidence after validating the environment does not intentionally use those exact tenants.
- Generic ScreenConnect detections require an organizational allowlist of sanctioned tenant identities.
- Do not suppress by executable path alone; malicious enrollment uses legitimate ConnectWise binaries and normal client paths.
- IP-based detections are supporting indicators and may be less durable or specific than tenant/relay names and tenant-specific hashes.

---

## 6. Response priorities

1. **ConnectWise:** report both observed tenants, relay names, installer URLs, hashes, and timestamps. Tenant suspension can remove a remote-access dependency across multiple potential victims.
2. **Compromised accounts:** report/recover legitimate sender accounts and review sessions, forwarding, recovery methods, MFA, and OAuth grants where authorized.
3. **Registrar/hosting:** report credential-phish domains and Cloudflare-hosted lure assets using full observed URLs and evidence.
4. **Community sharing:** submit appropriate public indicators to established phishing/malware intelligence exchanges.
5. **Victim response:** if ScreenConnect was executed, treat the endpoint as potentially remotely accessed; isolate and investigate rather than simply deleting the downloaded installer.

Provider-ready wording is maintained in `ABUSE_REPORT.md`.

---

## 7. Confidence and caveats

- **High confidence:** observed email structures, URLs, tenant/relay hostnames, installer hashes, file version/size, DNS/TLS observations, reused template artifacts.
- **Moderate confidence:** multiple personas belong to one coordinated campaign/operator based on repeated infrastructure and content correlation.
- **Unproven:** deliberate targeting of a particular family, faith community, or local group; operator identity; broader victim count.

All victim-identifying data is sanitized from the public/shareable repository representation.
