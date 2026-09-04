# Provider Abuse Report — ScreenConnect Campaign

> **TLP:** CLEAR  
> **Purpose:** Provider-ready summary for abuse/security teams. Replace bracketed contact fields as needed. Do not include victim PII unless the provider explicitly requires it.

## Summary

I am reporting observed malicious use of ConnectWise ScreenConnect SaaS tenants in an active phishing campaign. The campaign sends cloned Evite/Punchbowl invitation emails and directs recipients to legitimate, digitally signed `ScreenConnect.ClientSetup.exe` installers configured for unattended guest access using `e=Access&y=Guest`.

The observed behavior is consistent with abuse of ScreenConnect as a remote-access payload. The installer is legitimate ConnectWise software; the malicious element is the tenant configuration and social-engineering delivery.

## Observed ScreenConnect infrastructure

### Tenant A
- Tenant: `jeanies-journeys.screenconnect.com`
- Installer URL: `https://jeanies-journeys.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest`
- Relay: `instance-s7gewk-relay.screenconnect.com`
- Web IP observed: `148.113.219.237`
- Relay IP observed: `15.235.110.92`
- Installer SHA-256: `c68c432515df92ebe29b9eb3dab6a2d2cf1dea292eae3d5f5e081b05ae86f422`
- File version: `26.5.3.9691`
- File size: `12,809,272` bytes
- First observed: `2026-08-24`
- Still live at last validation: `2026-09-04`

### Tenant B
- Tenant: `ieee2.screenconnect.com`
- Installer URL: `https://ieee2.screenconnect.com/Bin/ScreenConnect.ClientSetup.exe?e=Access&y=Guest`
- Relay: `instance-ifkw0e-relay.screenconnect.com`
- Web IP observed: `40.160.1.134`
- Relay IP observed: `15.204.129.194`
- Installer SHA-256: `5d7a14e9719d05b1bd20099923b12e80911f03f989fe18199aa983054cc4605e`
- File version: `26.5.3.9691`
- File size: `12,809,272` bytes
- First observed: `2026-09-04`
- Still live at last validation: `2026-09-04`

## Delivery behavior

Observed phishing emails impersonate Evite and Punchbowl. The primary CTA is rewritten to the ScreenConnect installer URL. Some variants instruct the recipient to download/open the invitation and approve the Windows prompt. The same campaign has also delivered credential-phishing pages via unrelated attacker domains.

Observed ScreenConnect installers embed tenant-specific relay configuration, producing different SHA-256 hashes per tenant while retaining the same ScreenConnect build.

## Requested action

Please investigate the listed tenants and associated relay instances for abuse and, if confirmed, suspend or otherwise contain the malicious tenant access. If possible, please preserve relevant account/session/log data consistent with your policies in case it is needed by law-enforcement or incident-response partners.

I can provide sanitized email samples, full headers, screenshots, installer hashes, and additional timeline/context on request.

## Research scope

This report is based on defensive analysis of unsolicited phishing received directly by the researcher. No exploitation or unauthorized access of provider infrastructure was performed. Validation was limited to passive/OSINT checks and downloading the publicly linked installer for hashing and configuration analysis.

Contact: `[name/email]`
