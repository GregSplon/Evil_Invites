# Reporting

| File | Version | Date | Contents |
|---|---|---|---|
| `FINGERPRINT_v5_2026-09-04.md` | v5 (current) | 2026-09-04 | Consolidated campaign assessment with corrected targeting language, confidence/caveats, detection guidance, and response priorities |
| `ABUSE_REPORT.md` | current | 2026-09-04 | Provider-ready ScreenConnect abuse report with tenant, relay, hash, and timeline evidence |
| `FINGERPRINT_v4_2026-09-04.md` | v4 (superseded) | 2026-09-04 | Historical consolidated fingerprint prior to v5 detection/attribution cleanup |

v5 supersedes v4 for current analytical judgments. v4 is retained for provenance/history.

## Suggested report flow for a company advisory

1. **Executive summary** — brand-impersonation campaign delivering credential phish and legitimate signed ScreenConnect installers through abused legitimate webmail accounts.
2. **Fingerprint tables** — personas, payload families, infrastructure, and timeline.
3. **Why controls can fail** — authenticated senders, legitimate brand assets, signed RMM binary, all-anchor/CTA rewriting.
4. **Hunt/block rules** — IOC table plus detection queries in `../detection/`.
5. **Response playbook** — separate clicked-link, entered-credentials, and executed-installer response paths.
6. **Takedown channels** — provider/registrar/hosting abuse reporting, community intelligence sharing, and law-enforcement reporting where appropriate.

## Analytical discipline

- Separate **observed facts** from **assessments** and **unproven hypotheses**.
- Use tenant/relay identities and tenant-specific hashes as stronger ScreenConnect pivots than generic vendor IPs or signer/path data.
- Treat shared-provider IPs as supporting context rather than universally malicious infrastructure.
- TLP for sanitized repository material is **TLP:CLEAR**.
