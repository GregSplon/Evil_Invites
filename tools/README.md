# Tools

Generic utilities used during analysis. These are intentionally neutral parsers — they contain **no** case data or PII.

| File | Purpose |
|---|---|
| `eml_parse.py` | Parse one or more `.eml` files: extract key headers, Received chain, auth results, body text, all href/src URLs, MIME parts. |

## Usage

```bash
python3 tools/eml_parse.py sample1.eml sample2.eml
```

Run it against *your own* samples — do not include raw phishing emails in this repository.

## Notes for reproducing the analysis

1. Extract headers (From/To/Subject/Message-ID/Received/Authentication-Results/Received-SPF/DKIM) — proves compromised-legitimate-account delivery and lets you pivot on Message-ID patterns.
2. Enumerate every `href`/`src` — clone templates hotlink genuine CDN assets while rewriting CTAs; compare CTA domains vs. brand-owned domains.
3. Resolve payload domains (DNS A/NS/CNAME), WHOIS (registrar + creation date + NS pair), and check TLS cert issuer for hosted SaaS tenants.
4. Download the installer from the public URL once, `sha256sum` it, and inspect embedded relay config via `strings` (do not execute).
5. Re-check liveness periodically — domains rotate quickly; tenants and C2 stay stable.
