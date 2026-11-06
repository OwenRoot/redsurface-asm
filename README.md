# RedSurface ASM Console

A serverless Attack Surface Management (ASM) tool for **authorized, passive** reconnaissance of a domain you own or are permitted to assess. It runs on Netlify Functions with a vanilla JavaScript / Tailwind v4 frontend, and uses only Node's built-in modules on the server.

It has two modes:

| Mode | What it does |
|------|--------------|
| **Demo** | Simulated telecom estate (RFC 5737 documentation IPs). No network activity. Safe for showcasing. |
| **Live** | Passive recon of a real domain: certificate transparency discovery, DNS resolution, one HEAD request per host, banner/version matching, TLS and header hygiene checks, CISA KEV enrichment. |

> **Authorized use only.** Live mode requires an explicit authorization confirmation. Only assess domains you own or have written permission to test. The tool never port-scans, brute-forces, crawls, or sends exploit payloads.

---

## 1. Live mode pipeline

1. **Discovery**: subdomains from Certificate Transparency logs (crt.sh and CertSpotter, whichever answers first).
2. **Resolution**: real DNS A-record lookups for each discovered name.
3. **Probing**: for each host with a public IP, one `HEAD /` over HTTPS (falling back to HTTP). No redirects are followed. The connection goes to the validated IP, with the hostname supplied separately via Host header and SNI.
4. **Matching**: the Server / X-Powered-By / X-OWA-Version banner is matched against curated regex and version-range rules (Exchange, Tomcat, nginx, OpenSSH, Apache httpd).
5. **Enrichment**: findings are cross-referenced with the CISA Known Exploited Vulnerabilities catalog and flagged when actively exploited.
6. **Hygiene checks**: HTTPS availability, certificate expiry/trust, HSTS and security headers, version disclosure, private IPs in public DNS, publicly resolvable non-production hosts.
7. **Reporting**: every finding includes a structured **Remediation & Defense Recommendation** (patch, hardening, access control, verification).
8. **Delivery**: results are encrypted and signed (see section 3), then verified and decrypted in the browser.

### Known limitations (be upfront about these)

- Version matching only works where servers **disclose** versions. Many hardened hosts hide them, so no finding does not mean safe.
- Vendor **backports** (for example Debian OpenSSH) can cause false positives on version strings.
- The CVE rule set is small and curated. Verify it against vendor advisories. It is not a replacement for authenticated scanners such as Nessus or Qualys.
- Certificate Transparency only lists names that have had public certificates issued.
- Netlify's default function timeout is 10 seconds. The sweep uses a time budget and caps hosts (60 names, 15 probes), and reports partial results when it runs out.

## 2. Repository layout

```
.
├── netlify.toml                      # publish dir, functions dir, security headers
├── index.html                        # UI + client-side crypto (WebCrypto)
├── netlify/functions/recon-surface.js# sweep logic + encrypted envelope
└── README.md
```

## 3. Transport protection

```
Browser                                         Netlify Function
  | generate salt + ephemeral ECDH key pair            |
  |--- GET domain, mode, salt, client_pub ------------>|
  |                                    ephemeral ECDH key pair
  |                                    shared = ECDH(server_priv, client_pub)
  |                                    encKey = HKDF(shared, salt, "asm-enc-v1")
  |                                    macKey = HKDF(shared, salt, "asm-mac-v1")
  |                                    ct = AES-256-GCM(encKey, iv, payload)
  |                                    sig = HMAC-SHA256(macKey, "v1.pub.iv.ct")
  |<-- { envelope: {serverPub, iv, ct, sig}, metrics } |
  | derive same keys, verify HMAC (reject on failure)  |
  | AES-GCM decrypt, render DOM safely                 |
```

This is defence in depth on top of TLS, not a replacement for it.

## 4. Deployment

1. Push the four files to a GitHub repository, keeping the layout above.
2. In Netlify: **Add new site** -> **Import an existing project** -> GitHub -> select the repo.
3. Leave the build command empty (settings come from `netlify.toml`) and deploy.
4. Open the site, test **Demo** first, then **Live** against a domain you own.

Requires Node 18+ (Netlify default). No environment variables or dependencies.

---

## 5. Threat model

### 5.1 Security objectives

| ID | Objective |
|----|-----------|
| O1 | Confidentiality of telemetry against passive observers of the response. |
| O2 | Integrity: the client rejects any modified envelope. |
| O3 | The tool must not become an attack proxy, SSRF vector, or abuse platform. |
| O4 | The UI must not execute attacker-controlled content (XSS). |
| O5 | Minimal, proportionate impact on assessed targets. |

### 5.2 Assets, actors and boundaries

- **Assets**: the findings payload, ephemeral key material, function availability and platform reputation (outbound IPs).
- **Actors**: passive network observer, active MITM, malicious user of the public endpoint, hostile target (controls DNS and HTTP responses), compromised CDN script host.
- **Boundaries**: browser to Netlify edge; function to the internet (CT logs, DNS, targets, CISA); CDN to browser.

### 5.3 Threats and mitigations (STRIDE)

| # | Threat | Mitigation | Residual risk |
|---|--------|-----------|---------------|
| T1 | Passive observer reads response | AES-256-GCM under an ephemeral ECDH-derived key. URL contents alone cannot derive the key. | Metadata visible (domain, timing, size). |
| T2 | Response tampered in transit | Encrypt-then-MAC: HMAC-SHA256 verified (constant time) before decryption; GCM tag as second layer. | See T3. |
| T3 | Active MITM substitutes its own server key | TLS + HSTS. | The handshake is **unauthenticated**; a TLS-breaking attacker can negotiate with both sides. Fix: sign the server ephemeral key with a pinned long-term key. |
| T4 | Replay | Fresh client key per sweep; `no-store`. | Replay within the same session not blocked. Low impact. |
| T5 | Weak randomness / key reuse | Fresh ECDH keys, random 96-bit IV per response, separate AES/HMAC keys via HKDF with distinct labels. | Relies on platform CSPRNG. |
| T6 | Malformed input | Strict regexes for domain, salt and public key; GET only; blocked internal TLDs; generic error messages. | Invalid EC points return a generic 500. |
| T7 | **SSRF** against internal networks | The server only contacts names that resolve to **public** IPv4 addresses. Private, loopback, link-local, CGNAT, documentation and multicast ranges are rejected before any connection. Probing is limited to `HEAD /` on ports 80/443. Redirects are never followed. | IPv6 records are not resolved or probed at all. |
| T8 | **DNS rebinding** | DNS is resolved once, validated, and the connection is made to that IP. Host header and SNI carry the hostname separately. | None known. |
| T9 | **Abuse as a scanning proxy** | Authorization attestation, per-IP rate limit (8 per 10 min, best effort per warm instance), cap of 60 names / 15 probes, no port scanning, fixed request shape, identifying User-Agent. | No verified domain ownership. Add DNS TXT proof-of-ownership for stronger control. In-memory rate limiting is not shared across instances. |
| T10 | Hostile target responses | Headers are only displayed via `textContent`; response bodies are never read (HEAD, `res.resume()`); strict timeouts. | Large header values are shown as-is. |
| T11 | XSS in the UI | DOM built with `createElement`/`textContent`; no `innerHTML`; CSP, nosniff, frame-deny, no-referrer headers. | CSP allows `'unsafe-inline'` scripts because JS is inline. Move JS to a separate file to remove this. |
| T12 | CDN supply chain | CSP restricts script origins. | Tailwind CDN script has no SRI hash. Self-host compiled CSS for production. |
| T13 | Outbound dependency failure or poisoning (crt.sh, CertSpotter, CISA) | Timeouts; graceful degradation with visible warnings; KEV used only as a flag. Names are re-validated and must fall under the target domain. | A poisoned CT response could add fake names (bounded by validation and caps). |
| T14 | DoS / cost abuse of the endpoint | Time budget, caps and rate limiting. | No authentication. Use Netlify rate limiting or a WAF for real use. |
| T15 | Platform logs capture query strings | Body is encrypted. | Domain, salt and client public key appear in URL logs. Use POST to avoid this. |
| T16 | Static exposure of source | Nothing secret in the repo. | `publish = "."` serves source files. Publish a `public/` directory instead. |
| T17 | Legal and ethical misuse | Explicit authorization confirmation; passive-only design; documented scope. | A user can still lie. The operator remains responsible for acceptable use. |

### 5.4 Design decisions

- **Passive by design.** Discovery relies on public data (CT logs, DNS), and active contact is a single HEAD request per host, comparable to a browser visit. There is no port scanning or exploitation, which keeps impact low and the tool defensible.
- **Why ECDH with a salt?** A salt is not secret. It is used for HKDF domain separation while secrecy comes from the ephemeral private keys.
- **Why a demo mode?** It allows safe presentation without touching any real system.

### 5.5 Out of scope

Port scanning, authenticated scanning, exploitation, credentialed checks, persistence, user accounts, multi-tenancy.

### 5.6 Hardening roadmap

1. Sign the server's ephemeral key and verify it client-side (T3).
2. DNS TXT proof-of-ownership before live sweeps (T9, T17).
3. Self-host compiled Tailwind CSS and drop `'unsafe-inline'` (T11, T12).
4. Publish only a `public/` directory (T16).
5. Persistent rate limiting and authentication (T14).
6. POST requests with a nonce/timestamp (T4, T15).
7. IPv6 support with the same reserved-range checks.
8. Pull CVE data from NVD (CPE matching) instead of the curated rule set.

---

## 6. Credits

System Engineered & Developed by OwenRoot.
LinkedIn: Owen Michael Mt | X: [_OwenRoot](https://x.com/_OwenRoot) | GitHub: [OwenRoot](https://github.com/OwenRoot)
