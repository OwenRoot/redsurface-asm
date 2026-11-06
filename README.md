# RedSurface ASM Console

A serverless Attack Surface Management (ASM) and reconnaissance dashboard for a simulated telecom operator estate. It runs on Netlify Functions with a vanilla JavaScript / Tailwind v4 frontend and uses only Node's built-in `crypto` module on the server.

> **Simulation notice.** This project performs **no real scanning**. Assets, IP addresses (RFC 5737 documentation ranges) and software banners are generated from the supplied domain label. The vulnerability feed is a small illustrative mock. Verify every CVE detail against vendor advisories before relying on it.

---

## 1. What it does

1. The browser generates a random session salt and an ephemeral ECDH P-256 key pair.
2. The user enters a target domain and runs an "Encrypted Sweep".
3. `GET /.netlify/functions/recon-surface?domain=...&salt=...&pub=...` is called.
4. The function builds a simulated asset inventory, matches each banner against the mock feed with regex profiles, compares versions and flags unpatched software. Every finding carries a structured **Remediation & Defense Recommendation** (patch, hardening, access control, verification).
5. The telemetry is encrypted and signed, and returned as a JSON envelope.
6. The browser verifies the HMAC **first**, and only then decrypts and renders the report.

```
Browser                                         Netlify Function
  | generate salt + ephemeral ECDH key pair            |
  |--- GET domain, salt, client_pub ------------------>|
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

## 2. Repository layout

```
.
├── netlify.toml                      # publish dir, functions dir, security headers
├── index.html                        # UI + client-side crypto (WebCrypto)
├── netlify/functions/recon-surface.js# simulated sweep + encrypted envelope
└── README.md
```

## 3. Deployment

1. Keep the folder structure above.
2. Either push to a Git repository and import it in Netlify, or drag the folder into Netlify Drop.
3. No build command and no environment variables are required.
4. Open the site, click **Execute Encrypted Sweep**, and confirm the console prints "HMAC-SHA256 signature valid" followed by "AES-256-GCM decryption complete".

Runtime requirement: Node 18+ (Netlify default) for `crypto.hkdfSync` and `createECDH`.

---

## 4. Threat model

### 4.1 Security objectives

| ID | Objective |
|----|-----------|
| O1 | Confidentiality of the vulnerability telemetry against passive observers of the response (proxy logs, network snoopers, CDN/edge logging of bodies). |
| O2 | Integrity: the client must reject any envelope that was modified in transit. |
| O3 | No server-side abuse: the endpoint must not become a scanning, SSRF or injection vector. |
| O4 | The UI must not execute attacker-controlled content (XSS). |

### 4.2 Assets

- **Telemetry payload**: asset inventory, banners, CVE matches and remediation guidance (high sensitivity in a real deployment).
- **Session key material**: the ephemeral ECDH private keys (client: non-extractable `CryptoKey`; server: exists only for the lifetime of one invocation).
- **Availability** of the function (cost and abuse exposure on a public endpoint).

### 4.3 Trust boundaries and actors

- **Boundary A**: browser to Netlify edge (internet, TLS).
- **Boundary B**: Netlify edge to function runtime.
- **Boundary C**: third-party CDN (jsDelivr) to the browser (Tailwind script).
- **Actors**: passive network observer, active network attacker (MITM), malicious user of the public endpoint, compromised third-party script host, curious log reader with access to platform logs.

### 4.4 Threats and mitigations (STRIDE)

| # | Threat | Category | Mitigation in this project | Residual risk |
|---|--------|----------|----------------------------|---------------|
| T1 | Passive observer reads response body | Information disclosure | Payload is AES-256-GCM encrypted under a key from an ephemeral ECDH exchange. The URL alone (domain, salt, client public key) is not enough to derive the key; the observer would need a private key that never leaves the endpoints. | Metadata is still visible: domain, timing, response size. |
| T2 | Response tampered in transit | Tampering | Encrypt-then-MAC: HMAC-SHA256 over `v1.serverPub.iv.ct`, verified with WebCrypto `verify` (constant-time) **before** decryption. GCM adds a second authentication layer. | See T3 for active attackers. |
| T3 | Active MITM substitutes its own server key | Spoofing | Primary defence is TLS plus HSTS (set in `netlify.toml`). | **The handshake is unauthenticated.** An attacker who can break TLS can complete ECDH with both sides. A production design would pin or sign the server's ephemeral key (for example with a long-term signing key whose public half is embedded in the page). |
| T4 | Replay of an old response | Replay | A fresh client key pair is generated per sweep, so a captured response cannot be decrypted or validated under a different session. `Cache-Control: no-store` is set. | A replay against the same session (same client key) is not prevented, since there is no nonce or timestamp check client-side. Low impact for a read-only report. |
| T5 | Key reuse / weak randomness | Cryptographic failure | Fresh ECDH keys per request on both sides, random 96-bit GCM IV per response (`crypto.randomBytes`), separate AES and HMAC keys via HKDF with distinct labels. | Relies on platform CSPRNGs. |
| T6 | Malformed parameters used for injection or crashes | Tampering / DoS | Strict validation: domain regex (length and label rules), salt must be 32-64 hex chars, public key must be 130 hex chars starting with `04`. GET only; other methods return 405. Errors are generic. | Invalid EC points that pass the regex are caught by the `try/catch` and return a generic 500. |
| T7 | SSRF / use as a scanner | Elevation of privilege | **The function makes no outbound requests.** Assets are generated in-process, and the domain is only used as a string label. | None by design. Any future real scanning must add an allowlist and authorization checks. |
| T8 | XSS via reflected domain or server data | Tampering | The UI builds the DOM with `createElement` and `textContent` only; no `innerHTML`. The domain is validated client- and server-side, and the report is rendered from authenticated, decrypted data. CSP sets `default-src 'none'` with a narrow allowlist, plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. | CSP allows `'unsafe-inline'` scripts because the JS lives in `index.html`. Moving it to a separate file removes this need. |
| T9 | Compromised or swapped CDN script | Tampering / supply chain | CSP restricts script sources to `self` and `cdn.jsdelivr.net`. | The Tailwind script has **no Subresource Integrity** hash and is not pinned to an exact version. For production, build Tailwind at deploy time and self-host the CSS. |
| T10 | Abuse of the public endpoint (cost, DoS) | Denial of service | Cheap, deterministic computation; strict input validation. | **No authentication or rate limiting.** Add Netlify rate limiting, a WAF rule or an API token for any real use. |
| T11 | Sensitive data in platform logs | Information disclosure | The response body is encrypted, so logs of bodies reveal nothing readable. | Query strings (domain, salt, client public key) are logged by the platform. They are not secret, but they are metadata. Switching to POST would keep them out of URL logs. |
| T12 | Source and config exposure | Information disclosure | Nothing secret exists in the repository (no keys, no environment variables). | `publish = "."` serves repository files statically, including the function source and `netlify.toml`. Moving `index.html` into a `public/` directory and publishing only that is the recommended hardening. |

### 4.5 Design decisions worth noting

- **Why not just a salt?** A salt is not a secret. It travels in the URL, so anyone who sees the request would see it. Using it only as an HKDF input, alongside an ECDH shared secret, gives it a legitimate role (domain separation and key diversification) while the actual secrecy comes from the ephemeral private keys.
- **Why encrypt on top of TLS?** TLS already protects the channel. The envelope is defence in depth, covering hostile intermediaries that terminate TLS (corporate inspection proxies, logging layers) and demonstrating end-to-end session crypto. It is not a replacement for TLS.
- **Why encrypt-then-MAC with GCM?** The explicit HMAC meets the "validate signature before decrypt" requirement and lets the client reject tampered data without touching the decryption path. AES-GCM's own tag provides a second check.
- **Why a simulation?** It avoids legal and ethical risk (scanning third-party infrastructure without authorization) and removes SSRF entirely, while still demonstrating version parsing, CVE matching and remediation workflow.

### 4.6 Out of scope

- Real network discovery, port scanning or banner grabbing.
- User authentication and authorization.
- Persistence, audit logging and multi-tenancy.
- Protection against a fully compromised browser or endpoint.

### 4.7 Hardening roadmap

1. Sign the server's ephemeral public key with a long-term key and verify it client-side (closes T3).
2. Self-host a compiled Tailwind CSS and remove the CDN script and `'unsafe-inline'` (closes T8/T9 residuals).
3. Publish only a `public/` directory (T12).
4. Add authentication and rate limiting to the endpoint (T10).
5. Switch to POST and include a timestamp or nonce checked on the client (T4/T11).
6. Replace the mock feed with a live source such as NVD or CISA KEV, with caching and signature validation.

---

## 5. Credits

System Engineered & Developed by OwenRoot.
LinkedIn: Owen Michael Mt | X: [_OwenRoot](https://x.com/_OwenRoot) | GitHub: [OwenRoot](https://github.com/OwenRoot)
