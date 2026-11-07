# RedSurface Threat Model

This document describes what RedSurface protects, who it protects against, and where the remaining risks are.

## 1. Security objectives

| ID | Objective |
|----|-----------|
| O1 | Keep sweep results confidential from passive observers of the response. |
| O2 | Let the client detect any modification of the response. |
| O3 | Prevent the tool from being used as an attack proxy, SSRF vector or abuse platform. |
| O4 | Prevent attacker-controlled content from executing in the UI (XSS). |
| O5 | Keep the impact on assessed targets minimal and proportionate. |

## 2. Assets, actors and trust boundaries

- **Assets:** the findings payload, ephemeral key material, availability of the function, and the reputation of the platform's outbound IP addresses.
- **Actors:** passive network observer, active man-in-the-middle, malicious user of the public endpoint, hostile assessed target (controls its own DNS and HTTP responses), compromised script CDN.
- **Boundaries:** browser to Netlify edge; function to the internet (CT logs, DNS, targets, CISA); script CDN to browser.

## 3. Transport protection

Each sweep performs an ephemeral ECDH P-256 key exchange. Keys are derived with HKDF-SHA256 (using the client salt) into separate encryption and MAC keys. The payload is encrypted with AES-256-GCM and signed with HMAC-SHA256 (encrypt-then-MAC). The browser verifies the signature before decrypting. This is defence in depth on top of TLS, not a replacement for it.

## 4. Threats and mitigations (STRIDE)

| # | Threat | Mitigation | Residual risk |
|---|--------|-----------|---------------|
| T1 | Passive observer reads the response | AES-256-GCM under an ephemeral ECDH-derived key. The URL alone cannot derive the key. | Metadata is visible: domain, timing, response size. |
| T2 | Response modified in transit | Encrypt-then-MAC with constant-time HMAC verification before decryption; GCM tag as a second layer. | See T3. |
| T3 | Active MITM substitutes its own server key | TLS and HSTS. | The handshake is unauthenticated. An attacker who can break TLS could negotiate with both sides. Signing the server's ephemeral key with a pinned long-term key would close this. |
| T4 | Replay | Fresh client key pair per sweep; `Cache-Control: no-store`. | Replay within the same session is not blocked. Low impact for a read-only report. |
| T5 | Weak randomness or key reuse | Fresh ECDH keys per request, random 96-bit IV per response, separate AES and HMAC keys via HKDF with distinct labels. | Depends on the platform CSPRNG. |
| T6 | Malformed input | Strict validation of domain, salt and public key; GET only; internal-only TLDs blocked; generic error messages. | Invalid EC points return a generic 500. |
| T7 | SSRF against internal networks | Only names resolving to public IPv4 addresses are contacted. Private, loopback, link-local, CGNAT, documentation and multicast ranges are rejected. Requests are limited to `HEAD /` on ports 80 and 443, and redirects are never followed. | IPv6 records are not resolved or probed. |
| T8 | DNS rebinding | DNS is resolved once and validated; the connection goes to that IP, with Host header and SNI carrying the hostname. | None known. |
| T9 | Abuse as a scanning proxy | Authorization confirmation, per-client rate limit (8 per 10 minutes, best effort), caps of 60 names and 15 probes, fixed request shape, identifying User-Agent. | Domain ownership is not verified, and in-memory rate limiting is not shared across instances. DNS TXT proof of ownership would strengthen this. |
| T10 | Hostile target responses | Headers are displayed via `textContent` only; response bodies are never read; strict timeouts. | Long header values are shown as received. |
| T11 | XSS in the UI | DOM built with `createElement` and `textContent`; no `innerHTML`; CSP, `nosniff`, frame denial and no-referrer headers. | The CSP allows inline scripts because the JavaScript lives in `index.html`. Moving it to a separate file removes this. |
| T12 | Script CDN compromise | CSP restricts script origins. | The Tailwind CDN script has no Subresource Integrity hash. Self-hosting compiled CSS would remove the dependency. |
| T13 | Poisoned or unavailable upstream data (crt.sh, CertSpotter, CISA) | Timeouts, graceful degradation with visible warnings, names re-validated and required to fall under the target domain. | A poisoned CT response could add fake names, bounded by validation and host caps. |
| T14 | Denial of service or cost abuse | Time budget, caps and rate limiting. | No authentication. A WAF or Netlify rate limiting is recommended for wider use. |
| T15 | Query strings in platform logs | Response body is encrypted. | Domain, salt and client public key appear in URL logs. Using POST would avoid this. |
| T16 | Source files served statically | The repository contains no secrets. | `publish = "."` serves source files. Publishing a dedicated `public/` directory would avoid this. |
| T17 | Misuse against unauthorized targets | Authorization confirmation, passive-only design, documented scope. | A user can still misrepresent authorization. Operators remain responsible for acceptable use. |

## 5. Design decisions

- **Passive by design.** Discovery relies on public data, and active contact is one HEAD request per host, comparable to a browser visit. This keeps the impact low and the tool defensible.
- **Salt plus ECDH.** A salt is not secret. It provides HKDF domain separation, while secrecy comes from the ephemeral private keys.
- **Demo mode.** It allows the tool to be shown without touching any real system.

## 6. Out of scope

Port scanning, authenticated scanning, exploitation, credentialed checks, persistence, user accounts and multi-tenancy.

## 7. Hardening roadmap

1. Sign the server's ephemeral key and verify it in the client (T3).
2. Require DNS TXT proof of ownership before live sweeps (T9, T17).
3. Self-host compiled Tailwind CSS and remove `'unsafe-inline'` (T11, T12).
4. Publish only a `public/` directory (T16).
5. Add persistent rate limiting and authentication (T14).
6. Switch to POST with a nonce or timestamp (T4, T15).
7. Add IPv6 support with the same reserved-range checks (T7).
8. Pull vulnerability data from NVD using CPE matching instead of the curated rule set.
