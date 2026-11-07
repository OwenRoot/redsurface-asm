# RedSurface

RedSurface is a serverless attack surface management (ASM) tool. Give it a domain you are authorized to assess, and it finds the hosts exposed to the internet, checks how they are configured, and tells you what to fix first.

**Live demo:** [https://YOUR-SITE.netlify.app](https://YOUR-SITE.netlify.app)

<!-- Add a screenshot after deploying: ![RedSurface results](docs/screenshot.png) -->

## What it does

- **Finds hosts.** Discovers subdomains from public certificate transparency logs and confirms them with live DNS lookups.
- **Inspects them.** Sends a single HEAD request to each host to read the server banner, TLS certificate and security headers.
- **Matches known vulnerabilities.** Compares announced software versions (Exchange, Tomcat, nginx, OpenSSH, Apache httpd) against a curated CVE rule set, and flags anything on CISA's Known Exploited Vulnerabilities list.
- **Checks hygiene.** Reports missing HTTPS, expired or untrusted certificates, missing HSTS and security headers, version disclosure, internal IPs in public DNS, and publicly resolvable staging hosts.
- **Explains the fix.** Every finding has a recommended fix covering the patch, system hardening, access control and how to verify the result.
- **Protects the results in transit.** Responses are encrypted and signed, and the browser verifies the signature before decrypting.

## Modes

| Mode | Behavior |
|------|----------|
| Demo | Uses a simulated telecom estate (mail gateway, billing staging portal, USSD router, core network node). Nothing on the internet is contacted. |
| Live | Runs the passive checks above against a real domain. Requires confirming that you own it or have written permission to assess it. |

## Responsible use

Only run live sweeps against domains you own or have explicit written permission to test. RedSurface is passive by design: it never scans ports, brute-forces, crawls, or sends exploit payloads. It makes at most one HEAD request per discovered host.

## How it works

```
Browser                                    Netlify Function
  generate salt + one-time ECDH key pair
  ---- domain, mode, salt, public key ---->
                                           discover hosts (CT logs, DNS)
                                           probe hosts, match CVEs, check hygiene
                                           derive keys with ECDH + HKDF
                                           encrypt (AES-256-GCM), sign (HMAC-SHA256)
  <---- encrypted payload + signature ----
  verify signature, then decrypt
  render report
```

The encryption layer adds defence in depth on top of TLS: each sweep uses fresh keys, and the browser rejects any response whose signature does not verify.

## Security design

- Input validation on the domain, salt and public key, with internal-only domain suffixes blocked.
- SSRF protection: only public IPv4 addresses are contacted; private, loopback, link-local and reserved ranges are rejected.
- DNS-rebinding protection: the validated IP is connected to directly, with the hostname sent separately.
- No redirects followed and no response bodies read.
- Per-client rate limiting, host caps and a time budget on every sweep.
- Strict Content Security Policy and security headers, and DOM rendering without `innerHTML`.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis.

## Limitations

- Version-based detection only works when a server announces its version. A host with no finding is not necessarily safe.
- Vendor backports can cause false positives, for example on Debian OpenSSH builds.
- The CVE rule set is small and curated. It is not a replacement for authenticated scanners such as Nessus or Qualys, and rules should be checked against vendor advisories.
- Certificate transparency only lists names that have had public certificates issued.
- Netlify's default function timeout is 10 seconds, so large domains return partial results.

## Project structure

```
.
├── index.html                          Interface and client-side cryptography
├── netlify.toml                        Build settings and security headers
├── netlify/functions/recon-surface.js  Sweep logic and encrypted response
├── THREAT_MODEL.md                     Security analysis
└── README.md
```

## Deploy your own

1. Fork or clone this repository.
2. In Netlify, choose **Add new site**, then **Import an existing project**, and select the repository.
3. Leave the build command empty. Settings are read from `netlify.toml`.
4. Deploy. No environment variables or dependencies are needed (Node 18 or later).

## Built with

Node.js built-in modules (`crypto`, `dns`, `https`), the Web Crypto API, Tailwind CSS v4, and Netlify Functions.

## Author

System Engineered & Developed by OwenRoot.

LinkedIn: Owen Michael Mt | X: [@_OwenRoot](https://x.com/_OwenRoot) | GitHub: [OwenRoot](https://github.com/OwenRoot)
