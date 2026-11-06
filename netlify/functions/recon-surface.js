'use strict';

/**
 * recon-surface.js - Attack Surface Management sweep (demo + live passive modes).
 *
 * LIVE MODE (passive, low-impact, defensive):
 *   - Subdomain discovery from Certificate Transparency logs (crt.sh / CertSpotter)
 *   - Real DNS A-record resolution
 *   - One HEAD request to "/" per host (HTTPS first, HTTP fallback). No crawling,
 *     no port scanning, no payloads, no redirect following.
 *   - Banner/version matching against a curated CVE rule set
 *   - Enrichment with the CISA Known Exploited Vulnerabilities (KEV) catalog
 *   - Security-header and TLS certificate hygiene checks
 *
 * Safety controls: caller must attest authorization, strict input validation,
 * private/reserved IP blocking (SSRF), DNS-rebinding-safe probing (connect to the
 * validated IP, send Host/SNI separately), host cap, time budget, best-effort
 * rate limiting.
 *
 * DEMO MODE: no network activity; simulated assets (RFC 5737 IPs).
 *
 * Transport protection (defence in depth on top of TLS):
 *   ECDH P-256 ephemeral handshake -> HKDF-SHA256 (salt = client salt) ->
 *   AES-256-GCM encryption + HMAC-SHA256 signature (encrypt-then-MAC).
 *   The client verifies the HMAC before decrypting.
 */

const crypto = require('crypto');
const dns = require('dns').promises;
const https = require('https');
const http = require('http');

const SECURITY_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
const LABELS_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/;
const SALT_RE = /^[0-9a-f]{32,64}$/i;
const PUB_RE = /^04[0-9a-f]{128}$/i;
const BLOCKED_TLDS = new Set(['local', 'internal', 'localhost', 'lan', 'corp', 'home', 'invalid', 'test', 'example', 'arpa']);

const USER_AGENT = 'RedSurface-ASM/2.0 (defensive attack-surface assessment; passive)';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const TIME_BUDGET_MS = 8500; // keeps the sweep inside the default 10 s function limit
const MAX_NAMES = 60;
const MAX_PROBES = 15;

/* -------------------------------------------------------------------------- */
/* Vulnerability rule set (banner regex -> affected version ranges)           */
/* Verify against vendor advisories before relying on it.                     */
/* -------------------------------------------------------------------------- */

const VULN_FEED = [
  {
    product: 'Microsoft Exchange Server',
    banner: /Exchange Server[^0-9]*(\d+\.\d+\.\d+\.\d+)/i,
    vulns: [
      {
        cve: 'CVE-2024-21410',
        severity: 'CRITICAL',
        cvss: 9.8,
        title: 'Exchange Server NTLM credential relay / privilege escalation',
        description:
          'Without Extended Protection for Authentication, an attacker can relay captured NTLM credentials to Exchange and impersonate the victim.',
        ranges: [{ introduced: '15.1.0.0', fixed: '15.1.2507.6' }],
        remediation: {
          priority: 'P1 - remediate within 72 hours',
          patch: 'Upgrade Exchange Server 2016 to CU23 or later (build 15.1.2507.6+). Apply the latest Security Update on top.',
          hardening: [
            'Enable Extended Protection for Authentication on all Exchange virtual directories (ExchangeExtendedProtectionManagement.ps1).',
            'Disable legacy NTLMv1 and restrict NTLM via GPO where Kerberos is viable.',
            'Remove the OWA/ECP/EWS surface from direct internet exposure where possible.',
          ],
          accessControl: [
            'Publish mail access via a reverse proxy/WAF with pre-authentication.',
            'Restrict /ecp and /powershell to the admin jump-host subnet.',
            'Enforce MFA on all mailbox access.',
          ],
          verification: 'Run Get-ExchangeServer | fl Name,AdminDisplayVersion and the Microsoft HealthChecker script; confirm EP shows Required.',
        },
      },
    ],
  },
  {
    product: 'Apache Tomcat',
    banner: /Apache[- ]Tomcat\/?\s*(\d+(?:\.\d+)+)/i,
    vulns: [
      {
        cve: 'CVE-2025-24813',
        severity: 'CRITICAL',
        cvss: 9.8,
        title: 'Tomcat partial PUT path equivalence leading to RCE',
        description:
          'When the default servlet allows writes and partial PUT is enabled, a crafted request can plant a malicious serialized session file, enabling remote code execution.',
        ranges: [
          { introduced: '9.0.0', fixed: '9.0.99' },
          { introduced: '10.1.0', fixed: '10.1.35' },
          { introduced: '11.0.0', fixed: '11.0.3' },
        ],
        remediation: {
          priority: 'P1 - remediate within 72 hours',
          patch: 'Upgrade to Tomcat 9.0.99+, 10.1.35+ or 11.0.3+ (preferably the latest release of your branch).',
          hardening: [
            'Keep the DefaultServlet readonly="true" (default) and never enable writes in production.',
            'Disable file-based session persistence (PersistentManager/FileStore) or use a non-Java-serialization store.',
            'Run Tomcat as an unprivileged user with a read-only application filesystem.',
          ],
          accessControl: [
            'Block HTTP PUT/DELETE/PATCH at the WAF/load balancer for affected paths.',
            'Restrict the application to the corporate VPN / allowlisted ranges where it is internal.',
            'Remove /manager and /host-manager from internet-facing instances.',
          ],
          verification: 'Check version via bin/version.sh; confirm a PUT to the app root returns 403/405 from outside the allowlist.',
        },
      },
    ],
  },
  {
    product: 'nginx',
    banner: /nginx\/(\d+(?:\.\d+)+)/i,
    vulns: [
      {
        cve: 'CVE-2021-23017',
        severity: 'HIGH',
        cvss: 7.7,
        title: 'nginx resolver off-by-one heap write',
        description:
          'A crafted DNS response can cause a one-byte memory overwrite in the nginx resolver, leading to worker crashes and potentially code execution.',
        ranges: [{ introduced: '0.6.18', fixed: '1.20.1' }],
        remediation: {
          priority: 'P2 - remediate within 14 days',
          patch: 'Upgrade nginx to 1.20.1+ (stable) or 1.21.0+ (mainline); prefer the current stable release.',
          hardening: [
            'Only configure the "resolver" directive when required, and point it at trusted internal DNS.',
            'Set server_tokens off; to stop advertising the exact version in banners.',
            'Run workers as an unprivileged user under a seccomp/AppArmor profile.',
          ],
          accessControl: [
            'Restrict resolver traffic to internal DNS servers via firewall rules.',
            'Rate-limit and authenticate API clients (mTLS or signed requests).',
            'Expose only the required ports from the DMZ.',
          ],
          verification: 'Run nginx -v after upgrade; confirm curl -sI no longer reveals a version string.',
        },
      },
    ],
  },
  {
    product: 'OpenSSH',
    banner: /OpenSSH[_ ](\d+\.\d+(?:p\d+)?)/i,
    vulns: [
      {
        cve: 'CVE-2024-6387',
        severity: 'HIGH',
        cvss: 8.1,
        title: 'OpenSSH regreSSHion signal handler race condition',
        description:
          'A race condition in sshd signal handling may allow unauthenticated remote code execution as root on glibc-based Linux systems. Distribution backports may already fix a matching version string.',
        ranges: [{ introduced: '8.5', fixed: '9.8' }],
        remediation: {
          priority: 'P2 - remediate within 7 days',
          patch: 'Upgrade to OpenSSH 9.8p1+ or install the distribution security backport, then restart sshd.',
          hardening: [
            'Set LoginGraceTime 0 as a temporary mitigation (note: this exposes MaxStartups exhaustion).',
            'Disable password authentication; use hardware-backed keys or SSH certificates.',
            'Set MaxStartups conservatively and enable fail2ban-style rate limiting.',
          ],
          accessControl: [
            'Allow SSH only from the management/bastion VLAN.',
            'Enforce session logging through a PAM/bastion with MFA.',
            'Remove all internet-facing exposure of management interfaces.',
          ],
          verification: 'Run ssh -V and check the distro changelog for CVE-2024-6387; verify the firewall blocks port 22 from untrusted ranges.',
        },
      },
    ],
  },
  {
    product: 'Apache HTTP Server',
    banner: /Apache\/(\d+(?:\.\d+)+)/i,
    vulns: [
      {
        cve: 'CVE-2021-41773',
        severity: 'CRITICAL',
        cvss: 9.8,
        title: 'Apache HTTP Server path traversal and RCE',
        description:
          'A path normalisation flaw allows mapping URLs to files outside the document root, and to remote code execution when CGI is enabled.',
        ranges: [{ introduced: '2.4.49', fixed: '2.4.51' }],
        remediation: {
          priority: 'P1 - remediate within 72 hours',
          patch: 'Upgrade Apache httpd to 2.4.51+ (preferably the latest 2.4.x release).',
          hardening: [
            'Use "Require all denied" on the filesystem root: <Directory /> ... </Directory>.',
            'Disable mod_cgi/mod_cgid unless strictly needed.',
            'Set ServerTokens Prod and ServerSignature Off.',
          ],
          accessControl: [
            'Place legacy portals behind the corporate VPN.',
            'Add WAF rules rejecting encoded traversal sequences (%2e, .%2e).',
            'Decommission the host if the service is no longer required.',
          ],
          verification: 'Confirm httpd -v reports 2.4.51+; test that a traversal request returns 400/403.',
        },
      },
    ],
  },
];

/* -------------------------------------------------------------------------- */
/* Version comparison and feed matching                                       */
/* -------------------------------------------------------------------------- */

function parseVersion(v) {
  return String(v).split(/[^0-9]+/).filter(Boolean).map((n) => parseInt(n, 10));
}

function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

function matchingRange(version, ranges) {
  return ranges.find((r) => compareVersions(version, r.introduced) >= 0 && compareVersions(version, r.fixed) < 0);
}

function matchFeed(banner) {
  const out = { product: 'Unidentified', version: null, findings: [] };
  for (const rule of VULN_FEED) {
    const m = String(banner).match(rule.banner);
    if (!m) continue;
    out.product = rule.product;
    out.version = m[1];
    for (const v of rule.vulns) {
      const range = matchingRange(m[1], v.ranges);
      if (range) {
        out.findings.push({
          cve: v.cve,
          severity: v.severity,
          cvss: v.cvss,
          title: v.title,
          description: v.description,
          installed: m[1],
          fixedIn: range.fixed,
          knownExploited: false,
          remediation: v.remediation,
        });
      }
    }
    break;
  }
  return out;
}

function deriveStatus(asset) {
  if (asset.unreachable) return 'unreachable';
  const f = asset.findings;
  if (f.some((x) => x.cve || x.severity === 'CRITICAL' || x.severity === 'HIGH')) return 'vulnerable';
  if (f.length) return 'warning';
  return 'clean';
}

/* -------------------------------------------------------------------------- */
/* Networking helpers                                                         */
/* -------------------------------------------------------------------------- */

function withTimeout(promise, ms) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error('timeout')), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

async function fetchJson(url, ms) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    const r = await fetch(url, { signal: ac.signal, headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

// True for private, loopback, link-local, CGNAT, documentation, multicast and reserved IPv4.
function isReservedIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

async function discoverNames(domain, warnings, sources) {
  const crt = fetchJson(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, 5000)
    .then((rows) => ({ src: 'crt.sh', names: rows.flatMap((r) => String(r.name_value || '').split('\n')) }));
  const cs = fetchJson(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
    5000
  ).then((rows) => ({ src: 'certspotter', names: rows.flatMap((r) => r.dns_names || []) }));

  let result = { src: null, names: [] };
  try {
    result = await Promise.any([crt, cs]);
    sources.push(result.src);
  } catch (e) {
    warnings.push('Certificate Transparency lookup failed (crt.sh and CertSpotter unavailable); only the apex domain was assessed.');
  }

  const set = new Set([domain]);
  for (const raw of result.names) {
    const n = String(raw).trim().toLowerCase().replace(/^\*\./, '');
    if (LABELS_RE.test(n) && (n === domain || n.endsWith('.' + domain))) set.add(n);
  }
  const all = [...set];
  const truncated = all.length > MAX_NAMES;
  if (truncated) warnings.push(`Discovered ${all.length} names; only the first ${MAX_NAMES} were processed.`);
  return all.sort((a, b) => (a === domain ? -1 : b === domain ? 1 : a.length - b.length || a.localeCompare(b))).slice(0, MAX_NAMES);
}

async function resolveHost(host) {
  try {
    return await withTimeout(dns.resolve4(host), 2500);
  } catch (e) {
    return [];
  }
}

// Connects to the already-validated IP; Host header / SNI carry the hostname (DNS-rebinding safe).
function probe(host, ip, useTls, timeoutMs) {
  return new Promise((resolve) => {
    const opts = {
      host: ip,
      port: useTls ? 443 : 80,
      method: 'HEAD',
      path: '/',
      timeout: timeoutMs,
      agent: false,
      headers: { Host: host, 'User-Agent': USER_AGENT, Accept: '*/*', Connection: 'close' },
    };
    if (useTls) {
      opts.servername = host;
      opts.rejectUnauthorized = false; // we want to inspect broken certs, not fail on them
    }
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const req = (useTls ? https : http).request(opts, (res) => {
      const out = { status: res.statusCode, headers: res.headers, tls: null };
      if (useTls && res.socket && typeof res.socket.getPeerCertificate === 'function') {
        const c = res.socket.getPeerCertificate();
        if (c && c.valid_to) {
          const expires = Date.parse(c.valid_to);
          out.tls = {
            authorized: !!res.socket.authorized,
            error: res.socket.authorizationError ? String(res.socket.authorizationError) : null,
            validTo: new Date(expires).toISOString().slice(0, 10),
            daysLeft: Math.floor((expires - Date.now()) / 86400000),
            issuer: (c.issuer && (c.issuer.O || c.issuer.CN)) || 'unknown',
          };
        }
      }
      res.resume();
      finish(out);
    });
    req.on('timeout', () => { req.destroy(); finish(null); });
    req.on('error', () => finish(null));
    req.end();
  });
}

/* -------------------------------------------------------------------------- */
/* Hygiene checks                                                             */
/* -------------------------------------------------------------------------- */

function rem(priority, patch, hardening, accessControl, verification) {
  return { priority, patch, hardening, accessControl, verification };
}

function guessRole(host) {
  const h = host.split('.')[0];
  if (/^(mail|smtp|imap|pop|owa|webmail|exchange|autodiscover)/.test(h)) return 'Mail service';
  if (/(api|gw|gateway|ussd|sms)/.test(h)) return 'API / gateway';
  if (/(vpn|remote|ssl|access)/.test(h)) return 'Remote access';
  if (/(bill|pay|invoice|crm)/.test(h)) return 'Billing / customer system';
  if (/(admin|manage|console|portal)/.test(h)) return 'Portal / admin interface';
  if (/(dev|test|stg|stage|staging|uat|qa|sandbox)/.test(h)) return 'Non-production';
  return 'Web asset';
}

function hygieneFindings(host, ips, https_, http_) {
  const f = [];
  const primary = https_ || http_;
  const headers = (primary && primary.headers) || {};

  if (!https_ && http_) {
    f.push({
      id: 'ASM-TLS-001', severity: 'HIGH', cvss: null, knownExploited: false,
      title: 'HTTPS not available',
      description: 'The host answers on HTTP but not on HTTPS. Traffic and credentials can be read or modified on the network path.',
      remediation: rem('P2 - remediate within 14 days',
        'Deploy a valid TLS certificate and serve the site over HTTPS.',
        ['Redirect all HTTP to HTTPS (301).', 'Enable HSTS once HTTPS is stable.', 'Disable TLS 1.0/1.1.'],
        ['Close port 80 where it is not needed.', 'Restrict legacy HTTP-only systems to internal networks.'],
        'Run curl -I https://' + host + ' and confirm a valid certificate and HSTS header.'),
    });
  }

  if (https_ && https_.tls) {
    const t = https_.tls;
    if (t.daysLeft < 0) {
      f.push({
        id: 'ASM-TLS-002', severity: 'HIGH', cvss: null, knownExploited: false,
        title: 'TLS certificate expired',
        description: `The certificate expired on ${t.validTo} (${Math.abs(t.daysLeft)} days ago). Clients will show security errors and may be exposed to downgrade or interception.`,
        remediation: rem('P1 - remediate within 72 hours',
          'Renew and deploy a new certificate immediately.',
          ['Automate renewal (ACME / certbot / cert-manager).', 'Monitor expiry with alerts at 30/14/7 days.'],
          ['Keep an inventory of certificates and owners.'],
          'Check openssl s_client -connect ' + host + ':443 -servername ' + host + ' | openssl x509 -noout -dates'),
      });
    } else if (t.daysLeft < 30) {
      f.push({
        id: 'ASM-TLS-003', severity: 'MEDIUM', cvss: null, knownExploited: false,
        title: 'TLS certificate expiring soon',
        description: `The certificate expires on ${t.validTo} (${t.daysLeft} days left).`,
        remediation: rem('P3 - remediate within 14 days',
          'Renew the certificate before expiry.',
          ['Automate renewal and add expiry monitoring.'],
          ['Assign an owner for the certificate lifecycle.'],
          'Re-run the sweep after renewal and confirm daysLeft is above 30.'),
      });
    }
    if (!t.authorized && t.daysLeft >= 0) {
      f.push({
        id: 'ASM-TLS-004', severity: 'MEDIUM', cvss: null, knownExploited: false,
        title: 'TLS certificate not trusted for this hostname',
        description: `Certificate validation failed (${t.error || 'unknown reason'}). Issuer: ${t.issuer}.`,
        remediation: rem('P2 - remediate within 14 days',
          'Install a certificate from a trusted CA that covers this hostname, including the full intermediate chain.',
          ['Serve the complete certificate chain.', 'Avoid self-signed certificates on public hosts.'],
          ['Remove the DNS record if the host is decommissioned.'],
          'Test with openssl s_client -verify_return_error and an external TLS checker.'),
      });
    }
  }

  if (https_ && !headers['strict-transport-security']) {
    f.push({
      id: 'ASM-HDR-001', severity: 'MEDIUM', cvss: null, knownExploited: false,
      title: 'HSTS header missing',
      description: 'Without Strict-Transport-Security, browsers can be tricked into using HTTP (SSL-stripping).',
      remediation: rem('P3 - remediate within 30 days',
        'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains.',
        ['Roll out with a short max-age first, then increase.', 'Consider HSTS preload once all subdomains support HTTPS.'],
        ['Set the header at the reverse proxy or CDN for consistency.'],
        'Run curl -sI https://' + host + ' | grep -i strict-transport'),
    });
  }

  if (primary && primary.status >= 200 && primary.status < 300) {
    const missing = [];
    if (!headers['content-security-policy']) missing.push('Content-Security-Policy');
    if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'] || '')) missing.push('X-Frame-Options (or CSP frame-ancestors)');
    if (!headers['x-content-type-options']) missing.push('X-Content-Type-Options');
    if (missing.length) {
      f.push({
        id: 'ASM-HDR-002', severity: 'LOW', cvss: null, knownExploited: false,
        title: 'Security headers missing',
        description: 'Missing: ' + missing.join(', ') + '. These headers reduce XSS, clickjacking and MIME-sniffing risk.',
        remediation: rem('P4 - remediate within 60 days',
          'Add the missing response headers at the web server, reverse proxy or CDN.',
          ['Content-Security-Policy: start in report-only mode, then enforce.', 'X-Content-Type-Options: nosniff', 'Content-Security-Policy: frame-ancestors \'none\' (or X-Frame-Options: DENY)'],
          ['Manage headers centrally so every service inherits them.'],
          'Scan the host with securityheaders.com and confirm a grade of A or better.'),
      });
    }
  }

  const server = String(headers.server || '');
  const powered = String(headers['x-powered-by'] || '');
  if (/\d+\.\d+/.test(server) || powered) {
    f.push({
      id: 'ASM-INFO-001', severity: 'LOW', cvss: null, knownExploited: false,
      title: 'Software version disclosed in response headers',
      description: `Headers reveal: ${[server && 'Server: ' + server, powered && 'X-Powered-By: ' + powered].filter(Boolean).join('; ')}. This makes targeted exploit selection easier for attackers.`,
      remediation: rem('P4 - remediate within 60 days',
        'Remove or genericise the Server and X-Powered-By headers.',
        ['nginx: server_tokens off;', 'Apache: ServerTokens Prod; ServerSignature Off', 'Express/ASP.NET: disable X-Powered-By'],
        ['Strip these headers at the edge proxy.'],
        'Run curl -sI https://' + host + ' and confirm no version strings appear.'),
    });
  }

  if (ips.some(isReservedIPv4)) {
    f.push({
      id: 'ASM-DNS-001', severity: 'MEDIUM', cvss: null, knownExploited: false,
      title: 'Internal address published in public DNS',
      description: 'A public DNS record resolves to a private or reserved address, which leaks internal addressing and can aid reconnaissance.',
      remediation: rem('P3 - remediate within 30 days',
        'Remove the record from public DNS or move it to a private (split-horizon) zone.',
        ['Review all public zone records for internal addresses.'],
        ['Restrict zone changes to authorized administrators.'],
        'Run dig A ' + host + ' from an external resolver and confirm no private IPs are returned.'),
    });
  }

  if (/(^|[.-])(dev|test|stg|stage|staging|uat|qa|sandbox)([.-]|$)/.test(host.split('.')[0])) {
    f.push({
      id: 'ASM-EXP-001', severity: 'LOW', cvss: null, knownExploited: false,
      title: 'Non-production hostname is publicly resolvable',
      description: 'Development or staging systems are often less patched and may contain real data. Public exposure widens the attack surface.',
      remediation: rem('P4 - remediate within 60 days',
        'Restrict non-production systems to VPN or an IP allowlist.',
        ['Use separate credentials and synthetic data for non-production.'],
        ['Require SSO in front of staging environments.'],
        'Confirm the host is unreachable from an external network.'),
    });
  }

  return f;
}

/* -------------------------------------------------------------------------- */
/* Live sweep                                                                 */
/* -------------------------------------------------------------------------- */

async function liveSweep(domain, startedMs) {
  const warnings = [];
  const sources = [];
  const deadline = startedMs + TIME_BUDGET_MS;

  const kevPromise = fetchJson(KEV_URL, 5000)
    .then((d) => new Set((d.vulnerabilities || []).map((v) => v.cveID)))
    .catch(() => null);

  const names = await discoverNames(domain, warnings, sources);
  const resolved = await pool(names, 10, async (host) => ({ host, ips: await resolveHost(host) }));
  const live = resolved.filter((r) => r.ips.length);
  if (live.length) sources.push('dns');

  const targets = live.slice(0, MAX_PROBES);
  if (live.length > MAX_PROBES) warnings.push(`${live.length} hosts resolved; only the first ${MAX_PROBES} were probed.`);
  let skipped = 0;

  const assets = await pool(targets, 8, async ({ host, ips }) => {
    const publicIp = ips.find((ip) => !isReservedIPv4(ip));
    const asset = {
      host, ip: ips[0], role: guessRole(host), criticality: 'Unrated',
      banner: '(no banner disclosed)', product: 'Unidentified', version: null,
      findings: [], unreachable: false, http: null, tls: null,
    };

    let https_ = null;
    let http_ = null;
    if (publicIp) {
      const remaining = deadline - Date.now();
      if (remaining < 700) {
        skipped++;
        asset.unreachable = true;
        asset.note = 'Skipped: time budget exhausted.';
      } else {
        https_ = await probe(host, publicIp, true, Math.min(3500, remaining));
        if (!https_ && deadline - Date.now() > 700) http_ = await probe(host, publicIp, false, Math.min(3000, deadline - Date.now()));
      }
    } else {
      asset.note = 'Not probed: resolves only to a private/reserved address.';
    }

    const res = https_ || http_;
    if (!res && publicIp && !asset.note) {
      asset.unreachable = true;
      asset.note = 'No response on ports 80/443.';
    }
    if (res) {
      const h = res.headers;
      const parts = [];
      if (h.server) parts.push(String(h.server));
      if (h['x-powered-by']) parts.push(String(h['x-powered-by']));
      if (h['x-owa-version']) parts.push('Exchange Server ' + String(h['x-owa-version']));
      asset.banner = parts.join(' | ') || '(no banner disclosed)';
      asset.http = { status: res.status, scheme: https_ ? 'https' : 'http' };
      asset.tls = res.tls;
      const m = matchFeed(asset.banner);
      asset.product = m.product;
      asset.version = m.version;
      asset.findings.push(...m.findings);
    }
    asset.findings.push(...hygieneFindings(host, ips, https_, http_));
    return asset;
  });

  if (skipped) warnings.push(`${skipped} host(s) were skipped because the time budget was exhausted.`);

  const kev = await kevPromise;
  if (kev) {
    sources.push('cisa-kev');
    for (const a of assets) for (const f of a.findings) if (f.cve && kev.has(f.cve)) f.knownExploited = true;
  } else {
    warnings.push('CISA KEV catalog could not be fetched; known-exploited flags are unavailable.');
  }

  warnings.push('Version-based matching only works where servers disclose versions; absence of a finding is not proof of safety. Vendor backports can cause false positives.');
  return { assets, warnings, sources, partial: skipped > 0 };
}

/* -------------------------------------------------------------------------- */
/* Demo sweep (no network activity)                                           */
/* -------------------------------------------------------------------------- */

function demoSweep(domain) {
  const base = [
    { sub: 'mail', ip: '198.51.100.10', role: 'Corporate mail gateway', criticality: 'High', banner: 'Microsoft-IIS/10.0 | Exchange Server 15.1.2375.7' },
    { sub: 'billing-stg', ip: '198.51.100.24', role: 'Billing staging portal', criticality: 'High', banner: 'Apache Tomcat/9.0.85' },
    { sub: 'ussd-gw', ip: '203.0.113.31', role: 'USSD API router', criticality: 'Critical', banner: 'nginx/1.18.0 (Ubuntu)' },
    { sub: 'api', ip: '203.0.113.40', role: 'Customer self-service API', criticality: 'High', banner: 'nginx/1.25.3' },
    { sub: 'core-nr-01', ip: '192.0.2.15', role: 'Core network node (management plane)', criticality: 'Critical', banner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2' },
    { sub: 'sms-gw', ip: '203.0.113.55', role: 'SMS gateway', criticality: 'High', banner: 'Apache Tomcat/10.1.40' },
    { sub: 'oss-legacy', ip: '192.0.2.88', role: 'Legacy OSS portal', criticality: 'Medium', banner: 'Apache/2.4.49 (Unix)' },
    { sub: 'portal', ip: '198.51.100.77', role: 'Partner portal', criticality: 'Medium', banner: 'Apache/2.4.58 (Unix)' },
  ];
  return base.map((a) => {
    const m = matchFeed(a.banner);
    return {
      host: `${a.sub}.${domain}`, ip: a.ip, role: a.role, criticality: a.criticality,
      banner: a.banner, product: m.product, version: m.version, findings: m.findings,
      unreachable: false, http: null, tls: null,
    };
  });
}

/* -------------------------------------------------------------------------- */
/* Crypto envelope                                                            */
/* -------------------------------------------------------------------------- */

function hkdf(secret, salt, label) {
  return Buffer.from(crypto.hkdfSync('sha256', secret, salt, Buffer.from(label, 'utf8'), 32));
}

function buildEnvelope(payload, saltHex, clientPubHex) {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const serverPub = ecdh.getPublicKey('hex');
  const shared = ecdh.computeSecret(Buffer.from(clientPubHex, 'hex'));
  const salt = Buffer.from(saltHex, 'hex');

  const encKey = hkdf(shared, salt, 'asm-enc-v1');
  const macKey = hkdf(shared, salt, 'asm-mac-v1');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  const ivHex = iv.toString('hex');
  const ct = Buffer.concat([enc, tag]).toString('base64'); // WebCrypto expects ciphertext||tag
  const sig = crypto.createHmac('sha256', macKey).update(`v1.${serverPub}.${ivHex}.${ct}`).digest('hex');

  return { v: 1, alg: 'ECDH-P256+HKDF-SHA256+AES-256-GCM', serverPub, iv: ivHex, ct, sig, sigAlg: 'HMAC-SHA256' };
}

/* -------------------------------------------------------------------------- */
/* Rate limiting (best effort, per warm function instance)                    */
/* -------------------------------------------------------------------------- */

const hits = new Map();
function rateLimited(key) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < 10 * 60 * 1000);
  arr.push(now);
  hits.set(key, arr);
  if (hits.size > 500) hits.clear();
  return arr.length > 8;
}

/* -------------------------------------------------------------------------- */
/* Handler                                                                    */
/* -------------------------------------------------------------------------- */

function respond(statusCode, body) {
  return { statusCode, headers: SECURITY_HEADERS, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  const startedMs = Date.now();

  if (event.httpMethod !== 'GET') return respond(405, { error: 'Method not allowed' });

  const q = event.queryStringParameters || {};
  const domain = String(q.domain || '').trim().toLowerCase();
  const salt = String(q.salt || '').trim();
  const pub = String(q.pub || '').trim();
  const mode = q.mode === 'live' ? 'live' : 'demo';

  if (!DOMAIN_RE.test(domain)) return respond(400, { error: 'Invalid target domain' });
  if (BLOCKED_TLDS.has(domain.split('.').pop())) return respond(400, { error: 'This domain suffix is not allowed' });
  if (!SALT_RE.test(salt)) return respond(400, { error: 'Invalid client salt (expect 32-64 hex chars)' });
  if (!PUB_RE.test(pub)) return respond(400, { error: 'Invalid client public key' });

  if (mode === 'live') {
    if (q.ack !== '1') return respond(400, { error: 'Live mode requires confirmation that you own or are authorized to assess this domain' });
    const clientIp = (event.headers && (event.headers['x-nf-client-connection-ip'] || event.headers['x-forwarded-for'])) || 'unknown';
    if (rateLimited(String(clientIp).split(',')[0].trim())) {
      return respond(429, { error: 'Rate limit reached. Try again in a few minutes.' });
    }
  }

  try {
    let assets;
    let warnings = [];
    let sources = [];
    let partial = false;

    if (mode === 'live') {
      const r = await liveSweep(domain, startedMs);
      assets = r.assets; warnings = r.warnings; sources = r.sources; partial = r.partial;
    } else {
      assets = demoSweep(domain);
      warnings = ['Demo mode: assets and IP addresses are simulated. No network activity was performed.'];
      sources = ['simulation'];
    }

    for (const a of assets) a.status = deriveStatus(a);
    const allFindings = assets.flatMap((a) => a.findings);

    const payload = {
      target: domain,
      mode,
      simulated: mode === 'demo',
      generatedAt: new Date().toISOString(),
      sources,
      warnings,
      summary: {
        assetsScanned: assets.length,
        vulnerableAssets: assets.filter((a) => a.status === 'vulnerable').length,
        warningAssets: assets.filter((a) => a.status === 'warning').length,
        cleanAssets: assets.filter((a) => a.status === 'clean').length,
        unreachableAssets: assets.filter((a) => a.status === 'unreachable').length,
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === 'CRITICAL').length,
        knownExploited: allFindings.filter((f) => f.knownExploited).length,
      },
      assets,
    };

    const envelope = buildEnvelope(payload, salt, pub);
    return respond(200, {
      envelope,
      metrics: {
        executionMs: Date.now() - startedMs,
        feedSignatures: VULN_FEED.reduce((n, r) => n + r.vulns.length, 0),
        assetsProcessed: assets.length,
        mode,
        partial,
      },
    });
  } catch (err) {
    return respond(500, { error: 'Sweep failed' });
  }
};
