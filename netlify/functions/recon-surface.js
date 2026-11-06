'use strict';

/**
 * recon-surface.js — Simulated Attack Surface Management sweep.
 *
 * IMPORTANT: This function performs NO real network scanning. All assets are a
 * simulated telecom deployment generated from the supplied domain label, and the
 * vulnerability feed is an illustrative mock. Verify any CVE data against vendor
 * advisories before relying on it.
 *
 * Transport protection (defence in depth on top of TLS):
 *   1. Client sends: domain, salt (random hex), pub (ephemeral ECDH P-256 public key, hex).
 *   2. Server creates its own ephemeral ECDH key pair, derives a shared secret.
 *   3. HKDF-SHA256(shared, salt = client salt, info = label) -> separate AES and HMAC keys.
 *   4. Payload is encrypted with AES-256-GCM, then HMAC-SHA256 signed (encrypt-then-MAC).
 *   5. Client verifies the HMAC first, and only then decrypts.
 */

const crypto = require('crypto');

const SECURITY_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
const SALT_RE = /^[0-9a-f]{32,64}$/i;
const PUB_RE = /^04[0-9a-f]{128}$/i;

/* -------------------------------------------------------------------------- */
/* Simulated vulnerability intelligence feed                                  */
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
            'Block HTTP PUT/DELETE/PATCH at the WAF/load balancer for staging and billing paths.',
            'Restrict the staging portal to the corporate VPN / allowlisted ranges.',
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
            'Rate-limit and authenticate USSD API clients (mTLS or signed requests).',
            'Expose only the required ports from the DMZ to the USSD router.',
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
          'A race condition in sshd signal handling may allow unauthenticated remote code execution as root on glibc-based Linux systems.',
        ranges: [{ introduced: '8.5', fixed: '9.8' }],
        remediation: {
          priority: 'P2 - remediate within 7 days (core network node)',
          patch: 'Upgrade to OpenSSH 9.8p1+ or install the distribution security backport, then restart sshd.',
          hardening: [
            'Set LoginGraceTime 0 as a temporary mitigation (note: this exposes MaxStartups exhaustion).',
            'Disable password authentication; use hardware-backed keys or SSH certificates.',
            'Set MaxStartups conservatively and enable fail2ban-style rate limiting.',
          ],
          accessControl: [
            'Allow SSH to core network nodes only from the management/bastion VLAN.',
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
            'Place the legacy OSS portal behind the corporate VPN.',
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
/* Simulated telecom assets (documentation-range IPs, RFC 5737)               */
/* -------------------------------------------------------------------------- */

function buildAssets(domain) {
  return [
    { sub: 'mail', ip: '198.51.100.10', role: 'Corporate mail gateway', criticality: 'High', banner: 'Microsoft-IIS/10.0 | X-OWA-Version: Exchange Server 2016 15.1.2375.7' },
    { sub: 'billing-stg', ip: '198.51.100.24', role: 'Billing staging portal', criticality: 'High', banner: 'Apache Tomcat/9.0.85' },
    { sub: 'ussd-gw', ip: '203.0.113.31', role: 'USSD API router', criticality: 'Critical', banner: 'nginx/1.18.0 (Ubuntu)' },
    { sub: 'api', ip: '203.0.113.40', role: 'Customer self-service API', criticality: 'High', banner: 'nginx/1.25.3' },
    { sub: 'core-nr-01', ip: '192.0.2.15', role: 'Core network node (management plane)', criticality: 'Critical', banner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2' },
    { sub: 'sms-gw', ip: '203.0.113.55', role: 'SMS gateway', criticality: 'High', banner: 'Apache Tomcat/10.1.40' },
    { sub: 'oss-legacy', ip: '192.0.2.88', role: 'Legacy OSS portal', criticality: 'Medium', banner: 'Apache/2.4.49 (Unix)' },
    { sub: 'portal', ip: '198.51.100.77', role: 'Partner portal', criticality: 'Medium', banner: 'Apache/2.4.58 (Unix)' },
  ].map((a) => ({ host: `${a.sub}.${domain}`, ip: a.ip, role: a.role, criticality: a.criticality, banner: a.banner }));
}

/* -------------------------------------------------------------------------- */
/* Version comparison                                                         */
/* -------------------------------------------------------------------------- */

function parseVersion(v) {
  return String(v)
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map((n) => parseInt(n, 10));
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

function isAffected(version, ranges) {
  return ranges.some((r) => compareVersions(version, r.introduced) >= 0 && compareVersions(version, r.fixed) < 0);
}

function analyseAsset(asset) {
  const result = { ...asset, product: 'Unidentified', version: null, status: 'clean', findings: [] };
  for (const rule of VULN_FEED) {
    const m = asset.banner.match(rule.banner);
    if (!m) continue;
    result.product = rule.product;
    result.version = m[1];
    for (const v of rule.vulns) {
      if (isAffected(m[1], v.ranges)) {
        const branch = v.ranges.find((r) => compareVersions(m[1], r.introduced) >= 0 && compareVersions(m[1], r.fixed) < 0);
        result.findings.push({
          cve: v.cve,
          severity: v.severity,
          cvss: v.cvss,
          title: v.title,
          description: v.description,
          installed: m[1],
          fixedIn: branch.fixed,
          remediation: v.remediation,
        });
      }
    }
    break;
  }
  if (result.findings.length) result.status = 'vulnerable';
  return result;
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
  const signedMessage = `v1.${serverPub}.${ivHex}.${ct}`;
  const sig = crypto.createHmac('sha256', macKey).update(signedMessage).digest('hex');

  return { v: 1, alg: 'ECDH-P256+HKDF-SHA256+AES-256-GCM', serverPub, iv: ivHex, ct, sig, sigAlg: 'HMAC-SHA256' };
}

/* -------------------------------------------------------------------------- */
/* Handler                                                                    */
/* -------------------------------------------------------------------------- */

function respond(statusCode, body) {
  return { statusCode, headers: SECURITY_HEADERS, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  const started = process.hrtime.bigint();

  if (event.httpMethod !== 'GET') {
    return respond(405, { error: 'Method not allowed' });
  }

  const q = event.queryStringParameters || {};
  const domain = String(q.domain || '').trim().toLowerCase();
  const salt = String(q.salt || '').trim();
  const pub = String(q.pub || '').trim();

  if (!DOMAIN_RE.test(domain)) return respond(400, { error: 'Invalid target domain' });
  if (!SALT_RE.test(salt)) return respond(400, { error: 'Invalid client salt (expect 32-64 hex chars)' });
  if (!PUB_RE.test(pub)) return respond(400, { error: 'Invalid client public key' });

  try {
    const analysed = buildAssets(domain).map(analyseAsset);
    const vulnerable = analysed.filter((a) => a.status === 'vulnerable');
    const findingCount = vulnerable.reduce((n, a) => n + a.findings.length, 0);

    const payload = {
      target: domain,
      generatedAt: new Date().toISOString(),
      simulated: true,
      summary: {
        assetsScanned: analysed.length,
        vulnerableAssets: vulnerable.length,
        cleanAssets: analysed.length - vulnerable.length,
        totalFindings: findingCount,
        critical: vulnerable.flatMap((a) => a.findings).filter((f) => f.severity === 'CRITICAL').length,
      },
      assets: analysed,
    };

    const envelope = buildEnvelope(payload, salt, pub);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    return respond(200, {
      envelope,
      metrics: {
        executionMs: Math.round(elapsedMs * 100) / 100,
        feedSignatures: VULN_FEED.reduce((n, r) => n + r.vulns.length, 0),
        assetsProcessed: analysed.length,
      },
    });
  } catch (err) {
    return respond(500, { error: 'Sweep failed' });
  }
};
