const express = require('express');
const dns = require('dns').promises;
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Common DKIM selectors to try
const DKIM_SELECTORS = [
  'selector1', 'selector2',  // Microsoft 365
  'google',                   // Google Workspace
  'default', 'dkim', 'mail', 'email',
  'k1', 'k2', 'k3',
  's1', 's2',
  'smtp', 'mimecast', 'proofpoint'
];

// Major RBLs to check
const RBLS = [
  'zen.spamhaus.org',
  'b.barracudacentral.org',
  'bl.spamcop.net',
  'dnsbl.sorbs.net',
  'spam.dnsbl.sorbs.net',
  'http.dnsbl.sorbs.net',
  'dnsbl-1.uceprotect.net',
  'dnsbl-2.uceprotect.net',
  'bl.mailspike.net',
  'ix.dnsbl.manitu.net'
];

// Reverse an IP for RBL lookup
function reverseIP(ip) {
  return ip.split('.').reverse().join('.');
}

// MX Records
async function getMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    records.sort((a, b) => a.priority - b.priority);
    return { success: true, records };
  } catch (err) {
    return { success: false, error: err.code || err.message };
  }
}

// SPF Record
async function getSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const spf = records.map(r => r.join('')).find(r => r.startsWith('v=spf1'));
    if (!spf) return { success: false, error: 'No SPF record found' };

    let policy = 'Unknown';
    if (spf.includes('-all')) policy = 'Fail (hard fail) — unauthorized senders rejected';
    else if (spf.includes('~all')) policy = 'SoftFail — unauthorized senders marked but accepted';
    else if (spf.includes('?all')) policy = 'Neutral — no policy enforced';
    else if (spf.includes('+all')) policy = '⛔ Pass All — dangerous, accepts any sender';

    return { success: true, record: spf, policy };
  } catch (err) {
    return { success: false, error: err.code || err.message };
  }
}

// DMARC Record
async function getDMARC(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarc = records.map(r => r.join('')).find(r => r.startsWith('v=DMARC1'));
    if (!dmarc) return { success: false, error: 'No DMARC record found' };

    const get = (tag) => {
      const match = dmarc.match(new RegExp(`${tag}=([^;]+)`));
      return match ? match[1].trim() : null;
    };

    const policy = get('p');
    const subPolicy = get('sp');
    const pct = get('pct') || '100';
    const rua = get('rua');
    const ruf = get('ruf');
    const adkim = get('adkim') || 'r';
    const aspf = get('aspf') || 'r';

    let policyLabel = '';
    if (policy === 'none') policyLabel = 'None — monitoring only, no enforcement';
    else if (policy === 'quarantine') policyLabel = 'Quarantine — suspicious mail sent to spam';
    else if (policy === 'reject') policyLabel = 'Reject — unauthorized mail blocked outright';

    return {
      success: true, record: dmarc,
      policy, policyLabel, subPolicy,
      pct, rua, ruf,
      adkim: adkim === 'r' ? 'Relaxed' : 'Strict',
      aspf: aspf === 'r' ? 'Relaxed' : 'Strict'
    };
  } catch (err) {
    return { success: false, error: err.code || err.message };
  }
}

// DKIM Selector sweep
async function getDKIM(domain) {
  const found = [];
  const failed = [];

  await Promise.all(DKIM_SELECTORS.map(async (selector) => {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const dkim = records.map(r => r.join('')).find(r => r.includes('v=DKIM1') || r.includes('k='));
      if (dkim) found.push({ selector, record: dkim });
    } catch {
      failed.push(selector);
    }
  }));

  return {
    success: found.length > 0,
    found,
    tried: DKIM_SELECTORS.length,
    notFound: failed
  };
}

// BIMI Record
async function getBIMI(domain) {
  try {
    const records = await dns.resolveTxt(`default._bimi.${domain}`);
    const bimi = records.map(r => r.join('')).find(r => r.startsWith('v=BIMI1'));
    if (!bimi) return { success: false, error: 'No BIMI record found' };

    const lMatch = bimi.match(/l=([^;]+)/);
    const aMatch = bimi.match(/a=([^;]+)/);

    return {
      success: true,
      record: bimi,
      logoURL: lMatch ? lMatch[1].trim() : null,
      authorityURL: aMatch ? aMatch[1].trim() : null
    };
  } catch (err) {
    return { success: false, error: err.code || err.message };
  }
}

// RBL Blacklist check for an IP
async function checkRBLs(ip) {
  const reversed = reverseIP(ip);
  const results = await Promise.all(RBLS.map(async (rbl) => {
    try {
      await dns.resolve4(`${reversed}.${rbl}`);
      return { rbl, listed: true };
    } catch {
      return { rbl, listed: false };
    }
  }));
  return results;
}

// MTA-STS DNS record + policy file
async function getMTASTS(domain) {
  // Check DNS record
  let dnsRecord = null;
  let id = null;
  try {
    const records = await dns.resolveTxt(`_mta-sts.${domain}`);
    dnsRecord = records.map(r => r.join('')).find(r => r.startsWith('v=STSv1'));
    if (dnsRecord) {
      const idMatch = dnsRecord.match(/id=([^;]+)/);
      id = idMatch ? idMatch[1].trim() : null;
    }
  } catch { /* no record */ }

  if (!dnsRecord) return { success: false, error: 'No MTA-STS DNS record found' };

  // Fetch policy file
  const policy = await new Promise((resolve) => {
    const req = https.get(
      `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
      { timeout: 5000 },
      (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ success: true, raw: body }));
      }
    );
    req.on('error', () => resolve({ success: false }));
    req.on('timeout', () => { req.destroy(); resolve({ success: false }); });
  });

  let mode = null, maxAge = null, mx = [];
  if (policy.success && policy.raw) {
    const lines = policy.raw.split('\n').map(l => l.trim());
    mode = lines.find(l => l.startsWith('mode:'))?.replace('mode:', '').trim();
    maxAge = lines.find(l => l.startsWith('max_age:'))?.replace('max_age:', '').trim();
    mx = lines.filter(l => l.startsWith('mx:')).map(l => l.replace('mx:', '').trim());
  }

  return {
    success: true,
    dnsRecord, id,
    policyFetched: policy.success,
    mode, maxAge, mx
  };
}

// TLS-RPT record
async function getTLSRPT(domain) {
  try {
    const records = await dns.resolveTxt(`_smtp._tls.${domain}`);
    const rpt = records.map(r => r.join('')).find(r => r.startsWith('v=TLSRPTv1'));
    if (!rpt) return { success: false, error: 'No TLS-RPT record found' };
    const ruaMatch = rpt.match(/rua=([^;]+)/);
    return { success: true, record: rpt, rua: ruaMatch ? ruaMatch[1].trim() : null };
  } catch (err) {
    return { success: false, error: err.code || err.message };
  }
}

// Main route
app.post('/inspect', async (req, res) => {
  let { target } = req.body;
  if (!target) return res.status(400).json({ error: 'No target provided' });

  target = target.trim().toLowerCase();
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);

  let domain = target;
  let ip = isIP ? target : null;

  // If domain, resolve first MX to get an IP for RBL/TLS checks
  let mxResult = null;
  let mxHost = null;

  if (!isIP) {
    mxResult = await getMX(domain);
    if (mxResult.success && mxResult.records.length > 0) {
      mxHost = mxResult.records[0].exchange;
      try {
        const resolved = await dns.resolve4(mxHost);
        ip = resolved[0];
      } catch { /* no ip */ }
    }
  } else {
    // If IP given, try reverse DNS for TLS check host
    try {
      const reversed = await dns.reverse(ip);
      mxHost = reversed[0];
      domain = null;
    } catch {
      mxHost = ip;
    }
  }

  const results = {};

  if (!isIP) {
    const [spf, dmarc, dkim, bimi] = await Promise.all([
      getSPF(domain),
      getDMARC(domain),
      getDKIM(domain),
      getBIMI(domain)
    ]);
    results.mx = mxResult;
    results.spf = spf;
    results.dmarc = dmarc;
    results.dkim = dkim;
    results.bimi = bimi;
  }

  if (ip) {
    results.rbl = await checkRBLs(ip);
    results.resolvedIP = ip;
  }

  if (!isIP) {
    const [mtasts, tlsrpt] = await Promise.all([
      getMTASTS(domain),
      getTLSRPT(domain)
    ]);
    results.mtasts = mtasts;
    results.tlsrpt = tlsrpt;
  }

  res.json({ target, isIP, domain, ip, results });
});

app.listen(3000, () => console.log('Email Inspector running at http://localhost:3000'));