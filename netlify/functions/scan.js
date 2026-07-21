const dns = require('dns').promises;
const https = require('https');
const { scanStatsStore } = require('./blobs-store');

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;
  return false;
}

function sanitizeDomain(input) {
  if (!input) return null;
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0];
  d = d.split(':')[0];
  d = d.replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) return null;
  return d;
}

async function checkSPF(domain) {
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map((r) => r.join(''));
    const spf = flat.find((r) => r.toLowerCase().startsWith('v=spf1'));
    return { pass: !!spf, detail: spf ? 'SPF record found' : "No SPF record found — email can be spoofed more easily" };
  } catch (e) {
    return { pass: false, detail: "No SPF record found — email can be spoofed more easily" };
  }
}

async function checkDMARC(domain) {
  try {
    const records = await dns.resolveTxt('_dmarc.' + domain);
    const flat = records.map((r) => r.join(''));
    const dmarc = flat.find((r) => r.toLowerCase().startsWith('v=dmarc1'));
    if (!dmarc) return { pass: false, enforced: false, detail: "No DMARC record found — spoofed email from your domain won't be blocked" };
    const policyMatch = dmarc.match(/p=(\w+)/i);
    const policy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
    const enforced = policy === 'quarantine' || policy === 'reject';
    return { pass: true, enforced, detail: `DMARC record found (policy: ${policy})` };
  } catch (e) {
    return { pass: false, enforced: false, detail: "No DMARC record found — spoofed email from your domain won't be blocked" };
  }
}

function fetchHeaders(domain) {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: domain,
        path: '/',
        method: 'GET',
        timeout: 7000,
        rejectUnauthorized: false,
        headers: { 'User-Agent': 'MeridianSecurityScan/1.0 (+https://meridian-cyber-advisory.netlify.app)' },
      },
      (res) => {
        let cert = null;
        try {
          cert = res.socket.getPeerCertificate();
        } catch (e) {}
        resolve({ ok: true, headers: res.headers, statusCode: res.statusCode, cert });
        res.resume();
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'timeout' });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.end();
  });
}

function gradeFromScore(score) {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 50) return 'C';
  if (score >= 30) return 'D';
  return 'F';
}

async function scan(rawDomain) {
  const domain = sanitizeDomain(rawDomain);
  if (!domain) return { error: 'Please enter a valid domain, e.g. example.com' };

  let ips = [];
  try {
    ips = await dns.resolve4(domain);
  } catch (e) {
    return { error: `Could not resolve ${domain}. Check the domain and try again.` };
  }
  if (ips.some(isPrivateIP)) {
    return { error: 'Cannot scan private or internal addresses.' };
  }

  const [spf, dmarc, httpResult] = await Promise.all([checkSPF(domain), checkDMARC(domain), fetchHeaders(domain)]);

  const headers = httpResult.ok ? httpResult.headers : {};
  const hsts = !!headers['strict-transport-security'];
  const csp = !!headers['content-security-policy'];
  const xfo = !!headers['x-frame-options'] || (csp && /frame-ancestors/i.test(headers['content-security-policy'] || ''));
  const xcto = (headers['x-content-type-options'] || '').toLowerCase().includes('nosniff');
  const refPolicy = !!headers['referrer-policy'];
  const permPolicy = !!headers['permissions-policy'];

  let certValid = false;
  let certDetail = 'Could not verify certificate';
  if (httpResult.ok && httpResult.cert && httpResult.cert.valid_to) {
    const validTo = new Date(httpResult.cert.valid_to);
    const daysLeft = Math.round((validTo - new Date()) / 86400000);
    certValid = daysLeft > 0;
    certDetail = certValid ? `Certificate valid, expires in ${daysLeft} days` : 'Certificate expired';
  }

  const categories = [
    {
      name: 'Email Security',
      max: 30,
      score: (spf.pass ? 15 : 0) + (dmarc.pass ? 10 : 0) + (dmarc.enforced ? 5 : 0),
      checks: [
        { label: 'SPF record', pass: spf.pass, detail: spf.detail },
        { label: 'DMARC record', pass: dmarc.pass, detail: dmarc.detail },
        { label: 'DMARC enforcement', pass: !!dmarc.enforced, detail: dmarc.enforced ? 'Policy actively blocks/quarantines spoofed mail' : 'Policy is not set to quarantine/reject' },
      ],
    },
    {
      name: 'Transport Security',
      max: 35,
      score: (httpResult.ok ? 15 : 0) + (hsts ? 10 : 0) + (certValid ? 10 : 0),
      checks: [
        { label: 'HTTPS reachable', pass: httpResult.ok, detail: httpResult.ok ? `Site responded (HTTP ${httpResult.statusCode})` : 'Site did not respond over HTTPS' },
        { label: 'HSTS enabled', pass: hsts, detail: hsts ? 'Strict-Transport-Security header present' : 'No Strict-Transport-Security header' },
        { label: 'Valid TLS certificate', pass: certValid, detail: certDetail },
      ],
    },
    {
      name: 'Security Headers',
      max: 35,
      score: (csp ? 10 : 0) + (xfo ? 7 : 0) + (xcto ? 6 : 0) + (refPolicy ? 6 : 0) + (permPolicy ? 6 : 0),
      checks: [
        { label: 'Content-Security-Policy', pass: csp, detail: csp ? 'CSP header present' : "No CSP header — increases XSS risk" },
        { label: 'Clickjacking protection', pass: xfo, detail: xfo ? 'X-Frame-Options or frame-ancestors set' : 'Page can be embedded in a hidden iframe' },
        { label: 'X-Content-Type-Options', pass: xcto, detail: xcto ? 'nosniff set' : 'Browsers may MIME-sniff responses' },
        { label: 'Referrer-Policy', pass: refPolicy, detail: refPolicy ? 'Referrer-Policy header present' : 'No Referrer-Policy header' },
        { label: 'Permissions-Policy', pass: permPolicy, detail: permPolicy ? 'Permissions-Policy header present' : 'No Permissions-Policy header' },
      ],
    },
  ];

  const score = categories.reduce((s, c) => s + c.score, 0);
  const maxScore = categories.reduce((s, c) => s + c.max, 0);
  const grade = gradeFromScore(score);

  return { domain, score, maxScore, grade, categories };
}

// Records only aggregate, anonymized counts — never the scanned domain itself —
// so this builds a statistical picture of small-company security posture over
// time without storing who looked anyone up.
async function logAggregateStats(result) {
  try {
    const store = scanStatsStore();
    const current = (await store.get('aggregate', { type: 'json' })) || {
      totalScans: 0,
      gradeCounts: { A: 0, B: 0, C: 0, D: 0, F: 0 },
      checks: {},
      firstRecorded: new Date().toISOString(),
    };
    current.totalScans += 1;
    current.gradeCounts[result.grade] = (current.gradeCounts[result.grade] || 0) + 1;
    result.categories.forEach((cat) => {
      cat.checks.forEach((chk) => {
        const key = cat.name + ' — ' + chk.label;
        if (!current.checks[key]) current.checks[key] = { pass: 0, fail: 0 };
        if (chk.pass) current.checks[key].pass += 1;
        else current.checks[key].fail += 1;
      });
    });
    current.lastUpdated = new Date().toISOString();
    await store.setJSON('aggregate', current);
  } catch (e) {
    // Stats logging must never break the scan itself.
  }
}

exports.handler = async (event) => {
  const domain = event.queryStringParameters && event.queryStringParameters.domain;
  try {
    const result = await scan(domain);
    if (!result.error) {
      await logAggregateStats(result);
    }
    return {
      statusCode: result.error ? 400 : 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify(result),
    };
  } catch (e) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: 'Something went wrong running the scan. Please try again.' }),
    };
  }
};
