require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const dns = require('dns').promises;
const tls = require('tls');
const { simpleParser } = require('mailparser');

const app = express();

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname); // keep .png/.jpg/etc
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + ext);
  }
});
const upload = multer({ storage });

app.use(cors());
app.use(express.json());

// --- Input validation helpers ---
// Usernames: letters, numbers, dots, underscores, hyphens only (covers virtually every real platform's rules)
const USERNAME_REGEX = /^[a-zA-Z0-9._-]{1,64}$/;
// Domains: labels of letters/numbers/hyphens separated by dots
const DOMAIN_REGEX = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
// Reuses the same IPv4 pattern already used later in the file for Shodan/AbuseIPDB
const IPV4_VALIDATE_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isValidUsername(v) { return USERNAME_REGEX.test(v); }
function isValidDomain(v) { return DOMAIN_REGEX.test(v); }
function isValidIPv4(v) {
  return IPV4_VALIDATE_REGEX.test(v) && v.split('.').every(n => Number(n) >= 0 && Number(n) <= 255);
}

// Username Search
app.get('/api/username/:username', (req, res) => {
  const username = req.params.username;

  if (!isValidUsername(username)) {
    return res.json({ error: 'Invalid username format. Use only letters, numbers, dots, underscores, or hyphens.' });
  }

  // execFile passes the argument directly to python — no shell involved, so
  // there is no way for input like "; rm -rf /" to be interpreted as a command.
  execFile('python', ['../python-tools/username_search.py', username], (err, stdout) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// IP Lookup
app.get('/api/ip/:ip', async (req, res) => {
  const ip = req.params.ip;

  if (!isValidIPv4(ip)) {
    return res.json({ error: `"${ip}" doesn't look like a valid IPv4 address.` });
  }

  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    res.json(response.data);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// Domain Lookup
app.get('/api/domain/:domain', (req, res) => {
  const domain = req.params.domain;

  if (!isValidDomain(domain)) {
    return res.json({ error: `"${domain}" doesn't look like a valid domain name.` });
  }

  execFile('python', ['../python-tools/domain_lookup.py', domain], (err, stdout) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// Port Scanner
app.get('/api/scanner/:ip', (req, res) => {
  const ip = req.params.ip;

  if (!isValidIPv4(ip) && !isValidDomain(ip)) {
    return res.json({ error: `"${ip}" doesn't look like a valid IP address or domain.` });
  }

  execFile('python', ['../python-tools/port_scanner.py', ip], (err, stdout) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// Image Metadata Extractor
app.post('/api/metadata', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.json({ error: 'No image uploaded.' });
  }
  const filePath = req.file.path;

  execFile('python', ['../python-tools/metadata_tool.py', filePath], (err, stdout) => {
    if (err) {
      return res.json({ error: err.message });
    }
    res.json({ result: stdout });
  });
});

// DNS Records Lookup
app.get('/api/dns/:domain', async (req, res) => {
  const domain = req.params.domain;
  const recordTypes = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA'];
  const results = {};

  await Promise.all(recordTypes.map(async (type) => {
    try {
      const records = await dns.resolve(domain, type);
      results[type] = Array.isArray(records)
        ? records.map(r => (typeof r === 'object' ? JSON.stringify(r) : r)).join(', ')
        : String(records);
    } catch (err) {
      // ENODATA / ENOTFOUND just means that record type doesn't exist — skip it silently
      if (err.code !== 'ENODATA' && err.code !== 'ENOTFOUND') {
        results[type] = `Error: ${err.code || err.message}`;
      }
    }
  }));

  if (Object.keys(results).length === 0) {
    return res.json({ error: `No DNS records found for ${domain}` });
  }

  res.json(results);
});

// SSL/TLS Certificate Inspector
app.get('/api/ssl/:domain', (req, res) => {
  const domain = req.params.domain;

  const socket = tls.connect(
    { host: domain, port: 443, servername: domain, timeout: 6000 },
    () => {
      const cert = socket.getPeerCertificate();
      socket.end();

      if (!cert || Object.keys(cert).length === 0) {
        return res.json({ error: `No certificate found for ${domain}` });
      }

      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

      res.json({
        'Subject (CN)': cert.subject && cert.subject.CN || 'N/A',
        'Issuer': cert.issuer && cert.issuer.O ? `${cert.issuer.O} (${cert.issuer.CN || ''})` : (cert.issuer && cert.issuer.CN) || 'N/A',
        'Valid From': cert.valid_from,
        'Valid To': cert.valid_to,
        'Days Remaining': daysRemaining,
        'Serial Number': cert.serialNumber,
        'Fingerprint (SHA256)': cert.fingerprint256 || cert.fingerprint,
        'Subject Alt Names': cert.subjectaltname || 'N/A',
        'Protocol': socket.getProtocol ? socket.getProtocol() : 'N/A'
      });
    }
  );

  socket.on('error', (err) => {
    res.json({ error: `Could not connect: ${err.message}` });
  });

  socket.on('timeout', () => {
    socket.destroy();
    res.json({ error: 'Connection timed out' });
  });
});

// Subdomain Enumeration (crt.sh certificate transparency logs)
app.get('/api/subdomains/:domain', async (req, res) => {
  const domain = req.params.domain;

  try {
    const response = await axios.get(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      timeout: 15000
    });

    if (!Array.isArray(response.data) || response.data.length === 0) {
      return res.json({ error: `No certificate records found for ${domain}` });
    }

    const subdomains = new Set();
    response.data.forEach(entry => {
      if (entry.name_value) {
        entry.name_value.split('\n').forEach(name => {
          const clean = name.trim().toLowerCase();
          if (clean && !clean.startsWith('*.')) {
            subdomains.add(clean);
          }
        });
      }
    });

    const sorted = Array.from(subdomains).sort();
    res.json({ result: sorted.join('\n') });

  } catch (error) {
    res.json({ error: `crt.sh lookup failed: ${error.message}` });
  }
});

// Wayback Machine History Checker
app.get('/api/wayback/:domain', async (req, res) => {
  const domain = req.params.domain;
  const headers = { 'User-Agent': 'Mozilla/5.0 (compatible; CyberDashboard/1.0; +https://github.com)' };

  // The full CDX search is powerful but frequently overloaded/rate-limited by archive.org.
  // Retry a couple times before falling back to the lighter "availability" endpoint.
  const tryCDX = async (attempt = 1) => {
    try {
      const response = await axios.get('https://web.archive.org/cdx/search/cdx', {
        params: {
          url: domain,
          output: 'json',
          collapse: 'timestamp:8',
          fl: 'timestamp,original',
          limit: 5000
        },
        timeout: 10000,
        headers
      });

      const rows = response.data;
      if (!Array.isArray(rows) || rows.length <= 1) {
        return res.json({ error: `No archived snapshots found for ${domain}` });
      }

      const dataRows = rows.slice(1);
      const timestamps = dataRows.map(r => r[0]).sort();
      const first = timestamps[0];
      const last = timestamps[timestamps.length - 1];
      const formatTs = (ts) => `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;

      res.json({
        'Domain': domain,
        'Total Snapshots': dataRows.length,
        'First Archived': formatTs(first),
        'Last Archived': formatTs(last),
        'Earliest Snapshot URL': `https://web.archive.org/web/${first}/${domain}`,
        'Latest Snapshot URL': `https://web.archive.org/web/${last}/${domain}`
      });

    } catch (error) {
      const status = error.response ? error.response.status : null;

      // 503/502/429 usually mean "try again shortly" on archive.org's side
      if ((status === 503 || status === 502 || status === 429) && attempt < 2) {
        await new Promise(r => setTimeout(r, 1500));
        return tryCDX(attempt + 1);
      }

      // Fall back to the lightweight availability API (single latest snapshot, much less load)
      try {
        const fallback = await axios.get('https://archive.org/wayback/available', {
          params: { url: domain },
          timeout: 10000,
          headers
        });

        const snap = fallback.data && fallback.data.archived_snapshots && fallback.data.archived_snapshots.closest;
        if (snap) {
          return res.json({
            'Domain': domain,
            'Note': 'Full history search was unavailable — showing closest known snapshot only',
            'Snapshot Date': snap.timestamp,
            'Snapshot URL': snap.url
          });
        }
        return res.json({ error: `Wayback Machine is currently unavailable (HTTP ${status || 'no response'}). Try again in a moment.` });

      } catch (fallbackError) {
        return res.json({ error: `Wayback Machine is currently unavailable (HTTP ${status || 'no response'}). Try again in a moment.` });
      }
    }
  };

  tryCDX();
});

// Website Tech Stack Fingerprinter
app.get('/api/techstack/:domain', async (req, res) => {
  let domain = req.params.domain;
  if (!/^https?:\/\//i.test(domain)) {
    domain = `https://${domain}`;
  }

  try {
    const response = await axios.get(domain, {
      timeout: 10000,
      maxRedirects: 5,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberDashboard/1.0)' },
      validateStatus: () => true
    });

    const headers = response.headers || {};
    const html = typeof response.data === 'string' ? response.data : '';
    const findings = [];

    // --- Server / infrastructure from headers ---
    if (headers['server']) findings.push(['Server', headers['server']]);
    if (headers['x-powered-by']) findings.push(['Powered By', headers['x-powered-by']]);
    if (headers['x-aspnet-version']) findings.push(['ASP.NET Version', headers['x-aspnet-version']]);

    // --- CDN / hosting detection ---
    const cdnChecks = [
      ['cf-ray', 'Cloudflare'],
      ['x-served-by', 'Fastly'],
      ['x-amz-cf-id', 'Amazon CloudFront'],
      ['x-vercel-id', 'Vercel'],
      ['x-github-request-id', 'GitHub Pages'],
      ['x-nf-request-id', 'Netlify']
    ];
    cdnChecks.forEach(([header, name]) => {
      if (headers[header]) findings.push(['CDN / Host', name]);
    });

    // --- CMS detection via HTML patterns ---
    const cmsChecks = [
      [/wp-content|wp-includes|\/wp-json\//i, 'WordPress'],
      [/\/media\/system\/js\/|joomla/i, 'Joomla'],
      [/\/sites\/default\/files\/|drupal\.js/i, 'Drupal'],
      [/cdn\.shopify\.com|shopify/i, 'Shopify'],
      [/wix\.com|wixstatic/i, 'Wix'],
      [/squarespace/i, 'Squarespace'],
      [/ghost\.org|\/ghost\//i, 'Ghost']
    ];
    cmsChecks.forEach(([pattern, name]) => {
      if (pattern.test(html)) findings.push(['CMS', name]);
    });

    // --- JS framework detection ---
    const jsChecks = [
      [/data-reactroot|react-dom|_next\/static/i, 'React / Next.js'],
      [/ng-version|angular\.js|__ng/i, 'Angular'],
      [/vue\.js|__vue__|data-v-/i, 'Vue.js'],
      [/svelte/i, 'Svelte'],
      [/jquery(?:-|\.)/i, 'jQuery']
    ];
    jsChecks.forEach(([pattern, name]) => {
      if (pattern.test(html)) findings.push(['JS Framework', name]);
    });

    // --- Analytics / tracking detection ---
    const analyticsChecks = [
      [/googletagmanager\.com|gtag\(/i, 'Google Tag Manager / Analytics'],
      [/google-analytics\.com|ga\('/i, 'Google Analytics'],
      [/hotjar\.com/i, 'Hotjar'],
      [/cdn\.segment\.com/i, 'Segment'],
      [/facebook\.net\/.*\/fbevents\.js/i, 'Meta Pixel'],
      [/clarity\.ms/i, 'Microsoft Clarity']
    ];
    analyticsChecks.forEach(([pattern, name]) => {
      if (pattern.test(html)) findings.push(['Analytics', name]);
    });

    // --- Security headers (bonus, useful for OSINT/hardening context) ---
    if (headers['strict-transport-security']) findings.push(['Security Header', 'HSTS enabled']);
    if (headers['content-security-policy']) findings.push(['Security Header', 'CSP present']);
    if (!headers['x-frame-options'] && !headers['content-security-policy']) {
      findings.push(['Security Note', 'No X-Frame-Options or CSP — possible clickjacking exposure']);
    }

    if (findings.length === 0) {
      return res.json({ error: 'No recognizable technologies detected (site may use custom/obfuscated stack).' });
    }

    const result = {};
    findings.forEach(([key, value], i) => {
      // Allow duplicate keys (e.g multiple CDN matches) by suffixing
      const finalKey = result.hasOwnProperty(key) ? `${key} ${i}` : key;
      result[finalKey] = value;
    });

    res.json(result);

  } catch (error) {
    res.json({ error: `Could not fetch ${domain}: ${error.message}` });
  }
});

// Shodan Device Lookup
const IPV4_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

app.get('/api/shodan/:ip', async (req, res) => {
  const ip = req.params.ip;
  const apiKey = process.env.SHODAN_API_KEY;

  if (!apiKey) {
    return res.json({ error: 'Shodan API key not configured. Add SHODAN_API_KEY to backend/.env (see .env.example) and restart the server.' });
  }

  const octetsOk = IPV4_REGEX.test(ip) && ip.split('.').every(n => Number(n) >= 0 && Number(n) <= 255);
  if (!octetsOk) {
    return res.json({ error: `"${ip}" doesn't look like a valid IPv4 address.` });
  }

  try {
    const response = await axios.get(`https://api.shodan.io/shodan/host/${ip}`, {
      params: { key: apiKey },
      timeout: 10000
    });

    const data = response.data;
    const result = {
      'IP': data.ip_str,
      'Organization': data.org || 'N/A',
      'ISP': data.isp || 'N/A',
      'Country': data.country_name || 'N/A',
      'City': data.city || 'N/A',
      'Operating System': data.os || 'N/A',
      'Open Ports': (data.ports || []).join(', ') || 'None found',
      'Hostnames': (data.hostnames || []).join(', ') || 'None',
      'Last Update': data.last_update || 'N/A'
    };

    // Vulnerabilities, if Shodan has flagged any CVEs for this host
    if (data.vulns && Object.keys(data.vulns).length > 0) {
      result['Known Vulnerabilities'] = Object.keys(data.vulns).join(', ');
    }

    // Service banners per port (brief, first line only per service to keep it readable)
    if (Array.isArray(data.data)) {
      data.data.slice(0, 5).forEach(service => {
        const banner = (service.data || '').split('\n')[0].slice(0, 120);
        result[`Port ${service.port} (${service.transport || 'tcp'})`] = banner || (service.product || 'Service detected, no banner');
      });
    }

    res.json(result);

  } catch (error) {
    if (error.response && error.response.status === 404) {
      return res.json({ error: `No Shodan data found for ${ip} (not indexed or not scanned).` });
    }
    if (error.response && error.response.status === 401) {
      return res.json({ error: 'Invalid Shodan API key.' });
    }
    if (error.response && error.response.status === 429) {
      return res.json({ error: 'Shodan rate limit hit — free-tier keys allow limited requests per second/month. Wait and try again.' });
    }
    if (error.code === 'ECONNABORTED') {
      return res.json({ error: 'Shodan lookup timed out after 10s. Try again.' });
    }
    res.json({ error: `Shodan lookup failed: ${error.message}` });
  }
});

// VirusTotal Reputation Lookup — accepts a domain, IP, URL, or file hash and auto-detects which
const HASH_REGEX = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

function classifyIndicator(target) {
  if (IPV4_REGEX.test(target)) return 'ip';
  if (HASH_REGEX.test(target)) return 'hash';
  if (/^https?:\/\//i.test(target)) return 'url';
  return 'domain';
}

app.get('/api/virustotal/:target', async (req, res) => {
  const target = req.params.target;
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return res.json({ error: 'VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to backend/.env (see .env.example) and restart the server.' });
  }

  const kind = classifyIndicator(target);
  let url;

  if (kind === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${target}`;
  } else if (kind === 'hash') {
    url = `https://www.virustotal.com/api/v3/files/${target}`;
  } else if (kind === 'url') {
    // VT v3 identifies URLs by the unpadded base64url encoding of the URL string
    const id = Buffer.from(target).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    url = `https://www.virustotal.com/api/v3/urls/${id}`;
  } else {
    url = `https://www.virustotal.com/api/v3/domains/${target}`;
  }

  try {
    const response = await axios.get(url, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    const attrs = response.data.data.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const result = {
      'Indicator Type': kind.toUpperCase(),
      'Malicious': stats.malicious ?? 'N/A',
      'Suspicious': stats.suspicious ?? 'N/A',
      'Harmless': stats.harmless ?? 'N/A',
      'Undetected': stats.undetected ?? 'N/A',
      'Reputation Score': attrs.reputation ?? 'N/A'
    };

    if (kind === 'domain') {
      result['Registrar'] = attrs.registrar || 'N/A';
      result['Creation Date'] = attrs.creation_date ? new Date(attrs.creation_date * 1000).toISOString().slice(0, 10) : 'N/A';
      if (attrs.categories) result['Categories'] = Object.values(attrs.categories).join(', ');
    } else if (kind === 'ip') {
      result['Country'] = attrs.country || 'N/A';
      result['AS Owner'] = attrs.as_owner || 'N/A';
      result['ASN'] = attrs.asn || 'N/A';
    } else if (kind === 'url') {
      result['Final URL'] = attrs.last_final_url || target;
      if (attrs.categories) result['Categories'] = Object.values(attrs.categories).join(', ');
    } else if (kind === 'hash') {
      result['File Type'] = attrs.type_description || 'N/A';
      result['File Size'] = attrs.size ? `${attrs.size} bytes` : 'N/A';
      if (attrs.meaningful_name) result['File Name'] = attrs.meaningful_name;
      if (attrs.md5) result['MD5'] = attrs.md5;
      if (attrs.sha1) result['SHA1'] = attrs.sha1;
      if (attrs.sha256) result['SHA256'] = attrs.sha256;
    }

    // Surface a few engines that flagged it, if any did
    if (attrs.last_analysis_results && stats.malicious > 0) {
      const flagged = Object.entries(attrs.last_analysis_results)
        .filter(([, v]) => v.category === 'malicious')
        .slice(0, 5)
        .map(([engine, v]) => `${engine}: ${v.result}`);
      if (flagged.length) result['Flagged By'] = flagged.join(' | ');
    }

    res.json(result);

  } catch (error) {
    if (error.response && error.response.status === 404) {
      return res.json({ error: `No VirusTotal data found for "${target}" (not previously scanned or indexed).` });
    }
    if (error.response && error.response.status === 401) {
      return res.json({ error: 'Invalid VirusTotal API key.' });
    }
    if (error.response && error.response.status === 429) {
      return res.json({ error: 'VirusTotal rate limit hit — free tier allows 4 requests/minute. Wait and try again.' });
    }
    if (error.code === 'ECONNABORTED') {
      return res.json({ error: 'VirusTotal lookup timed out after 10s. Try again.' });
    }
    res.json({ error: `VirusTotal lookup failed: ${error.message}` });
  }
});

// AbuseIPDB Reputation Check
app.get('/api/abuseipdb/:ip', async (req, res) => {
  const ip = req.params.ip;
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey) {
    return res.json({ error: 'AbuseIPDB API key not configured. Add ABUSEIPDB_API_KEY to backend/.env (see .env.example) and restart the server.' });
  }

  const octetsOk = IPV4_REGEX.test(ip) && ip.split('.').every(n => Number(n) >= 0 && Number(n) <= 255);
  if (!octetsOk) {
    return res.json({ error: `"${ip}" doesn't look like a valid IPv4 address.` });
  }

  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
      headers: { 'Key': apiKey, 'Accept': 'application/json' },
      timeout: 10000
    });

    const data = response.data.data || {};

    const result = {
      'IP': data.ipAddress || ip,
      'Abuse Confidence Score': data.abuseConfidenceScore != null ? `${data.abuseConfidenceScore}%` : 'N/A',
      'Total Reports': data.totalReports ?? 0,
      'Distinct Reporters': data.numDistinctUsers ?? 0,
      'Last Reported': data.lastReportedAt || 'Never reported',
      'Country': data.countryCode || 'N/A',
      'ISP': data.isp || 'N/A',
      'Usage Type': data.usageType || 'N/A',
      'Domain': data.domain || 'N/A',
      'Is Whitelisted': data.isWhitelisted ? 'Yes' : 'No',
      'Is Public': data.isPublic ? 'Yes' : 'No'
    };

    if (Array.isArray(data.hostnames) && data.hostnames.length > 0) {
      result['Hostnames'] = data.hostnames.join(', ');
    }

    // Brief per-category summary of the most recent reports, if verbose data came back
    if (Array.isArray(data.reports) && data.reports.length > 0) {
      const recent = data.reports.slice(0, 3).map(r => {
        const date = (r.reportedAt || '').slice(0, 10);
        const comment = (r.comment || '').replace(/\s+/g, ' ').slice(0, 100);
        return `[${date}] ${comment}`;
      });
      result['Recent Reports'] = recent.join(' | ');
    }

    res.json(result);

  } catch (error) {
    if (error.response && error.response.status === 401) {
      return res.json({ error: 'Invalid AbuseIPDB API key.' });
    }
    if (error.response && error.response.status === 422) {
      return res.json({ error: `AbuseIPDB rejected "${ip}" as an invalid IP address.` });
    }
    if (error.response && error.response.status === 429) {
      return res.json({ error: 'AbuseIPDB rate limit hit — free tier allows 1,000 checks/day. Wait and try again.' });
    }
    if (error.code === 'ECONNABORTED') {
      return res.json({ error: 'AbuseIPDB lookup timed out after 10s. Try again.' });
    }
    res.json({ error: `AbuseIPDB lookup failed: ${error.message}` });
  }
});

// Raw Email Spam/Phishing Analyzer
// Parses raw email source (headers + body) and produces a transparent 0-10 risk score
// based on auth results (SPF/DKIM/DMARC), sender mismatches, brand impersonation,
// suspicious language, risky links/attachments, and (optionally) the originating IP's
// AbuseIPDB reputation.

const PRIVATE_IP_REGEX = /^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly'];
const DANGEROUS_EXTENSIONS = /\.(exe|scr|bat|cmd|js|vbs|jar|ps1|msi|com|pif)$/i;
const DOUBLE_EXTENSION = /\.\w{2,5}\.(exe|scr|bat|cmd|js|vbs|jar|ps1|msi)$/i;
const BRAND_KEYWORDS = ['paypal', 'amazon', 'microsoft', 'apple', 'netflix', 'google', 'facebook', 'instagram', 'whatsapp', 'dhl', 'fedex', 'ups', 'irs', 'bank of america', 'chase', 'wells fargo'];
const SUSPICIOUS_PHRASES = [
  'verify your account', 'verify now', 'click here', 'act now', 'limited time',
  'account suspended', 'congratulations', 'you have won', 'you have been selected',
  'free gift', 'password will expire', 'confirm your identity', 'update your payment',
  'unusual activity', 'wire transfer', 'gift card', 'urgent action required', 'winner'
];

// Parses the raw header block manually (more reliable for repeated headers like
// Received/Authentication-Results than relying on mailparser's structured output)
function parseRawHeaders(raw) {
  const splitIdx = raw.search(/\r?\n\r?\n/);
  const headerBlock = splitIdx === -1 ? raw : raw.slice(0, splitIdx);
  const lines = headerBlock.split(/\r?\n/);
  const headers = {};
  let currentName = null;

  for (const line of lines) {
    if (/^[ \t]/.test(line) && currentName) {
      headers[currentName][headers[currentName].length - 1] += ' ' + line.trim();
    } else {
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const name = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();
      if (!headers[name]) headers[name] = [];
      headers[name].push(value);
      currentName = name;
    }
  }
  return headers;
}

function extractDomain(headerValue) {
  if (!headerValue) return null;
  const match = headerValue.match(/@([\w.-]+\.\w+)/);
  return match ? match[1].toLowerCase() : null;
}

function getAuthResult(headers, mechanism) {
  const values = headers['authentication-results'] || [];
  for (const v of values) {
    const m = v.match(new RegExp(`${mechanism}=(\\w+)`, 'i'));
    if (m) return m[1].toLowerCase();
  }
  return null;
}

function findOriginatingIP(headers) {
  const received = headers['received'] || [];
  const spfValue = (headers['received-spf'] || []).join(' ');

  // Received headers are prepended by each hop, so the earliest (bottom-most in the
  // raw file, last in our array) is closest to the true sender. Walk upward from there
  // skipping private/reserved ranges.
  for (let i = received.length - 1; i >= 0; i--) {
    const matches = received[i].match(/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/g) || [];
    for (const raw of matches) {
      const ip = raw.replace(/[[\]]/g, '');
      if (!PRIVATE_IP_REGEX.test(ip)) return ip;
    }
  }

  // Fallback: try to pull an ip4= value out of an SPF-related header
  const spfMatch = spfValue.match(/ip4=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
  if (spfMatch) return spfMatch[1];

  return null;
}

app.post('/api/emailanalyzer', express.text({ type: '*/*', limit: '2mb' }), async (req, res) => {
  const rawEmail = req.body;

  if (!rawEmail || typeof rawEmail !== 'string' || rawEmail.trim().length === 0) {
    return res.json({ error: 'No email content received. Paste the full raw email source (headers included).' });
  }

  let parsed;
  try {
    parsed = await simpleParser(rawEmail);
  } catch (err) {
    return res.json({ error: `Could not parse this as an email: ${err.message}` });
  }

  const headers = parseRawHeaders(rawEmail);
  const breakdown = [];
  let score = 0;

  const fromHeaderRaw = (headers['from'] || [])[0] || '';
  const replyToRaw = (headers['reply-to'] || [])[0] || '';
  const returnPathRaw = (headers['return-path'] || [])[0] || '';

  const fromDomain = extractDomain(fromHeaderRaw);
  const replyToDomain = extractDomain(replyToRaw);
  const returnPathDomain = extractDomain(returnPathRaw);

  // --- Authentication results ---
  const spf = getAuthResult(headers, 'spf');
  const dkim = getAuthResult(headers, 'dkim');
  const dmarc = getAuthResult(headers, 'dmarc');

  if (spf === 'fail') { score += 2; breakdown.push('SPF fail (+2)'); }
  else if (spf === 'softfail') { score += 1; breakdown.push('SPF softfail (+1)'); }
  else if (!spf) { score += 0.5; breakdown.push('No SPF result found (+0.5)'); }

  if (dkim === 'fail') { score += 2; breakdown.push('DKIM fail (+2)'); }
  else if (!dkim) { score += 0.5; breakdown.push('No DKIM result found (+0.5)'); }

  if (dmarc === 'fail') { score += 1.5; breakdown.push('DMARC fail (+1.5)'); }

  // --- Sender mismatches ---
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    score += 1;
    breakdown.push(`Reply-To domain (${replyToDomain}) differs from From domain (${fromDomain}) (+1)`);
  }
  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    score += 0.5;
    breakdown.push(`Return-Path domain (${returnPathDomain}) differs from From domain (${fromDomain}) (+0.5)`);
  }

  // --- Brand impersonation ---
  const displayName = fromHeaderRaw.split('<')[0].toLowerCase();
  let impersonatedBrand = null;
  for (const brand of BRAND_KEYWORDS) {
    if (displayName.includes(brand) && fromDomain && !fromDomain.includes(brand.replace(/\s+/g, ''))) {
      impersonatedBrand = brand;
      break;
    }
  }
  if (impersonatedBrand) {
    score += 2;
    breakdown.push(`Display name claims to be "${impersonatedBrand}" but sends from ${fromDomain} (+2)`);
  }

  // --- Suspicious language ---
  const subject = parsed.subject || '';
  const bodyText = `${subject} ${parsed.text || ''}`.toLowerCase();
  const matchedPhrases = SUSPICIOUS_PHRASES.filter(p => bodyText.includes(p));
  if (matchedPhrases.length > 0) {
    const points = Math.min(2, matchedPhrases.length * 0.3);
    score += points;
    breakdown.push(`Suspicious phrases found: ${matchedPhrases.join(', ')} (+${points.toFixed(1)})`);
  }

  const letters = subject.replace(/[^a-zA-Z]/g, '');
  if (letters.length > 5 && letters === letters.toUpperCase()) {
    score += 0.5;
    breakdown.push('Subject is ALL CAPS (+0.5)');
  }
  if ((subject.match(/!/g) || []).length >= 3) {
    score += 0.5;
    breakdown.push('Subject has excessive exclamation marks (+0.5)');
  }

  // --- Links ---
  const htmlBody = parsed.html || '';
  const linkMatches = [...htmlBody.matchAll(/<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi)];
  let ipLinkCount = 0, shortenerCount = 0, mismatchCount = 0;

  for (const [, href, text] of linkMatches) {
    if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(href)) ipLinkCount++;
    if (SHORTENER_DOMAINS.some(d => href.includes(d))) shortenerCount++;
    const textLooksLikeUrl = /^(https?:\/\/|www\.)/i.test(text.trim());
    if (textLooksLikeUrl) {
      const hrefDomain = (href.match(/^https?:\/\/([^/]+)/i) || [])[1] || '';
      const textDomain = (text.trim().match(/^(?:https?:\/\/)?([^/]+)/i) || [])[1] || '';
      if (hrefDomain && textDomain && !hrefDomain.includes(textDomain) && !textDomain.includes(hrefDomain)) {
        mismatchCount++;
      }
    }
  }

  if (ipLinkCount > 0) {
    const points = Math.min(2, ipLinkCount);
    score += points;
    breakdown.push(`${ipLinkCount} link(s) point to a raw IP address instead of a domain (+${points})`);
  }
  if (shortenerCount > 0) {
    score += 0.5;
    breakdown.push(`Uses a URL shortener (+0.5)`);
  }
  if (mismatchCount > 0) {
    const points = Math.min(2, mismatchCount);
    score += points;
    breakdown.push(`${mismatchCount} link(s) where displayed text doesn't match the actual destination (+${points})`);
  }

  // --- Attachments ---
  const riskyAttachments = [];
  for (const att of parsed.attachments || []) {
    const name = att.filename || '';
    if (DOUBLE_EXTENSION.test(name)) {
      riskyAttachments.push(`${name} (double extension)`);
    } else if (DANGEROUS_EXTENSIONS.test(name)) {
      riskyAttachments.push(`${name} (executable/script)`);
    }
  }
  if (riskyAttachments.length > 0) {
    score += 2.5;
    breakdown.push(`Risky attachment(s): ${riskyAttachments.join(', ')} (+2.5)`);
  }

  // --- Missing standard headers ---
  if (!headers['date']) { score += 0.3; breakdown.push('Missing Date header (+0.3)'); }
  if (!headers['message-id']) { score += 0.3; breakdown.push('Missing Message-ID header (+0.3)'); }

  // --- Originating IP reputation (optional, only if AbuseIPDB key is configured) ---
  const originatingIP = findOriginatingIP(headers);
  let abuseScoreText = 'Not checked';

  if (originatingIP && process.env.ABUSEIPDB_API_KEY) {
    try {
      const abuseRes = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: { ipAddress: originatingIP, maxAgeInDays: 90 },
        headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
        timeout: 8000
      });
      const abuseScore = abuseRes.data.data.abuseConfidenceScore || 0;
      abuseScoreText = `${abuseScore}%`;
      if (abuseScore > 0) {
        const points = Math.min(3, (abuseScore / 100) * 3);
        score += points;
        breakdown.push(`Originating IP ${originatingIP} has a ${abuseScore}% AbuseIPDB confidence score (+${points.toFixed(1)})`);
      }
    } catch (err) {
      abuseScoreText = 'Lookup failed';
    }
  } else if (originatingIP) {
    abuseScoreText = 'AbuseIPDB key not configured — skipped';
  } else {
    abuseScoreText = 'Could not determine originating IP';
  }

  score = Math.min(10, Math.round(score * 10) / 10);
  let verdict;
  if (score <= 3) verdict = 'Likely legitimate';
  else if (score <= 6) verdict = 'Suspicious — review carefully';
  else verdict = 'Likely spam/phishing';

  res.json({
    'Spam/Phishing Score': `${score} / 10`,
    'Verdict': verdict,
    'Subject': subject || 'N/A',
    'From': fromHeaderRaw || 'N/A',
    'Reply-To': replyToRaw || 'Not present',
    'Return-Path': returnPathRaw || 'Not present',
    'SPF': spf || 'No result',
    'DKIM': dkim || 'No result',
    'DMARC': dmarc || 'No result',
    'Originating IP': originatingIP || 'Not found',
    'AbuseIPDB Confidence': abuseScoreText,
    'Score Breakdown': breakdown.length > 0 ? breakdown.join(' | ') : 'No risk signals detected'
  });
});

// Typosquat / Lookalike Domain Checker
function generateTypoVariants(domain) {
  const parts = domain.split('.');
  const name = parts[0];
  const rest = parts.slice(1).join('.');
  const variants = new Set();

  // Adjacent-key substitution (common typo neighbors on QWERTY)
  const neighbors = {
    a: 'qsz', b: 'vghn', c: 'xdfv', d: 'serfcx', e: 'wsdr', f: 'drtgvc',
    g: 'ftyhbv', h: 'gyujnb', i: 'ujko', j: 'huikmn', k: 'jiolm', l: 'kop',
    m: 'njk', n: 'bhjm', o: 'iklp', p: 'ol', q: 'wa', r: 'edft', s: 'awedxz',
    t: 'rfgy', u: 'yhji', v: 'cfgb', w: 'qase', x: 'zsdc', y: 'tghu', z: 'asx'
  };

  for (let i = 0; i < name.length; i++) {
    const ch = name[i];

    // 1. Character omission (missing letter)
    variants.add(name.slice(0, i) + name.slice(i + 1));

    // 2. Character duplication (double letter)
    variants.add(name.slice(0, i + 1) + ch + name.slice(i + 1));

    // 3. Adjacent-key substitution
    if (neighbors[ch]) {
      for (const sub of neighbors[ch]) {
        variants.add(name.slice(0, i) + sub + name.slice(i + 1));
      }
    }

    // 4. Adjacent transposition
    if (i < name.length - 1) {
      variants.add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2));
    }
  }

  // 5. Common TLD swaps
  const tldSwaps = ['com', 'net', 'org', 'co', 'info', 'biz'];
  tldSwaps.forEach(tld => variants.add(`${name}.${tld}`));

  variants.delete(name); // remove the original itself
  return Array.from(variants)
    .filter(v => v.length > 0)
    .map(v => (v.includes('.') ? v : `${v}.${rest}`))
    .slice(0, 40); // cap to keep DNS checks fast
}

app.get('/api/typosquat/:domain', async (req, res) => {
  const domain = req.params.domain;
  const variants = generateTypoVariants(domain);

  const results = await Promise.all(variants.map(async (variant) => {
    try {
      await dns.resolve4(variant);
      return variant;
    } catch {
      return null;
    }
  }));

  const registered = results.filter(Boolean);

  if (registered.length === 0) {
    return res.json({ result: `Checked ${variants.length} lookalike variants of ${domain} — none are currently registered.` });
  }

  res.json({ result: `${registered.length} of ${variants.length} lookalike domains ARE registered (potential typosquats):\n${registered.join('\n')}` });
});

// Reverse WHOIS (requires a paid data source — WhoisXMLAPI's Reverse WHOIS API)
app.get('/api/reversewhois/:query', async (req, res) => {
  const query = req.params.query; // typically an email or registrant name
  const apiKey = process.env.REVERSE_WHOIS_API_KEY;

  if (!apiKey) {
    return res.json({ error: 'Reverse WHOIS requires a paid API key (e.g. WhoisXMLAPI). Add REVERSE_WHOIS_API_KEY to backend/.env to enable this.' });
  }

  try {
    const response = await axios.post('https://reverse-whois.whoisxmlapi.com/api/v2', {
      apiKey,
      searchType: 'current',
      mode: 'purchase',
      punycode: true,
      basicSearchTerms: { include: [query] }
    }, { timeout: 15000 });

    const domainsFound = response.data.domainsList || [];
    if (domainsFound.length === 0) {
      return res.json({ error: `No domains found associated with "${query}"` });
    }

    res.json({ result: `${domainsFound.length} domain(s) found for "${query}":\n${domainsFound.join('\n')}` });

  } catch (error) {
    res.json({ error: `Reverse WHOIS lookup failed: ${error.message}` });
  }
});

app.listen(5000, () => {
  console.log('Server running on port 5000');
});