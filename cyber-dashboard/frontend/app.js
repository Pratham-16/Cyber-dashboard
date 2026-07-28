function showPanel(id, btn) {
  document.querySelectorAll('.panel').forEach(panel => {
    panel.classList.remove('active');
  });
  document.getElementById(id).classList.add('active');

  document.querySelectorAll('.nav-card').forEach(card => {
    card.classList.remove('active');
  });
  if (btn) btn.classList.add('active');
}

function renderResult(containerId, data) {
  const container = document.getElementById(containerId);

  if (!data || data.error) {
    container.innerHTML = `<p class="result-error"><i class="fa-solid fa-triangle-exclamation"></i> ${
      (data && data.error) ? escapeHtml(data.error) : 'No result returned.'
    }</p>`;
    return;
  }

  // Python tools return { result: "Label: value\nLabel: value\n..." } — parse those lines
  if (typeof data.result === 'string' && Object.keys(data).length === 1) {
    renderLineResult(container, data.result);
    return;
  }

  // Otherwise render as a key/value table (e.g. IP lookup JSON from ip-api.com)
  let rows = '';
  for (const [key, value] of Object.entries(data)) {
    rows += `<tr><td class="key">${escapeHtml(key)}</td><td class="val">${formatValue(String(value))}</td></tr>`;
  }
  container.innerHTML = `<table class="result-table">${rows}</table>`;
}

// Parses "Label: value\nLabel: value" style output from the python tools
// into a clean row layout, turning URLs into clickable links.
function renderLineResult(container, raw) {
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);

  if (lines.length === 0) {
    container.innerHTML = `<p class="placeholder">No data found.</p>`;
    return;
  }

  let rows = '';
  let matchedAny = false;

  for (const line of lines) {
    const splitIndex = line.indexOf(':');
    if (splitIndex > -1) {
      const label = line.slice(0, splitIndex).trim();
      const value = line.slice(splitIndex + 1).trim();
      matchedAny = true;
      rows += `<tr><td class="key">${escapeHtml(label)}</td><td class="val">${formatValue(value)}</td></tr>`;
    } else {
      rows += `<tr><td class="key"></td><td class="val">${escapeHtml(line)}</td></tr>`;
    }
  }

  if (matchedAny) {
    container.innerHTML = `<table class="result-table">${rows}</table>`;
  } else {
    container.innerHTML = `<pre class="raw-text">${escapeHtml(raw)}</pre>`;
  }
}

// Turns bare URLs into clickable links, otherwise escapes normally
function formatValue(value) {
  if (/^https?:\/\/\S+$/i.test(value)) {
    return `<a class="result-link" href="${escapeHtml(value)}" target="_blank" rel="noopener">${escapeHtml(value)}</a>`;
  }
  return escapeHtml(value);
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function showLoading(containerId) {
  document.getElementById(containerId).innerHTML =
    `<p class="placeholder"><i class="fa-solid fa-spinner fa-spin"></i> Working...</p>`;
}

async function searchUsername() {
  const username = document.getElementById('usernameInput').value;
  if (!username) return;
  showLoading('usernameResult');
  const res = await fetch(`http://localhost:5000/api/username/${encodeURIComponent(username)}`);
  const data = await res.json();
  renderResult('usernameResult', data);
}

async function lookupIP() {
  const ip = document.getElementById('ipInput').value;
  if (!ip) return;
  showLoading('ipResult');
  const res = await fetch(`http://localhost:5000/api/ip/${encodeURIComponent(ip)}`);
  const data = await res.json();
  renderResult('ipResult', data);
}

async function lookupDomain() {
  const domain = document.getElementById('domainInput').value;
  if (!domain) return;
  showLoading('domainResult');
  const res = await fetch(`http://localhost:5000/api/domain/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('domainResult', data);
}

async function scanPorts() {
  const ip = document.getElementById('scannerInput').value;
  if (!ip) return;
  showLoading('scannerResult');
  const res = await fetch(`http://localhost:5000/api/scanner/${encodeURIComponent(ip)}`);
  const data = await res.json();
  renderResult('scannerResult', data);
}



async function extractMetadata() {
  const fileInput = document.getElementById('metadataFile');
  if (!fileInput.files[0]) return;
  showLoading('metadataResult');

  const formData = new FormData();
  formData.append('image', fileInput.files[0]);

  const res = await fetch('http://localhost:5000/api/metadata', {
    method: 'POST',
    body: formData
  });
  const data = await res.json();
  renderResult('metadataResult', data);
}

async function lookupDNS() {
  const domain = document.getElementById('dnsInput').value;
  if (!domain) return;
  showLoading('dnsResult');
  const res = await fetch(`http://localhost:5000/api/dns/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('dnsResult', data);
}

async function inspectSSL() {
  const domain = document.getElementById('sslInput').value;
  if (!domain) return;
  showLoading('sslResult');
  const res = await fetch(`http://localhost:5000/api/ssl/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('sslResult', data);
}

async function enumerateSubdomains() {
  const domain = document.getElementById('subdomainsInput').value;
  if (!domain) return;
  showLoading('subdomainsResult');
  const res = await fetch(`http://localhost:5000/api/subdomains/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('subdomainsResult', data);
}

async function checkWayback() {
  const domain = document.getElementById('waybackInput').value;
  if (!domain) return;
  showLoading('waybackResult');
  const res = await fetch(`http://localhost:5000/api/wayback/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('waybackResult', data);
}

async function fingerprintTechStack() {
  const domain = document.getElementById('techstackInput').value;
  if (!domain) return;
  showLoading('techstackResult');
  const res = await fetch(`http://localhost:5000/api/techstack/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('techstackResult', data);
}

async function lookupShodan() {
  const ip = document.getElementById('shodanInput').value.trim();
  if (!ip) return;
  showLoading('shodanResult');

  try {
    const res = await fetch(`http://localhost:5000/api/shodan/${encodeURIComponent(ip)}`);
    const data = await res.json();
    renderResult('shodanResult', data);
  } catch (err) {
    renderResult('shodanResult', { error: `Request failed: ${err.message}` });
  }
}

async function lookupVirusTotal() {
  const target = document.getElementById('virustotalInput').value.trim();
  if (!target) return;
  showLoading('virustotalResult');

  try {
    const res = await fetch(`http://localhost:5000/api/virustotal/${encodeURIComponent(target)}`);
    const data = await res.json();
    renderResult('virustotalResult', data);
  } catch (err) {
    renderResult('virustotalResult', { error: `Request failed: ${err.message}` });
  }
}

async function lookupAbuseIPDB() {
  const ip = document.getElementById('abuseipdbInput').value.trim();
  if (!ip) return;
  showLoading('abuseipdbResult');

  try {
    const res = await fetch(`http://localhost:5000/api/abuseipdb/${encodeURIComponent(ip)}`);
    const data = await res.json();
    renderResult('abuseipdbResult', data);
  } catch (err) {
    renderResult('abuseipdbResult', { error: `Request failed: ${err.message}` });
  }
}

async function analyzeEmail() {
  const rawEmail = document.getElementById('emailInput').value;
  if (!rawEmail.trim()) return;
  showLoading('emailanalyzerResult');

  try {
    const res = await fetch('http://localhost:5000/api/emailanalyzer', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: rawEmail
    });
    const data = await res.json();
    renderResult('emailanalyzerResult', data);
  } catch (err) {
    renderResult('emailanalyzerResult', { error: `Request failed: ${err.message}` });
  }
}
function generateDorks() {
  const domain = document.getElementById('dorkInput').value.trim();
  if (!domain) return;

  const dorks = [
    // --- General indexing ---
    { category: 'General', label: 'All indexed pages', query: `site:${domain}` },
    { category: 'General', label: 'Indexed subdomains', query: `site:*.${domain} -site:www.${domain}` },
    { category: 'General', label: 'Pages with "index of" (open directories)', query: `site:${domain} intitle:"index of"` },
    { category: 'General', label: 'Cached/related pages', query: `related:${domain}` },

    // --- Exposed files ---
    { category: 'Exposed Files', label: 'PDF documents', query: `site:${domain} filetype:pdf` },
    { category: 'Exposed Files', label: 'Excel/CSV files (possible data leaks)', query: `site:${domain} filetype:xlsx OR filetype:csv` },
    { category: 'Exposed Files', label: 'Word/PowerPoint documents', query: `site:${domain} filetype:doc OR filetype:docx OR filetype:ppt OR filetype:pptx` },
    { category: 'Exposed Files', label: 'Config/env/log files', query: `site:${domain} ext:sql OR ext:env OR ext:log OR ext:cfg OR ext:conf` },
    { category: 'Exposed Files', label: 'Backup files', query: `site:${domain} ext:bak OR ext:old OR ext:backup OR ext:swp` },
    { category: 'Exposed Files', label: 'Database dumps', query: `site:${domain} filetype:sql "INSERT INTO" OR "CREATE TABLE"` },
    { category: 'Exposed Files', label: 'XML/JSON API responses', query: `site:${domain} filetype:xml OR filetype:json` },

    // --- Login / admin surfaces ---
    { category: 'Access Points', label: 'Login/admin pages', query: `site:${domain} inurl:login OR inurl:admin OR inurl:signin` },
    { category: 'Access Points', label: 'Dashboard/portal pages', query: `site:${domain} inurl:dashboard OR inurl:portal OR inurl:cpanel` },
    { category: 'Access Points', label: 'phpMyAdmin / database UIs', query: `site:${domain} inurl:phpmyadmin OR intitle:"phpMyAdmin"` },
    { category: 'Access Points', label: 'WordPress admin/login', query: `site:${domain} inurl:wp-admin OR inurl:wp-login.php` },
    { category: 'Access Points', label: 'API endpoints exposed', query: `site:${domain} inurl:api OR inurl:v1 OR inurl:v2` },

    // --- Sensitive content ---
    { category: 'Sensitive Content', label: 'Pages mentioning passwords/credentials', query: `site:${domain} intext:password OR intext:credentials` },
    { category: 'Sensitive Content', label: 'API keys / secrets in text', query: `site:${domain} intext:"api_key" OR intext:"secret_key" OR intext:"api key"` },
    { category: 'Sensitive Content', label: 'Confidential/internal-marked pages', query: `site:${domain} intext:"confidential" OR intext:"internal use only"` },
    { category: 'Sensitive Content', label: 'Error messages (info disclosure)', query: `site:${domain} intext:"warning" OR intext:"error" intext:"sql"` },
    { category: 'Sensitive Content', label: 'Exposed email addresses', query: `site:${domain} intext:"@${domain}"` },

    // --- Employee / people info ---
    { category: 'People & Org', label: 'LinkedIn profiles mentioning the company', query: `site:linkedin.com/in "${domain.split('.')[0]}"` },
    { category: 'People & Org', label: 'Resumes mentioning the domain', query: `filetype:pdf "${domain}" resume OR cv` },
    { category: 'People & Org', label: 'GitHub repos mentioning the domain', query: `site:github.com "${domain}"` },
    { category: 'People & Org', label: 'Pastebin mentions (possible leaks)', query: `site:pastebin.com "${domain}"` }
  ];

  const container = document.getElementById('dorkResult');
  let html = '';
  let lastCategory = null;

  dorks.forEach(d => {
    if (d.category !== lastCategory) {
      html += `<h4 class="dork-category">${escapeHtml(d.category)}</h4>`;
      lastCategory = d.category;
    }
    const url = `https://www.google.com/search?q=${encodeURIComponent(d.query)}`;
    html += `<div class="dork-row">
      <span class="dork-label">${escapeHtml(d.label)}</span>
      <a class="result-link" href="${url}" target="_blank" rel="noopener">${escapeHtml(d.query)}</a>
    </div>`;
  });

  container.innerHTML = html;
}

async function checkTyposquat() {
  const domain = document.getElementById('typosquatInput').value.trim();
  if (!domain) return;
  showLoading('typosquatResult');
  const res = await fetch(`http://localhost:5000/api/typosquat/${encodeURIComponent(domain)}`);
  const data = await res.json();
  renderResult('typosquatResult', data);
}

async function lookupReverseWhois() {
  const query = document.getElementById('reversewhoisInput').value.trim();
  if (!query) return;
  showLoading('reversewhoisResult');
  const res = await fetch(`http://localhost:5000/api/reversewhois/${encodeURIComponent(query)}`);
  const data = await res.json();
  renderResult('reversewhoisResult', data);
}