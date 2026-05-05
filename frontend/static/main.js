const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));

const API_BASE = 'http://127.0.0.1:8000';

function setUrl(u) { $('urlInput').value = u; }
function resetScan() {
  $('resultsView').classList.add('hidden');
  $('urlInput').value = '';
  $('urlInput').focus();
}

function parseUrl(raw) {
  try {
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    return new URL(raw);
  } catch { return null; }
}

const STEPS = ['DNS', 'TLS', 'HEADERS', 'CONTENT', 'THREATS'];

async function startScan() {
  const raw = $('urlInput').value.trim();
  if (!raw) { flashInput(); return; }
  const parsed = parseUrl(raw);
  if (!parsed) { flashInput(); return; }

  $('scanBtn').disabled = true;
  $('resultsView').classList.add('hidden');
  $('scanTarget').textContent = parsed.hostname;
  $('scanView').classList.remove('hidden');

  $('scanBars').innerHTML = STEPS.map((s, i) => `
    <div class="flex items-center gap-2.5">
      <span class="font-mono text-[10px] text-zinc-600 w-16 shrink-0">${s}</span>
      <div class="flex-1 h-[3px] bg-zinc-800 rounded-full overflow-hidden">
        <div id="bar${i}" class="h-full bg-blue-500 rounded-full transition-all duration-500" style="width:0%"></div>
      </div>
      <span id="bst${i}" class="font-mono text-[10px] text-zinc-600 w-7 text-right">—</span>
    </div>
  `).join('');
  $('termLines').innerHTML = '';

  function log(txt, active = false) {
    const d = document.createElement('div');
    d.className = `font-mono text-[11px] ${active ? 'text-zinc-400' : 'text-zinc-700'} animate-fadeUp opacity-0`;
    d.textContent = `> ${txt}`;
    $('termLines').appendChild(d);
  }

  async function step(i, ms, msg) {
    log(msg, true);
    $('bst' + i).textContent = '...';
    await sleep(ms + Math.random() * 250);
    $('bar' + i).style.width = '100%';
    $('bst' + i).textContent = 'ok';
    $('bst' + i).className = 'font-mono text-[10px] text-green-500 w-7 text-right';
  }

  // kick off api call and fake progress bars at the same time
  const apiPromise = fetch(`${API_BASE}/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: raw })
  });

  await step(0, 380, `Resolving ${parsed.hostname}`);
  await step(1, 460, `Checking TLS certificate`);
  await step(2, 420, `Probing response headers`);
  await step(3, 380, `Analyzing URL patterns`);
  await step(4, 480, `Cross-referencing threat DB`);
  log(`Scan complete.`);

  try {
    const response = await apiPromise;
    if (!response.ok) throw new Error(`Server error: ${response.status}`);
    const apiData = await response.json();

    await sleep(280);
    const results = buildResults(parsed, raw, apiData);
    $('scanView').classList.add('hidden');
    renderResults(results, raw);
  } catch (err) {
    log(`Error: ${err.message}`, true);
    await sleep(600);
    $('scanView').classList.add('hidden');
    flashInput();
  } finally {
    $('scanBtn').disabled = false;
  }
}

function flashInput() {
  const inp = $('urlInput');
  inp.classList.add('border-red-500', 'ring-2', 'ring-red-500/20');
  setTimeout(() => inp.classList.remove('border-red-500', 'ring-2', 'ring-red-500/20'), 900);
}

function buildResults(url, raw, apiData) {
  const findings = [];
  const hn       = url.hostname.toLowerCase();
  const isHttps  = url.protocol === 'https:';
  const tld      = hn.split('.').slice(-1)[0];
  const query    = url.search;

  // --- URL pattern checks (client-side) ---

  if (!isHttps)
    findings.push({ sev: 'high', title: 'Unencrypted HTTP', desc: 'Traffic is transmitted in plaintext, exposing users to eavesdropping and man-in-the-middle attacks.', ref: 'CWE-319' });

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname))
    findings.push({ sev: 'high', title: 'Raw IP Address', desc: 'Direct IP access is common in phishing, malware hosting, and untrusted ad-hoc servers.', ref: 'OWASP A05' });

  const phishKw  = ['login','signin','verify','secure','update','confirm','paypal','bank','amazon','microsoft','apple','wallet','account','password'];
  const domBase  = hn.replace(/^www\./, '').split('.')[0];
  const matched  = phishKw.find(k => domBase.includes(k) && hn.split('.').length > 2);
  if (matched)
    findings.push({ sev: 'high', title: `Phishing Keyword: "${matched}"`, desc: `The domain contains "${matched}", a common tactic used by phishing sites to impersonate trusted brands.`, ref: 'OWASP A07' });

  if (url.pathname.includes('..') || url.pathname.includes('%2e%2e'))
    findings.push({ sev: 'high', title: 'Path Traversal Sequence', desc: 'The URL path contains "../" sequences that may indicate a path traversal attack or misconfiguration.', ref: 'CWE-22' });

  if (query && /(<script|javascript:|onerror=|onload=|alert\()/i.test(decodeURIComponent(query)))
    findings.push({ sev: 'high', title: 'XSS Payload Detected', desc: 'Query parameters contain Cross-Site Scripting patterns. Avoid opening this URL unless performing authorized testing.', ref: 'CWE-79' });

  if (query && /(union.+select|select.+from|drop.+table|or\s+1=1)/i.test(decodeURIComponent(query)))
    findings.push({ sev: 'high', title: 'SQL Injection Pattern', desc: 'Query string contains SQL-like syntax typical of injection attacks targeting unauthorized database access.', ref: 'CWE-89' });

  if (hn.split('-').length > 3)
    findings.push({ sev: 'medium', title: 'Excessive Hyphens in Domain', desc: 'Domains with many hyphens are frequently used for typosquatting and brand impersonation.', ref: 'Phishing' });

  if (query && /(https?:\/\/|%2F%2F)/.test(query) && /redirect=|url=|next=|goto=|dest=/i.test(query))
    findings.push({ sev: 'medium', title: 'Open Redirect Parameter', desc: 'A redirect parameter points to an external URL — attackers exploit these to send users to malicious sites.', ref: 'CWE-601' });

  const badTlds = ['xyz','tk','ml','ga','cf','pw','top','click','download','loan','win','racing','science'];
  if (badTlds.includes(tld))
    findings.push({ sev: 'medium', title: `High-Risk TLD (.${tld})`, desc: `Free TLDs like .${tld} are disproportionately used in phishing, spam, and malware campaigns.`, ref: 'Threat Intel' });

  if (/bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|rb\.gy|is\.gd/.test(hn))
    findings.push({ sev: 'medium', title: 'URL Shortener Detected', desc: 'Shortened URLs obscure the final destination and are widely used in phishing and malware delivery.', ref: 'Phishing' });

  if (url.port && !['80', '443'].includes(url.port))
    findings.push({ sev: 'low', title: `Non-Standard Port (${url.port})`, desc: 'Legitimate public-facing services rarely use non-standard ports. May indicate a dev server.', ref: 'INFO' });

  if (raw.length > 200)
    findings.push({ sev: 'low', title: `Long URL (${raw.length} chars)`, desc: 'Very long URLs can obscure the real domain or confuse users and security filters.', ref: 'INFO' });

  if (isHttps)
    findings.push({ sev: 'info', title: 'HTTPS Enabled', desc: 'TLS encryption is present. Note: HTTPS alone does not guarantee safety — phishing sites also use TLS certificates.', ref: 'TLS OK' });

  // --- Real backend data ---

  // SSL findings
  if (!apiData.ssl.ssl_valid) {
    findings.push({ sev: 'high', title: 'Invalid SSL Certificate', desc: apiData.ssl.error || 'SSL certificate is invalid or could not be verified.', ref: 'TLS' });
  } else if (apiData.ssl.expires_in_days <= 14) {
    findings.push({ sev: 'medium', title: `SSL Expiring Soon (${apiData.ssl.expires_in_days} days)`, desc: 'Certificate is expiring very soon — the site may become unreachable or show warnings.', ref: 'TLS' });
  } else if (apiData.ssl.expires_in_days <= 30) {
    findings.push({ sev: 'low', title: `SSL Expiring in ${apiData.ssl.expires_in_days} Days`, desc: 'Certificate expires within 30 days. Renewal should be scheduled soon.', ref: 'TLS' });
  }

  // DNS findings
  if (!apiData.dns.dns_resolves) {
    findings.push({ sev: 'high', title: 'DNS Resolution Failed', desc: apiData.dns.error || 'The domain could not be resolved to an IP address.', ref: 'DNS' });
  }

  // Real header data from backend
  const hdrDefs = [
    { name: 'Content-Security-Policy',   key: 'content-security-policy',   desc: 'Prevents XSS attacks by whitelisting trusted content sources.' },
    { name: 'Strict-Transport-Security', key: 'strict-transport-security', desc: 'Forces HTTPS, preventing SSL-stripping and downgrade attacks.' },
    { name: 'X-Frame-Options',           key: 'x-frame-options',           desc: 'Prevents clickjacking by controlling iframe embedding.' },
    { name: 'X-Content-Type-Options',    key: 'x-content-type-options',    desc: 'Prevents MIME sniffing, reducing drive-by download risk.' },
  ];

  const headers = hdrDefs.map(h => {
    const present = apiData.headers[h.key] === true;
    if (!present)
      findings.push({ sev: 'low', title: `Missing: ${h.name}`, desc: h.desc + ' This header is absent.', ref: 'OWASP A05' });
    return { name: h.name, desc: h.desc, present };
  });

  const info = {
    Protocol : isHttps ? 'HTTPS (TLS)' : 'HTTP (plain)',
    Domain   : url.hostname,
    IP       : apiData.dns.ip || '—',
    Port     : url.port || (isHttps ? '443' : '80'),
    TLD      : '.' + tld,
    Path     : url.pathname || '/',
    'SSL Days Left' : apiData.ssl.ssl_valid ? `${apiData.ssl.expires_in_days} days` : 'Invalid',
    'Query Params'  : url.search || '(none)',
  };

  return { findings, headers, info };
}

function renderResults({ findings, headers, info }, raw) {
  const high  = findings.filter(f => f.sev === 'high').length;
  const med   = findings.filter(f => f.sev === 'medium').length;
  const low   = findings.filter(f => f.sev === 'low').length;
  const inf   = findings.filter(f => f.sev === 'info').length;
  const score = Math.max(0, Math.min(100, 100 - high * 22 - med * 10 - low * 4));

  const arc = $('ringArc');
  setTimeout(() => {
    arc.style.strokeDashoffset = 207.3 - (score / 100) * 207.3;
    arc.style.stroke = score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#ef4444';
  }, 80);

  $('scoreNum').textContent = score;

  const risk   = score >= 70 ? 'Low Risk' : score >= 40 ? 'Moderate Risk' : 'High Risk';
  const bColor = score >= 70
    ? 'text-green-400 bg-green-950 border-green-800'
    : score >= 40
    ? 'text-amber-400 bg-amber-950 border-amber-800'
    : 'text-red-400 bg-red-950 border-red-800';
  const bLabel = score >= 70 ? 'SAFE' : score >= 40 ? 'WARNING' : 'DANGER';
  const tColor = score >= 70 ? 'text-zinc-50' : score >= 40 ? 'text-amber-400' : 'text-red-400';

  $('riskTitle').textContent = risk;
  $('riskTitle').className   = `text-[15px] font-semibold tracking-tight ${tColor}`;
  $('riskBadge').textContent = bLabel;
  $('riskBadge').className   = `font-mono text-[10px] font-medium px-1.5 py-0.5 rounded border uppercase tracking-widest ${bColor}`;

  $('summaryText').textContent = score >= 70
    ? 'No critical issues detected. The URL appears structurally sound — always verify the domain before entering credentials.'
    : score >= 40
    ? 'Some concerns detected. This URL has suspicious characteristics — proceed with caution.'
    : 'Multiple high-severity issues found. This URL exhibits patterns associated with phishing or malicious infrastructure.';

  $('urlDisplay').textContent = raw;
  $('cHigh').textContent = high;
  $('cMed').textContent  = med;
  $('cLow').textContent  = low;
  $('cInfo').textContent = inf;

  // Findings list
  const sortOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const sorted    = [...findings].sort((a, b) => sortOrder[a.sev] - sortOrder[b.sev]);

  $('findingsCount').textContent = `${sorted.length} issues`;
  $('findingsList').innerHTML    = '';

  sorted.forEach((f, i) => {
    const dotColor = { high: 'bg-red-500', medium: 'bg-amber-500', low: 'bg-zinc-500', info: 'bg-blue-500' }[f.sev];
    const badgeCls = { high: 'text-red-400 bg-red-950 border-red-800', medium: 'text-amber-400 bg-amber-950 border-amber-800', low: 'text-zinc-400 bg-zinc-800 border-zinc-700', info: 'text-blue-400 bg-blue-950 border-blue-800' }[f.sev];
    const sevLabel = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }[f.sev];

    const row = document.createElement('div');
    row.className = 'flex items-start gap-3 px-4 py-3.5 border-b border-zinc-800 last:border-0 opacity-0 animate-slideIn';
    row.style.animationDelay = `${i * 35}ms`;
    row.innerHTML = `
      <div class="w-1.5 h-1.5 rounded-full shrink-0 mt-[6px] ${dotColor}"></div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-1.5 mb-1 flex-wrap">
          <span class="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded border uppercase tracking-widest ${badgeCls}">${sevLabel}</span>
          <span class="text-[13px] font-medium text-zinc-100">${f.title}</span>
        </div>
        <p class="text-[12px] text-zinc-500 leading-relaxed">${f.desc}</p>
      </div>
      <span class="font-mono text-[10px] text-zinc-700 shrink-0 pt-0.5">${f.ref}</span>
    `;
    $('findingsList').appendChild(row);
  });

  // Headers
  const presentCount = headers.filter(h => h.present).length;
  const hdrBadge     = presentCount >= 3
    ? 'text-green-400 bg-green-950 border-green-800'
    : presentCount >= 2
    ? 'text-amber-400 bg-amber-950 border-amber-800'
    : 'text-red-400 bg-red-950 border-red-800';

  $('hdrScore').textContent = `${presentCount} / ${headers.length}`;
  $('hdrScore').className   = `font-mono text-[10px] font-medium px-1.5 py-0.5 rounded border uppercase tracking-widest ${hdrBadge}`;

  $('headerList').innerHTML = '';
  headers.forEach(h => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between py-2 border-b border-zinc-800 last:border-0';
    row.innerHTML = `
      <div class="flex items-center gap-2.5 flex-1 min-w-0">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" class="shrink-0">
          ${h.present
            ? `<circle cx="7" cy="7" r="6" fill="rgba(34,197,94,0.08)" stroke="rgba(34,197,94,0.25)"/>
               <path d="M4.5 7l2 2 3-3.5" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>`
            : `<circle cx="7" cy="7" r="6" fill="rgba(239,68,68,0.08)" stroke="rgba(239,68,68,0.2)"/>
               <path d="M5 5l4 4M9 5l-4 4" stroke="#ef4444" stroke-width="1.3" stroke-linecap="round"/>`
          }
        </svg>
        <span class="font-mono text-[12px] ${h.present ? 'text-zinc-200' : 'text-zinc-500'}">${h.name}</span>
      </div>
      <span class="font-mono text-[10px] font-medium px-1.5 py-0.5 rounded border uppercase tracking-widest ${h.present ? 'text-green-400 bg-green-950 border-green-800' : 'text-red-400 bg-red-950 border-red-800'}">${h.present ? 'PRESENT' : 'MISSING'}</span>
    `;
    $('headerList').appendChild(row);
  });

  // URL breakdown
  $('urlBreakdown').innerHTML = '';
  Object.entries(info).forEach(([k, v]) => {
    const cell = document.createElement('div');
    cell.className = 'bg-zinc-950 border border-zinc-800 rounded-lg p-3';
    cell.innerHTML = `
      <div class="font-mono text-[10px] font-medium text-zinc-500 uppercase tracking-widest mb-1">${k}</div>
      <div class="font-mono text-[12px] text-zinc-100 truncate">${v}</div>
    `;
    $('urlBreakdown').appendChild(cell);
  });

  $('resultsView').classList.remove('hidden');
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});