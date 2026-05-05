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

  const apiPromise = fetch(`${API_BASE}/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: raw })
  });

  await step(0, 380, `Resolving ${parsed.hostname}`);
  await step(1, 460, `Checking TLS certificate`);
  await step(2, 420, `Analyzing response headers`);
  await step(3, 380, `Analyzing URL patterns`);
  await step(4, 480, `Cross-referencing threat DB`);
  log(`Scan complete.`);

  try {
    const response = await apiPromise;
    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const apiData = await response.json();

    await sleep(250);

    const results = buildResults(parsed, raw, apiData);

    $('scanView').classList.add('hidden');
    renderResults(results, raw, apiData);

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
  setTimeout(() =>
    inp.classList.remove('border-red-500', 'ring-2', 'ring-red-500/20'),
  900);
}

/* =========================
   RESULTS ENGINE
========================= */

function buildResults(url, raw, apiData) {
  const findings = [];
  const hn = url.hostname.toLowerCase();
  const isHttps = url.protocol === 'https:';

  if (!isHttps) {
    findings.push({
      sev: 'high',
      title: 'Unencrypted HTTP',
      desc: 'Traffic is plaintext.',
      ref: 'CWE-319'
    });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
    findings.push({
      sev: 'high',
      title: 'Raw IP Address',
      desc: 'Direct IP usage detected.',
      ref: 'OWASP A05'
    });
  }

  if (isHttps) {
    findings.push({
      sev: 'info',
      title: 'HTTPS Enabled',
      desc: 'TLS is present.',
      ref: 'TLS OK'
    });
  }

  if (!apiData.ssl.ssl_valid) {
    findings.push({
      sev: 'high',
      title: 'Invalid SSL Certificate',
      desc: apiData.ssl.error || 'Invalid SSL.',
      ref: 'TLS'
    });
  }

  if (!apiData.dns.dns_resolves) {
    findings.push({
      sev: 'high',
      title: 'DNS Resolution Failed',
      desc: apiData.dns.error || 'DNS failed.',
      ref: 'DNS'
    });
  }

  /* =========================
     HEADERS (FIXED SECTION)
  ========================= */

  const hdrDefs = [
    { name: 'Content-Security-Policy', key: 'content-security-policy' },
    { name: 'Strict-Transport-Security', key: 'strict-transport-security' },
    { name: 'X-Frame-Options', key: 'x-frame-options' },
    { name: 'X-Content-Type-Options', key: 'x-content-type-options' },
  ];

  const headers = hdrDefs.map(h => {
    const present = !!apiData.headers?.[h.key];

    if (!present) {
      findings.push({
        sev: 'low',
        title: `Missing Security Header: ${h.name}`,
        desc: 'This security header is not present.',
        ref: 'HEADERS'
      });
    }

    return {
      name: h.name,
      present
    };
  });

  /* =========================
     OSINT
  ========================= */

  const whois = apiData.osint?.whois || {};
  const reputation = apiData.osint?.reputation || {};
  const serverInfo = apiData.osint?.server_info || {};

  if (whois.org) {
    findings.push({
      sev: 'info',
      title: 'Hosting Provider Identified',
      desc: `${whois.org} (ASN ${whois.asn})`,
      ref: 'OSINT'
    });
  }

  if (serverInfo.risk_flag) {
    findings.push({
      sev: 'medium',
      title: 'Server Fingerprinting Risk',
      desc: serverInfo.risk_reason,
      ref: 'Fingerprinting'
    });
  }

  const info = {
    Domain: url.hostname,
    IP: apiData.dns.ip || '—',
    ASN: whois.asn || '—',
    Hosting: whois.org || reputation.isp || '—',
    Country: whois.country || reputation.country || '—',
    'SSL Days Left': apiData.ssl.ssl_valid
      ? `${apiData.ssl.expires_in_days} days`
      : 'Invalid'
  };

  return { findings, headers, info };
}

/* =========================
   RENDER OSINT
========================= */

function renderOSINT(apiData) {
  const whois = apiData.osint?.whois || {};
  const rep = apiData.osint?.reputation || {};
  const srv = apiData.osint?.server_info || {};

  const grid = $('osintGrid');
  if (!grid) return;

  const osint = {
    'IP Address': whois.ip || '—',
    'ASN': whois.asn || '—',
    'Hosting': whois.org || rep.isp || '—',
    'Country': whois.country || rep.country || '—',
    'Proxy': rep.is_proxy ? 'Yes ⚠️' : 'No',
    'Server': srv.server || '—'
  };

  grid.innerHTML = '';

  Object.entries(osint).forEach(([k, v]) => {
    const cell = document.createElement('div');
    cell.className = 'bg-zinc-950 border border-zinc-800 rounded-lg p-3';
    cell.innerHTML = `
      <div class="font-mono text-[10px] text-zinc-500 mb-1">${k}</div>
      <div class="font-mono text-[12px] text-zinc-100">${v}</div>
    `;
    grid.appendChild(cell);
  });
}

/* =========================
   FINAL RENDER
========================= */

function renderResults({ findings, headers, info }, raw, apiData) {
  const high = findings.filter(f => f.sev === 'high').length;
  const med = findings.filter(f => f.sev === 'medium').length;
  const low = findings.filter(f => f.sev === 'low').length;
  const inf = findings.filter(f => f.sev === 'info').length;

  const score = Math.max(0, Math.min(100, 100 - high * 22 - med * 10 - low * 4));

  const arc = $('ringArc');
  setTimeout(() => {
    arc.style.strokeDashoffset = 207.3 - (score / 100) * 207.3;
    arc.style.stroke =
      score >= 70 ? '#22c55e' :
      score >= 40 ? '#f59e0b' :
      '#ef4444';
  }, 80);

  $('scoreNum').textContent = score;

  $('riskTitle').textContent =
    score >= 70 ? 'Low Risk' :
    score >= 40 ? 'Moderate Risk' :
    'High Risk';

  $('riskBadge').textContent =
    score >= 70 ? 'SAFE' :
    score >= 40 ? 'WARNING' :
    'DANGER';

  $('cHigh').textContent = high;
  $('cMed').textContent = med;
  $('cLow').textContent = low;
  $('cInfo').textContent = inf;

  $('urlDisplay').textContent = raw;

  /* FINDINGS */
  $('findingsList').innerHTML = '';
  findings.forEach(f => {
    const row = document.createElement('div');
    row.className = 'p-3 border-b border-zinc-800';
    row.innerHTML = `<b>${f.title}</b><br><span>${f.desc}</span>`;
    $('findingsList').appendChild(row);
  });

  /* HEADERS UI (RESTORED) */
  $('headerList').innerHTML = headers.map(h => `
    <div class="flex justify-between py-2 border-b border-zinc-800">
      <span class="font-mono text-[12px] text-zinc-300">${h.name}</span>
      <span class="font-mono text-[11px] ${h.present ? 'text-green-400' : 'text-red-400'}">
        ${h.present ? 'PRESENT' : 'MISSING'}
      </span>
    </div>
  `).join('');

  /* URL breakdown */
  $('urlBreakdown').innerHTML = '';
  Object.entries(info).forEach(([k, v]) => {
    const div = document.createElement('div');
    div.className = 'bg-zinc-950 p-3 border border-zinc-800 rounded';
    div.innerHTML = `<div>${k}</div><div>${v}</div>`;
    $('urlBreakdown').appendChild(div);
  });

  renderOSINT(apiData);

  $('resultsView').classList.remove('hidden');
}

/* ENTER KEY */
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});