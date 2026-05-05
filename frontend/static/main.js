const API_BASE = 'http://127.0.0.1:8000';
const sleep = ms => new Promise(r => setTimeout(r, ms));

const ICONS = {
  router:  c=>`<path d="M-8 2 Q0-6 8 2" fill="none" stroke="${c}" stroke-width="1.5" stroke-linecap="round"/><path d="M-11 5 Q0-10 11 5" fill="none" stroke="${c}" stroke-width="1.3" stroke-linecap="round" opacity=".55"/><circle cx="0" cy="4" r="2.2" fill="${c}"/>`,
  laptop:  c=>`<rect x="-7" y="-4" width="14" height="9" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><line x1="-9" y1="5" x2="9" y2="5" stroke="${c}" stroke-width="1.3" stroke-linecap="round"/>`,
  phone:   c=>`<rect x="-4" y="-7" width="8" height="14" rx="2" fill="none" stroke="${c}" stroke-width="1.3"/><circle cx="0" cy="5" r="1" fill="${c}"/>`,
  tablet:  c=>`<rect x="-6" y="-7" width="12" height="14" rx="2" fill="none" stroke="${c}" stroke-width="1.3"/><circle cx="0" cy="5.5" r="1" fill="${c}"/>`,
  desktop: c=>`<rect x="-7" y="-6" width="14" height="10" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><line x1="0" y1="4" x2="0" y2="7" stroke="${c}" stroke-width="1.3" stroke-linecap="round"/><line x1="-3" y1="7" x2="3" y2="7" stroke="${c}" stroke-width="1.3" stroke-linecap="round"/>`,
  printer: c=>`<rect x="-7" y="-2" width="14" height="8" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><rect x="-4" y="-7" width="8" height="5" rx="1" fill="none" stroke="${c}" stroke-width="1.1"/><line x1="-4" y1="2" x2="4" y2="2" stroke="${c}" stroke-width="1" stroke-linecap="round" opacity=".6"/>`,
  tv:      c=>`<rect x="-8" y="-6" width="16" height="11" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><line x1="-2" y1="5" x2="-4" y2="8" stroke="${c}" stroke-width="1.2" stroke-linecap="round"/><line x1="2" y1="5" x2="4" y2="8" stroke="${c}" stroke-width="1.2" stroke-linecap="round"/>`,
  nas:     c=>`<rect x="-7" y="-6" width="14" height="12" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><line x1="-4" y1="-2" x2="4" y2="-2" stroke="${c}" stroke-width="1" stroke-linecap="round"/><line x1="-4" y1="1" x2="4" y2="1" stroke="${c}" stroke-width="1" stroke-linecap="round"/><circle cx="-5.5" cy="-2" r=".8" fill="${c}"/><circle cx="-5.5" cy="1" r=".8" fill="${c}"/>`,
  unknown: c=>`<text x="0" y="5" text-anchor="middle" style="font-size:13px;fill:${c};font-family:'Geist',sans-serif">?</text>`,
};

function resolveIcon(type, vendor) {
  const t = (type||'').toLowerCase(), v = (vendor||'').toLowerCase();
  if(t.includes('router')||t.includes('gateway')||t.includes('network device')) return 'router';
  if(t.includes('phone')||t.includes('mobile')||t.includes('android')||t.includes('iphone')) return 'phone';
  if(t.includes('tablet')||t.includes('ipad')) return 'tablet';
  if(t.includes('laptop')||t.includes('notebook')||t.includes('macbook')) return 'laptop';
  if(t.includes('desktop')||t.includes('workstation')||t.includes('pc')) return 'desktop';
  if(t.includes('printer')) return 'printer';
  if(t.includes('tv')||t.includes('television')||t.includes('smart tv')) return 'tv';
  if(t.includes('nas')||t.includes('storage')||t.includes('synology')) return 'nas';
  if(v.includes('apple')) return 'phone';
  if(v.includes('samsung')||v.includes('xiaomi')) return 'phone';
  if(v.includes('canon')||v.includes('epson')) return 'printer';
  if(v.includes('sony')||v.includes('lg')) return 'tv';
  return 'unknown';
}

function isUnknown(d) {
  return resolveIcon(d.type, d.vendor) === 'unknown' || (d.type||'').toLowerCase().includes('unknown');
}

function nodeColor(d, clicked) {
  if(d._you) return '#10b981';
  if(clicked) return '#10b981';
  const t = (d.type||'').toLowerCase();
  if(t.includes('router')||t.includes('gateway')) return '#3b82f6';
  if(isUnknown(d)) return '#ef4444';
  return '#6b7280';
}

const CX = 320, CY = 195;
function getPositions(count){const out=[];for(let i=0;i<count;i++){const a=(i/count)*Math.PI*2-Math.PI/2;out.push({x:Math.round(CX+Math.cos(a)*148),y:Math.round(CY+Math.sin(a)*140)});}return out;}

const $ = id => document.getElementById(id);

function setUrl(u) { $('urlInput').value = u; }

function resetAll() {
  $('urlInput').value = '';
  $('inputCard').style.display = 'block';
  $('scanView').style.display = 'none';
  $('resultsView').style.display = 'none';
  $('netScanView').style.display = 'none';
}

function flashInput() {
  const inp = $('urlInput');
  inp.style.borderColor = '#ef4444';
  inp.style.boxShadow = '0 0 0 2px rgba(239,68,68,.2)';
  setTimeout(() => { inp.style.borderColor = '#27272a'; inp.style.boxShadow = ''; }, 900);
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
  $('inputCard').style.display = 'none';
  $('resultsView').style.display = 'none';
  $('netScanView').style.display = 'none';
  $('scanView').style.display = 'block';

  $('scanTarget').textContent = parsed.hostname;
  $('scanBars').innerHTML = '';
  $('termLines').innerHTML = '';

  const barDefs = [
    {label:'DNS resolution',  key:'dns',  dur:600},
    {label:'SSL certificate', key:'ssl',  dur:900},
    {label:'HTTP headers',    key:'hdr',  dur:1100},
    {label:'URL analysis',    key:'url2', dur:500},
    {label:'Threat intelligence', key:'ti', dur:1400},
    {label:'Scanning Ports', key:'sp', dur:1700},
  ];

  barDefs.forEach(b => {
    const el = document.createElement('div');
    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
        <span class="mono" style="font-size:11px;color:#71717a">${b.label}</span>
        <span id="bar-lbl-${b.key}" class="mono" style="font-size:10px;color:#3f3f46">—</span>
      </div>
      <div style="height:2px;background:#27272a;border-radius:1px">
        <div id="bar-${b.key}" style="height:100%;width:0;background:#3b82f6;border-radius:1px;transition:width ${b.dur}ms ease"></div>
      </div>`;
    $('scanBars').appendChild(el);
  });

  function log(txt, active = false) {
    const d = document.createElement('div');
    d.textContent = `> ${txt}`;
    d.className = 'mono';
    d.style.cssText = `font-size:10px;color:${active ? '#a1a1aa' : '#52525b'}`;
    $('termLines').appendChild(d);
  }

  const apiPromise = fetch(`${API_BASE}/scans/`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: raw})
  });

  const terms = [
    `Resolving ${parsed.hostname}`,
    'Connecting to host...',
    'Parsing TLS certificate...',
    'Checking headers...',
    'Running pattern match...',
    'Cross-referencing threat DB...',
    'Building report...'
  ];

  let delay = 200;
  barDefs.forEach((b, i) => {
    setTimeout(() => {
      if (i < terms.length) log(terms[i], true);
      $('bar-' + b.key).style.width = '100%';
    }, delay);
    setTimeout(() => {
      const el = $('bar-lbl-' + b.key);
      el.textContent = 'done';
      el.style.color = '#10b981';
    }, delay + b.dur);
    delay += b.dur + 100;
  });

  const totalAnimTime = barDefs.reduce((a, b) => a + b.dur + 100, 200) + 300;

  try {
    const [, response] = await Promise.all([
      sleep(totalAnimTime),
      apiPromise
    ]);

    if (!response.ok) throw new Error(`Server error: ${response.status}`);
    const apiData = await response.json();

    log('Scan complete.');
    await sleep(200);

    $('scanView').style.display = 'none';
    renderResults(parsed, raw, apiData);

  } catch (err) {
    log(`Error: ${err.message}`, true);
    await sleep(600);
    $('scanView').style.display = 'none';
    $('inputCard').style.display = 'block';
    flashInput();
  } finally {
    $('scanBtn').disabled = false;
  }
}

function buildResults(url, raw, apiData) {
  const findings = [];
  const isHttps = url.protocol === 'https:';

  if (!isHttps) {
    findings.push({sev:'critical', title:'No HTTPS encryption', desc:'Traffic is transmitted in plaintext, exposing users to MITM attacks.', ref:'CWE-319'});
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
    findings.push({sev:'critical', title:'Raw IP address as host', desc:'Direct IP usage is atypical for legitimate services.', ref:'OWASP A05'});
  }

  if (!apiData.ssl?.ssl_valid) {
    findings.push({sev:'critical', title:'Invalid SSL certificate', desc:apiData.ssl?.error || 'SSL certificate could not be validated.', ref:'TLS'});
  } else if (isHttps) {
    findings.push({sev:'info', title:'HTTPS enabled', desc:`TLS is present. Certificate expires in ${apiData.ssl?.expires_in_days ?? '?'} days.`, ref:'TLS OK'});
  }

  if (!apiData.dns?.dns_resolves) {
    findings.push({sev:'critical', title:'DNS resolution failed', desc:apiData.dns?.error || 'Could not resolve hostname.', ref:'DNS'});
  }

  const lh = url.hostname.toLowerCase(), lp = url.pathname.toLowerCase(), lq = url.search.toLowerCase();
  const phishWords = ['login','secure','verify','account','update','confirm','paypal','apple','microsoft','amazon','bank'];
  const phishMatches = phishWords.filter(w => lh.includes(w));
  if (phishMatches.length >= 2) {
    findings.push({sev:'critical', title:'High phishing probability', desc:`Domain contains ${phishMatches.length} suspicious keywords: ${phishMatches.join(', ')}.`, ref:'PHISH'});
  } else if (phishMatches.length === 1) {
    findings.push({sev:'warning', title:'Potential phishing keyword', desc:`Domain contains suspicious keyword: ${phishMatches[0]}.`, ref:'PHISH'});
  }

  const suspTLDs = ['.xyz','.top','.click','.loan','.work','.tk','.ml','.ga'];
  const badTld = suspTLDs.find(t => lh.endsWith(t));
  if (badTld) findings.push({sev:'warning', title:'High-risk TLD', desc:`"${badTld}" is commonly associated with malicious infrastructure.`, ref:'TLD'});

  if (lp.includes('<script') || lq.includes('<script') || lq.includes('alert(')) {
    findings.push({sev:'critical', title:'XSS payload detected', desc:'Script injection pattern found in URL path or query string.', ref:'XSS'});
  }

  if (lq.includes('redirect=') || lq.includes('url=') || lq.includes('next=')) {
    findings.push({sev:'warning', title:'Open redirect parameter', desc:'Query string contains a redirect parameter exploitable for phishing.', ref:'REDIRECT'});
  }

  const hdrDefs = [
    {name:'Content-Security-Policy',    key:'content-security-policy'},
    {name:'Strict-Transport-Security',  key:'strict-transport-security'},
    {name:'X-Frame-Options',            key:'x-frame-options'},
    {name:'X-Content-Type-Options',     key:'x-content-type-options'},
    {name:'Referrer-Policy',            key:'referrer-policy'},
    {name:'Permissions-Policy',         key:'permissions-policy'},
  ];

  const missingHeaders = [];
  const headers = hdrDefs.map(h => {
    const present = !!apiData.headers?.[h.key];
    if (!present) missingHeaders.push(h.name);
    return {name: h.name, present};
  });
  if (missingHeaders.length > 0) {
    const sev = missingHeaders.length >= 4 ? 'warning' : 'low';
    findings.push({
      sev,
      title: `${missingHeaders.length} security header${missingHeaders.length > 1 ? 's' : ''} missing`,
      desc: missingHeaders.join(', '),
      ref: 'HEADERS'
    });
  }

  const whois = apiData.osint?.whois || {};
  const rep   = apiData.osint?.reputation || {};
  const srv   = apiData.osint?.server || apiData.osint?.server_info || {};

  if (whois.org) findings.push({sev:'info', title:'Hosting provider identified', desc:`${whois.org} (ASN ${whois.asn || '—'})`, ref:'OSINT'});
  if (whois.risk_flag) findings.push({sev:'warning', title:'Suspicious registrant data', desc:'WHOIS data contains risk indicators.', ref:'WHOIS'});
  if (srv.risk_flag) findings.push({sev:'warning', title:'Server fingerprinting risk', desc:srv.risk_reason || 'Server version exposed in headers.', ref:'Fingerprinting'});
  if (rep.risk_flag || rep.is_proxy) findings.push({sev:'warning', title:'Proxy / VPN / suspicious IP detected', desc:'The server IP is flagged by reputation intelligence.', ref:'OSINT'});

  findings.push({sev:'info', title:'Scan complete', desc:`Analyzed ${raw.length} characters against multiple threat categories.`, ref:'—'});

  const high = findings.filter(f => f.sev === 'critical').length;
  const med  = findings.filter(f => f.sev === 'warning').length;
  const low  = findings.filter(f => f.sev === 'low').length;
  const inf  = findings.filter(f => f.sev === 'info').length;
  const score = Math.max(0, Math.min(100, 100 - high*22 - med*10 - low*4));

  const osint = [
    {label:'IP Address', value: apiData.dns?.ip || whois.ip || '—'},
    {label:'ASN',        value: whois.asn || '—'},
    {label:'Org / Hosting', value: whois.org || rep.isp || '—'},
    {label:'Country',    value: whois.country || rep.country || '—'},
    {label:'Proxy / VPN', value: (rep.is_proxy || rep.risk_flag) ? 'Yes ⚠' : 'No'},
    {label:'Server',     value: srv.server || apiData.headers?.['server'] || '—'},
    {label:'Risk level', value: apiData.risk_level || '—'},
    {label:'SSL days',   value: apiData.ssl?.ssl_valid ? `${apiData.ssl.expires_in_days} days` : 'Invalid'},
  ];

  const breakdown = [
    {label:'Protocol', value: url.protocol},
    {label:'Hostname', value: url.hostname},
    {label:'Path',     value: url.pathname},
    {label:'Query',    value: url.search},
    {label:'Port',     value: url.port || '(default)'},
    {label:'URL length', value: raw.length + ' chars'},
  ];

  return {score, findings, counts:{high,med,low,inf}, headers, osint, breakdown};
}

function renderPorts(apiData) {
  const container = $('portList');
  if (!container) return;

  const ports = apiData?.port_scans || [];

  container.innerHTML = '';

  if (ports.length === 0) {
    container.innerHTML = `
      <div style="color:#71717a;font-size:12px">No ports detected</div>
    `;
    return;
  }

  ports.forEach(p => {
    const el = document.createElement('div');

    const color = p.open ? '#10b981' : '#ef4444';
    const status = p.open ? 'OPEN' : 'CLOSED';

    el.style.cssText = `
      display:flex;
      justify-content:space-between;
      align-items:center;
      padding:10px 12px;
      background:#09090b;
      border:.5px solid #27272a;
      border-radius:8px;
    `;

    el.innerHTML = `
      <div style="display:flex;gap:10px;align-items:center">
        <span class="mono" style="color:#fafafa;font-size:12px">:${p.port}</span>
        <span style="font-size:12px;color:#71717a">${p.label}</span>
      </div>

      <div style="display:flex;align-items:center;gap:6px">
        <div style="width:6px;height:6px;border-radius:50%;background:${color}"></div>
        <span class="mono" style="font-size:10px;color:${color}">${status}</span>
      </div>
    `;

    container.appendChild(el);
  });
}

function renderResults(parsed, raw, apiData) {
  renderPorts(apiData);
  const {score, findings, counts, headers, osint, breakdown} = buildResults(parsed, raw, apiData);

  const arc = $('ringArc');
  setTimeout(() => {
    arc.style.strokeDashoffset = 207.3 * (1 - score / 100);
    arc.style.stroke = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#ef4444';
  }, 80);
  $('scoreNum').textContent = score;

  const backendRisk = (apiData.risk_level || '').toLowerCase();
  const riskLevel = backendRisk === 'high' ? 'high' : backendRisk === 'medium' ? 'medium' : backendRisk === 'low' ? 'low'
    : score >= 70 ? 'low' : score >= 40 ? 'medium' : 'high';
  const riskLabel = score >= 70 ? 'Low Risk' : score >= 40 ? 'Moderate Risk' : 'High Risk';
  const badgeCfg = {
    low:    {bg:'rgba(16,185,129,.12)',  color:'#10b981', border:'rgba(16,185,129,.3)',  text:'SAFE'},
    medium: {bg:'rgba(245,158,11,.12)', color:'#f59e0b', border:'rgba(245,158,11,.3)', text:'WARNING'},
    high:   {bg:'rgba(239,68,68,.12)',  color:'#ef4444', border:'rgba(239,68,68,.3)',  text:'DANGER'},
  };
  const bc = badgeCfg[riskLevel];

  $('riskTitle').textContent = riskLabel;
  const rb = $('riskBadge');
  rb.textContent = bc.text;
  rb.style.cssText = `font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:${bc.bg};color:${bc.color};border:.5px solid ${bc.border}`;

  function buildSummary(riskLevel, findings, apiData) {
    const criticals = findings.filter(f => f.sev === 'critical').map(f => f.title);
    const warnings  = findings.filter(f => f.sev === 'warning').map(f => f.title);
    const ssl       = apiData.ssl || {};
    const dns       = apiData.dns || {};
    const parts     = [];

    if (riskLevel === 'low') {
      parts.push('No critical issues detected.');
      if (ssl.ssl_valid && ssl.expires_in_days > 30) parts.push(`SSL valid for ${ssl.expires_in_days} days.`);
      const missingHdrs = findings.filter(f => f.sev === 'low' && f.title.startsWith('Missing header')).length;
      if (missingHdrs > 0) parts.push(`${missingHdrs} security header${missingHdrs > 1 ? 's' : ''} missing.`);
      return parts.join(' ');
    }

    if (riskLevel === 'medium') {
      if (warnings.length > 0) parts.push(warnings.slice(0,2).join('; ') + '.');
      const missingHdrs = findings.filter(f => f.sev === 'low' && f.title.startsWith('Missing header')).length;
      if (missingHdrs >= 3) parts.push(`${missingHdrs} of 6 security headers absent.`);
      if (ssl.expires_in_days && ssl.expires_in_days < 30) parts.push(`SSL expires in ${ssl.expires_in_days} days.`);
      return parts.length ? parts.join(' ') : 'Moderate risk — review findings before proceeding.';
    }

    if (criticals.length > 0) parts.push(criticals.slice(0,2).join('; ') + '.');
    if (!dns.dns_resolves) parts.push('Domain does not resolve.');
    if (!ssl.ssl_valid) parts.push('SSL certificate invalid.');
    return parts.length ? parts.join(' ') : 'Multiple high-risk indicators detected.';
  }
  $('summaryText').textContent = buildSummary(riskLevel, findings, apiData);
  $('urlDisplay').textContent = raw;

  $('cHigh').textContent = counts.high;
  $('cMed').textContent  = counts.med;
  $('cLow').textContent  = counts.low;
  $('cInfo').textContent = counts.inf;

  // Findings
  $('findingsCount').textContent = findings.length + ' findings';
  const sevCfg = {
    critical: {dot:'#ef4444', bg:'rgba(239,68,68,.07)',   label:'Critical'},
    warning:  {dot:'#f59e0b', bg:'rgba(245,158,11,.07)',  label:'Warning'},
    low:      {dot:'#a1a1aa', bg:'rgba(161,161,170,.07)', label:'Low'},
    info:     {dot:'#60a5fa', bg:'rgba(96,165,250,.07)',  label:'Info'},
  };
  $('findingsList').innerHTML = findings.map(f => {
    const c = sevCfg[f.sev] || sevCfg.info;
    return `<div style="padding:12px 16px;border-bottom:.5px solid rgba(39,39,42,.6);background:${c.bg}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
        <span style="width:6px;height:6px;border-radius:50%;background:${c.dot};flex-shrink:0"></span>
        <span style="font-size:12px;font-weight:500;color:#e4e4e7;flex:1">${f.title}</span>
        <span class="mono" style="font-size:10px;color:${c.dot}">${c.label}</span>
      </div>
      <div style="font-size:11px;color:#71717a;padding-left:14px">${f.desc}</div>
    </div>`;
  }).join('');

  const presentCount = headers.filter(h => h.present).length;
  const hdrLabel = presentCount >= 5 ? 'Strong' : presentCount >= 3 ? 'Moderate' : 'Weak';
  const hdrEl = $('hdrScore');
  hdrEl.textContent = hdrLabel;
  hdrEl.style.cssText = presentCount >= 5
    ? 'font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:\'Geist Mono\',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(16,185,129,.1);color:#10b981;border:.5px solid rgba(16,185,129,.3)'
    : presentCount >= 3
    ? 'font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:\'Geist Mono\',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(245,158,11,.1);color:#f59e0b;border:.5px solid rgba(245,158,11,.3)'
    : 'font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:\'Geist Mono\',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(239,68,68,.1);color:#ef4444;border:.5px solid rgba(239,68,68,.3)';

  $('headerList').innerHTML = headers.map(h =>
    `<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:.5px solid rgba(39,39,42,.5)">
      <span class="mono" style="font-size:11px;color:${h.present?'#a1a1aa':'#52525b'}">${h.name}</span>
      <span style="font-size:10px;padding:1px 6px;border-radius:3px;${h.present?'background:rgba(16,185,129,.1);color:#10b981':'background:rgba(239,68,68,.1);color:#ef4444'}">${h.present?'present':'missing'}</span>
    </div>`
  ).join('');

  $('osintGrid').innerHTML = osint.map(o =>
    `<div style="background:#27272a;border-radius:8px;padding:10px 12px">
      <div style="font-size:10px;color:#71717a;margin-bottom:3px">${o.label}</div>
      <div class="mono" style="font-size:12px;color:#e4e4e7;word-break:break-all">${o.value}</div>
    </div>`
  ).join('');

  $('urlBreakdown').innerHTML = breakdown.map(b =>
    `<div style="background:#27272a;border-radius:8px;padding:10px 12px">
      <div style="font-size:10px;color:#71717a;margin-bottom:3px">${b.label}</div>
      <div class="mono" style="font-size:12px;color:#e4e4e7;word-break:break-all">${b.value||'—'}</div>
    </div>`
  ).join('');

  $('resultsView').style.display = 'block';
}

const SCAN = {
  local_ip: '192.168.100.115',
  subnet:   '192.168.100.0/24',
  devices: [
    {ip:'192.168.100.1',   type:'Router',  vendor:'Huawei Technologies'},
    {ip:'192.168.100.115', type:'Laptop',  vendor:'—', _you:true},
    {ip:'192.168.100.55',  type:'Phone',   vendor:'Samsung Electronics'},
    {ip:'192.168.100.61',  type:'Unknown', vendor:'Unknown'},
    {ip:'192.168.100.73',  type:'Phone',   vendor:'Apple'},
    {ip:'192.168.100.15',  type:'Desktop', vendor:'Unknown'},
  ]
};

function runNetworkScan() {
  // Reset state
  $('netError').style.display = 'none';
  $('netDeviceList').style.display = 'none';
  $('netDeviceList').innerHTML = '';
  $('netLocalIp').style.display = 'none';
  $('netDeviceCount').style.display = 'none';
  $('netMapContainer').style.display = 'none';
  $('netSubnet').textContent = '';
  $('detail-card').style.display = 'none';

  $('inputCard').style.display = 'none';
  $('scanView').style.display = 'none';
  $('resultsView').style.display = 'none';
  $('netScanView').style.display = 'block';

  $('netSpinner').style.display = 'block';
  $('netScanPlaceholder').style.display = 'flex';
  $('netSubnet').textContent = SCAN.subnet;

  setTimeout(() => {
    $('netSpinner').style.display = 'none';
    $('netScanPlaceholder').style.display = 'none';

    $('netLocalIpVal').textContent = SCAN.local_ip;
    $('netLocalIp').style.display = 'flex';

    const countEl = $('netDeviceCount');
    countEl.textContent = SCAN.devices.length + ' devices';
    countEl.style.display = 'inline';

    const list = $('netDeviceList');
    list.innerHTML = SCAN.devices.map(d => {
      const isYou = !!d._you;
      const isGw  = d.type.toLowerCase().includes('router');
      const iconKey = resolveIcon(d.type, d.vendor);
      const color = nodeColor(d, false);
      const svgIcon = `<svg width="14" height="14" viewBox="-8 -8 16 16">${(ICONS[iconKey]||ICONS.unknown)(color)}</svg>`;
      return `<div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:.5px solid rgba(39,39,42,.6);cursor:pointer;transition:background .12s" onmouseover="this.style.background='rgba(39,39,42,.4)'" onmouseout="this.style.background='transparent'" onclick="showCard(SCAN.devices[${SCAN.devices.indexOf(d)}])">
        ${svgIcon}
        <div style="flex:1;min-width:0">
          <div class="mono" style="font-size:12px;color:${isYou?'#10b981':isGw?'#60a5fa':'#e4e4e7'}">${d.ip}</div>
          <div style="font-size:11px;color:#71717a;margin-top:1px">${(d.vendor&&d.vendor!=='Unknown'&&d.vendor!=='—')?d.vendor:'Unknown vendor'} · ${d.type}</div>
        </div>
        ${isYou?`<span class="mono" style="font-size:10px;padding:2px 6px;background:rgba(16,185,129,.12);color:#10b981;border-radius:4px;border:.5px solid rgba(16,185,129,.3)">you</span>`:''}
        ${isGw?`<span class="mono" style="font-size:10px;padding:2px 6px;background:rgba(59,130,246,.12);color:#60a5fa;border-radius:4px;border:.5px solid rgba(59,130,246,.3)">gateway</span>`:''}
      </div>`;
    }).join('');
    list.style.display = 'flex';

    $('mapSubnet').textContent = SCAN.subnet;
    $('mapDevCount').textContent = SCAN.devices.length + ' devices';
    $('netMapContainer').style.display = 'block';
    renderMap(SCAN.devices);
  }, 1500);
}

const _lineRefs = new Map();
const _nodeRefs = new Map();

function renderMap(devices) {
  const svg = $('netsvg');
  while (svg.children.length > 2) svg.removeChild(svg.lastChild);
  _lineRefs.clear();
  _nodeRefs.clear();

  const router = devices.find(d => resolveIcon(d.type, d.vendor) === 'router');
  const others = devices.filter(d => d !== router);
  const positions = getPositions(others.length);

  others.forEach((d, i) => {
    const pos = positions[i];
    const isYou = !!d._you;
    const unk = isUnknown(d);
    const lineColor = isYou ? '#10b981' : unk ? '#ef4444' : '#4b5563';
    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', CX); line.setAttribute('y1', CY);
    line.setAttribute('x2', pos.x); line.setAttribute('y2', pos.y);
    line.setAttribute('class', isYou ? 'edge-you' : 'edge');
    line.setAttribute('stroke', lineColor);
    line.setAttribute('stroke-width', isYou || unk ? '1.5' : '1');
    line.setAttribute('opacity', isYou ? '.7' : unk ? '.6' : '.4');
    svg.appendChild(line);
    _lineRefs.set(d.ip, line);
  });

  if (router) drawNode(svg, router, CX, CY, true);
  others.forEach((d, i) => {
    const pos = positions[i];
    drawNode(svg, d, pos.x, pos.y, false);
  });

  buildMapLegend(devices);
}
const _clickedIp = {current: null};

function resetNode(ip) {
  const refs = _nodeRefs.get(ip);
  if (!refs) return;
  const d = SCAN.devices.find(x => x.ip === ip);
  if (!d || d._you) return;
  const orig = nodeColor(d, false);
  refs.bg.setAttribute('stroke', orig);
  refs.ring.setAttribute('fill', orig);
  refs.iconG.innerHTML = (ICONS[refs.iconKey]||ICONS.unknown)(orig);
  refs.ipText.setAttribute('fill', isUnknown(d) ? '#ef4444' : '#71717a');
  const line = _lineRefs.get(ip);
  if (line) {
    line.setAttribute('stroke', isUnknown(d) ? '#ef4444' : '#4b5563');
    line.setAttribute('stroke-width', isUnknown(d) ? '1.5' : '1');
    line.setAttribute('opacity', isUnknown(d) ? '.6' : '.4');
    line.setAttribute('class', 'edge');
  }
}

function recolorNode(d) {
  // reset previously clicked node back to original color
  if (_clickedIp.current && _clickedIp.current !== d.ip) {
    resetNode(_clickedIp.current);
  }
  // if clicking the same node again, toggle it off
  if (_clickedIp.current === d.ip) {
    resetNode(d.ip);
    _clickedIp.current = null;
    return;
  }
  _clickedIp.current = d.ip;
  const green = '#10b981';
  const refs = _nodeRefs.get(d.ip);
  if (!refs) return;
  refs.bg.setAttribute('stroke', green);
  refs.ring.setAttribute('fill', green);
  refs.iconG.innerHTML = (ICONS[refs.iconKey]||ICONS.unknown)(green);
  refs.ipText.setAttribute('fill', green);
  const line = _lineRefs.get(d.ip);
  if (line) {
    line.setAttribute('stroke', green);
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('opacity', '.7');
    line.setAttribute('class', 'edge-you');
  }
}

function drawNode(svg, d, x, y, isRouter) {
  const color = nodeColor(d, false), iconKey = resolveIcon(d.type, d.vendor), isYou = !!d._you;
  const r = isRouter ? 22 : 16, labelY = y + r + 14, subY = labelY + 11;
  const g = document.createElementNS('http://www.w3.org/2000/svg','g');
  g.setAttribute('class','node-g');
  g.addEventListener('click', () => {
    if (!isRouter && !isYou && !isUnknown(d)) recolorNode(d);
    showCard(d);
  });

  if (isRouter) {
    const ping = document.createElementNS('http://www.w3.org/2000/svg','circle');
    ping.setAttribute('cx',x); ping.setAttribute('cy',y); ping.setAttribute('r','6');
    ping.setAttribute('fill','none'); ping.setAttribute('stroke',color);
    ping.setAttribute('stroke-width','0.8'); ping.setAttribute('opacity','.35');
    ping.setAttribute('class','ping');
    g.appendChild(ping);
  }

  const ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
  ring.setAttribute('cx',x); ring.setAttribute('cy',y); ring.setAttribute('r',String(r-4));
  ring.setAttribute('fill',color); ring.setAttribute('opacity','.1'); ring.setAttribute('class','ring');
  g.appendChild(ring);

  const bg = document.createElementNS('http://www.w3.org/2000/svg','circle');
  bg.setAttribute('cx',x); bg.setAttribute('cy',y); bg.setAttribute('r',String(r));
  bg.setAttribute('fill','#18181b'); bg.setAttribute('stroke',color);
  bg.setAttribute('stroke-width', isRouter||isYou ? '1.5' : '0.8');
  g.appendChild(bg);

  const iconG = document.createElementNS('http://www.w3.org/2000/svg','g');
  iconG.setAttribute('transform',`translate(${x},${y})`);
  iconG.innerHTML = (ICONS[iconKey]||ICONS.unknown)(color);
  g.appendChild(iconG);

  const ipText = document.createElementNS('http://www.w3.org/2000/svg','text');
  ipText.setAttribute('x',x); ipText.setAttribute('y',labelY); ipText.setAttribute('text-anchor','middle');
  ipText.style.cssText = `font-size:9px;font-family:'Geist Mono',monospace`;
  ipText.setAttribute('fill', isYou ? '#10b981' : isUnknown(d) ? '#ef4444' : '#71717a');
  ipText.textContent = '.' + d.ip.split('.').pop();
  g.appendChild(ipText);

  if (isYou || isRouter) {
    const sub = document.createElementNS('http://www.w3.org/2000/svg','text');
    sub.setAttribute('x',x); sub.setAttribute('y',subY); sub.setAttribute('text-anchor','middle');
    sub.style.cssText = `font-size:9px;fill:${color};font-weight:500`;
    sub.textContent = isYou ? 'you' : 'gateway';
    g.appendChild(sub);
  }

  _nodeRefs.set(d.ip, {bg, ring, iconG, ipText, iconKey});

  svg.appendChild(g);
}

function buildMapLegend(devices) {
  const seen = new Set(), items = [];
  devices.forEach(d => {
    const k = resolveIcon(d.type, d.vendor);
    if (!seen.has(k)) {
      seen.add(k);
      items.push({key:k, label:k.charAt(0).toUpperCase()+k.slice(1), color:nodeColor(d,false)});
    }
  });
  $('legendItems').innerHTML = '<span style="margin-right:4px">Icons:</span>' +
    items.map(it => `<span style="display:flex;align-items:center;gap:2px"><svg width="16" height="16" viewBox="-8 -8 16 16">${(ICONS[it.key]||ICONS.unknown)(it.color)}</svg>${it.label}</span>`).join('');
  $('map-legend').innerHTML = [
    {color:'#3b82f6', label:'Gateway'},
    {color:'#10b981', label:'This machine'},
    {color:'#6b7280', label:'Other device'}
  ].map(l => `<span style="display:flex;align-items:center;gap:5px;font-size:11px;color:#71717a"><span style="width:10px;height:10px;border-radius:50%;border:1.5px solid ${l.color};display:inline-block"></span>${l.label}</span>`).join('');
}

function showCard(d) {
  const color = nodeColor(d, false);
  $('dc-ip').textContent = d.ip;
  $('dc-dot').style.background = color;
  const badge = $('dc-badge');
  badge.textContent = d.type || 'Unknown';
  badge.style.cssText = `font-size:10px;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;background:${color}18;color:${color};border:.5px solid ${color}44`;
  $('dc-body').innerHTML = [['IP',d.ip],['MAC',d.mac||'—'],['Vendor',d.vendor||'—'],['Type',d.type||'Unknown']]
    .map(([k,v]) => `<span style="color:#71717a">${k}</span><span style="font-family:'Geist Mono',monospace;color:#fafafa;word-break:break-all">${v}</span>`).join('');
  const card = $('detail-card');
  card.style.display = 'block';
  card.style.animation = 'none';
  requestAnimationFrame(() => { card.style.animation = ''; });
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});