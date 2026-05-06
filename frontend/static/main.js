const API_BASE = 'http://127.0.0.1:8000';
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Topology node icon paths ────────────────────────────────────────────────
const TOPO_ICONS = {
  domain:   c=>`<circle cx="0" cy="0" r="6" fill="none" stroke="${c}" stroke-width="1.3"/><path d="M0-6Q3.5-2.5 3.5 0Q3.5 2.5 0 6" fill="none" stroke="${c}" stroke-width="1.1"/><path d="M0-6Q-3.5-2.5-3.5 0Q-3.5 2.5 0 6" fill="none" stroke="${c}" stroke-width="1.1"/><line x1="-6" y1="0" x2="6" y2="0" stroke="${c}" stroke-width="1.1"/><line x1="-5" y1="-3" x2="5" y2="-3" stroke="${c}" stroke-width=".9" opacity=".6"/><line x1="-5" y1="3" x2="5" y2="3" stroke="${c}" stroke-width=".9" opacity=".6"/>`,
  ports:    c=>`<rect x="-5" y="-6" width="10" height="12" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><circle cx="0" cy="1" r="2" fill="${c}" opacity=".6"/>`,
  tls:      c=>`<rect x="-4" y="-2" width="8" height="7" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><path d="M-3-2 L-3-4 Q-3-6 0-6 Q3-6 3-4 L3-2" fill="none" stroke="${c}" stroke-width="1.3" stroke-linecap="round"/>`,
  infra:    c=>`<rect x="-6" y="-6" width="12" height="5" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><rect x="-6" y="1" width="12" height="5" rx="1.5" fill="none" stroke="${c}" stroke-width="1.3"/><circle cx="-3.5" cy="-3.5" r=".9" fill="${c}"/><circle cx="-3.5" cy="3.5" r=".9" fill="${c}"/>`,
  threats:  c=>`<path d="M0-6 L5.2 3 L-5.2 3 Z" fill="none" stroke="${c}" stroke-width="1.3" stroke-linejoin="round"/><line x1="0" y1="-2" x2="0" y2="1" stroke="${c}" stroke-width="1.4" stroke-linecap="round"/><circle cx="0" cy="3.5" r=".8" fill="${c}"/>`,
  endpoints:c=>`<path d="M-6-4 L2-4 L6 0 L2 4 L-6 4 Z" fill="none" stroke="${c}" stroke-width="1.2"/><line x1="-3" y1="0" x2="2" y2="0" stroke="${c}" stroke-width="1.2" stroke-linecap="round"/>`,
};

// ─── Category colour ──────────────────────────────────────────────────────────
function categoryColor(kind, hasDanger) {
  switch (kind) {
    case 'domain':    return '#3b82f6';
    case 'ports':     return hasDanger ? '#ef4444' : '#6b7280';
    case 'tls':       return hasDanger ? '#ef4444' : '#6b7280';
    case 'infra':     return '#6b7280';
    case 'threats':   return '#ef4444';
    case 'endpoints': return '#6b7280';
    default:          return '#6b7280';
  }
}

// ─── Build GROUPED topology nodes ────────────────────────────────────────────
// findings is now passed in so threats node can show real warnings
function buildTopoNodes(parsed, raw, apiData, findings) {
  const nodes = [];

  // ── Root: Domain ──────────────────────────────────────────────────────────
  nodes.push({
    id: 'domain',
    kind: 'domain',
    label: parsed.hostname,
    sub: parsed.protocol.replace(':', ''),
    _root: true,
    items: [
      { label: 'URL',      value: raw },
      { label: 'Protocol', value: parsed.protocol },
      { label: 'Host',     value: parsed.hostname },
      { label: 'Port',     value: parsed.port || '(default)' },
    ],
  });

  // ── Ports ─────────────────────────────────────────────────────────────────
  const portScans = apiData.port_scans || [];
  if (portScans.length > 0) {
    const openPorts   = portScans.filter(p => p.open);
    const closedPorts = portScans.filter(p => !p.open);
    nodes.push({
      id: 'ports',
      kind: 'ports',
      label: 'Ports',
      sub: `${openPorts.length} open / ${closedPorts.length} closed`,
      _hasDanger: closedPorts.length > 0 && openPorts.length === 0,
      items: portScans.map(p => ({
        label: `:${p.port} ${p.label || ''}`.trim(),
        value: p.open ? 'OPEN' : 'CLOSED',
        valueColor: p.open ? '#10b981' : '#ef4444',
      })),
    });
  }

  // ── TLS / SSL ─────────────────────────────────────────────────────────────
  const ssl = apiData.ssl || {};
  const tlsItems = [
    { label: 'Valid',       value: ssl.ssl_valid ? 'Yes' : 'No', valueColor: ssl.ssl_valid ? '#10b981' : '#ef4444' },
    { label: 'Expires in',  value: ssl.expires_in_days ? `${ssl.expires_in_days} days` : '—' },
    { label: 'Protocol',    value: parsed.protocol },
    { label: 'Error',       value: ssl.error || 'None' },
  ];
  nodes.push({
    id: 'tls',
    kind: 'tls',
    label: 'TLS / SSL',
    sub: ssl.ssl_valid ? `valid · ${ssl.expires_in_days ?? '?'}d` : 'invalid',
    _hasDanger: !ssl.ssl_valid,
    items: tlsItems,
  });

  // ── Infrastructure ────────────────────────────────────────────────────────
  const whois = apiData.osint?.whois || {};
  const rep   = apiData.osint?.reputation || {};
  const srv   = apiData.osint?.server || apiData.osint?.server_info || {};
  const ip    = apiData.dns?.ip || whois.ip;
  const infraItems = [
    { label: 'IP Address', value: ip || '—' },
    { label: 'ASN',        value: whois.asn || '—' },
    { label: 'Org',        value: whois.org || rep.isp || '—' },
    { label: 'Country',    value: whois.country || rep.country || '—' },
    { label: 'Server',     value: srv.server || apiData.headers?.['server'] || '—' },
    { label: 'Proxy/VPN',  value: (rep.is_proxy || rep.risk_flag) ? 'Yes ⚠' : 'No', valueColor: (rep.is_proxy || rep.risk_flag) ? '#f59e0b' : undefined },
    { label: 'DNS resolves', value: apiData.dns?.dns_resolves ? 'Yes' : 'No', valueColor: apiData.dns?.dns_resolves ? '#10b981' : '#ef4444' },
    { label: 'Risk level', value: apiData.risk_level || '—' },
  ];
  nodes.push({
    id: 'infra',
    kind: 'infra',
    label: 'Infrastructure',
    sub: whois.org ? whois.org.split(' ')[0].substring(0, 12) : (ip || 'OSINT'),
    _hasDanger: !!(rep.is_proxy || rep.risk_flag || whois.risk_flag),
    items: infraItems,
  });

  // ── Threats ───────────────────────────────────────────────────────────────
  const lh = parsed.hostname.toLowerCase();
  const lq = (parsed.search || '').toLowerCase();
  const lp = (parsed.pathname || '').toLowerCase();
  const phishWords = ['login','secure','verify','account','update','confirm','paypal','apple','microsoft','amazon','bank'];
  const phishMatches = phishWords.filter(w => lh.includes(w));
  const hasXss = lp.includes('<script') || lq.includes('<script') || lq.includes('alert(');
  const hasRedirect = lq.includes('redirect=') || lq.includes('url=') || lq.includes('next=');
  const suspTLDs = ['.xyz','.top','.click','.loan','.work','.tk','.ml','.ga'];
  const badTld = suspTLDs.find(t => lh.endsWith(t));
  const isRawIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname);

  const threatItems = [];

  // URL-pattern checks
  threatItems.push({ label: 'Phishing keywords', value: phishMatches.length > 0 ? phishMatches.join(', ') : 'None', valueColor: phishMatches.length >= 2 ? '#ef4444' : phishMatches.length === 1 ? '#f59e0b' : '#10b981' });
  threatItems.push({ label: 'XSS pattern',       value: hasXss ? 'Detected ⚠' : 'Clean', valueColor: hasXss ? '#ef4444' : '#10b981' });
  threatItems.push({ label: 'Open redirect',     value: hasRedirect ? 'Detected ⚠' : 'None', valueColor: hasRedirect ? '#f59e0b' : '#10b981' });
  threatItems.push({ label: 'Suspicious TLD',    value: badTld ? `${badTld} ⚠` : 'None', valueColor: badTld ? '#f59e0b' : '#10b981' });
  threatItems.push({ label: 'Raw IP host',       value: isRawIp ? 'Yes ⚠' : 'No', valueColor: isRawIp ? '#ef4444' : '#10b981' });
  threatItems.push({ label: 'HTTPS',             value: parsed.protocol === 'https:' ? 'Yes' : 'No ⚠', valueColor: parsed.protocol === 'https:' ? '#10b981' : '#ef4444' });

  // ── Append real findings (critical + warning) from scan results ──
  if (findings && findings.length > 0) {
    const importantFindings = findings.filter(f => f.sev === 'critical' || f.sev === 'warning');
    if (importantFindings.length > 0) {
      threatItems.push({ label: '─── Findings ───', value: '', valueColor: '#3f3f46' });
      importantFindings.slice(0, 5).forEach(f => {
        threatItems.push({
          label: f.ref || f.sev.toUpperCase(),
          value: f.title,
          valueColor: f.sev === 'critical' ? '#ef4444' : '#f59e0b',
        });
      });
    }
  }

  // ── Append missing security headers ──
  const hdrKeys = ['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy','permissions-policy'];
  const hdrNames = ['CSP','HSTS','X-Frame-Options','X-Content-Type','Referrer-Policy','Permissions-Policy'];
  const missingHdrs = hdrKeys.filter(h => !apiData.headers?.[h]);
  if (missingHdrs.length > 0) {
    threatItems.push({ label: '─── Headers ───', value: '', valueColor: '#3f3f46' });
    missingHdrs.forEach((h, i) => {
      const idx = hdrKeys.indexOf(h);
      threatItems.push({
        label: hdrNames[idx] || h,
        value: 'MISSING',
        valueColor: '#ef4444',
      });
    });
  }

  const hasThreat = phishMatches.length >= 2 || hasXss || isRawIp;
  nodes.push({
    id: 'threats',
    kind: 'threats',
    label: 'Threats',
    sub: hasThreat ? 'risk detected' : 'no threats',
    _hasDanger: hasThreat,
    items: threatItems,
  });

  // ── Endpoints ─────────────────────────────────────────────────────────────
  const endpointItems = [
    { label: 'Path',       value: parsed.pathname || '/' },
    { label: 'Query',      value: parsed.search || '(none)' },
    { label: 'Hash',       value: parsed.hash || '(none)' },
    { label: 'URL length', value: raw.length + ' chars', valueColor: raw.length > 200 ? '#f59e0b' : undefined },
  ];
  if (hasRedirect) {
    const qp = new URLSearchParams(parsed.search);
    const rTarget = qp.get('redirect') || qp.get('url') || qp.get('next') || '—';
    endpointItems.push({ label: 'Redirect target', value: rTarget, valueColor: '#f59e0b' });
  }
  nodes.push({
    id: 'endpoints',
    kind: 'endpoints',
    label: 'Endpoints',
    sub: parsed.pathname !== '/' ? parsed.pathname.substring(0, 14) : '/',
    _hasDanger: hasRedirect,
    items: endpointItems,
  });

  return nodes;
}

// ─── SVG topology map renderer ───────────────────────────────────────────────
const TCX = 270, TCY = 178;

// Slightly irregular positions for a more organic, cyber feel
function getTopoPositions(count) {
  // Predefined offsets so it never looks like a boring clock face
  const angleOffsets = [0, 15, -10, 8, -5, 12, -8];
  const radiusJitter = [0, 8, -5, 10, -8, 5, -10];
  const out = [];
  for (let i = 0; i < count; i++) {
    const baseAngle = (i / count) * Math.PI * 2 - Math.PI / 2;
    const jitterDeg = ((angleOffsets[i % angleOffsets.length]) * Math.PI) / 180;
    const a = baseAngle + jitterDeg;
    const r = 128 + (radiusJitter[i % radiusJitter.length]);
    out.push({ x: Math.round(TCX + Math.cos(a) * r), y: Math.round(TCY + Math.sin(a) * (r * 0.88)) });
  }
  return out;
}

const _topoLineRefs = new Map();
const _topoNodeRefs = new Map();
const _clickedTopoId = { current: null };
let _currentTopoNodes = [];

function renderTopoMap(nodes) {
  const svg = document.getElementById('topoSvg');

  // Clear everything except the first 3 original defs children (dots pattern, bg gradient)
  while (svg.children.length > 3) svg.removeChild(svg.lastChild);
  _topoLineRefs.clear();
  _topoNodeRefs.clear();

  // ── Inject cyber defs (glow filters, grid pattern, sweep gradient) ──
  const cyberDefs = document.createElementNS('http://www.w3.org/2000/svg','defs');
  cyberDefs.innerHTML = `
    <pattern id="cyber-grid" x="0" y="0" width="32" height="32" patternUnits="userSpaceOnUse">
      <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#1c1c2e" stroke-width="0.6"/>
    </pattern>
    <radialGradient id="cyber-sweep" cx="50%" cy="52%" r="46%">
      <stop offset="0%" stop-color="#3b82f6" stop-opacity=".08"/>
      <stop offset="55%" stop-color="#3b82f6" stop-opacity=".02"/>
      <stop offset="100%" stop-color="#3b82f6" stop-opacity="0"/>
    </radialGradient>
    <filter id="glow-blue" x="-70%" y="-70%" width="240%" height="240%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-red" x="-70%" y="-70%" width="240%" height="240%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-green" x="-70%" y="-70%" width="240%" height="240%">
      <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>`;
  svg.appendChild(cyberDefs);

  // ── Dark background ──
  const bgFill = document.createElementNS('http://www.w3.org/2000/svg','rect');
  bgFill.setAttribute('x','0'); bgFill.setAttribute('y','0');
  bgFill.setAttribute('width','540'); bgFill.setAttribute('height','360');
  bgFill.setAttribute('fill','#0a0a0f');
  svg.appendChild(bgFill);

  // ── Dot grid ──
  const gridFill = document.createElementNS('http://www.w3.org/2000/svg','rect');
  gridFill.setAttribute('x','0'); gridFill.setAttribute('y','0');
  gridFill.setAttribute('width','540'); gridFill.setAttribute('height','360');
  gridFill.setAttribute('fill','url(#cyber-grid)');
  svg.appendChild(gridFill);

  // ── Radial sweep ──
  const sweepFill = document.createElementNS('http://www.w3.org/2000/svg','ellipse');
  sweepFill.setAttribute('cx', TCX); sweepFill.setAttribute('cy', TCY);
  sweepFill.setAttribute('rx','200'); sweepFill.setAttribute('ry','160');
  sweepFill.setAttribute('fill','url(#cyber-sweep)');
  svg.appendChild(sweepFill);

  // ── Orbit rings ──
  [[95, '3 8', '.5'], [148, '2 11', '.3']].forEach(([r, dash, op]) => {
    const ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
    ring.setAttribute('cx', TCX); ring.setAttribute('cy', TCY);
    ring.setAttribute('r', r); ring.setAttribute('fill','none');
    ring.setAttribute('stroke','#1e2d40'); ring.setAttribute('stroke-width','0.6');
    ring.setAttribute('stroke-dasharray', dash); ring.setAttribute('opacity', op);
    svg.appendChild(ring);
  });

  const root   = nodes.find(n => n._root);
  const others = nodes.filter(n => !n._root);
  const positions = getTopoPositions(others.length);

  // ── Edges first (drawn under nodes) ──
  others.forEach((node, i) => {
    const pos   = positions[i];
    const color = categoryColor(node.kind, node._hasDanger);
    const isDanger = node._hasDanger;

    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', TCX); line.setAttribute('y1', TCY);
    line.setAttribute('x2', pos.x); line.setAttribute('y2', pos.y);
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', isDanger ? '1.5' : '1');
    line.setAttribute('opacity', isDanger ? '.7' : '.4');
    line.setAttribute('stroke-dasharray', isDanger ? '4 4' : '5 6');
    // CSS animation class
    line.setAttribute('class', isDanger ? 'edge-active' : 'edge');
    svg.appendChild(line);
    _topoLineRefs.set(node.id, line);
  });

  if (root) drawTopoNode(svg, root, TCX, TCY, true);
  others.forEach((node, i) => drawTopoNode(svg, node, positions[i].x, positions[i].y, false));

  buildTopoLegend(nodes);
}

function drawTopoNode(svg, node, x, y, isRoot) {
  const color    = categoryColor(node.kind, node._hasDanger);
  const iconKey  = node.kind;
  const isDanger = node._hasDanger;
  const r        = isRoot ? 22 : 17;
  const labelY   = y + r + 14;

  const g = document.createElementNS('http://www.w3.org/2000/svg','g');
  g.setAttribute('class','node-g');
  g.style.cursor = 'pointer';
  g.addEventListener('click', () => showTopoCard(node));

  // ── Glow filter on root (blue) and danger nodes (red/green) ──
  if (isRoot) {
    g.setAttribute('filter','url(#glow-blue)');
  } else if (isDanger && node.kind === 'threats') {
    g.setAttribute('filter','url(#glow-red)');
  } else if (isDanger && (node.kind === 'tls' || node.kind === 'ports')) {
    g.setAttribute('filter','url(#glow-red)');
  } else if (!isDanger && (node.kind === 'tls' || node.kind === 'ports')) {
    g.setAttribute('filter','url(#glow-green)');
  }

  // ── SVG animate pulse rings ──
  if (isRoot || isDanger) {
    const pulseColor = isRoot ? '#3b82f6' : '#ef4444';
    const dur1 = isRoot ? '2.4s' : '1.3s';
    const dur2 = isRoot ? '2.4s' : '1.3s';
    const begin2 = isRoot ? '1.2s' : '0.65s';

    [{ dur: dur1, begin: '0s' }, { dur: dur2, begin: begin2 }].forEach(cfg => {
      const pa = document.createElementNS('http://www.w3.org/2000/svg','circle');
      pa.setAttribute('cx', x); pa.setAttribute('cy', y);
      pa.setAttribute('r', String(r));
      pa.setAttribute('fill','none');
      pa.setAttribute('stroke', pulseColor);
      pa.setAttribute('stroke-width','0.7');
      pa.setAttribute('opacity','0');
      // SVG SMIL animations (no CSS needed)
      const animR = document.createElementNS('http://www.w3.org/2000/svg','animate');
      animR.setAttribute('attributeName','r');
      animR.setAttribute('values', `${r};${r + 16}`);
      animR.setAttribute('dur', cfg.dur);
      animR.setAttribute('begin', cfg.begin);
      animR.setAttribute('repeatCount','indefinite');
      pa.appendChild(animR);
      const animO = document.createElementNS('http://www.w3.org/2000/svg','animate');
      animO.setAttribute('attributeName','opacity');
      animO.setAttribute('values','0.5;0');
      animO.setAttribute('dur', cfg.dur);
      animO.setAttribute('begin', cfg.begin);
      animO.setAttribute('repeatCount','indefinite');
      pa.appendChild(animO);
      g.appendChild(pa);
    });
  }

  // ── Node body ──
  const ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
  ring.setAttribute('cx', x); ring.setAttribute('cy', y);
  ring.setAttribute('r', String(r - 4));
  ring.setAttribute('fill', color); ring.setAttribute('opacity','.1');
  ring.setAttribute('class','ring');
  g.appendChild(ring);

  const bg = document.createElementNS('http://www.w3.org/2000/svg','circle');
  bg.setAttribute('cx', x); bg.setAttribute('cy', y);
  bg.setAttribute('r', String(r));
  bg.setAttribute('fill','#0d0d14');
  bg.setAttribute('stroke', color);
  bg.setAttribute('stroke-width', isRoot ? '1.8' : '1');
  g.appendChild(bg);

  // ── Icon ──
  const iconG = document.createElementNS('http://www.w3.org/2000/svg','g');
  iconG.setAttribute('transform', `translate(${x},${y})`);
  iconG.innerHTML = (TOPO_ICONS[iconKey] || TOPO_ICONS.infra)(color);
  g.appendChild(iconG);

  // ── Label ──
  const lbl = document.createElementNS('http://www.w3.org/2000/svg','text');
  lbl.setAttribute('x', x); lbl.setAttribute('y', labelY);
  lbl.setAttribute('text-anchor','middle');
  lbl.style.cssText = `font-size:9px;font-family:'Geist Mono',monospace`;
  lbl.setAttribute('fill', color);
  lbl.textContent = node.label;
  g.appendChild(lbl);

  if (node.sub) {
    const sub = document.createElementNS('http://www.w3.org/2000/svg','text');
    sub.setAttribute('x', x); sub.setAttribute('y', labelY + 11);
    sub.setAttribute('text-anchor','middle');
    sub.style.cssText = `font-size:7.5px;fill:#4a4a5a;font-family:'Geist',sans-serif`;
    sub.textContent = node.sub;
    g.appendChild(sub);
  }

  _topoNodeRefs.set(node.id, { bg, ring, iconG, iconKey, lbl, color });
  svg.appendChild(g);
}

function resetTopoNode(id) {
  const refs = _topoNodeRefs.get(id);
  if (!refs) return;
  const node = _currentTopoNodes.find(n => n.id === id);
  if (!node || node._root) return;
  refs.bg.setAttribute('stroke', refs.color);
  refs.ring.setAttribute('fill', refs.color);
  refs.iconG.innerHTML = (TOPO_ICONS[refs.iconKey] || TOPO_ICONS.infra)(refs.color);
  refs.lbl.setAttribute('fill', refs.color);
  const line = _topoLineRefs.get(id);
  if (line) {
    const isAlert = node._hasDanger;
    line.setAttribute('stroke', refs.color);
    line.setAttribute('stroke-width', isAlert ? '1.5' : '1');
    line.setAttribute('opacity', isAlert ? '.7' : '.4');
    line.setAttribute('stroke-dasharray', isAlert ? '4 4' : '5 6');
    line.setAttribute('class', isAlert ? 'edge-active' : 'edge');
  }
}

function recolorTopoNode(node) {
  const green = '#10b981';
  if (_clickedTopoId.current && _clickedTopoId.current !== node.id) {
    resetTopoNode(_clickedTopoId.current);
  }
  if (_clickedTopoId.current === node.id) {
    resetTopoNode(node.id);
    _clickedTopoId.current = null;
    return false;
  }
  _clickedTopoId.current = node.id;
  const refs = _topoNodeRefs.get(node.id);
  if (!refs) return true;
  refs.bg.setAttribute('stroke', green);
  refs.ring.setAttribute('fill', green);
  refs.iconG.innerHTML = (TOPO_ICONS[refs.iconKey] || TOPO_ICONS.infra)(green);
  refs.lbl.setAttribute('fill', green);
  const line = _topoLineRefs.get(node.id);
  if (line) {
    line.setAttribute('stroke', green);
    line.setAttribute('stroke-width','1.5');
    line.setAttribute('opacity','.75');
    line.setAttribute('stroke-dasharray','4 4');
    line.setAttribute('class','edge-active');
  }
  return true;
}

// ─── Show grouped detail card ─────────────────────────────────────────────────
function showTopoCard(node) {
  const toggled = node._root ? true : recolorTopoNode(node);
  if (!toggled) {
    document.getElementById('topo-detail').style.display = 'none';
    return;
  }

  const color = categoryColor(node.kind, node._hasDanger);

  document.getElementById('td-dot').style.background = color;
  document.getElementById('td-label').textContent = node.label;

  const badge = document.getElementById('td-badge');
  badge.textContent = node.kind;
  badge.style.cssText = `font-size:10px;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;background:${color}18;color:${color};border:.5px solid ${color}44`;

  const items = node.items || [];
  document.getElementById('td-body').innerHTML = `
    <div style="display:flex;flex-direction:column;gap:0">
      ${items.map((item, i) => {
        // Divider rows (section labels)
        if (item.label.startsWith('───')) {
          return `<div style="padding:6px 0 4px;font-size:10px;color:#3f3f46;font-family:'Geist Mono',monospace;letter-spacing:.08em">${item.label}</div>`;
        }
        return `<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;${i < items.length - 1 ? 'border-bottom:.5px solid rgba(39,39,42,.5)' : ''}">
          <span style="font-size:11px;color:#71717a;flex-shrink:0;margin-right:12px">${item.label}</span>
          <span class="mono" style="font-size:11px;color:${item.valueColor || '#e4e4e7'};word-break:break-all;text-align:right">${item.value}</span>
        </div>`;
      }).join('')}
    </div>
  `;

  const card = document.getElementById('topo-detail');
  card.style.display = 'block';
  card.style.animation = 'none';
  requestAnimationFrame(() => { card.style.animation = ''; });
}

// ─── Topology legend ──────────────────────────────────────────────────────────
function buildTopoLegend(nodes) {
  const kindMeta = {
    domain:    { color: '#3b82f6', label: 'Domain' },
    ports:     { color: '#10b981', label: 'Ports' },
    tls:       { color: '#10b981', label: 'TLS' },
    infra:     { color: '#6b7280', label: 'Infrastructure' },
    threats:   { color: '#ef4444', label: 'Threats' },
    endpoints: { color: '#f59e0b', label: 'Endpoints' },
  };
  const seen = new Set();
  const items = nodes
    .map(n => {
      const meta = { ...kindMeta[n.kind] };
      if (n._hasDanger) meta.color = '#ef4444';
      return meta;
    })
    .filter(m => m && !seen.has(m.label) && seen.add(m.label));

  document.getElementById('topoLegend').innerHTML =
    '<span style="margin-right:4px;color:#52525b">Nodes:</span>' +
    items.map(m =>
      `<span style="display:flex;align-items:center;gap:5px">
        <span style="width:8px;height:8px;border-radius:50%;border:1.5px solid ${m.color};display:inline-block"></span>${m.label}
      </span>`
    ).join('');
}

// ─── See Details toggle ────────────────────────────────────────────────────────
let _detailsOpen = false;

function toggleDetails() {
  _detailsOpen = !_detailsOpen;
  const sec = document.getElementById('detailSections');
  const chevron = document.getElementById('detailsChevron');
  const btn = document.getElementById('seeDetailsBtn');

  if (_detailsOpen) {
    sec.classList.remove('collapsed');
    sec.classList.add('expanded');
    sec.style.maxHeight = sec.scrollHeight + 'px';
    chevron.style.transform = 'rotate(180deg)';
    btn.style.background = 'rgba(59,130,246,.18)';
  } else {
    sec.style.maxHeight = sec.scrollHeight + 'px';
    requestAnimationFrame(() => {
      sec.style.maxHeight = '0';
    });
    sec.classList.remove('expanded');
    sec.classList.add('collapsed');
    chevron.style.transform = 'rotate(0deg)';
    btn.style.background = 'rgba(59,130,246,.1)';
    document.getElementById('topo-detail').style.display = 'none';
  }
}

// ─── Utilities ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function setUrl(u) { $('urlInput').value = u; }

function resetAll() {
  $('urlInput').value = '';
  $('inputCard').style.display   = 'block';
  $('scanView').style.display    = 'none';
  $('resultsView').style.display = 'none';
  _currentTopoNodes = [];
  _clickedTopoId.current = null;
  _detailsOpen = false;
  const sec = $('detailSections');
  sec.classList.add('collapsed');
  sec.classList.remove('expanded');
  sec.style.maxHeight = '0';
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

// ─── Scan flow ────────────────────────────────────────────────────────────────
async function startScan() {
  const raw = $('urlInput').value.trim();
  if (!raw) { flashInput(); return; }
  const parsed = parseUrl(raw);
  if (!parsed) { flashInput(); return; }

  $('scanBtn').disabled = true;
  $('inputCard').style.display = 'none';
  $('resultsView').style.display = 'none';
  $('scanView').style.display = 'block';

  $('scanTarget').textContent = parsed.hostname;
  $('scanBars').innerHTML = '';
  $('termLines').innerHTML = '';

  const barDefs = [
    { label: 'DNS resolution',      key: 'dns',  dur: 600  },
    { label: 'SSL certificate',     key: 'ssl',  dur: 900  },
    { label: 'HTTP headers',        key: 'hdr',  dur: 1100 },
    { label: 'URL analysis',        key: 'url2', dur: 500  },
    { label: 'Threat intelligence', key: 'ti',   dur: 1400 },
    { label: 'Scanning ports',      key: 'sp',   dur: 1700 },
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
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: raw }),
  });

  const terms = [
    `Resolving ${parsed.hostname}`,
    'Connecting to host...',
    'Parsing TLS certificate...',
    'Checking headers...',
    'Running pattern match...',
    'Cross-referencing threat DB...',
    'Building topology map...',
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
    const [, response] = await Promise.all([sleep(totalAnimTime), apiPromise]);
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

// ─── Build findings / score ───────────────────────────────────────────────────
function buildResults(url, raw, apiData) {
  const findings = [];
  const isHttps = url.protocol === 'https:';

  if (!isHttps)
    findings.push({ sev: 'critical', title: 'No HTTPS encryption', desc: 'Traffic is transmitted in plaintext, exposing users to MITM attacks.', ref: 'CWE-319' });

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname))
    findings.push({ sev: 'critical', title: 'Raw IP address as host', desc: 'Direct IP usage is atypical for legitimate services.', ref: 'OWASP A05' });

  if (!apiData.ssl?.ssl_valid)
    findings.push({ sev: 'critical', title: 'Invalid SSL certificate', desc: apiData.ssl?.error || 'SSL certificate could not be validated.', ref: 'TLS' });
  else if (isHttps)
    findings.push({ sev: 'info', title: 'HTTPS enabled', desc: `TLS is present. Certificate expires in ${apiData.ssl?.expires_in_days ?? '?'} days.`, ref: 'TLS OK' });

  if (!apiData.dns?.dns_resolves)
    findings.push({ sev: 'critical', title: 'DNS resolution failed', desc: apiData.dns?.error || 'Could not resolve hostname.', ref: 'DNS' });

  const lh = url.hostname.toLowerCase(), lp = url.pathname.toLowerCase(), lq = url.search.toLowerCase();
  const phishWords = ['login','secure','verify','account','update','confirm','paypal','apple','microsoft','amazon','bank'];
  const phishMatches = phishWords.filter(w => lh.includes(w));
  if (phishMatches.length >= 2)
    findings.push({ sev: 'critical', title: 'High phishing probability', desc: `Domain contains ${phishMatches.length} suspicious keywords: ${phishMatches.join(', ')}.`, ref: 'PHISH' });
  else if (phishMatches.length === 1)
    findings.push({ sev: 'warning', title: 'Potential phishing keyword', desc: `Domain contains suspicious keyword: ${phishMatches[0]}.`, ref: 'PHISH' });

  const suspTLDs = ['.xyz','.top','.click','.loan','.work','.tk','.ml','.ga'];
  const badTld = suspTLDs.find(t => lh.endsWith(t));
  if (badTld)
    findings.push({ sev: 'warning', title: 'High-risk TLD', desc: `"${badTld}" is commonly associated with malicious infrastructure.`, ref: 'TLD' });

  if (lp.includes('<script') || lq.includes('<script') || lq.includes('alert('))
    findings.push({ sev: 'critical', title: 'XSS payload detected', desc: 'Script injection pattern found in URL path or query string.', ref: 'XSS' });

  if (lq.includes('redirect=') || lq.includes('url=') || lq.includes('next='))
    findings.push({ sev: 'warning', title: 'Open redirect parameter', desc: 'Query string contains a redirect parameter exploitable for phishing.', ref: 'REDIRECT' });

  const hdrDefs = [
    { name: 'Content-Security-Policy',   key: 'content-security-policy' },
    { name: 'Strict-Transport-Security', key: 'strict-transport-security' },
    { name: 'X-Frame-Options',           key: 'x-frame-options' },
    { name: 'X-Content-Type-Options',    key: 'x-content-type-options' },
    { name: 'Referrer-Policy',           key: 'referrer-policy' },
    { name: 'Permissions-Policy',        key: 'permissions-policy' },
  ];
  const missingHeaders = [];
  const headers = hdrDefs.map(h => {
    const present = !!apiData.headers?.[h.key];
    if (!present) missingHeaders.push(h.name);
    return { name: h.name, present };
  });
  if (missingHeaders.length > 0) {
    const sev = missingHeaders.length >= 4 ? 'warning' : 'low';
    findings.push({ sev, title: `${missingHeaders.length} security header${missingHeaders.length > 1 ? 's' : ''} missing`, desc: missingHeaders.join(', '), ref: 'HEADERS' });
  }

  const whois = apiData.osint?.whois || {};
  const rep   = apiData.osint?.reputation || {};
  const srv   = apiData.osint?.server || apiData.osint?.server_info || {};
  if (whois.org)        findings.push({ sev: 'info',    title: 'Hosting provider identified',        desc: `${whois.org} (ASN ${whois.asn || '—'})`, ref: 'OSINT' });
  if (whois.risk_flag)  findings.push({ sev: 'warning', title: 'Suspicious registrant data',         desc: 'WHOIS data contains risk indicators.', ref: 'WHOIS' });
  if (srv.risk_flag)    findings.push({ sev: 'warning', title: 'Server fingerprinting risk',         desc: srv.risk_reason || 'Server version exposed in headers.', ref: 'Fingerprinting' });
  if (rep.risk_flag || rep.is_proxy) findings.push({ sev: 'warning', title: 'Proxy / VPN / suspicious IP detected', desc: 'The server IP is flagged by reputation intelligence.', ref: 'OSINT' });
  findings.push({ sev: 'info', title: 'Scan complete', desc: `Analyzed ${raw.length} characters against multiple threat categories.`, ref: '—' });

  const high  = findings.filter(f => f.sev === 'critical').length;
  const med   = findings.filter(f => f.sev === 'warning').length;
  const low   = findings.filter(f => f.sev === 'low').length;
  const inf   = findings.filter(f => f.sev === 'info').length;
  const score = Math.max(0, Math.min(100, 100 - high * 22 - med * 10 - low * 4));

  const osint = [
    { label: 'IP Address',    value: apiData.dns?.ip || whois.ip || '—' },
    { label: 'ASN',           value: whois.asn || '—' },
    { label: 'Org / Hosting', value: whois.org || rep.isp || '—' },
    { label: 'Country',       value: whois.country || rep.country || '—' },
    { label: 'Proxy / VPN',   value: (rep.is_proxy || rep.risk_flag) ? 'Yes ⚠' : 'No' },
    { label: 'Server',        value: srv.server || apiData.headers?.['server'] || '—' },
    { label: 'Risk level',    value: apiData.risk_level || '—' },
    { label: 'SSL days',      value: apiData.ssl?.ssl_valid ? `${apiData.ssl.expires_in_days} days` : 'Invalid' },
  ];

  const breakdown = [
    { label: 'Protocol',   value: url.protocol },
    { label: 'Hostname',   value: url.hostname },
    { label: 'Path',       value: url.pathname },
    { label: 'Query',      value: url.search },
    { label: 'Port',       value: url.port || '(default)' },
    { label: 'URL length', value: raw.length + ' chars' },
  ];

  return { score, findings, counts: { high, med, low, inf }, headers, osint, breakdown };
}

// ─── Port list renderer ───────────────────────────────────────────────────────
function renderPorts(apiData) {
  const container = $('portList');
  if (!container) return;
  const ports = apiData?.port_scans || [];
  container.innerHTML = '';
  if (ports.length === 0) {
    container.innerHTML = `<div style="color:#71717a;font-size:12px">No ports detected</div>`;
    return;
  }
  ports.forEach(p => {
    const el = document.createElement('div');
    const color  = p.open ? '#10b981' : '#ef4444';
    const status = p.open ? 'OPEN' : 'CLOSED';
    el.style.cssText = `display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:#09090b;border:.5px solid #27272a;border-radius:8px;margin-bottom:6px`;
    el.innerHTML = `
      <div style="display:flex;gap:10px;align-items:center">
        <span class="mono" style="color:#fafafa;font-size:12px">:${p.port}</span>
        <span style="font-size:12px;color:#71717a">${p.label}</span>
      </div>
      <div style="display:flex;align-items:center;gap:6px">
        <div style="width:6px;height:6px;border-radius:50%;background:${color}"></div>
        <span class="mono" style="font-size:10px;color:${color}">${status}</span>
      </div>`;
    container.appendChild(el);
  });
}

// ─── Main render ──────────────────────────────────────────────────────────────
function renderResults(parsed, raw, apiData) {
  // Reset details panel state for fresh scan
  _detailsOpen = false;
  const sec = $('detailSections');
  sec.classList.add('collapsed');
  sec.classList.remove('expanded');
  sec.style.maxHeight = '0';

  renderPorts(apiData);

  const { score, findings, counts, headers, osint, breakdown } = buildResults(parsed, raw, apiData);

  // Score ring
  const arc = $('ringArc');
  setTimeout(() => {
    arc.style.strokeDashoffset = 207.3 * (1 - score / 100);
    arc.style.stroke = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#ef4444';
  }, 80);
  $('scoreNum').textContent = score;

  const backendRisk = (apiData.risk_level || '').toLowerCase();
  const riskLevel = backendRisk === 'high' ? 'high' : backendRisk === 'medium' ? 'medium' : backendRisk === 'low' ? 'low'
    : score >= 70 ? 'low' : score >= 40 ? 'medium' : 'high';

  const badgeCfg = {
    low:    { bg: 'rgba(16,185,129,.12)',  color: '#10b981', border: 'rgba(16,185,129,.3)',  text: 'SAFE' },
    medium: { bg: 'rgba(245,158,11,.12)', color: '#f59e0b', border: 'rgba(245,158,11,.3)', text: 'WARNING' },
    high:   { bg: 'rgba(239,68,68,.12)',  color: '#ef4444', border: 'rgba(239,68,68,.3)',  text: 'DANGER' },
  };
  const bc = badgeCfg[riskLevel];

  $('riskTitle').textContent = score >= 70 ? 'Low Risk' : score >= 40 ? 'Moderate Risk' : 'High Risk';
  const rb = $('riskBadge');
  rb.textContent = bc.text;
  rb.style.cssText = `font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:${bc.bg};color:${bc.color};border:.5px solid ${bc.border}`;

  function buildSummary(riskLevel, findings, apiData) {
    const criticals = findings.filter(f => f.sev === 'critical').map(f => f.title);
    const warnings  = findings.filter(f => f.sev === 'warning').map(f => f.title);
    const ssl = apiData.ssl || {};
    const dns = apiData.dns || {};
    const parts = [];
    if (riskLevel === 'low') {
      parts.push('No critical issues detected.');
      if (ssl.ssl_valid && ssl.expires_in_days > 30) parts.push(`SSL valid for ${ssl.expires_in_days} days.`);
      return parts.join(' ');
    }
    if (riskLevel === 'medium') {
      if (warnings.length > 0) parts.push(warnings.slice(0, 2).join('; ') + '.');
      if (ssl.expires_in_days && ssl.expires_in_days < 30) parts.push(`SSL expires in ${ssl.expires_in_days} days.`);
      return parts.length ? parts.join(' ') : 'Moderate risk — review findings before proceeding.';
    }
    if (criticals.length > 0) parts.push(criticals.slice(0, 2).join('; ') + '.');
    if (!dns.dns_resolves)    parts.push('Domain does not resolve.');
    if (!ssl.ssl_valid)       parts.push('SSL certificate invalid.');
    return parts.length ? parts.join(' ') : 'Multiple high-risk indicators detected.';
  }
  $('summaryText').textContent = buildSummary(riskLevel, findings, apiData);
  $('urlDisplay').textContent  = raw;

  $('cHigh').textContent = counts.high;
  $('cMed').textContent  = counts.med;
  $('cLow').textContent  = counts.low;
  $('cInfo').textContent = counts.inf;

  // Findings list
  $('findingsCount').textContent = findings.length + ' findings';
  const sevCfg = {
    critical: { dot: '#ef4444', bg: 'rgba(239,68,68,.07)',   label: 'Critical' },
    warning:  { dot: '#f59e0b', bg: 'rgba(245,158,11,.07)',  label: 'Warning'  },
    low:      { dot: '#a1a1aa', bg: 'rgba(161,161,170,.07)', label: 'Low'      },
    info:     { dot: '#60a5fa', bg: 'rgba(96,165,250,.07)',  label: 'Info'     },
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

  // Headers
  const presentCount = headers.filter(h => h.present).length;
  const hdrLabel = presentCount >= 5 ? 'Strong' : presentCount >= 3 ? 'Moderate' : 'Weak';
  const hdrEl = $('hdrScore');
  hdrEl.textContent = hdrLabel;
  hdrEl.style.cssText = presentCount >= 5
    ? "font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(16,185,129,.1);color:#10b981;border:.5px solid rgba(16,185,129,.3)"
    : presentCount >= 3
    ? "font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(245,158,11,.1);color:#f59e0b;border:.5px solid rgba(245,158,11,.3)"
    : "font-size:10px;font-weight:500;padding:2px 7px;border-radius:4px;font-family:'Geist Mono',monospace;text-transform:uppercase;letter-spacing:.06em;background:rgba(239,68,68,.1);color:#ef4444;border:.5px solid rgba(239,68,68,.3)";

  $('headerList').innerHTML = headers.map(h =>
    `<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:.5px solid rgba(39,39,42,.5)">
      <span class="mono" style="font-size:11px;color:${h.present ? '#a1a1aa' : '#52525b'}">${h.name}</span>
      <span style="font-size:10px;padding:1px 6px;border-radius:3px;${h.present ? 'background:rgba(16,185,129,.1);color:#10b981' : 'background:rgba(239,68,68,.1);color:#ef4444'}">${h.present ? 'present' : 'missing'}</span>
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
      <div class="mono" style="font-size:12px;color:#e4e4e7;word-break:break-all">${b.value || '—'}</div>
    </div>`
  ).join('');

  // ── Topology map — now passes findings so threats node is enriched ──
  const topoNodes = buildTopoNodes(parsed, raw, apiData, findings);
  _currentTopoNodes = topoNodes;

  $('topoHostname').textContent = parsed.hostname;
  $('topoNodeCount').textContent = topoNodes.length + ' nodes';
  $('topo-detail').style.display = 'none';
  _clickedTopoId.current = null;

  $('resultsView').style.display = 'block';
  requestAnimationFrame(() => renderTopoMap(topoNodes));
}

// ─── Enter key ────────────────────────────────────────────────────────────────
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});