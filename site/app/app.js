const $ = (q) => document.querySelector(q);
const $$ = (q) => Array.from(document.querySelectorAll(q));

function esc(s){
  return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function labelDevice(d){
  return d.name || (d.mdns && d.mdns[0]) || d.hostname || d.vendor || d.id;
}

function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }

function typeColor(t){
  const m = {
    gateway: 'rgba(168, 255, 214, .95)',
    ap: 'rgba(122,162,255,.95)',
    nas: 'rgba(255,211,107,.95)',
    tv: 'rgba(255,107,158,.95)',
    printer: 'rgba(205,180,255,.95)',
    server: 'rgba(255,165,85,.95)',
    iot: 'rgba(140,240,255,.95)',
    client: 'rgba(180,255,180,.95)',
    unknown: 'rgba(170,180,210,.85)',
  };
  return m[t] || 'rgba(170,180,210,.85)';
}

function heatColor(x){
  // x in [0..1]
  const a = clamp(x,0,1);
  // blend from dark -> blue
  const r = Math.round(18 + a*90);
  const g = Math.round(28 + a*120);
  const b = Math.round(55 + a*200);
  return `rgb(${r},${g},${b})`;
}

function sparkline(values){
  return spark(values, {stroke:'rgba(122,162,255,.95)'});
}

function spark(values, opts={}){
  if(!values || !values.length) return '';
  const w=560, h=64, pad=6;
  const mn=Math.min(...values), mx=Math.max(...values);
  const rng=(mx-mn)||1;

  const pts=values.map((v,i)=>{
    const x = pad + (i/(Math.max(1,values.length-1)))*(w-2*pad);
    const y = pad + (1-((v-mn)/rng))*(h-2*pad);
    return [x,y];
  });

  const d = 'M ' + pts.map(p=>p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' L ');
  const stroke = opts.stroke || 'rgba(122,162,255,.95)';
  const fill = opts.fill || 'rgba(122,162,255,.16)';
  const area = `M ${pts[0][0].toFixed(1)} ${(h-pad).toFixed(1)} L ` + pts.map(p=>p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' L ') + ` L ${pts[pts.length-1][0].toFixed(1)} ${(h-pad).toFixed(1)} Z`;

  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
    <path d="${area}" fill="${fill}" stroke="none" />
    <path d="${d}" fill="none" stroke="${stroke}" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
}

let latest = null;
let history = null;
let deviceStats = null;
let lessons = null;
let selectedId = null;
let learnOpenId = null;

function route(){
  const h = (location.hash || '#overview').slice(1);
  return h || 'overview';
}

function learnEnabled(){
  return (localStorage.getItem('nw.learn.enabled') ?? '0') === '1';
}

function setLearnEnabled(v){
  localStorage.setItem('nw.learn.enabled', v ? '1' : '0');
}

function setActiveNav(r){
  $$('.nav__item').forEach(b => b.classList.toggle('is-active', b.dataset.route === r));
}

function applyLearnVisibility(){
  const on = learnEnabled();
  const learnBtn = $(`.nav__item[data-route="learn"]`);
  if(learnBtn) learnBtn.style.display = on ? '' : 'none';
  // Hide any contextual learn buttons when off
  $$('[data-learn]').forEach(el => {
    el.style.display = on ? '' : 'none';
  });
  if(!on && route() === 'learn') location.hash = '#overview';
}

function filteredDevices(){
  if(!latest) return [];
  const q = ($('#search').value || '').toLowerCase().trim();
  const type = $('#filterType').value;
  const risk = $('#filterRisk').value;
  return (latest.devices||[]).filter(d => {
    if(type && (d.type||'') !== type) return false;
    if(risk === 'risky' && !(d.risk_flags||[]).length) return false;
    if(risk === 'unknown' && (d.type||'') !== 'unknown') return false;
    if(!q) return true;
    const hay = [labelDevice(d), d.vendor, d.hostname, ...(d.mdns||[]), d.mac, d.ip].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function renderOverview(){
  const devs = filteredDevices();
  const total = (latest.devices||[]).length;
  const openHosts = (latest.devices||[]).filter(d => (d.open_ports||[]).length).length;
  const openPorts = (latest.devices||[]).reduce((s,d)=>s+(d.open_ports||[]).length,0);
  const risks = (latest.devices||[]).reduce((s,d)=>s+(d.risk_flags||[]).length,0);

  // Inventory-first metrics
  const unnamed = (latest.devices||[]).filter(d => !(d.name||'').trim()).length;
  const unknownType = (latest.devices||[]).filter(d => (d.type||'') === 'unknown').length;
  const weakIdentity = (latest.devices||[]).filter(d =>
    !(d.mdns_services||[]).length && !(d.ssdp||[]).length && !((d.open_ports||[]).length)
  ).length;

  const diff = latest.diff || {};
  const newN = (diff.new_ids||[]).length;
  const goneN = (diff.gone_ids||[]).length;

  const types = {};
  (latest.devices||[]).forEach(d => { types[d.type||'unknown'] = (types[d.type||'unknown']||0)+1; });
  const typeLine = Object.entries(types).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`${k}:${v}`).join(', ');

  const typeEntries = Object.entries(types).sort((a,b)=>b[1]-a[1]);
  const typeTotal = typeEntries.reduce((s,kv)=>s+kv[1],0) || 1;
  const typePill = `<div class="typePill">${typeEntries.map(([t,c])=>{
    const w = (c/typeTotal)*100;
    return `<div class="typeSeg" title="${esc(t)}: ${c}" style="width:${w.toFixed(2)}%; background:${typeColor(t)}"></div>`;
  }).join('')}</div>`;
  const typeLegend = `<div class="typeLegend">${typeEntries.slice(0,8).map(([t,c])=>{
    return `<span class="typeKey" title="${esc(t)}"><span class="typeDot" style="background:${typeColor(t)}"></span>${esc(t)} <span class="muted">${c}</span></span>`;
  }).join('')}${typeEntries.length>8?`<span class="muted small">+${typeEntries.length-8} more</span>`:''}</div>`;

  const timeSeries = history ? {
    t: history.t || [],
    devices: history.devices || [],
    openPorts: history.openPorts || [],
    risks: history.risks || []
  } : null;

  // Stability stats from device_stats.json
  const stats = (deviceStats && deviceStats.devices) ? Object.values(deviceStats.devices) : [];
  const mostFlappy = stats.slice().sort((a,b)=> (b.flaps||0) - (a.flaps||0)).slice(0,5);
  const mostIpChg = stats.slice().sort((a,b)=> (b.uniqueIps||0) - (a.uniqueIps||0)).slice(0,5);

  const content = `
    <div class="card">
      <div class="card__hd"><h2>Household snapshot</h2><div class="card__sub">Inventory first, posture second</div></div>
      <div class="card__bd">
        <div class="kpis">
          <div class="kpi"><div class="label">Devices now</div><div class="value">${total}</div><div class="muted small">filtered: ${devs.length}</div></div>
          <div class="kpi"><div class="label">Unnamed (no alias)</div><div class="value">${unnamed}</div></div>
          <div class="kpi"><div class="label">Unknown type <button class="drawer__btn" data-learn="ports-and-services" style="padding:2px 6px; margin-left:6px">?</button></div><div class="value">${unknownType}</div></div>
          <div class="kpi"><div class="label">Weak identity <button class="drawer__btn" data-learn="mdns-basics" style="padding:2px 6px; margin-left:6px">?</button></div><div class="value">${weakIdentity}</div></div>
        </div>
        <div style="height:10px"></div>
        <div class="flex">
          <span class="badge good">+${newN} new</span>
          <span class="badge warn">-${goneN} gone</span>
          <span class="muted small">Types</span>
        </div>
        <div style="height:8px"></div>
        ${typePill}
        ${typeLegend}

        ${timeSeries ? `<div style="height:12px"></div>
          <div class="card" style="border-radius:14px; box-shadow:none; background:rgba(0,0,0,.10)">
            <div class="card__hd" style="border-bottom:0"><h2>Trends</h2><div class="card__sub">Last ~48 snapshots</div></div>
            <div class="card__bd">
              <div class="trendGrid">
                <div class="trend">
                  <div class="label">Devices</div>
                  <div class="value">${timeSeries.devices.slice(-1)[0] ?? total}</div>
                  <div class="spark">${spark(timeSeries.devices.slice(-48), {stroke:'rgba(122,162,255,.95)', fill:'rgba(122,162,255,.18)'})}</div>
                  ${(()=>{
                    const vals = timeSeries.devices.slice(-48);
                    const mn = Math.min(...vals), mx = Math.max(...vals);
                    const rng = (mx-mn)||1;
                    const cells = vals.map(v=>{
                      const a = (v-mn)/rng;
                      return `<div class="heatCell" style="background:${heatColor(a)}" title="${v} devices"></div>`;
                    }).join('');
                    return `<div class="heatLabel"><span>Presence strip</span><span>${mn}–${mx}</span></div><div class="heatStrip">${cells}</div>`;
                  })()}
                </div>
                <div class="trend">
                  <div class="label">Open ports</div>
                  <div class="value">${timeSeries.openPorts.slice(-1)[0] ?? openPorts}</div>
                  <div class="spark">${spark(timeSeries.openPorts.slice(-48), {stroke:'rgba(255,211,107,.95)', fill:'rgba(255,211,107,.18)'})}</div>
                </div>
                <div class="trend">
                  <div class="label">Risk flags</div>
                  <div class="value">${timeSeries.risks.slice(-1)[0] ?? risks}</div>
                  <div class="spark">${spark(timeSeries.risks.slice(-48), {stroke:'rgba(255,107,158,.95)', fill:'rgba(255,107,158,.18)'})}</div>
                </div>
              </div>
            </div>
          </div>` : `<div class="muted small">(history.json not loaded)</div>`}

        <div style="height:12px"></div>
        <div class="card" style="border-radius:14px; box-shadow:none; background:rgba(0,0,0,.10)">
          <div class="card__hd" style="border-bottom:0"><h2>Stability</h2><div class="card__sub">flaps + IP churn (top 5)</div></div>
          <div class="card__bd" style="display:grid; grid-template-columns:1fr 1fr; gap:14px">
            <div>
              <div class="muted small" style="margin-bottom:6px">Most flappy</div>
              ${(mostFlappy.length? '<ul class="small">' + mostFlappy.map(s=>`<li>${esc(s.display)} — flaps ${s.flaps}</li>`).join('') + '</ul>' : '<div class="muted small">(no stats yet)</div>')}
            </div>
            <div>
              <div class="muted small" style="margin-bottom:6px">Most IP changes</div>
              ${(mostIpChg.length? '<ul class="small">' + mostIpChg.map(s=>`<li>${esc(s.display)} — IPs ${s.uniqueIps}</li>`).join('') + '</ul>' : '<div class="muted small">(no stats yet)</div>')}
            </div>
          </div>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="card__hd"><h2>Security (secondary)</h2><div class="card__sub">Top risky devices right now</div></div>
      <div class="card__bd">
        <table class="table">
          <thead><tr><th>Device</th><th>Type</th><th>IP</th><th>Risk flags</th></tr></thead>
          <tbody>
            ${ (latest.devices||[])
                .filter(d => (d.risk_flags||[]).length)
                .sort((a,b)=> (b.risk_flags.length - a.risk_flags.length))
                .slice(0, 12)
                .map(d => `<tr>
                  <td><a href="#devices" data-focus="${esc(d.id)}">${esc(labelDevice(d))}</a><div class="muted small">${esc(d.mac||'')}</div></td>
                  <td><span class="badge">${esc(d.type||'')}</span></td>
                  <td><code>${esc(d.ip||'')}</code></td>
                  <td>${(d.risk_flags||[]).slice(0,4).map(f=>`<span class="badge bad">${esc(f)}</span>`).join(' ')}</td>
                </tr>`).join('') }
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#content').innerHTML = content;

  // clicking a device here switches to devices view
  $$('#content a[data-focus]').forEach(a => {
    a.addEventListener('click', (e)=>{
      e.preventDefault();
      location.hash = '#devices';
      sessionStorage.setItem('focusDevice', a.dataset.focus);
    });
  });

  // contextual learn buttons
  $$('#content [data-learn]').forEach(b => {
    b.addEventListener('click', (e)=>{
      e.preventDefault();
      e.stopPropagation();
      openLearn(b.getAttribute('data-learn'));
    });
  });
}


function renderDevices(){
  const devs = filteredDevices().slice();

  // Inventory-first sort: type -> name, then risk as tiebreak
  devs.sort((a,b)=>{
    const ta = (a.type||'unknown');
    const tb = (b.type||'unknown');
    if(ta !== tb) return ta.localeCompare(tb);
    const na = labelDevice(a);
    const nb = labelDevice(b);
    if(na !== nb) return na.localeCompare(nb);
    return (b.risk_flags||[]).length - (a.risk_flags||[]).length;
  });

  const groups = {};
  devs.forEach(d => {
    const t = d.type || 'unknown';
    groups[t] = groups[t] || [];
    groups[t].push(d);
  });

  const typeOrder = ['gateway','ap','nas','tv','printer','server','iot','client','unknown'];
  const types = Object.keys(groups).sort((a,b)=>{
    const ia = typeOrder.indexOf(a); const ib = typeOrder.indexOf(b);
    if(ia === -1 && ib === -1) return a.localeCompare(b);
    if(ia === -1) return 1;
    if(ib === -1) return -1;
    return ia - ib;
  });

  function deviceRow(d){
    const flags = (d.risk_flags||[]);
    const mdnsSvc = (d.mdns_services||[]).slice(0,3).join(', ');
    const ssdp = (d.ssdp||[]).slice(0,1).map(s=> (s.server||s.st||'')).join('');
    const stability = deviceStats?.devices?.[d.id];
    const stabText = stability ? `seen ${stability.seenHours}/${stability.totalHours} • flaps ${stability.flaps} • IPs ${stability.uniqueIps}` : '–';

    return `<tr class="devRow" data-id="${esc(d.id)}">
      <td>
        <div><b>${esc(labelDevice(d))}</b></div>
        <div class="muted small">${esc(d.mac||d.id)} • ${esc(d.vendor||'')}</div>
      </td>
      <td><span class="badge">${esc(d.type||'unknown')}</span></td>
      <td><code>${esc(d.ip||'')}</code></td>
      <td class="small">
        ${flags.length ? flags.slice(0,3).map(f=>`<span class="badge bad">${esc(f)}</span>`).join(' ') : '<span class="muted">–</span>'}
      </td>
      <td class="small">
        <div class="muted">Stability: ${esc(stabText)}</div>
        <div class="muted">mDNS: ${esc((d.mdns||[]).slice(0,2).join(', '))}</div>
        <div class="muted">svc: ${esc(mdnsSvc || '–')}</div>
        <div class="muted">SSDP: ${esc(ssdp || '–')}</div>
      </td>
    </tr>`;
  }

  const sections = types.map(t => {
    const list = groups[t];
    const rows = list.map(deviceRow).join('');
    return `
      <div class="group" data-group="${esc(t)}">
        <div class="group__hd" data-toggle="${esc(t)}">
          <div class="group__title">${esc(t)}</div>
          <div class="group__count">${list.length} devices</div>
        </div>
        <div class="group__bd" id="grp_${esc(t)}">
          <div class="card" style="box-shadow:none">
            <div class="card__bd">
              <table class="table">
                <thead><tr><th>Device</th><th>Type</th><th>IP</th><th>Risk</th><th>Signals</th></tr></thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  $('#content').innerHTML = `
    <div class="card">
      <div class="card__hd"><h2>Inventory</h2><div class="card__sub">Grouped by type → named identity. Click a device for details.</div></div>
      <div class="card__bd">
        <div class="muted small">Tip: filter “Unknown only” to focus on classification.</div>
      </div>
    </div>
    ${sections || '<div class="muted">No devices match.</div>'}
  `;

  // group collapse
  $$('#content [data-toggle]').forEach(hd => {
    hd.addEventListener('click', ()=>{
      const t = hd.getAttribute('data-toggle');
      const bd = document.getElementById('grp_'+t);
      if(!bd) return;
      const open = bd.style.display !== 'none';
      bd.style.display = open ? 'none' : '';
    });
  });

  // row click -> drawer
  $$('#content .devRow').forEach(tr => {
    tr.addEventListener('click', ()=> openDrawer(tr.dataset.id));
  });

  const focus = sessionStorage.getItem('focusDevice');
  if(focus){
    sessionStorage.removeItem('focusDevice');
    openDrawer(focus);
  }
}

function renderTimeline(){
  const t = (history?.t || []).slice(-48);
  const devices = (history?.devices || []).slice(-48);
  const openPorts = (history?.openPorts || []).slice(-48);
  const risks = (history?.risks || []).slice(-48);

  $('#content').innerHTML = `
    <div class="card">
      <div class="card__hd"><h2>Timeline</h2><div class="card__sub">Quick glance trends (last ~48 snapshots)</div></div>
      <div class="card__bd">
        <div class="kpis">
          <div class="kpi"><div class="label">Snapshots</div><div class="value">${t.length}</div></div>
          <div class="kpi"><div class="label">Devices (min/max)</div><div class="value">${devices.length?Math.min(...devices):'–'} / ${devices.length?Math.max(...devices):'–'}</div></div>
          <div class="kpi"><div class="label">Open ports (min/max)</div><div class="value">${openPorts.length?Math.min(...openPorts):'–'} / ${openPorts.length?Math.max(...openPorts):'–'}</div></div>
          <div class="kpi"><div class="label">Risks (min/max)</div><div class="value">${risks.length?Math.min(...risks):'–'} / ${risks.length?Math.max(...risks):'–'}</div></div>
        </div>
        <div style="height:12px"></div>
        <div class="card" style="border-radius:14px; box-shadow:none; background:rgba(0,0,0,.10)">
          <div class="card__hd" style="border-bottom:0"><h2>Devices</h2><div class="card__sub">sparkline</div></div>
          <div class="card__bd"><div class="spark">${sparkline(devices)}</div></div>
        </div>
      </div>
    </div>
    <div class="muted small">For animated multi-series charts, use <a href="/fancy-timeline.html">Fancy timeline</a>.</div>
  `;
}

function suggestType(d){
  const svc = (d.mdns_services||[]).map(s=>String(s).toLowerCase());
  const ssdp = (d.ssdp||[]).map(x => ((x.server||'')+' '+(x.st||'')+' '+(x.location||'')).toLowerCase());
  const host = ((d.hostname||'') + ' ' + (d.mdns||[]).join(' ')).toLowerCase();
  const ports = new Set((d.open_ports||[]).map(p=>String(p.port||'')));

  const hasSvc = (needle) => svc.some(s=>s.includes(needle));
  const hasSsdp = (needle) => ssdp.some(s=>s.includes(needle));

  // Strong mDNS signals
  if(hasSvc('_googlecast._tcp')) return {type:'tv', reason:'mDNS: _googlecast._tcp'};
  if(hasSvc('_airplay._tcp') || hasSvc('_raop._tcp')) return {type:'tv', reason:'mDNS: AirPlay/RAOP'};
  if(hasSvc('_hap._tcp')) return {type:'iot', reason:'mDNS: HomeKit (_hap._tcp)'};
  if(hasSvc('_ipp._tcp') || hasSvc('_printer._tcp') || hasSvc('_pdl-datastream._tcp')) return {type:'printer', reason:'mDNS: printer service'};

  // SSDP strings
  if(hasSsdp('synology') || hasSsdp('diskstation') || hasSsdp('dsm')) return {type:'nas', reason:'SSDP: Synology/DSM'};
  if(hasSsdp('roku') || hasSsdp('chromecast') || hasSsdp('webos') || hasSsdp('dlna')) return {type:'tv', reason:'SSDP: media/TV signature'};
  if(hasSsdp('printer') || hasSsdp('epson') || hasSsdp('hp')) return {type:'printer', reason:'SSDP: printer signature'};

  // Hostname hints
  if(host.includes('webos') || host.includes('tv') || host.includes('chromecast') || host.includes('apple.tv')) return {type:'tv', reason:'hostname hint'};
  if(host.includes('vacuum') || host.includes('roborock') || host.includes('dyson') || host.includes('thermostat')) return {type:'iot', reason:'hostname hint'};

  // Port patterns (we scan top-100 TCP)
  if(ports.has('445/tcp') || ports.has('139/tcp') || ports.has('5000/tcp') || ports.has('5001/tcp')) return {type:'server', reason:'server/NAS port pattern'};
  if(ports.has('9100/tcp') || ports.has('631/tcp')) return {type:'printer', reason:'printing ports'};
  if(ports.has('8008/tcp') || ports.has('8009/tcp') || ports.has('8443/tcp')) return {type:'tv', reason:'cast/TV port pattern'};

  return {type:'unknown', reason:'insufficient signal'};
}

function renderInsights(){
  // Focus on unknown type OR unnamed: this is the "classification queue"
  const queue = (latest.devices||[]).filter(d => (d.type||'') === 'unknown' || !(d.name||'').trim());

  const scored = queue
    .map(d => {
      const s = (d.mdns_services||[]).length + (d.ssdp||[]).length + (d.open_ports||[]).length + (d.web||[]).length;
      const sug = suggestType(d);
      return {d, score:s, sug};
    })
    .sort((a,b)=> (b.score-a.score))
    .slice(0, 40);

  $('#content').innerHTML = `
    <div class="card">
      <div class="card__hd"><h2>Classify</h2><div class="card__sub">Unknown types + unnamed devices, sorted by strongest signals</div></div>
      <div class="card__bd">
        <div class="muted small">Queue size: <b>${queue.length}</b> (showing top ${scored.length})</div>
        <div style="height:10px"></div>
        <table class="table" id="classifyTable">
          <thead><tr><th>Device</th><th>IP</th><th>Signals</th><th>Suggested</th><th>Actions</th></tr></thead>
          <tbody>
            ${scored.map(({d,sug}) => {
              const sig = [
                (d.mdns_services||[]).slice(0,4).join(', '),
                (d.ssdp||[]).slice(0,1).map(s=>s.server||s.st||'').join(''),
                (d.open_ports||[]).slice(0,6).map(p=>p.port).join(', ')
              ].filter(Boolean).join(' • ');

              const id = d.id;
              const mac = d.mac || id;
              const proposedName = (d.name||'').trim() ? d.name : (labelDevice(d) || mac);
              const proposedType = sug.type;
              const snippet = {
                types: { [mac]: proposedType },
                names: { [mac]: proposedName }
              };
              const snippetText = JSON.stringify(snippet, null, 2);

              const badgeCls = proposedType === 'unknown' ? 'warn' : 'good';

              return `<tr>
                <td><b>${esc(labelDevice(d))}</b><div class="muted small">${esc(mac)} • ${esc(d.vendor||'')}</div></td>
                <td><code>${esc(d.ip||'')}</code></td>
                <td class="small">${esc(sig || '–')}</td>
                <td>
                  <span class="badge ${badgeCls}">${esc(proposedType)}</span>
                  <div class="muted small">${esc(sug.reason)}</div>
                </td>
                <td class="small">
                  <button class="drawer__btn" data-copy="${esc(id)}">Copy override snippet</button>
                  <button class="drawer__btn" data-open="${esc(id)}">Open details</button>
                  <textarea style="position:absolute; left:-9999px; top:-9999px" id="snip_${esc(id)}">${esc(snippetText)}</textarea>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
        <div class="muted small">Copy-paste into <code>state/overrides.json</code>. (We can add one-click apply later.)</div>
      </div>
    </div>
  `;

  // Actions
  $$('#classifyTable [data-open]').forEach(b => {
    b.addEventListener('click', ()=> openDrawer(b.getAttribute('data-open')));
  });
  $$('#classifyTable [data-copy]').forEach(b => {
    b.addEventListener('click', async ()=>{
      const id = b.getAttribute('data-copy');
      const ta = document.getElementById('snip_'+id);
      if(!ta) return;
      const text = ta.value;
      try{
        await navigator.clipboard.writeText(text);
        b.textContent = 'Copied';
        setTimeout(()=> b.textContent = 'Copy override snippet', 1200);
      }catch(e){
        // fallback
        ta.select();
        document.execCommand('copy');
        b.textContent = 'Copied';
        setTimeout(()=> b.textContent = 'Copy override snippet', 1200);
      }
    });
  });
}

function renderSettings(){
  const learnOn = learnEnabled();
  $('#content').innerHTML = `
    <div class="card">
      <div class="card__hd"><h2>Settings</h2><div class="card__sub">Preferences + where to edit inventory</div></div>
      <div class="card__bd">

        <div class="section">
          <div class="section__title">Learning</div>
          <div class="kv">
            <div class="k">Learn mode</div>
            <div>
              <label style="display:flex; gap:10px; align-items:center;">
                <input type="checkbox" id="learnToggle" ${learnOn ? 'checked' : ''} />
                <span class="muted">Show Learn navigation, “?” helpers, and guided onboarding.</span>
              </label>
            </div>
          </div>
        </div>

        <div class="section">
          <div class="section__title">Files</div>
          <div class="muted">On this host:</div>
          <ul class="small">
            <li><code>/home/prateek/.openclaw/workspace/network-watch/state/aliases.json</code> (MAC → friendly name)</li>
            <li><code>/home/prateek/.openclaw/workspace/network-watch/state/overrides.json</code> (MAC → forced type/name)</li>
            <li><code>/home/prateek/.openclaw/workspace/network-watch/state/alerts.json</code> (alert mode + rate limits)</li>
          </ul>
        </div>

        <div class="section">
          <div class="section__title">Override snippet template</div>
          <pre class="snip"><code>{
  "types": {
    "aa:bb:cc:dd:ee:ff": "tv"
  },
  "names": {
    "aa:bb:cc:dd:ee:ff": "Living Room TV"
  }
}</code></pre>
        </div>
      </div>
    </div>
  `;

  const t = $('#learnToggle');
  if(t){
    t.addEventListener('change', ()=>{
      setLearnEnabled(t.checked);
      applyLearnVisibility();
    });
  }
}

function render(){
  const r = route();
  setActiveNav(r);

  if(!latest){
    $('#content').innerHTML = `<div class="card"><div class="card__bd" class="muted">Loading…</div></div>`;
    return;
  }

  if(r === 'overview') return renderOverview();
  if(r === 'devices') return renderDevices();
  if(r === 'timeline') return renderTimeline();
  if(r === 'insights') return renderInsights();
  if(r === 'learn') return renderLearn();
  if(r === 'settings') return renderSettings();
  return renderOverview();
}

function findLesson(id){
  const list = (lessons && lessons.lessons) ? lessons.lessons : [];
  return list.find(x=>x.id===id);
}

function closeLearn(){
  learnOpenId = null;
  $('#learnDrawer')?.classList.remove('is-open');
}

function openLearn(id){
  const lesson = findLesson(id);
  if(!lesson) return;
  learnOpenId = id;
  $('#learnTitle').textContent = lesson.title || 'Learn';
  $('#learnSub').textContent = lesson.summary || '';
  const body = [
    ...(lesson.body||[]).map(x=>`<li>${esc(x)}</li>`),
  ].join('');

  const todo = [
    ...(lesson.what_to_do_now||[]).map(x=>`<li>${esc(x)}</li>`),
  ].join('');

  $('#learnBody').innerHTML = `
    <div class="section">
      <div class="section__title">Explainer</div>
      <ul class="small">${body || '<li class="muted">No content yet.</li>'}</ul>
    </div>
    <div class="section">
      <div class="section__title">Try this now</div>
      <ul class="small">${todo || '<li class="muted">No suggested actions yet.</li>'}</ul>
    </div>
  `;

  $('#learnDrawer')?.classList.add('is-open');
}

function renderLearn(){
  const list = (lessons && lessons.lessons) ? lessons.lessons : [];
  const cards = list.map(l => `
    <div class="card" style="box-shadow:none; background:rgba(0,0,0,.10)">
      <div class="card__hd"><h2>${esc(l.title)}</h2><div class="card__sub">${esc(l.level||'')}</div></div>
      <div class="card__bd">
        <div class="muted">${esc(l.summary||'')}</div>
        <div style="height:10px"></div>
        <button class="drawer__btn" data-lesson="${esc(l.id)}">Open lesson</button>
      </div>
    </div>
  `).join('');

  $('#content').innerHTML = `
    <div class="card">
      <div class="card__hd"><h2>Learn</h2><div class="card__sub">Networking basics, grounded in your own LAN inventory.</div></div>
      <div class="card__bd">
        <div class="muted small">Tip: click the “?” icons across the app to open contextual lessons.</div>
      </div>
    </div>
    ${cards || '<div class="muted">No lessons loaded.</div>'}
  `;

  $$('#content [data-lesson]').forEach(b=> b.addEventListener('click', ()=> openLearn(b.getAttribute('data-lesson'))));
}

function closeDrawer(){
  selectedId = null;
  $('#drawer').classList.remove('is-open');
  $('#backdrop').classList.remove('is-open');
}

function openDrawer(id){
  selectedId = id;
  const d = (latest.devices||[]).find(x=>x.id===id);
  if(!d) return;

  const st = deviceStats?.devices?.[id];
  const title = labelDevice(d);
  const sub = `${d.type||'unknown'} • ${d.mac||id} • ${d.ip||''}`;
  $('#drawerTitle').textContent = title;
  $('#drawerSub').textContent = sub;

  const mdnsH = (d.mdns||[]).join(', ');
  const mdnsS = (d.mdns_services||[]).join(', ');
  const ssdp = (d.ssdp||[]).slice(0,4).map(s => `${s.st||''} | ${s.server||''} | ${s.location||''}`.trim()).join('\n');

  const ports = (d.open_ports||[]).map(p=>p.raw).join('\n');
  const web = (d.web||[]).slice(0,6).map(w => `${w.url||''} HTTP ${w.status||''} ${(w.title||'')}`.trim()).join('\n');

  const stability = st ? `seen ${st.seenHours}/${st.totalHours}\nflaps ${st.flaps}\nunique IPs ${st.uniqueIps}` : '(no stats yet)';
  const flags = (d.risk_flags||[]).join('\n') || '(none)';

  // IP lane (from device_stats.json)
  function ipColor(ip){
    if(!ip) return 'rgba(255,255,255,.05)';
    let h=0;
    for(const ch of ip){ h = (h*131 + ch.charCodeAt(0)) % 0xFFFFFF; }
    const r = 160 + (h & 0x5F);
    const g = 160 + ((h>>6) & 0x5F);
    const b = 160 + ((h>>12) & 0x5F);
    return `rgb(${r},${g},${b})`;
  }

  const tail = (st && st.ipTail) ? st.ipTail : [];

  // Legend: unique IPs (limit)
  const uniq = [];
  const seenIps = new Set();
  tail.forEach(ip => {
    if(!ip) return;
    if(!seenIps.has(ip)) { seenIps.add(ip); uniq.push(ip); }
  });

  const legendHtml = uniq.length ? `
    <div class="ipLegend">
      ${uniq.slice(0,8).map(ip => {
        const sw = ipColor(ip);
        const oct = ip.split('.').slice(-1)[0];
        return `<span class="ipKey" title="${esc(ip)}"><span class="ipSwatch" style="background:${sw}"></span>${esc(oct)}</span>`;
      }).join('')}
      ${uniq.length > 8 ? `<span class="muted small">+${uniq.length-8} more</span>` : ''}
    </div>
  ` : '';

  const ipLane = tail.length ? tail.map((ip, idx)=>{
    const on = !!ip;
    const bg = on ? ipColor(ip) : 'rgba(255,255,255,.05)';
    const txt = on ? ip.split('.').slice(-1)[0] : '';
    const title = on ? ip : 'not seen';

    let cls = on ? 'ipCell' : 'ipCell off';
    const prev = idx > 0 ? tail[idx-1] : '';
    if(ip && prev && ip !== prev) cls += ' change';

    return `<div class="${cls}" style="background:${bg}" title="${esc(title)}">${esc(txt)}</div>`;
  }).join('') : '<div class="muted small">(no IP history yet)</div>';

  // Suggest override snippet
  const snippet = `{
  "types": {
    "${d.mac||id}": "${d.type||'unknown'}"
  },
  "names": {
    "${d.mac||id}": "${(d.name||'') || title}"
  }
}`;

  $('#drawerBody').innerHTML = `
    <div class="section">
      <div class="section__title">Identity</div>
      <div class="kv">
        <div class="k">Name</div><div>${esc(d.name||'')}</div>
        <div class="k">Hostname</div><div>${esc(d.hostname||'')}</div>
        <div class="k">Vendor</div><div>${esc(d.vendor||'')}</div>
        <div class="k">mDNS hostnames</div><div>${esc(mdnsH||'–')}</div>
        <div class="k">mDNS services</div><div>${esc(mdnsS||'–')}</div>
      </div>
    </div>

    <div class="section">
      <div class="section__title">Stability</div>
      <pre class="snip"><code>${esc(stability)}</code></pre>
      <div class="ipLaneLabel"><span>IP history (last ${tail.length || 0} snapshots)</span><span>cell=last octet • outline=changed</span></div>
      <div class="ipLane">${ipLane}</div>
      ${legendHtml}
    </div>

    <div class="section">
      <div class="section__title">Exposure</div>
      <div class="kv">
        <div class="k">Open ports</div><div><pre class="snip"><code>${esc(ports||'(none)')}</code></pre></div>
        <div class="k">Web</div><div><pre class="snip"><code>${esc(web||'(none)')}</code></pre></div>
      </div>
    </div>

    <div class="section">
      <div class="section__title">SSDP/UPnP</div>
      <pre class="snip"><code>${esc(ssdp||'(none)')}</code></pre>
    </div>

    <div class="section">
      <div class="section__title">Risk flags</div>
      <pre class="snip"><code>${esc(flags)}</code></pre>
    </div>

    <div class="section">
      <div class="section__title">Override snippet (copy/paste into overrides.json)</div>
      <pre class="snip"><code>${esc(snippet)}</code></pre>
    </div>
  `;

  // point classic link to same device
  $('#drawerClassic').href = `/device.html?id=${encodeURIComponent(id)}`;

  $('#drawer').classList.add('is-open');
  $('#backdrop').classList.add('is-open');
}

async function load(){
  const [a,b,c,d] = await Promise.all([
    fetch('/latest.json', {cache:'no-store'}).catch(()=>null),
    fetch('/history.json', {cache:'no-store'}).catch(()=>null),
    fetch('/device_stats.json', {cache:'no-store'}).catch(()=>null),
    fetch('/app/learn/lessons.json', {cache:'no-store'}).catch(()=>null),
  ]);

  if(a){ latest = await a.json(); }
  if(b){ history = await b.json(); }
  if(c && c.ok){ deviceStats = await c.json(); }
  if(d && d.ok){ lessons = await d.json(); }

  $('#lastUpdated').innerHTML = latest ? `Updated <b>${esc(latest.timestamp_human||'')}</b><div class="muted small">Subnet: ${esc(latest.subnet||'')}</div>` : 'Failed to load latest';

  // populate type filter
  const types = new Set((latest.devices||[]).map(d=>d.type||'unknown'));
  const sel = $('#filterType');
  sel.innerHTML = '<option value="">All types</option>' + Array.from(types).sort().map(t=>`<option value="${esc(t)}">${esc(t)}</option>`).join('');

  // Default: Learn mode OFF (public)
  if(localStorage.getItem('nw.learn.enabled') === null){
    localStorage.setItem('nw.learn.enabled', '0');
  }

  applyLearnVisibility();
  render();
}

function closeNav(){
  $('#sidebar')?.classList.remove('is-open');
  $('#navBackdrop')?.classList.remove('is-open');
}
function openNav(){
  $('#sidebar')?.classList.add('is-open');
  $('#navBackdrop')?.classList.add('is-open');
}

// events
$$('.nav__item').forEach(btn => btn.addEventListener('click', ()=>{
  closeNav();
  location.hash = '#'+btn.dataset.route;
}));
window.addEventListener('hashchange', ()=>{ closeNav(); closeDrawer(); render(); });
$('#search').addEventListener('input', ()=>{
  // If user is searching, jump to Devices view so results are obvious.
  const q = ($('#search').value || '').trim();
  if(q && route() !== 'devices') {
    location.hash = '#devices';
    return;
  }
  closeDrawer();
  render();
});
$('#filterType').addEventListener('change', ()=>{
  // Filters are most meaningful on the inventory view.
  if(route() !== 'devices') location.hash = '#devices';
  closeDrawer();
  render();
});
$('#filterRisk').addEventListener('change', ()=>{
  if(route() !== 'devices') location.hash = '#devices';
  closeDrawer();
  render();
});

$('#drawerClose').addEventListener('click', closeDrawer);
$('#backdrop').addEventListener('click', closeDrawer);

$('#learnClose').addEventListener('click', closeLearn);

$('#navToggle').addEventListener('click', ()=>{
  const open = $('#sidebar')?.classList.contains('is-open');
  if(open) closeNav(); else openNav();
});
$('#navBackdrop').addEventListener('click', closeNav);

window.addEventListener('keydown', (e)=>{
  if(e.key==='Escape') { closeNav(); closeDrawer(); closeLearn(); }
});

load();
