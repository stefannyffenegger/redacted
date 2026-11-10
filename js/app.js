/* UI wiring. Settings are stored in localStorage; document content never is. */
(function (R) {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = R.render.escapeHtml;
  const STORAGE_KEY = 'redacted.settings.v1';
  const THEME_KEY = 'redacted.theme';

  const SAMPLE = [
    '# sample: app config + logs',
    'server:',
    '  host: api01.prod.acme-corp.internal',
    '  listen: 10.20.30.40:8443',
    'database:',
    '  url: postgres://svc_billing:S3cr3t-Pa55@db-main.acme-corp.internal:5432/billing',
    '  password: "hunter2-but-longer"',
    'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    '',
    '2026-11-10T08:13:02Z INFO  request from 192.168.1.23 user=jane.doe@acme-corp.com id=5f3c2a9e-8b1d-4c7a-9e2f-1a2b3c4d5e6f',
    '2026-11-10T08:13:05Z WARN  retry to api01 via fe80::1ff:fe23:4567:890a (mac 00:1A:2B:3C:4D:5E)',
    '2026-11-10T08:13:09Z DEBUG Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqYW5lIn0.dQw4w9WgXcQ_signature',
    '2026-11-10T08:13:11Z INFO  request from 192.168.1.23 path=/home/jdoe/.ssh/config',
    '2026-11-10T08:13:15Z INFO  health check 127.0.0.1 ok, docs at https://example.com/help',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumq7nY0fKfGiDZoMnlBQ3t1Kq',
    'kWFBi0bG3hQ1h0P6qL0Zyv4BV8lXo6rUDl0EXAMPLEONLYDONOTUSE00000000000',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');

  // ---------------------------------------------------------------- settings
  function defaults() {
    return {
      enabled: {},
      template: R.DEFAULT_TEMPLATE,
      propagate: true,
      shortHosts: true,
      terms: [],
      customRules: [],
      allowlist: R.DEFAULT_ALLOWLIST.slice(),
    };
  }

  function sanitize(s) {
    const d = defaults();
    if (!s || typeof s !== 'object') return d;
    return {
      enabled: s.enabled && typeof s.enabled === 'object' ? s.enabled : d.enabled,
      template: typeof s.template === 'string' && s.template.includes('{N}') ? s.template : d.template,
      propagate: s.propagate !== false,
      shortHosts: s.shortHosts !== false,
      terms: Array.isArray(s.terms) ? s.terms.filter(t => t && t.value).map(t => ({ value: String(t.value), type: String(t.type || 'CUSTOM').toUpperCase() })) : d.terms,
      customRules: Array.isArray(s.customRules) ? s.customRules.filter(c => c && c.pattern).map((c, i) => ({
        id: 'custom-' + i, name: String(c.name || c.pattern), pattern: String(c.pattern),
        type: String(c.type || 'CUSTOM').toUpperCase(), flags: String(c.flags || ''), enabled: c.enabled !== false,
      })) : d.customRules,
      allowlist: Array.isArray(s.allowlist) ? s.allowlist.map(String) : d.allowlist,
    };
  }

  function loadSettings() {
    try { return sanitize(JSON.parse(localStorage.getItem(STORAGE_KEY))); } catch (e) { return defaults(); }
  }
  function saveSettings() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(settings)); } catch (e) { /* storage unavailable */ }
  }

  const state = {
    text: '',
    fileName: null,
    result: null,
    gridDirty: true,
    tab: 'input',
  };
  let settings = loadSettings();

  function isEnabled(rule) {
    return rule.id in settings.enabled ? settings.enabled[rule.id] : rule.enabled;
  }

  function options() {
    return {
      rules: R.rules.filter(isEnabled),
      customRules: settings.customRules.map((c, i) => Object.assign({}, c, { id: 'custom-' + i })),
      terms: settings.terms,
      allowlist: settings.allowlist,
      template: settings.template,
      propagate: settings.propagate,
      shortHosts: settings.shortHosts,
    };
  }

  // ---------------------------------------------------------------- run
  let timer = null;
  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(run, state.text.length > 1e6 ? 500 : 150);
  }

  function run() {
    clearTimeout(timer);
    const t0 = performance.now();
    state.result = R.redact(state.text, options());
    const ms = Math.round(performance.now() - t0);
    state.gridDirty = true;
    $('output').value = state.result.text;
    if (state.tab === 'compare') renderGrid();
    renderCounts();
    renderMapping();
    renderCustom();
    const lines = state.text ? state.text.split('\n').length : 0;
    const n = state.result.spans.length;
    $('stats').textContent = state.text ? `${lines.toLocaleString()} lines · ${n.toLocaleString()} redactions · ${state.result.mapping.length.toLocaleString()} unique values` : '';
    $('status').textContent = state.text ? `processed in ${ms} ms` : '';
  }

  function renderGrid() {
    if (!state.gridDirty || !state.result) return;
    const grid = $('grid');
    const top = grid.scrollTop;
    grid.innerHTML = state.text ? R.render.sideBySide(state.text, state.result) : '';
    grid.scrollTop = top;
    state.gridDirty = false;
  }

  // ---------------------------------------------------------------- sidebar
  function renderRules() {
    const groups = {};
    for (const r of R.rules) (groups[r.group] = groups[r.group] || []).push(r);
    let html = '';
    for (const g of Object.keys(groups)) {
      html += `<div class="group-title">${esc(g)}</div>`;
      for (const r of groups[g]) {
        html += `<label class="rule" title="type ${esc(r.type)}"><input type="checkbox" data-rule="${esc(r.id)}"${isEnabled(r) ? ' checked' : ''}>` +
          `<span class="swatch p${R.render.slotFor(r.type)}"></span><span class="name">${esc(r.name)}</span><span class="n" data-count="${esc(r.id)}"></span></label>`;
      }
    }
    html += `<div class="group-title">Propagation</div><div class="rule"><span class="swatch p5"></span><span class="name">Other occurrences of detected values</span><span class="n" data-count="propagated"></span></div>`;
    $('ruleList').innerHTML = html;
  }

  function renderCounts() {
    const counts = state.result ? state.result.counts : {};
    document.querySelectorAll('[data-count]').forEach(el => {
      const n = counts[el.dataset.count] || 0;
      el.textContent = n ? n.toLocaleString() : '';
      el.classList.toggle('hit', n > 0);
    });
    const total = state.result ? state.result.spans.length : 0;
    $('totalCount').textContent = total ? `(${total.toLocaleString()})` : '';
    $('termCount').textContent = settings.terms.length ? `(${settings.terms.length})` : '';
    $('customCount').textContent = settings.customRules.length ? `(${settings.customRules.length})` : '';
    $('allowCount').textContent = `(${settings.allowlist.filter(a => a.trim()).length})`;
  }

  function renderTerms() {
    $('termList').innerHTML = settings.terms.map((t, i) =>
      `<li><span class="v" title="${esc(t.value)}">${esc(t.value)}</span><span class="t p${R.render.slotFor(t.type)}">${esc(t.type)}</span><button class="x" data-del-term="${i}" title="Remove">×</button></li>`
    ).join('');
  }

  function renderCustom() {
    const errors = {};
    for (const e of (state.result && state.result.errors) || []) errors[e.ruleId] = e.message;
    $('customList').innerHTML = settings.customRules.map((c, i) => {
      const err = errors['custom-' + i];
      const n = (state.result && state.result.counts['custom-' + i]) || 0;
      return `<li class="${err ? 'bad' : ''}" title="${esc(err || '/' + c.pattern + '/' + c.flags)}">` +
        `<input type="checkbox" data-toggle-custom="${i}"${c.enabled ? ' checked' : ''}>` +
        `<span class="v">${esc(c.name)}${err ? ' ⚠' : ''}</span><span class="t p${R.render.slotFor(c.type)}">${esc(c.type)}</span>` +
        `<span class="muted">${n || ''}</span><button class="x" data-del-custom="${i}" title="Remove">×</button></li>`;
    }).join('');
  }

  function renderMapping() {
    const mapping = state.result ? state.result.mapping : [];
    $('mapCount').textContent = mapping.length ? `(${mapping.length.toLocaleString()})` : '';
    const f = $('mapFilter').value.trim().toLowerCase();
    const rows = (f ? mapping.filter(m => m.value.toLowerCase().includes(f) || m.placeholder.toLowerCase().includes(f)) : mapping);
    const shown = rows.slice(0, 1000);
    $('mapTable').tBodies[0].innerHTML = shown.map(m =>
      `<tr><td><span class="hl p${R.render.slotFor(m.type)}">${esc(m.placeholder)}</span></td><td>${esc(m.value.length > 200 ? m.value.slice(0, 200) + '…' : m.value)}</td><td>${m.count}</td></tr>`
    ).join('') + (rows.length > shown.length ? `<tr><td colspan="3" class="muted">… ${rows.length - shown.length} more (use export)</td></tr>` : '');
  }

  function renderSettingsForm() {
    $('optTemplate').value = settings.template;
    $('optPropagate').checked = settings.propagate;
    $('optShortHosts').checked = settings.shortHosts;
    $('allowlist').value = settings.allowlist.join('\n');
    renderRules();
    renderTerms();
    renderCustom();
  }

  function changed() {
    saveSettings();
    renderTerms();
    run();
  }

  // ---------------------------------------------------------------- helpers
  let toastTimer = null;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 2200);
  }

  function download(name, content, type) {
    const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
  }

  function setTab(name) {
    state.tab = name;
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.dataset.panel === name));
    if (name === 'compare') {
      if (timer) run();
      renderGrid();
    }
    hidePopover();
  }

  function setText(text, fileName) {
    state.text = text;
    state.fileName = fileName || null;
    $('input').value = text;
    $('fileName').textContent = fileName || 'pasted snippet';
    $('fileName').title = fileName ? 'Saves as ' + R.redactedFilename(fileName) : 'Saves as snippet.redacted.txt';
    run();
  }

  async function openFile(file) {
    if (!file) return;
    if (file.size > 50 * 1024 * 1024 && !confirm(`${file.name} is ${(file.size / 1048576).toFixed(0)} MB. Processing it may be slow. Continue?`)) return;
    const text = await file.text();
    if (text.slice(0, 8192).includes('\u0000') && !confirm(`${file.name} looks like a binary file. Open it anyway?`)) return;
    setText(text, file.name);
    setTab('compare');
    toast(`Loaded ${file.name}`);
  }

  // ---------------------------------------------------------------- popover
  const pop = $('popover');
  function hidePopover() { pop.hidden = true; pop.innerHTML = ''; }

  function showPopover(html, rect) {
    pop.innerHTML = html;
    pop.hidden = false;
    const w = pop.offsetWidth;
    const h = pop.offsetHeight;
    let x = Math.min(rect.left, window.innerWidth - w - 8);
    let y = rect.bottom + 6;
    if (y + h > window.innerHeight - 8) y = Math.max(8, rect.top - h - 6);
    pop.style.left = Math.max(8, x) + 'px';
    pop.style.top = y + 'px';
  }

  function showSpanInfo(i, el) {
    const s = state.result.spans[i];
    if (!s) return;
    const how = s.ruleId === 'propagated' ? 'other occurrence of a detected value'
      : s.ruleId === 'term' ? 'term list'
      : (R.rules.find(r => r.id === s.ruleId) || settings.customRules[+String(s.ruleId).replace('custom-', '')] || { name: s.ruleId }).name;
    const value = s.value.length > 300 ? s.value.slice(0, 300) + '…' : s.value;
    showPopover(
      `<div class="kv"><b>Type</b><span>${esc(s.type)}</span><b>Original</b><span>${esc(value)}</span>` +
      `<b>Placeholder</b><span>${esc(s.placeholder)}</span><b>Found by</b><span>${esc(how)}</span></div>` +
      `<div class="row-buttons"><button class="btn small" data-act="allow">Don't redact this value</button>` +
      `<button class="btn small ghost" data-act="close">Close</button></div>`,
      el.getBoundingClientRect()
    );
    pop.dataset.value = s.value;
  }

  // Returns the selected text in the input textarea or the original column.
  function currentSelection() {
    if (state.tab === 'input') {
      const ta = $('input');
      return ta.value.slice(ta.selectionStart, ta.selectionEnd);
    }
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed || !sel.rangeCount) return '';
    const node = sel.anchorNode && (sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentElement);
    if (!node || !node.closest('#grid .o, #output')) return '';
    return sel.toString();
  }

  function promptRedactSelection(rect) {
    const text = currentSelection().trim();
    if (!text) { toast('Select some text in the original first'); return; }
    if (text.includes('\n')) { toast('Select text within a single line'); return; }
    showPopover(
      `<div class="kv"><b>Redact</b><span>${esc(text.length > 120 ? text.slice(0, 120) + '…' : text)}</span></div>` +
      `<div class="row-buttons"><input id="selType" list="typeList" value="CUSTOM" spellcheck="false" aria-label="type">` +
      `<button class="btn small primary" data-act="add-term">Redact everywhere</button>` +
      `<button class="btn small ghost" data-act="close">Cancel</button></div>`,
      rect
    );
    pop.dataset.value = text;
    const input = $('selType');
    input.select();
    input.focus();
  }

  pop.addEventListener('click', e => {
    const act = e.target.dataset && e.target.dataset.act;
    if (!act) return;
    const value = pop.dataset.value;
    if (act === 'allow') {
      settings.allowlist.push(value);
      $('allowlist').value = settings.allowlist.join('\n');
      toast('Added to allowlist');
      changed();
    } else if (act === 'add-term') {
      const type = ($('selType').value || 'CUSTOM').trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
      addTerm(value, type);
    }
    hidePopover();
  });
  pop.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.id === 'selType') {
      addTerm(pop.dataset.value, (e.target.value || 'CUSTOM').trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_'));
      hidePopover();
    }
  });

  function addTerm(value, type) {
    if (!value) return;
    if (!settings.terms.some(t => t.value.toLowerCase() === value.toLowerCase())) {
      settings.terms.push({ value, type: type || 'CUSTOM' });
    }
    // Drop it from the allowlist if it was there.
    settings.allowlist = settings.allowlist.filter(a => a.toLowerCase() !== value.toLowerCase());
    $('allowlist').value = settings.allowlist.join('\n');
    toast(`Redacting "${value.length > 40 ? value.slice(0, 40) + '…' : value}" everywhere`);
    changed();
  }

  // ---------------------------------------------------------------- events
  $('input').addEventListener('input', e => {
    state.text = e.target.value;
    schedule();
  });
  $('input').addEventListener('paste', () => {
    // A paste into an empty box jumps straight to the comparison.
    if (!$('input').value) setTimeout(() => { state.text = $('input').value; run(); setTab('compare'); }, 0);
  });

  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => setTab(t.dataset.tab)));

  $('fileInput').addEventListener('change', e => { openFile(e.target.files[0]); e.target.value = ''; });

  let dragDepth = 0;
  window.addEventListener('dragenter', e => {
    if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes('Files')) return;
    dragDepth++;
    $('dropOverlay').hidden = false;
  });
  window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('dropOverlay').hidden = true; } });
  window.addEventListener('dragover', e => e.preventDefault());
  window.addEventListener('drop', e => {
    e.preventDefault();
    dragDepth = 0;
    $('dropOverlay').hidden = true;
    const f = e.dataTransfer && e.dataTransfer.files[0];
    if (f) {
      if (e.target && e.target.id === 'profileInput') return;
      openFile(f);
    }
  });

  $('btnCopy').addEventListener('click', async () => {
    if (!state.result || !state.text) return toast('Nothing to copy');
    await copyText(state.result.text);
    toast('Redacted text copied');
  });

  function doDownload() {
    if (!state.result || !state.text) return toast('Nothing to download');
    const name = R.redactedFilename(state.fileName);
    download(name, state.result.text);
    toast('Saved ' + name);
  }
  $('btnDownload').addEventListener('click', doDownload);

  $('btnSelection').addEventListener('mousedown', e => e.preventDefault()); // keep the selection
  $('btnSelection').addEventListener('click', e => promptRedactSelection(e.currentTarget.getBoundingClientRect()));

  $('btnClear').addEventListener('click', () => { setText('', null); setTab('input'); $('input').focus(); });
  $('btnSample').addEventListener('click', () => { setText(SAMPLE, 'sample-app.log'); setTab('compare'); });

  $('btnTheme').addEventListener('click', () => {
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch (e) { /* ignore */ }
  });
  $('btnSidebar').addEventListener('click', () => document.body.classList.toggle('no-sidebar'));

  // Grid: hover links the original and placeholder, click shows details.
  const grid = $('grid');
  let hovered = [];
  grid.addEventListener('mouseover', e => {
    const m = e.target.closest('mark.hl');
    hovered.forEach(h => h.classList.remove('focus'));
    hovered = m ? Array.from(grid.querySelectorAll(`mark[data-i="${m.dataset.i}"]`)) : [];
    hovered.forEach(h => h.classList.add('focus'));
  });
  grid.addEventListener('click', e => {
    const m = e.target.closest('mark.hl');
    if (m && window.getSelection().isCollapsed) showSpanInfo(+m.dataset.i, m);
  });
  grid.addEventListener('mouseup', () => {
    setTimeout(() => {
      const text = currentSelection();
      if (text && text.trim() && !text.includes('\n')) {
        const r = window.getSelection().getRangeAt(0).getBoundingClientRect();
        promptRedactSelection(r);
      }
    }, 0);
  });

  document.addEventListener('mousedown', e => {
    if (!pop.hidden && !pop.contains(e.target) && !e.target.closest('mark.hl')) hidePopover();
  });
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); doDownload(); }
    if (e.key === 'Escape') hidePopover();
  });

  // Sidebar controls
  $('ruleList').addEventListener('change', e => {
    const id = e.target.dataset.rule;
    if (!id) return;
    settings.enabled[id] = e.target.checked;
    changed();
  });
  $('optTemplate').addEventListener('input', e => {
    const v = e.target.value;
    if (!v.includes('{N}') && !v.includes('{TYPE}')) return;
    settings.template = v;
    saveSettings();
    schedule();
  });
  $('optPropagate').addEventListener('change', e => { settings.propagate = e.target.checked; changed(); });
  $('optShortHosts').addEventListener('change', e => { settings.shortHosts = e.target.checked; changed(); });

  $('termForm').addEventListener('submit', e => {
    e.preventDefault();
    const v = $('termValue').value.trim();
    if (!v) return;
    addTerm(v, ($('termType').value || 'CUSTOM').trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_'));
    $('termValue').value = '';
  });
  $('termList').addEventListener('click', e => {
    const i = e.target.dataset.delTerm;
    if (i === undefined) return;
    settings.terms.splice(+i, 1);
    changed();
  });

  $('customForm').addEventListener('submit', e => {
    e.preventDefault();
    const pattern = $('customPattern').value;
    const flags = $('customFlags').value.replace(/[^imsuv]/g, '');
    try {
      new RegExp(pattern, flags + 'gd');
    } catch (err) {
      $('customError').textContent = err.message;
      return;
    }
    if (new RegExp(pattern, flags).test('')) {
      $('customError').textContent = 'Pattern matches empty text; make it more specific.';
      return;
    }
    $('customError').textContent = '';
    settings.customRules.push({
      name: $('customName').value.trim() || pattern, pattern, flags,
      type: ($('customType').value || 'CUSTOM').trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_'), enabled: true,
    });
    $('customName').value = '';
    $('customPattern').value = '';
    changed();
  });
  $('customList').addEventListener('click', e => {
    const i = e.target.dataset.delCustom;
    if (i === undefined) return;
    settings.customRules.splice(+i, 1);
    changed();
  });
  $('customList').addEventListener('change', e => {
    const i = e.target.dataset.toggleCustom;
    if (i === undefined) return;
    settings.customRules[+i].enabled = e.target.checked;
    changed();
  });

  $('allowlist').addEventListener('input', e => {
    settings.allowlist = e.target.value.split('\n');
    saveSettings();
    schedule();
  });

  $('mapFilter').addEventListener('input', renderMapping);

  function confirmMappingExport() {
    if (!state.result || !state.result.mapping.length) { toast('No mapping yet'); return false; }
    return confirm('The mapping contains the ORIGINAL sensitive values. Do not share it together with the redacted file.\n\nExport anyway?');
  }
  const baseName = () => R.redactedFilename(state.fileName).replace(/\.[^.]*$/, '');
  $('btnMapJson').addEventListener('click', () => {
    if (!confirmMappingExport()) return;
    const out = {};
    for (const m of state.result.mapping) out[m.placeholder] = { type: m.type, original: m.value, count: m.count };
    download(baseName() + '.mapping.json', JSON.stringify(out, null, 2), 'application/json');
  });
  $('btnMapCsv').addEventListener('click', () => {
    if (!confirmMappingExport()) return;
    const q = v => '"' + String(v).replace(/"/g, '""') + '"';
    const lines = ['placeholder,type,original,count'].concat(state.result.mapping.map(m => [q(m.placeholder), q(m.type), q(m.value), m.count].join(',')));
    download(baseName() + '.mapping.csv', lines.join('\r\n'), 'text/csv;charset=utf-8');
  });

  $('btnProfileExport').addEventListener('click', () => {
    download('redacted-profile.json', JSON.stringify(Object.assign({ app: 'redacted', version: 1 }, settings), null, 2), 'application/json');
  });
  $('profileInput').addEventListener('change', async e => {
    const f = e.target.files[0];
    e.target.value = '';
    if (!f) return;
    try {
      settings = sanitize(JSON.parse(await f.text()));
      saveSettings();
      renderSettingsForm();
      run();
      toast('Profile imported');
    } catch (err) {
      toast('Could not read profile: ' + err.message);
    }
  });
  $('btnReset').addEventListener('click', () => {
    if (!confirm('Reset all detectors, terms, custom patterns and the allowlist to defaults?')) return;
    settings = defaults();
    saveSettings();
    renderSettingsForm();
    run();
  });

  // ---------------------------------------------------------------- init
  try {
    const theme = localStorage.getItem(THEME_KEY);
    if (theme === 'dark' || theme === 'light') document.documentElement.dataset.theme = theme;
  } catch (e) { /* ignore */ }
  renderSettingsForm();
  run();
  if (location.hash === '#sample') { setText(SAMPLE, 'sample-app.log'); setTab('compare'); }
  R.app = { setText, setTab, state, run };
})(window.Redacted = window.Redacted || {});
