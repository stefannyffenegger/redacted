/*
 * Redaction engine. Pure functions, no DOM access.
 *
 *   Redacted.redact(text, options) -> {
 *     text,      redacted text
 *     spans,     [{origStart, origEnd, redStart, redEnd, type, value, placeholder, ruleId}]
 *     mapping,   [{type, value, placeholder, count}]  (first-seen order)
 *     counts,    {ruleId: n}
 *     errors,    [{ruleId, message}]  (invalid custom regexes)
 *   }
 *
 *   Redacted.restore(text, entries) reverses it using a mapping (see below).
 */
(function (R) {
  'use strict';

  const DEFAULT_TEMPLATE = '<{TYPE}_{N}>';
  const DEFAULT_ALLOWLIST = ['127.0.0.1', '0.0.0.0', '255.255.255.255', 'localhost', 'localhost.localdomain', '::1', 'example.com', '*.example.com', 'example.org', 'example.net'];

  // Common first labels that should not be redacted as standalone short hostnames.
  const COMMON_LABELS = new Set(['www', 'mail', 'smtp', 'imap', 'pop', 'pop3', 'ftp', 'api', 'app', 'web', 'dns', 'ns1', 'ns2', 'vpn', 'git', 'dev', 'test', 'prod', 'stage', 'staging', 'admin', 'auth', 'login', 'docs', 'blog', 'shop', 'static', 'cdn', 'assets', 'media', 'img', 'images', 'files', 'download', 'downloads', 'update', 'updates', 'repo', 'mirror', 'proxy', 'gateway', 'portal', 'status', 'help', 'support', 'internal', 'local', 'corp', 'home', 'server', 'client', 'host', 'node', 'master', 'main', 'default', 'service', 'services', 'cluster', 'kube', 'kubernetes', 'docker', 'registry', 'github', 'gitlab', 'google', 'amazonaws', 'azure', 'cloudflare', 'microsoft', 'apple', 'ubuntu', 'debian', 'fedora', 'redhat', 'centos', 'archive', 'security', 'login']);

  // Types compared case-insensitively when numbering placeholders.
  const CASE_INSENSITIVE_TYPES = new Set(['HOST', 'EMAIL', 'IPV6', 'MAC', 'UUID']);

  const regexCache = new Map();

  function compile(source, flags) {
    const key = flags + '\u0000' + source;
    let re = regexCache.get(key);
    if (!re) {
      re = new RegExp(source, flags);
      regexCache.set(key, re);
    }
    re.lastIndex = 0;
    return re;
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function uniqFlags(flags) {
    return Array.from(new Set(flags.split(''))).join('');
  }

  function normalize(type, value, caseInsensitive) {
    let v = value;
    if (type === 'MAC') v = v.replace(/-/g, ':');
    if (caseInsensitive || CASE_INSENSITIVE_TYPES.has(type)) v = v.toLowerCase();
    return v;
  }

  function buildAllowlist(entries) {
    const exact = new Set();
    const globs = [];
    for (const raw of entries || []) {
      const e = String(raw).trim();
      if (!e || e.startsWith('#')) continue;
      if (e.includes('*') || e.includes('?')) {
        const src = '^' + e.split('').map(c => c === '*' ? '.*' : c === '?' ? '.' : escapeRegExp(c)).join('') + '$';
        globs.push(new RegExp(src, 'i'));
      } else {
        exact.add(e.toLowerCase());
      }
    }
    return value => {
      const v = value.toLowerCase();
      return exact.has(v) || globs.some(g => g.test(value));
    };
  }

  function placeholderMatcher(template) {
    const src = escapeRegExp(template)
      .replace(escapeRegExp('{TYPE}'), '[A-Z0-9_]+')
      .replace(escapeRegExp('{N}'), '\\d+');
    return new RegExp('^' + src + '$');
  }

  // Runs one regex rule over the text and pushes candidate matches.
  function collect(text, rule, re, out) {
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      let start, end, value;
      const named = m.indices.groups && m.indices.groups.v;
      if (named) {
        [start, end] = named;
        value = m.groups.v;
      } else if (rule.capture) {
        const idx = m.indices[rule.capture];
        if (!idx) continue;
        [start, end] = idx;
        value = m[rule.capture];
      } else {
        start = m.index;
        end = m.index + m[0].length;
        value = m[0];
      }
      if (!value) continue;
      if (rule.validate && !rule.validate(value)) continue;
      out.push({ start, end, value, type: rule.type, priority: rule.priority, ruleId: rule.id, ci: !!rule.ci });
    }
  }

  // Finds literal terms case-insensitively (substring match: over-redacting is the safe side).
  function collectTerms(text, lower, terms, out) {
    for (const t of terms) {
      const value = String(t.value || '').trim();
      if (!value) continue;
      const needle = value.toLowerCase();
      let i = lower.indexOf(needle);
      while (i !== -1) {
        out.push({ start: i, end: i + needle.length, value: text.slice(i, i + needle.length), type: t.type || 'CUSTOM', priority: 99, ruleId: 'term', ci: true });
        i = lower.indexOf(needle, i + needle.length);
      }
    }
  }

  // Accepts candidates greedily by priority, then length, rejecting overlaps.
  function resolve(candidates, occupied, accepted) {
    candidates.sort((a, b) => (b.priority - a.priority) || ((b.end - b.start) - (a.end - a.start)) || (a.start - b.start));
    for (const c of candidates) {
      let free = true;
      for (let i = c.start; i < c.end; i++) {
        if (occupied[i]) { free = false; break; }
      }
      if (!free) continue;
      occupied.fill(1, c.start, c.end);
      accepted.push(c);
    }
  }

  function redact(text, options) {
    const opts = options || {};
    const template = opts.template || DEFAULT_TEMPLATE;
    const isAllowed = buildAllowlist(opts.allowlist || DEFAULT_ALLOWLIST);
    const isPlaceholder = placeholderMatcher(template);
    const counts = {};
    const errors = [];
    const candidates = [];

    const rules = (opts.rules || R.rules.filter(r => r.enabled)).slice();
    for (const cr of opts.customRules || []) {
      if (cr.enabled === false || !cr.pattern) continue;
      rules.push({
        id: cr.id || 'custom', type: (cr.type || 'CUSTOM').toUpperCase(), priority: 98,
        pattern: cr.pattern, flags: (cr.flags || '').replace(/[gdy]/g, ''), ci: /i/.test(cr.flags || ''),
      });
    }

    for (const rule of rules) {
      let re;
      try {
        re = compile(rule.pattern, uniqFlags('gd' + (rule.flags || '')));
      } catch (e) {
        errors.push({ ruleId: rule.id, message: e.message });
        continue;
      }
      collect(text, rule, re, candidates);
    }
    const lower = text.toLowerCase();
    if (opts.terms && opts.terms.length) collectTerms(text, lower, opts.terms, candidates);

    const keep = c => !isAllowed(c.value) && !isPlaceholder.test(c.value);
    const occupied = new Uint8Array(text.length);
    const accepted = [];
    resolve(candidates.filter(keep), occupied, accepted);

    // Propagation: redact every other verbatim occurrence of detected values.
    if (opts.propagate !== false && accepted.length) {
      const known = new Map(); // normalized value -> {type, ci}
      const add = (type, value, ci) => {
        if (value.length < 3) return;
        const key = normalize(type, value, ci);
        if (!known.has(key)) known.set(key, { type, ci: ci || CASE_INSENSITIVE_TYPES.has(type) });
      };
      for (const c of accepted) {
        if (c.value.includes('\n')) continue;
        add(c.type, c.value, c.ci);
        if (opts.shortHosts !== false && c.type === 'HOST' && c.value.includes('.')) {
          const label = c.value.split('.')[0];
          if (label.length >= 4 && !/^\d+$/.test(label) && !COMMON_LABELS.has(label.toLowerCase()) && !isAllowed(label)) {
            add('HOST', label, true);
          }
        }
      }
      const extra = [];
      for (const ci of [true, false]) {
        const values = Array.from(known.entries()).filter(([, v]) => v.ci === ci).map(([k]) => k);
        if (!values.length) continue;
        values.sort((a, b) => b.length - a.length);
        const re = new RegExp('(?<![A-Za-z0-9])(?:' + values.map(escapeRegExp).join('|') + ')(?![A-Za-z0-9])', ci ? 'gi' : 'g');
        let m;
        while ((m = re.exec(text)) !== null) {
          const info = known.get(ci ? m[0].toLowerCase() : m[0]);
          if (!info) continue;
          extra.push({ start: m.index, end: m.index + m[0].length, value: m[0], type: info.type, priority: 10, ruleId: 'propagated', ci: info.ci });
        }
      }
      resolve(extra.filter(keep), occupied, accepted);
    }

    accepted.sort((a, b) => a.start - b.start);

    // Number placeholders in order of first appearance.
    const byKey = new Map();
    const perType = {};
    const mapping = [];
    let out = '';
    let pos = 0;
    const spans = [];
    for (const c of accepted) {
      const key = c.type + '\u0000' + normalize(c.type, c.value, c.ci);
      let entry = byKey.get(key);
      if (!entry) {
        perType[c.type] = (perType[c.type] || 0) + 1;
        entry = {
          type: c.type,
          value: c.value,
          placeholder: template.split('{TYPE}').join(c.type).split('{N}').join(String(perType[c.type])),
          count: 0,
        };
        byKey.set(key, entry);
        mapping.push(entry);
      }
      entry.count++;
      counts[c.ruleId] = (counts[c.ruleId] || 0) + 1;
      out += text.slice(pos, c.start);
      const redStart = out.length;
      out += entry.placeholder;
      spans.push({ origStart: c.start, origEnd: c.end, redStart, redEnd: out.length, type: c.type, value: c.value, placeholder: entry.placeholder, ruleId: c.ruleId });
      pos = c.end;
    }
    out += text.slice(pos);

    return { text: out, spans, mapping, counts, errors };
  }

  // ---------------------------------------------------------------- restore

  // Minimal RFC 4180 CSV parser: quoted fields may contain commas, quotes ("") and newlines.
  function parseCsv(text) {
    const rows = [];
    let row = [], field = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false;
        } else field += c;
      } else if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); rows.push(row); row = []; field = '';
      } else field += c;
    }
    if (quoted) throw new Error('unterminated quoted field');
    if (field || row.length) { row.push(field); rows.push(row); }
    return rows.filter(r => r.length > 1 || r[0] !== '');
  }

  /*
   * Parses an exported mapping into [{placeholder, type, value}]. Accepts:
   *   JSON object  {"<IP_1>": {"type": "IP", "original": "10.0.0.5", "count": 2}, ...}  (the export format)
   *   JSON array   [{"placeholder": "<IP_1>", "original"|"value": "10.0.0.5", "type": "IP"}, ...]
   *   CSV          placeholder,type,original[,count]  (header required)
   * Throws if the content is not a mapping.
   */
  function parseMapping(content) {
    const src = String(content || '').replace(/^﻿/, '');
    const trimmed = src.trim();
    let entries;
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      const data = JSON.parse(trimmed);
      const list = Array.isArray(data) ? data : Object.keys(data).map(k => Object.assign({ placeholder: k }, data[k]));
      entries = list.map(e => {
        if (!e || typeof e !== 'object') throw new Error('not a mapping');
        const value = 'original' in e ? e.original : e.value;
        if (typeof e.placeholder !== 'string' || typeof value !== 'string') throw new Error('not a mapping: each entry needs a placeholder and an original value');
        return { placeholder: e.placeholder, type: String(e.type || ''), value };
      });
    } else {
      const rows = parseCsv(src);
      const head = (rows.shift() || []).map(h => h.trim().toLowerCase());
      const pi = head.indexOf('placeholder');
      const vi = head.indexOf('original') !== -1 ? head.indexOf('original') : head.indexOf('value');
      const ti = head.indexOf('type');
      if (pi === -1 || vi === -1) throw new Error('not a mapping: CSV needs "placeholder" and "original" columns');
      entries = rows.map(r => ({ placeholder: r[pi] || '', type: ti === -1 ? '' : (r[ti] || ''), value: r[vi] || '' }));
    }
    entries = entries.filter(e => e.placeholder);
    if (!entries.length) throw new Error('mapping is empty');
    return entries;
  }

  // Guesses the placeholder template ("<{TYPE}_{N}>") from mapping entries, to spot unknown placeholders.
  function inferTemplates(entries) {
    const out = new Set();
    for (const e of entries) {
      const i = e.type ? e.placeholder.indexOf(e.type) : -1;
      if (i === -1) continue;
      const rest = e.placeholder.slice(i + e.type.length);
      const m = rest.match(/^(.*?)(\d+)(\D*)$/);
      if (m) out.add(e.placeholder.slice(0, i) + '{TYPE}' + m[1] + '{N}' + m[3]);
    }
    return Array.from(out);
  }

  /*
   * Puts the original values back in place of placeholders.
   *   Redacted.restore(text, entries) -> {
   *     text,        restored text
   *     count,       number of replacements
   *     used,        [{placeholder, value, count}] mapping entries that occurred
   *     unresolved,  placeholder-like tokens with no mapping entry (e.g. from another file's mapping)
   *   }
   * `entries` is [{placeholder, value, type?}], e.g. from parseMapping() or redact().mapping.
   */
  function restore(text, entries) {
    const src = String(text || '');
    const byPh = new Map();
    for (const e of entries || []) if (e.placeholder && !byPh.has(e.placeholder)) byPh.set(e.placeholder, e);
    const used = new Map();
    let count = 0;
    let out = src;
    if (byPh.size && src) {
      // Longest first so <IP_12> wins over <IP_1>; word-char edges must not touch other word chars.
      const alts = Array.from(byPh.keys()).sort((a, b) => b.length - a.length).map(p =>
        (/^\w/.test(p) ? '(?<!\\w)' : '') + escapeRegExp(p) + (/\w$/.test(p) ? '(?!\\w)' : ''));
      const re = new RegExp(alts.join('|'), 'g');
      out = src.replace(re, ph => {
        const e = byPh.get(ph);
        count++;
        const u = used.get(ph) || used.set(ph, { placeholder: ph, value: e.value, count: 0 }).get(ph);
        u.count++;
        return e.value;
      });
    }
    const unresolved = new Set();
    for (const t of inferTemplates(Array.from(byPh.values()))) {
      const reSrc = escapeRegExp(t).replace(escapeRegExp('{TYPE}'), '[A-Z][A-Z0-9_]*').replace(escapeRegExp('{N}'), '\\d+');
      const re = new RegExp((/^\w/.test(t) ? '(?<!\\w)' : '') + reSrc + (/\w$/.test(t) ? '(?!\\w)' : ''), 'g');
      for (const m of src.matchAll(re)) if (!byPh.has(m[0])) unresolved.add(m[0]);
    }
    return { text: out, count, used: Array.from(used.values()), unresolved: Array.from(unresolved) };
  }

  // ---------------------------------------------------------------- filenames

  function tagFilename(name, tag, fallback) {
    const n = (name || '').trim();
    if (!n) return fallback;
    const compound = n.match(/^(.+?)(\.tar\.(?:gz|bz2|xz|zst))$/i);
    if (compound) return compound[1] + tag + compound[2];
    const dot = n.lastIndexOf('.');
    if (dot <= 0) return n + tag;
    return n.slice(0, dot) + tag + n.slice(dot);
  }

  // app.log -> app.redacted.log, a.tar.gz -> a.redacted.tar.gz, Dockerfile -> Dockerfile.redacted
  function redactedFilename(name) {
    return tagFilename(name, '.redacted', 'snippet.redacted.txt');
  }

  // app.redacted.log -> app.restored.log, notes.txt -> notes.restored.txt
  function restoredFilename(name) {
    const n = (name || '').trim();
    if (/\.redacted(?=\.|$)/.test(n)) return n.replace(/\.redacted(?=\.|$)/, '.restored');
    return tagFilename(n, '.restored', 'snippet.restored.txt');
  }

  R.DEFAULT_TEMPLATE = DEFAULT_TEMPLATE;
  R.DEFAULT_ALLOWLIST = DEFAULT_ALLOWLIST;
  R.redact = redact;
  R.restore = restore;
  R.parseMapping = parseMapping;
  R.redactedFilename = redactedFilename;
  R.restoredFilename = restoredFilename;
  R.escapeRegExp = escapeRegExp;
})(window.Redacted = window.Redacted || {});
