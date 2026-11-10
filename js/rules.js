/*
 * Built-in detectors.
 *
 * Each rule:
 *   id        stable key (used for settings)
 *   name      label in the UI
 *   group     UI grouping
 *   type      placeholder type, e.g. IP -> <IP_1>
 *   priority  wins over lower priorities when matches overlap
 *   pattern   RegExp source; flags are added by the engine ('g' + 'd' + extra flags)
 *   flags     extra flags ('i', 'm')
 *   capture   optional capture group index: only that group is redacted
 *   validate  optional fn(value) -> bool to drop false positives
 *   enabled   default on/off
 */
(function (R) {
  'use strict';

  const H = '[0-9A-Fa-f]{1,4}';
  const IPV4 = '(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';

  // Ordered so longer forms are tried first; the lookarounds force backtracking
  // into another alternative when a shorter one would stop mid-address.
  const IPV6 = '(?:' + [
    `(?:${H}:){7}${H}`,
    `(?:${H}:){1,4}:${IPV4}`,
    `::(?:ffff(?::0{1,4})?:)?${IPV4}`,
    `(?:${H}:){1,6}:${H}`,
    `(?:${H}:){1,5}(?::${H}){1,2}`,
    `(?:${H}:){1,4}(?::${H}){1,3}`,
    `(?:${H}:){1,3}(?::${H}){1,4}`,
    `(?:${H}:){1,2}(?::${H}){1,5}`,
    `${H}:(?::${H}){1,6}`,
    `:(?::${H}){1,7}`,
    `(?:${H}:){1,7}:`,
  ].join('|') + ')';

  // Real TLDs plus common internal suffixes. File extensions that are also
  // TLDs (see AMBIGUOUS_TLDS) need at least three labels to count.
  const TLDS = new Set((
    'com net org io dev app cloud ai co info biz edu gov mil int me tv cc ' +
    'us uk de fr nl eu ch at be it es se no dk fi pl cz sk hu ro bg gr pt ie lu li ' +
    'ru ua by kz cn jp kr tw hk sg in id my th vn ph au nz ca br mx ar cl za ' +
    'is ee lv lt si hr rs tr il ae sa ' +
    'online site tech xyz cloud page systems services solutions network ' +
    'local lan internal corp intra intranet home localdomain private priv ' +
    'test example invalid localhost arpa svc cluster'
  ).split(/\s+/));
  const AMBIGUOUS_TLDS = new Set(['sh', 'py', 'md', 'pl', 'rs', 'ps', 'so', 'cc', 'in', 'it', 'me', 'tv', 'ai', 'co', 'is', 'at', 'id', 'by', 'no', 'app', 'page']);

  function isHostname(value) {
    const labels = value.split('.');
    if (labels.length < 2) return false;
    const tld = labels[labels.length - 1].toLowerCase();
    if (!TLDS.has(tld) && !AMBIGUOUS_TLDS.has(tld)) return false;
    if (AMBIGUOUS_TLDS.has(tld) && labels.length < 3) return false;
    // Skip version-like strings such as 1.2.3.in
    if (labels.slice(0, -1).every(l => /^\d+$/.test(l))) return false;
    return true;
  }

  function luhn(value) {
    const digits = value.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let d = +digits[digits.length - 1 - i];
      if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }

  function entropy(s) {
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    let e = 0;
    for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
    return e;
  }

  // Values that look like a secret key/value but are clearly not secrets.
  const NOT_SECRET = /^(?:bearer|basic|token|digest|negotiate|null|none|nil|true|false|yes|no|required|optional|\*+|x+|changeme|<[^>]*>|\$\{.*\}|\$\w+|%\w+%|\{\{.*\}\})$/i;

  R.rules = [
    // ---- Secrets -------------------------------------------------------
    {
      id: 'private-key', group: 'Secrets', name: 'PEM private key blocks', type: 'PRIVATE_KEY', priority: 100, enabled: true,
      pattern: '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----',
    },
    {
      id: 'jwt', group: 'Secrets', name: 'JSON Web Tokens', type: 'TOKEN', priority: 95, enabled: true,
      pattern: '\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*',
    },
    {
      id: 'aws-key', group: 'Secrets', name: 'AWS access key IDs', type: 'AWS_KEY', priority: 95, enabled: true,
      pattern: '\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\\b',
    },
    {
      id: 'url-cred', group: 'Secrets', name: 'Credentials in URLs (user:pass@)', type: 'CREDENTIAL', priority: 92, enabled: true,
      pattern: '\\b[a-z][a-z0-9+.-]*://([^\\s:@/]+:[^\\s@/]+)@', flags: 'i', capture: 1,
    },
    {
      id: 'auth-header', group: 'Secrets', name: 'Authorization: Bearer/Basic values', type: 'SECRET', priority: 90, enabled: true,
      pattern: '\\b(?:Bearer|Basic|Token|Digest)\\s+([A-Za-z0-9\\-._~+/]{8,}=*)', capture: 1,
    },
    {
      id: 'api-token', group: 'Secrets', name: 'Known API tokens (GitHub, Stripe, Slack, Google, GitLab)', type: 'TOKEN', priority: 94, enabled: true,
      pattern: '\\b(?:(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})',
    },
    {
      id: 'k8s-env-secret', group: 'Secrets', name: 'Kubernetes env secrets (name: *PASSWORD / value:)', type: 'SECRET', priority: 86, enabled: true,
      pattern: 'name:\\s*["\']?[\\w.-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|CREDENTIALS?|_PASS)\\w*["\']?[ \\t]*\\r?\\n[ \\t]*value:[ \\t]*["\']?([^\\s"\']+)',
      flags: 'i', capture: 1,
      validate: v => !NOT_SECRET.test(v),
    },
    {
      id: 'kv-secret', group: 'Secrets', name: 'password= / secret: / token= / api_key …', type: 'SECRET', priority: 85, enabled: true,
      pattern: '[\\w.-]*?(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credentials?|auth)["\']?[ \\t]*[=:][ \\t]*["\']?(\\$\\{[^}\\s]*\\}|[^\\s"\',;}]+)',
      flags: 'i', capture: 1,
      validate: v => !NOT_SECRET.test(v),
    },
    {
      id: 'entropy', group: 'Secrets', name: 'High-entropy strings (24+ chars)', type: 'SECRET', priority: 40, enabled: false,
      pattern: '(?<![\\w/+=-])[A-Za-z0-9+/_=-]{24,}(?![\\w/+=-])',
      validate: v => /\d/.test(v) && /[a-zA-Z]/.test(v) && entropy(v) > 4.0,
    },

    // ---- Network -------------------------------------------------------
    {
      id: 'ipv4', group: 'Network', name: 'IPv4 addresses (incl. CIDR)', type: 'IP', priority: 80, enabled: true,
      pattern: `(?<![\\d.])${IPV4}(?:/(?:3[0-2]|[12]?\\d))?(?!\\.?\\d)`,
    },
    {
      id: 'ipv6', group: 'Network', name: 'IPv6 addresses', type: 'IPV6', priority: 79, enabled: true,
      pattern: `(?<![\\w:.])${IPV6}(?:/\\d{1,3})?(?![\\w:])`,
      // Require at least two hex groups so things like "a::" are ignored.
      validate: v => v.split('/')[0].split(/:+/).filter(Boolean).length >= 2,
    },
    {
      id: 'mac', group: 'Network', name: 'MAC addresses', type: 'MAC', priority: 78, enabled: true,
      pattern: '(?<![\\w:.-])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\\1){4}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4})(?![\\w:.-])',
    },
    {
      id: 'email', group: 'Identity', name: 'Email addresses', type: 'EMAIL', priority: 75, enabled: true,
      pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}\\b',
    },
    {
      id: 'fqdn', group: 'Network', name: 'Hostnames / domains (FQDN)', type: 'HOST', priority: 60, enabled: true,
      pattern: '(?<![\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z][a-z0-9-]{0,62}(?![\\w-]|\\.[a-z0-9])',
      flags: 'i',
      validate: isHostname,
    },
    {
      id: 'host-kv', group: 'Network', name: 'host= / server: / HostName values', type: 'HOST', priority: 55, enabled: true,
      pattern: '(?:\\b(?:host|hostname|host_name|server|server_name|servername|node|nodename|node_name)["\']?[ \\t]*[=:][ \\t]*["\']?|^[ \\t]*(?:HostName|ServerName|server_name|Host)[ \\t]+)([A-Za-z0-9][\\w.-]*[\\w])',
      flags: 'im', capture: 1,
      validate: v => !/^\d+$/.test(v) && !/^(?:true|false|none|null|any|all|default|on|off|yes|no)$/i.test(v),
    },

    // ---- Identity ------------------------------------------------------
    {
      id: 'home-user', group: 'Identity', name: 'Usernames in home paths', type: 'USER', priority: 70, enabled: true,
      pattern: '(?:/home/|/Users/|[A-Za-z]:\\\\Users\\\\)([A-Za-z0-9._-]+)', capture: 1,
      validate: v => !/^(?:shared|public|default|all users)$/i.test(v),
    },

    // ---- Other ---------------------------------------------------------
    {
      id: 'uuid', group: 'Other', name: 'UUIDs', type: 'UUID', priority: 65, enabled: true,
      pattern: '\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b',
    },
    {
      id: 'card', group: 'Other', name: 'Credit card numbers (Luhn-checked)', type: 'CARD', priority: 66, enabled: true,
      pattern: '(?<![\\d-])\\d{4}(?:[ -]?\\d{4}){2}[ -]?\\d{1,7}(?![\\d-])',
      // Card numbers start with 2-6; this also skips epoch-millisecond timestamps.
      validate: v => /^[2-6]/.test(v) && luhn(v),
    },
    {
      id: 'hash', group: 'Other', name: 'Hex hashes (32+ chars)', type: 'HASH', priority: 45, enabled: false,
      pattern: '\\b[0-9a-fA-F]{32,128}\\b',
    },
  ];

  R.ruleHelpers = { isHostname, luhn, entropy };
})(window.Redacted = window.Redacted || {});
