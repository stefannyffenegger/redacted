/* Minimal in-browser test runner. Open tests.html, or run headless:
 *   google-chrome --headless --dump-dom tests/tests.html | grep summary
 */
(function (R) {
  'use strict';
  const results = [];
  function test(name, fn) {
    try { fn(); results.push({ name, ok: true }); } catch (e) { results.push({ name, ok: false, msg: e.message }); }
  }
  function eq(actual, expected, label) {
    const a = JSON.stringify(actual), b = JSON.stringify(expected);
    if (a !== b) throw new Error(`${label || ''} expected ${b}, got ${a}`);
  }
  function ok(cond, label) { if (!cond) throw new Error(label || 'assertion failed'); }

  const red = (text, opts) => R.redact(text, opts).text;
  // Values detected (by type) in text, ignoring propagation.
  const found = (text, opts) => R.redact(text, Object.assign({ propagate: false }, opts)).spans.map(s => [s.type, s.value]);
  const only = id => ({ rules: R.rules.filter(r => r.id === id), propagate: false, allowlist: [] });

  // ---- detectors: positive & negative --------------------------------
  const cases = {
    ipv4: {
      yes: ['10.0.0.1', '192.168.1.23', '172.16.0.0/12', 'from 8.8.8.8:53', 'ip=100.64.1.1.'],
      no: ['999.1.1.1', '1.2.3', '10.0.0.1.5', 'v1.2.3.4.5', '2026.11.10'],
    },
    ipv6: {
      yes: ['2001:db8::1', 'fe80::1ff:fe23:4567:890a', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', '::ffff:192.0.2.1'],
      no: ['12:34:56', 'std::vector', 'a::', '08:13:02Z'],
    },
    mac: {
      yes: ['00:1A:2B:3C:4D:5E', '00-1a-2b-3c-4d-5e', '001a.2b3c.4d5e'],
      no: ['00:1A:2B:3C:4D', '12:34:56', '00:1A-2B:3C:4D:5E'],
    },
    email: { yes: ['jane.doe@acme-corp.com', 'a+b@x.co.uk'], no: ['@foo', 'user@localhost'] },
    fqdn: {
      yes: ['api01.prod.acme-corp.internal', 'www.google.com', 'db.corp', 'build.example.sh', 'host.local'],
      no: ['nginx.conf', 'README.md', 'app.py', 'config.json', 'java.lang.String', 'file.txt', '1.2.3.in'],
    },
    'kv-secret': {
      yes: ['password=hunter2', 'db_password: "s3cret"', 'api_key=abc123', 'client_secret = xyz789', 'Pwd=Abc;', 'TOKEN: tkn_123'],
      no: ['password_file: /etc/x', 'max_tokens=100', 'author: John', 'password: ${DB_PASS}', 'password: null', 'PasswordAuthentication yes'],
    },
    'auth-header': { yes: ['Authorization: Bearer abcdef123456', 'Basic dXNlcjpwYXNz'], no: ['Bearer x', 'the token'] },
    jwt: { yes: ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqYW5lIn0.sig_part'], no: ['eyJ.short'] },
    'aws-key': { yes: ['AKIAIOSFODNN7EXAMPLE'], no: ['AKIA123', 'XKIAIOSFODNN7EXAMPLE'] },
    'url-cred': { yes: ['postgres://user:pa55@db:5432/x', 'https://bob:secret@host.com/'], no: ['https://host.com/a@b', 'mailto:a@b.com'] },
    'home-user': { yes: ['/home/jdoe/.ssh', 'C:\\Users\\Jane\\Desktop', '/Users/bob/x'], no: ['/home/', '/opt/home'] },
    uuid: { yes: ['5f3c2a9e-8b1d-4c7a-9e2f-1a2b3c4d5e6f'], no: ['5f3c2a9e-8b1d-4c7a-9e2f'] },
    card: { yes: ['4111 1111 1111 1111', '5500-0000-0000-0004', '4111111111111111'], no: ['4111 1111 1111 1112', '1699999999999', '1234567812345678'] },
    'private-key': { yes: ['-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----'], no: ['-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----'] },
    'api-token': { yes: ['sk_' + 'live_' + 'X'.repeat(20), 'ghp_' + 'a'.repeat(36), 'xoxb-1234567890-abc'], no: ['sk_live_short', 'ghp_abc'] },
    'k8s-env-secret': { yes: ['- name: DB_PASSWORD\n  value: s3cr3t', '- name: "STRIPE_API_KEY"\n  value: "abc"'], no: ['- name: DB_HOST\n  value: db1', '- name: DB_PASSWORD\n  valueFrom:'] },
    'host-kv': { yes: ['host: db1', 'HostName bastion01', '"hostname": "web7"', 'server_name shop;'], no: ['host: true', 'Host *', 'host: 8080'] },
  };
  for (const [id, c] of Object.entries(cases)) {
    for (const s of c.yes) test(`${id} matches ${JSON.stringify(s)}`, () => ok(found(s, only(id)).length > 0, 'no match'));
    for (const s of c.no) test(`${id} ignores ${JSON.stringify(s)}`, () => eq(found(s, only(id)), [], 'unexpected match'));
  }

  test('key/value rules do not cross lines', () => {
    eq(red('server:\n  host: db1.corp.local\npassword:\n  user: bob', { shortHosts: false }), 'server:\n  host: <HOST_1>\npassword:\n  user: bob');
  });
  test('kv-secret redacts only the value', () => eq(red('password=hunter2', only('kv-secret')), 'password=<SECRET_1>'));
  test('url-cred keeps scheme and host', () => eq(red('postgres://u:p@db:5432', only('url-cred')), 'postgres://<CREDENTIAL_1>@db:5432'));
  test('ipv4 keeps CIDR together', () => eq(red('net 10.0.0.0/8 ok', only('ipv4')), 'net <IP_1> ok'));

  // ---- engine -------------------------------------------------------------
  test('consistent numbering', () => {
    eq(red('a 10.0.0.5 b 10.0.0.9 c 10.0.0.5'), 'a <IP_1> b <IP_2> c <IP_1>');
  });
  test('numbering is per type', () => {
    eq(red('10.0.0.5 web.corp.local 10.0.0.6', { shortHosts: false }), '<IP_1> <HOST_1> <IP_2>');
  });
  test('hostnames are case-insensitive', () => {
    eq(red('Web.Corp.Local web.corp.local', { shortHosts: false }), '<HOST_1> <HOST_1>');
  });
  test('MAC separators normalize to the same placeholder', () => {
    eq(red('00:1a:2b:3c:4d:5e 00-1A-2B-3C-4D-5E'), '<MAC_1> <MAC_1>');
  });
  test('overlap: URL credential beats email', () => {
    eq(red('https://bob:pw@host.corp/'), 'https://<CREDENTIAL_1>@<HOST_1>/');
  });
  test('overlap: email beats hostname', () => {
    eq(found('mail jane@acme.com now'), [['EMAIL', 'jane@acme.com']]);
  });
  test('default allowlist keeps localhost and 127.0.0.1', () => {
    eq(red('127.0.0.1 localhost 10.1.1.1'), '127.0.0.1 localhost <IP_1>');
  });
  test('allowlist globs', () => {
    eq(red('a.example.com b.acme.com', { allowlist: ['*.example.com'], shortHosts: false }), 'a.example.com <HOST_1>');
  });
  test('propagation catches values outside the pattern context', () => {
    eq(red('password=hunter22\nlogin with hunter22 failed'), 'password=<SECRET_1>\nlogin with <SECRET_1> failed');
  });
  test('propagation respects word boundaries', () => {
    eq(red('password=abc12 abc123'), 'password=<SECRET_1> abc123');
  });
  test('propagation can be turned off', () => {
    eq(red('password=hunter22 hunter22', { propagate: false }), 'password=<SECRET_1> hunter22');
  });
  test('short hostnames propagate', () => {
    eq(red('db01.corp.local is down; ping db01'), '<HOST_1> is down; ping <HOST_2>');
  });
  test('common short labels are not propagated', () => {
    eq(red('www.acme.com and www'), '<HOST_1> and www');
  });
  test('terms are case-insensitive and numbered', () => {
    eq(red('Acme acme ACME', { terms: [{ value: 'acme', type: 'ORG' }] }), '<ORG_1> <ORG_1> <ORG_1>');
  });
  test('custom regex with named group', () => {
    eq(red('ticket JIRA-123 and JIRA-456', { customRules: [{ id: 'c', pattern: 'JIRA-(?<v>\\d+)', type: 'TICKET' }] }), 'ticket JIRA-<TICKET_1> and JIRA-<TICKET_2>');
  });
  test('invalid custom regex reports error and does not throw', () => {
    const r = R.redact('x', { customRules: [{ id: 'bad', pattern: '(' }] });
    eq(r.errors.length, 1);
  });
  test('custom template', () => {
    eq(red('10.0.0.1', { template: '[{TYPE}-{N}]' }), '[IP-1]');
  });
  test('idempotent: redacting redacted text changes nothing', () => {
    const once = red('host: db1\n10.0.0.1 web01.corp.local', { template: '{TYPE}_{N}' });
    eq(red(once, { template: '{TYPE}_{N}' }), once);
  });
  test('PEM block collapses to one placeholder', () => {
    eq(red('a\n-----BEGIN PRIVATE KEY-----\nAAA\nBBB\n-----END PRIVATE KEY-----\nb'), 'a\n<PRIVATE_KEY_1>\nb');
  });
  test('CRLF is preserved', () => {
    eq(red('ip 10.0.0.1\r\nnext\r\n'), 'ip <IP_1>\r\nnext\r\n');
  });
  test('spans point at the right places', () => {
    const r = R.redact('x 10.0.0.1 y');
    const s = r.spans[0];
    eq(['x 10.0.0.1 y'.slice(s.origStart, s.origEnd), r.text.slice(s.redStart, s.redEnd)], ['10.0.0.1', '<IP_1>']);
  });
  test('mapping lists first-seen order and counts', () => {
    const m = R.redact('10.0.0.2 10.0.0.1 10.0.0.2').mapping;
    eq(m.map(x => [x.placeholder, x.value, x.count]), [['<IP_1>', '10.0.0.2', 2], ['<IP_2>', '10.0.0.1', 1]]);
  });
  test('empty input', () => eq(R.redact('').text, ''));

  // ---- rendering ---------------------------------------------------------
  test('HTML is escaped', () => {
    const t = '<script>alert(1)</script> 10.0.0.1 & "x"';
    const html = R.render.sideBySide(t, R.redact(t));
    ok(!html.includes('<script>'), 'raw <script> in output');
    ok(html.includes('&lt;script&gt;'), 'escaped tag missing');
    ok(html.includes('&lt;IP_1&gt;'), 'placeholder not escaped');
  });
  test('one row per original line, continuation rows for collapsed blocks', () => {
    const t = 'a\n-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nb';
    const div = document.createElement('div');
    div.innerHTML = R.render.sideBySide(t, R.redact(t));
    eq(div.querySelectorAll('.row').length, 5);
    eq(div.querySelectorAll('.row.cont').length, 2);
    const rightNums = Array.from(div.querySelectorAll('.row')).map(r => r.children[2].textContent);
    eq(rightNums, ['1', '2', '', '', '3']);
    eq(div.querySelectorAll('.row')[4].children[3].textContent, 'b');
  });
  test('rendered columns reproduce original and redacted text', () => {
    const t = 'ip 10.0.0.1 and 10.0.0.2\nhost web.corp.local\n\nend';
    const r = R.redact(t);
    const div = document.createElement('div');
    div.innerHTML = R.render.sideBySide(t, r);
    const rows = Array.from(div.querySelectorAll('.row'));
    eq(rows.map(x => x.children[1].textContent).join('\n'), t);
    eq(rows.map(x => x.children[3].textContent).join('\n'), r.text);
  });

  // ---- filenames ---------------------------------------------------------
  test('filenames', () => {
    eq([
      'app.log', 'nginx.conf', 'a.tar.gz', 'Dockerfile', '.env', 'x.y.yaml', '', null,
    ].map(R.redactedFilename), [
      'app.redacted.log', 'nginx.redacted.conf', 'a.redacted.tar.gz', 'Dockerfile.redacted', '.env.redacted', 'x.y.redacted.yaml', 'snippet.redacted.txt', 'snippet.redacted.txt',
    ]);
  });

  // ---- report ----------------------------------------------------------------
  const failed = results.filter(r => !r.ok);
  document.getElementById('summary').textContent = `${failed.length ? 'FAIL' : 'PASS'}: ${results.length - failed.length}/${results.length} passed`;
  document.getElementById('summary').className = failed.length ? 'fail' : 'pass';
  document.getElementById('log').innerHTML = results
    .sort((a, b) => a.ok - b.ok)
    .map(r => `<div class="${r.ok ? 'pass' : 'fail'}">${r.ok ? '✓' : '✗'} ${R.render.escapeHtml(r.name)}${r.ok ? '' : ' — ' + R.render.escapeHtml(r.msg)}</div>`)
    .join('');
})(window.Redacted);
