/*
 * Side-by-side rendering. One grid row per ORIGINAL line, so both columns
 * stay aligned and scroll together. When a multi-line match (e.g. a PEM key)
 * collapses into one placeholder, the following rows on the redacted side
 * are marked as continuations and have no line number.
 */
(function (R) {
  'use strict';

  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ESC[c]);
  }

  const SLOTS = {
    IP: 0, IPV6: 0, MAC: 1, HOST: 2, EMAIL: 3, USER: 3,
    SECRET: 4, TOKEN: 4, AWS_KEY: 4, PRIVATE_KEY: 4, CREDENTIAL: 4,
    UUID: 5, HASH: 5, CARD: 6,
  };
  function slotFor(type) {
    if (type in SLOTS) return SLOTS[type];
    let h = 0;
    for (const c of type) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return h % 8;
  }

  function mark(cls, i, span, inner) {
    return `<mark class="hl p${slotFor(span.type)} ${cls}" data-i="${i}">${inner}</mark>`;
  }

  function sideBySide(original, result) {
    const spans = result.spans;
    const rows = [];
    let lineStart = 0;
    let lineNo = 0;
    let redLineNo = 0;
    let j = 0; // first span that may touch the current line
    const len = original.length;

    while (lineStart <= len) {
      let nl = original.indexOf('\n', lineStart);
      if (nl === -1) nl = len;
      // Hide a trailing \r from CRLF files.
      const lineEnd = nl > lineStart && original[nl - 1] === '\r' ? nl - 1 : nl;
      lineNo++;

      // Skip spans that ended before this line (keep one that swallowed the previous newline).
      while (j < spans.length && spans[j].origEnd < lineStart) j++;
      const continuation = lineStart > 0 && j < spans.length && spans[j].origStart <= lineStart - 1;

      let orig = '';
      let red = '';
      let oPos = lineStart;
      let rPos = lineStart;
      let changed = false;
      for (let k = j; k < spans.length && spans[k].origStart <= nl; k++) {
        const s = spans[k];
        if (s.origEnd <= lineStart && s.origStart < lineStart) continue;
        changed = true;
        if (s.origStart < lineEnd && s.origEnd > lineStart) {
          const a = Math.max(s.origStart, lineStart);
          const b = Math.min(s.origEnd, lineEnd);
          orig += escapeHtml(original.slice(oPos, a));
          orig += mark('o', k, s, escapeHtml(original.slice(a, b)));
          oPos = b;
        }
        if (s.origStart >= lineStart) {
          red += escapeHtml(original.slice(rPos, Math.min(s.origStart, lineEnd)));
          red += mark('r', k, s, escapeHtml(s.placeholder));
        }
        rPos = Math.max(rPos, Math.min(s.origEnd, lineEnd));
      }
      orig += escapeHtml(original.slice(oPos, lineEnd));
      red += escapeHtml(original.slice(rPos, lineEnd));

      const rn = continuation ? '' : String(++redLineNo);
      rows.push(
        `<div class="row${changed ? ' changed' : ''}${continuation ? ' cont' : ''}">` +
        `<span class="ln">${lineNo}</span><span class="o">${orig}</span>` +
        `<span class="ln">${rn}</span><span class="r">${red}</span></div>`
      );

      if (nl === len) break;
      lineStart = nl + 1;
    }
    return rows.join('');
  }

  R.render = { escapeHtml, sideBySide, slotFor };
})(window.Redacted = window.Redacted || {});
