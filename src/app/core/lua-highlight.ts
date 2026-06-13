/**
 * Tiny, dependency-free Lua syntax highlighter.
 *
 * Tokenizes a script into contiguous tokens, then renders them as HTML <span>s
 * with syntax classes. An optional list of "malicious" character ranges (from a
 * threat pattern's maliciousSpans()) is overlaid: any token — or part of a token
 * — inside one of those ranges also gets the `lua-mal` class so the viewer can
 * paint the worm payload red.
 *
 * All text is HTML-escaped, so the output is safe to inject.
 */
import type { CodeSpan } from './threat-patterns';

type TokenKind = 'comment' | 'string' | 'number' | 'keyword' | 'builtin' | 'operator' | 'plain';

interface Token {
  start: number;
  end: number;
  kind: TokenKind;
}

const KEYWORDS = new Set([
  'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function', 'goto',
  'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true',
  'until', 'while',
]);

// Common TTS / Lua globals worth distinguishing from ordinary identifiers.
const BUILTINS = new Set([
  'self', 'Global', 'Player', 'Wait', 'WebRequest', 'Timer', 'UI', 'JSON', 'Physics',
  'Notes', 'Turns', 'Lighting', 'getObjects', 'getObjectFromGUID', 'spawnObject',
  'spawnObjectJSON', 'string', 'table', 'math', 'os', 'io', 'print', 'log', 'tostring',
  'tonumber', 'type', 'pairs', 'ipairs', 'pcall', 'error', 'assert', 'select',
  'setmetatable', 'getmetatable', 'rawget', 'rawset', 'next', 'load', 'loadstring',
  'require', 'coroutine',
]);

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_]/;
const DIGIT = /[0-9]/;

/** Length of a Lua long-bracket opener `[=*[` starting at i, or -1. */
function longBracketLevel(src: string, i: number): number {
  if (src[i] !== '[') return -1;
  let j = i + 1;
  let level = 0;
  while (src[j] === '=') {
    level++;
    j++;
  }
  return src[j] === '[' ? level : -1;
}

/** Index just past a long bracket `]=*]` of the given level, or src.length. */
function longBracketEnd(src: string, from: number, level: number): number {
  const close = ']' + '='.repeat(level) + ']';
  const idx = src.indexOf(close, from);
  return idx === -1 ? src.length : idx + close.length;
}

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = src.length;
  let plainStart = -1;

  const flushPlain = (end: number) => {
    if (plainStart !== -1) {
      tokens.push({ start: plainStart, end, kind: 'plain' });
      plainStart = -1;
    }
  };

  while (i < n) {
    const c = src[i];

    // comments (line and long)
    if (c === '-' && src[i + 1] === '-') {
      flushPlain(i);
      const afterDashes = i + 2;
      const level = longBracketLevel(src, afterDashes);
      let end: number;
      if (level !== -1) {
        end = longBracketEnd(src, afterDashes + level + 2, level);
      } else {
        const nl = src.indexOf('\n', afterDashes);
        end = nl === -1 ? n : nl;
      }
      tokens.push({ start: i, end, kind: 'comment' });
      i = end;
      continue;
    }

    // long strings
    const strLevel = longBracketLevel(src, i);
    if (strLevel !== -1) {
      flushPlain(i);
      const end = longBracketEnd(src, i + strLevel + 2, strLevel);
      tokens.push({ start: i, end, kind: 'string' });
      i = end;
      continue;
    }

    // quoted strings
    if (c === '"' || c === "'") {
      flushPlain(i);
      let j = i + 1;
      while (j < n && src[j] !== c) {
        if (src[j] === '\\') j++;
        j++;
      }
      tokens.push({ start: i, end: Math.min(j + 1, n), kind: 'string' });
      i = Math.min(j + 1, n);
      continue;
    }

    // numbers
    if (DIGIT.test(c) || (c === '.' && DIGIT.test(src[i + 1] ?? ''))) {
      flushPlain(i);
      let j = i + 1;
      const hex = c === '0' && (src[j] === 'x' || src[j] === 'X');
      if (hex) j++;
      const numPart = hex ? /[0-9a-fA-F.]/ : /[0-9.eE+\-]/;
      while (j < n && numPart.test(src[j])) j++;
      tokens.push({ start: i, end: j, kind: 'number' });
      i = j;
      continue;
    }

    // identifiers / keywords / builtins
    if (IDENT_START.test(c)) {
      flushPlain(i);
      let j = i + 1;
      while (j < n && IDENT_PART.test(src[j])) j++;
      const word = src.slice(i, j);
      const kind: TokenKind = KEYWORDS.has(word) ? 'keyword' : BUILTINS.has(word) ? 'builtin' : 'plain';
      tokens.push({ start: i, end: j, kind });
      i = j;
      continue;
    }

    // operators / punctuation
    if (/[-+*/%^#=~<>(){}[\];:,.]/.test(c)) {
      flushPlain(i);
      tokens.push({ start: i, end: i + 1, kind: 'operator' });
      i++;
      continue;
    }

    // whitespace and anything else → plain
    if (plainStart === -1) plainStart = i;
    i++;
  }
  flushPlain(n);
  return tokens;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>]/g, (ch) => (ch === '&' ? '&amp;' : ch === '<' ? '&lt;' : '&gt;'));
}

/** Merge & sort spans so overlap testing is a simple forward scan. */
function normalizeSpans(spans: CodeSpan[]): CodeSpan[] {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start);
  const merged: CodeSpan[] = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ ...s });
  }
  return merged;
}

function isMalicious(pos: number, spans: CodeSpan[]): boolean {
  for (const s of spans) {
    if (pos < s.start) return false;
    if (pos < s.end) return true;
  }
  return false;
}

/**
 * Returns highlighted HTML for a Lua script. `maliciousSpans` ranges are
 * additionally wrapped with the `lua-mal` class.
 */
export function highlightLua(src: string, maliciousSpans: CodeSpan[] = []): string {
  const spans = normalizeSpans(maliciousSpans);
  const tokens = tokenize(src);
  let out = '';

  for (const tok of tokens) {
    // Split the token at malicious-span boundaries so we can mark sub-ranges.
    let pos = tok.start;
    while (pos < tok.end) {
      const mal = isMalicious(pos, spans);
      // advance to the next boundary (either span edge or token end)
      let next = tok.end;
      for (const s of spans) {
        if (pos < s.start && s.start < next) next = s.start;
        if (pos >= s.start && pos < s.end && s.end < next) next = s.end;
      }
      const text = escapeHtml(src.slice(pos, next));
      const cls = `lua-${tok.kind}${mal ? ' lua-mal' : ''}`;
      out += tok.kind === 'plain' && !mal ? text : `<span class="${cls}">${text}</span>`;
      pos = next;
    }
  }
  return out;
}
