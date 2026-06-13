/**
 * ════════════════════════════════════════════════════════════════════════════
 *  THREAT PATTERN REGISTRY
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  Every threat the scanner knows about is one self-contained `ThreatPattern`
 *  object in the `THREAT_PATTERNS` array at the bottom of this file.
 *
 *  To add a detector for a new worm / malicious pattern:
 *
 *    1. Write a new `ThreatPattern` literal in this file:
 *         - `id`          stable kebab-case identifier (never reuse one)
 *         - `name`        short human-readable title shown in the UI
 *         - `description` one or two sentences explaining the threat
 *         - `severity`    'critical' (malware), 'warning' (suspicious),
 *                         or 'info' (worth knowing, not a threat)
 *         - `detect(lua)` return a `ThreatDetection` when the script matches,
 *                         or `null` when it does not. Keep it pure & fast —
 *                         it runs on every script in the save, inside a worker.
 *         - `cleanse(lua)` OPTIONAL — return the script with the threat
 *                         removed. Only provide it when removal is precise and
 *                         safe; the UI only offers auto-cleansing for patterns
 *                         that have it.
 *    2. Append it to `THREAT_PATTERNS`. Order matters: cleansable critical
 *       patterns run first, and later patterns are evaluated against the
 *       *cleansed* script so a worm's own internals (WebRequest, setLuaScript,
 *       …) don't double-report on infected objects.
 *    3. That's it — the worker, the UI severity styling, and the results list
 *       all pick it up automatically. No other file needs to change.
 *
 *  This module is pure TypeScript with zero Angular / DOM dependencies, so it
 *  is shared verbatim between the main thread and the analysis Web Worker.
 * ════════════════════════════════════════════════════════════════════════════
 */

export type Severity = 'critical' | 'warning' | 'info';

export interface ThreatDetection {
  /** What specifically matched in this script. */
  detail: string;
  /** Short excerpt around the match for display. */
  excerpt: string;
  /** Worm-only flag: meaningful code exists outside the payload. */
  extraCodeOutsidePayload?: boolean;
}

export interface ThreatPattern {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  detect(luaScript: string): ThreatDetection | null;
  cleanse?(luaScript: string): string;
  /**
   * OPTIONAL — character ranges of the malicious/matched content. The script
   * viewer marks these red in the "Original" tab so the user can see exactly
   * what detect() found (and what cleanse() would remove).
   */
  maliciousSpans?(luaScript: string): CodeSpan[];
  /**
   * OPTIONAL — the case-specific instruction for the "Copy AI prompt" button.
   * Lets a non-technical user paste the script + a tailored question into any
   * chatbot. If omitted, a sensible default based on severity is used.
   */
  aiInstruction?(ctx: PromptContext): AiInstruction;
}

export interface CodeSpan {
  start: number;
  end: number;
}

/** Context handed to a pattern when it builds its tailored LLM prompt. */
export interface PromptContext {
  /** The script exactly as it exists in the save right now. */
  script: string;
  /** The script after auto-cleansing (worm removed). Equals `script` if nothing cleanses. */
  cleansedScript: string;
  /** Worm-only: meaningful code remains after the payload is removed. */
  extraCodeOutsidePayload: boolean;
}

/** A pattern's case-specific instruction for the "Copy AI prompt" feature. */
export interface AiInstruction {
  /** What the LLM should do, phrased for the script being embedded. */
  task: string;
  /** Which script to embed: the full current script (default) or just the leftover after cleansing. */
  include?: 'original' | 'cleansed';
}

/* ─── helpers ─────────────────────────────────────────────────────── */

/** Single-line excerpt of `len` chars starting at `index`. */
function excerptAt(script: string, index: number, len = 180): string {
  const raw = script.slice(Math.max(0, index), index + len);
  return raw.replace(/\s+/g, ' ').trim() + (index + len < script.length ? ' …' : '');
}

function firstMatchExcerpt(script: string, re: RegExp): string {
  const m = re.exec(script);
  return m ? excerptAt(script, Math.max(0, m.index - 30), 160) : '';
}

/** All match ranges of a regex (fresh global copy, capped to stay fast). */
function spansOf(script: string, re: RegExp): CodeSpan[] {
  const global = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  const spans: CodeSpan[] = [];
  let m: RegExpExecArray | null;
  while ((m = global.exec(script)) !== null && spans.length < 200) {
    spans.push({ start: m.index, end: m.index + m[0].length });
    if (m[0].length === 0) global.lastIndex++;
  }
  return spans;
}

/* ─── the known "Object base code" worm ───────────────────────────── */

const WORM_OPEN = '--[[Object base code]]';
const WORM_CLOSE = '--[[Spawning object]]';
const WORM_FINGERPRINTS = [WORM_OPEN, WORM_CLOSE, 'tcejbo gninwapS', 'ereh edoc resU', 'edoc esab tcejbO'];

/**
 * The worm payload spans from the FIRST occurrence of the opening marker to
 * the end of the LAST occurrence of the closing marker (the worm — and its
 * remote-update mechanism — can stack multiple generations of payload between
 * those two points).
 */
function wormSpan(script: string): { start: number; end: number } | null {
  const start = script.indexOf(WORM_OPEN);
  if (start === -1) return null;
  const lastClose = script.lastIndexOf(WORM_CLOSE);
  if (lastClose === -1 || lastClose < start) return null;
  return { start, end: lastClose + WORM_CLOSE.length };
}

/**
 * Remove ONLY the worm payload, preserving any original user code around it.
 * The worm pads itself onto victims with `string.rep(" ", 100)` before the
 * payload and appends "\n\n" after it, so the surrounding whitespace it
 * introduced is stripped along with the payload.
 */
function stripWorm(script: string): string {
  const span = wormSpan(script);
  if (!span) return script;
  const before = script.slice(0, span.start).replace(/\s+$/, '');
  const after = script.slice(span.end).replace(/^\s+/, '');
  if (before && after) return before + '\n\n' + after;
  return before || after;
}

/* ─── registry ────────────────────────────────────────────────────── */

export const THREAT_PATTERNS: ThreatPattern[] = [
  {
    id: 'worm-object-base-code',
    name: 'Self-replicating Lua worm',
    description:
      'The known TTS worm delimited by "--[[Object base code]] … --[[Spawning object]]". It copies ' +
      'itself onto every object in the save, re-infects objects as they spawn, and pulls remote ' +
      'payload updates over WebRequest. Cleansing removes exactly the payload and keeps your own code.',
    severity: 'critical',
    detect(lua) {
      const span = wormSpan(lua);
      if (!span) return null;
      const remaining = stripWorm(lua).trim();
      return {
        detail:
          remaining.length > 0
            ? 'Worm payload found — and additional code exists outside it. After cleansing, review the remaining code manually.'
            : 'Script consists solely of the worm payload. Cleansing leaves the script empty.',
        excerpt: excerptAt(lua, span.start, 200),
        extraCodeOutsidePayload: remaining.length > 0,
      };
    },
    cleanse: stripWorm,
    maliciousSpans(lua) {
      const span = wormSpan(lua);
      return span ? [span] : [];
    },
    aiInstruction(ctx) {
      if (ctx.extraCodeOutsidePayload) {
        // The worm itself is known; the unknown is the user code left behind.
        return {
          include: 'cleansed',
          task:
            'A known self-replicating worm was found on this object and removed. The code below is what ' +
            'remained afterwards. Tell the player, in simple terms, whether this leftover code looks like a ' +
            "normal game script that's safe to keep, or whether it does anything dangerous or suspicious " +
            '(for example: contacting the internet, changing other objects, or hiding more worm code).',
        };
      }
      return {
        include: 'original',
        task:
          "This is a known self-replicating Tabletop Simulator worm. In simple terms, briefly explain what " +
          'it does (how it spreads and why it is harmful) and reassure the player that removing it is safe.',
      };
    },
  },

  {
    id: 'worm-fragment',
    name: 'Worm fragment / variant markers',
    description:
      'Fingerprints of the known worm (its markers or reversed search strings like "tcejbo gninwapS") ' +
      'are present, but not the complete payload. This may be a damaged copy or an altered variant — ' +
      'it cannot be cleansed automatically, inspect it manually.',
    severity: 'warning',
    detect(lua) {
      // The complete worm is handled (and cleansed) by 'worm-object-base-code';
      // since this pattern runs after it, any leftovers here are genuine fragments.
      for (const fp of WORM_FINGERPRINTS) {
        const idx = lua.indexOf(fp);
        if (idx !== -1) {
          return {
            detail: `Worm fingerprint "${fp}" found without a complete payload.`,
            excerpt: excerptAt(lua, Math.max(0, idx - 40), 160),
          };
        }
      }
      return null;
    },
    maliciousSpans(lua) {
      const spans: CodeSpan[] = [];
      for (const fp of WORM_FINGERPRINTS) {
        let from = 0;
        let idx: number;
        while ((idx = lua.indexOf(fp, from)) !== -1) {
          spans.push({ start: idx, end: idx + fp.length });
          from = idx + fp.length;
        }
      }
      return spans;
    },
    aiInstruction: () => ({
      task:
        'This script contains pieces or markers of a known worm, but not the complete worm. In simple terms, ' +
        'tell the player whether this looks dangerous, what it might do, and what they should do about it.',
    }),
  },

  {
    id: 'webrequest-usage',
    name: 'Network request (WebRequest)',
    description:
      'The script talks to the internet via WebRequest. Plenty of legitimate mods do this, but it is ' +
      'also how malware fetches payloads or exfiltrates data — check where it connects to.',
    severity: 'warning',
    detect(lua) {
      const re = /WebRequest\s*[.:]\s*(get|post|put|delete|head|custom)\b/;
      const m = re.exec(lua);
      if (!m) return null;
      return {
        detail: `Calls WebRequest.${m[1]}(…).`,
        excerpt: firstMatchExcerpt(lua, re),
      };
    },
    maliciousSpans: (lua) => spansOf(lua, /WebRequest\s*[.:]\s*(get|post|put|delete|head|custom)\b/),
    aiInstruction: () => ({
      task:
        'This script connects to the internet. Look at which web address(es) it contacts and tell the player, ' +
        'in simple terms, whether that looks normal and harmless or suspicious — and what information it might ' +
        'be sending out or pulling in.',
    }),
  },

  {
    id: 'script-injection',
    name: 'Rewrites other objects’ scripts',
    description:
      'The script calls setLuaScript() to overwrite Lua code on objects at runtime. This is the core ' +
      'mechanism worms use to spread; legitimate uses are rare (script-deployment tools).',
    severity: 'warning',
    detect(lua) {
      const re = /[.:]\s*setLuaScript\s*\(/;
      if (!re.test(lua)) return null;
      return {
        detail: 'Calls setLuaScript() on game objects.',
        excerpt: firstMatchExcerpt(lua, re),
      };
    },
    maliciousSpans: (lua) => spansOf(lua, /[.:]\s*setLuaScript\s*\(/),
    aiInstruction: () => ({
      task:
        'This script can change the programming of other objects in the game while it runs. In simple terms, ' +
        'tell the player whether this looks like normal mod behaviour or something dangerous like a worm that ' +
        'spreads itself.',
    }),
  },

  {
    id: 'dynamic-code-load',
    name: 'Dynamic code execution',
    description:
      'The script compiles and runs Lua source at runtime via load()/loadstring(). Combined with a ' +
      'network call this allows arbitrary remote code execution.',
    severity: 'warning',
    detect(lua) {
      const re = /(?<![.:\w])(loadstring|load)\s*\(/;
      const m = re.exec(lua);
      if (!m) return null;
      return {
        detail: `Calls ${m[1]}(…) to execute dynamically built code.`,
        excerpt: firstMatchExcerpt(lua, re),
      };
    },
    maliciousSpans: (lua) => spansOf(lua, /(?<![.:\w])(loadstring|load)\s*\(/),
    aiInstruction: () => ({
      task:
        'This script builds and runs brand-new code while the game is running. In simple terms, tell the player ' +
        'whether that looks risky (it can be used to hide harmful behaviour) and what it appears to be doing here.',
    }),
  },

  {
    id: 'on-update-handler',
    name: 'onUpdate handler',
    description:
      'Defines onUpdate(), which Tabletop Simulator calls every single frame. Not a threat — but a ' +
      'very common cause of save-file lag, so it is worth knowing which objects do it.',
    severity: 'info',
    detect(lua) {
      const re = /function\s+onUpdate\s*\(/;
      if (!re.test(lua)) return null;
      return {
        detail: 'Defines a per-frame onUpdate() handler (performance, not security).',
        excerpt: firstMatchExcerpt(lua, re),
      };
    },
    maliciousSpans: (lua) => spansOf(lua, /function\s+onUpdate\s*\(/),
    aiInstruction: () => ({
      task:
        'This script runs many times every second while the game is open. This is usually about performance, ' +
        'not safety. In simple terms, briefly explain what it seems to do and whether it could slow the game down.',
    }),
  },
];

export function patternById(id: string): ThreatPattern | undefined {
  return THREAT_PATTERNS.find((p) => p.id === id);
}
