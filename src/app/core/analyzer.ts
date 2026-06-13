/**
 * Pure analysis engine — no Angular, no DOM. Runs inside the Web Worker.
 *
 * Walks a parsed TTS save, recursing through `ContainedObjects` (and object
 * `States`) to arbitrary depth, runs every registered threat pattern against
 * every non-empty LuaScript, and can re-serialize the save with worm payloads
 * cleansed.
 */
import { THREAT_PATTERNS, type ThreatPattern, type ThreatDetection } from './threat-patterns';
import type { AnalysisResult, Finding, Occurrence, ScriptGroup } from './models';

/** One scripted node in the save, addressable for cleansing. */
export interface ScriptNode {
  nodeId: number;
  /** The object that owns the LuaScript (mutated in place when cleansing). */
  holder: Record<string, unknown>;
  script: string;
  hash: string;
  pathSegments: string[];
  guid?: string;
}

export class TtsParseError extends Error {}

export interface ParsedSave {
  save: Record<string, unknown>;
  nodes: ScriptNode[];
  totalObjects: number;
  saveName?: string;
}

/* ─── parsing & walking ───────────────────────────────────────────── */

function friendlyType(name: unknown): string {
  if (typeof name !== 'string' || !name) return 'Object';
  return name.replace(/^Custom_/, '').replace(/_/g, ' ');
}

function labelOf(obj: Record<string, unknown>): string {
  const type = friendlyType(obj['Name']);
  const nick = typeof obj['Nickname'] === 'string' ? obj['Nickname'].trim() : '';
  if (nick) return `${type} "${nick}"`;
  const guid = typeof obj['GUID'] === 'string' ? obj['GUID'] : '';
  return guid ? `${type} (${guid})` : type;
}

export function parseSave(jsonText: string): ParsedSave {
  const trimmed = jsonText.trim();
  if (!trimmed) {
    throw new TtsParseError('The input is empty. Drop a Tabletop Simulator .json save file or paste its contents.');
  }

  let save: unknown;
  try {
    save = JSON.parse(trimmed);
  } catch (e) {
    throw new TtsParseError(`That isn't valid JSON (${(e as Error).message}). TTS saves live in Documents/My Games/Tabletop Simulator/Saves.`);
  }

  if (typeof save !== 'object' || save === null || Array.isArray(save)) {
    throw new TtsParseError('Valid JSON, but not a Tabletop Simulator save — expected an object with an "ObjectStates" array.');
  }

  const root = save as Record<string, unknown>;
  if (!Array.isArray(root['ObjectStates'])) {
    throw new TtsParseError('This JSON has no "ObjectStates" array, so it doesn\'t look like a TTS save or saved object.');
  }

  const nodes: ScriptNode[] = [];
  let totalObjects = 0;

  const pushNode = (holder: Record<string, unknown>, pathSegments: string[]) => {
    const script = holder['LuaScript'];
    if (typeof script === 'string' && script.trim().length > 0) {
      nodes.push({
        nodeId: nodes.length,
        holder,
        script,
        hash: '',
        pathSegments,
        guid: typeof holder['GUID'] === 'string' ? holder['GUID'] : undefined,
      });
    }
  };

  const walkObject = (obj: unknown, parentPath: string[]) => {
    if (typeof obj !== 'object' || obj === null) return;
    const o = obj as Record<string, unknown>;
    totalObjects++;
    const path = [...parentPath, labelOf(o)];
    pushNode(o, path);

    const contained = o['ContainedObjects'];
    if (Array.isArray(contained)) {
      for (const child of contained) walkObject(child, path);
    }
    // Alternate states (the "state swap" feature) each carry their own script tree.
    const states = o['States'];
    if (typeof states === 'object' && states !== null && !Array.isArray(states)) {
      for (const [key, stateObj] of Object.entries(states as Record<string, unknown>)) {
        walkObject(stateObj, [...path, `State ${key}`]);
      }
    }
  };

  // The save root itself carries the Global script.
  pushNode(root, ['Global script']);
  for (const obj of root['ObjectStates'] as unknown[]) {
    walkObject(obj, []);
  }

  return {
    save: root,
    nodes,
    totalObjects,
    saveName: typeof root['SaveName'] === 'string' && root['SaveName'] ? root['SaveName'] : undefined,
  };
}

/* ─── hashing ─────────────────────────────────────────────────────── */

const encoder = new TextEncoder();

export async function hashScript(script: string): Promise<string> {
  if (globalThis.crypto?.subtle) {
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode(script));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback for non-secure contexts (e.g. plain http on a LAN): FNV-1a, 2×32-bit.
  let h1 = 0x811c9dc5;
  let h2 = 0xcbf29ce4;
  for (let i = 0; i < script.length; i++) {
    const c = script.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ ((c >> 8) ^ (c << 3)), 0x01000193) >>> 0;
  }
  return `fnv-${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}-${script.length.toString(16)}`;
}

/* ─── analysis ────────────────────────────────────────────────────── */

interface PatternHit {
  pattern: ThreatPattern;
  detection: ThreatDetection;
}

/**
 * Run every registered pattern against one script. When a cleansable critical
 * pattern (the worm) matches, the remaining patterns are evaluated against the
 * CLEANSED script — so the worm's own internals don't double-report, and any
 * additional finding genuinely belongs to the user's residual code.
 */
export function runPatterns(script: string): PatternHit[] {
  const hits: PatternHit[] = [];
  let effective = script;
  for (const pattern of THREAT_PATTERNS) {
    const detection = pattern.detect(effective);
    if (!detection) continue;
    hits.push({ pattern, detection });
    if (pattern.severity === 'critical' && pattern.cleanse) {
      effective = pattern.cleanse(effective);
    }
  }
  return hits;
}

export async function analyzeParsedSave(
  parsed: ParsedSave,
  fileName: string,
  byteSize: number,
  safeHashes: ReadonlySet<string>,
  onProgress: (processed: number, total: number) => void,
): Promise<AnalysisResult> {
  const started = performance.now();
  const hashCache = new Map<string, string>();
  const total = parsed.nodes.length;
  const criticalNodes = new Set<number>();
  const nodesWithFindings = new Set<number>();

  /** One group per unique script hash. */
  const groupsByHash = new Map<string, ScriptGroup>();

  for (let i = 0; i < parsed.nodes.length; i++) {
    const node = parsed.nodes[i];

    let hash = hashCache.get(node.script);
    if (!hash) {
      hash = await hashScript(node.script);
      hashCache.set(node.script, hash);
    }
    node.hash = hash;

    const hits = runPatterns(node.script);
    if (hits.length === 0) {
      if (i % 20 === 0 || i === total - 1) onProgress(i + 1, total);
      continue;
    }

    nodesWithFindings.add(node.nodeId);
    if (hits.some((h) => h.pattern.severity === 'critical')) criticalNodes.add(node.nodeId);

    const occurrence: Occurrence = {
      nodeId: node.nodeId,
      pathSegments: node.pathSegments,
      guid: node.guid,
    };

    // First object with this exact script creates the group; later identical
    // scripts just add their object to the existing group's occurrence list.
    let group = groupsByHash.get(hash);
    if (!group) {
      const trusted = safeHashes.has(hash);
      const findings: Finding[] = hits.map(({ pattern, detection }) => ({
        patternId: pattern.id,
        patternName: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        detail: detection.detail,
        excerpt: detection.excerpt,
        cleansable: !!pattern.cleanse,
        extraCodeOutsidePayload: !!detection.extraCodeOutsidePayload,
      }));
      const cleansable = findings.some((f) => f.cleansable);
      const extraCode = findings.some((f) => f.extraCodeOutsidePayload);

      // For worm+extra groups, hash the leftover so the "approve remaining code"
      // decision can be remembered (and pre-applied if already trusted).
      let cleansedScriptHash: string | undefined;
      let approvedExtra = false;
      if (cleansable && extraCode) {
        cleansedScriptHash = await hashScript(cleanseScript(node.script));
        approvedExtra = safeHashes.has(cleansedScriptHash);
      }

      group = {
        scriptHash: hash,
        scriptLength: node.script.length,
        severity: highestSeverity(findings),
        findings,
        occurrences: [occurrence],
        representativeNodeId: node.nodeId,
        // A worm (critical) can never be trusted away.
        trusted: trusted && !findings.some((f) => f.severity === 'critical'),
        cleansable,
        extraCodeOutsidePayload: extraCode,
        cleansedScriptHash,
        approvedExtra,
      };
      groupsByHash.set(hash, group);
    } else {
      group.occurrences.push(occurrence);
    }

    if (i % 20 === 0 || i === total - 1) onProgress(i + 1, total);
  }

  const severityRank: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  const groups = [...groupsByHash.values()].sort(
    (a, b) =>
      severityRank[a.severity] - severityRank[b.severity] ||
      b.occurrences.length - a.occurrences.length ||
      a.representativeNodeId - b.representativeNodeId,
  );

  return {
    fileName,
    saveName: parsed.saveName,
    totalObjects: parsed.totalObjects,
    scriptedObjects: parsed.nodes.length,
    groups,
    cleanScripted: parsed.nodes.length - nodesWithFindings.size,
    infectedObjects: criticalNodes.size,
    durationMs: Math.round(performance.now() - started),
    byteSize,
  };
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 };

function highestSeverity(findings: Finding[]): Finding['severity'] {
  return findings.reduce<Finding['severity']>(
    (best, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[best] ? f.severity : best),
    'info',
  );
}

/* ─── cleansing ───────────────────────────────────────────────────── */

/**
 * Apply every cleansable pattern to every scripted node in the save. Works
 * straight off the parsed nodes (each node carries the patterns that matched it
 * is re-derived here), so it is independent of the grouped result shape.
 */
export function cleanseSave(parsed: ParsedSave): {
  json: string;
  cleansedCount: number;
  extraCodePaths: string[][];
} {
  let cleansedCount = 0;
  const extraCodePaths: string[][] = [];

  for (const node of parsed.nodes) {
    const original = node.holder['LuaScript'];
    if (typeof original !== 'string' || !original) continue;
    let current: string = original;
    let changed = false;

    for (const pattern of THREAT_PATTERNS) {
      if (!pattern.cleanse) continue;
      if (!pattern.detect(current)) continue;
      const next = pattern.cleanse(current);
      if (next !== current) {
        current = next;
        changed = true;
      }
    }

    if (changed) {
      // Mutate only the save object (for the downloaded JSON). Keep node.script
      // as the ORIGINAL so the script viewer can still show the infected code
      // with its red worm markers and a meaningful Original→Cleansed diff.
      node.holder['LuaScript'] = current;
      cleansedCount++;
      if (current.trim().length > 0) extraCodePaths.push(node.pathSegments);
    }
  }

  return {
    json: JSON.stringify(parsed.save, null, 2),
    cleansedCount,
    extraCodePaths,
  };
}

/** Compute the cleansed form of a single script (for the viewer's diff tab). */
export function cleanseScript(script: string): string {
  let current = script;
  for (const pattern of THREAT_PATTERNS) {
    if (!pattern.cleanse) continue;
    if (!pattern.detect(current)) continue;
    current = pattern.cleanse(current);
  }
  return current;
}
