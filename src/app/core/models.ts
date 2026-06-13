import type { Severity } from './threat-patterns';

/** One object in the save that carries a particular script. */
export interface Occurrence {
  /** Index into the analyzer's flattened node list (used to fetch the full script / apply cleanse). */
  nodeId: number;
  /** Human-readable path, e.g. ['Bag "Player Red\'s Stuff"', 'Deck "Spells"', 'Card "Fireball"']. */
  pathSegments: string[];
  guid?: string;
}

/** A single pattern match against a script (shared by every object with that exact script). */
export interface Finding {
  patternId: string;
  patternName: string;
  severity: Severity;
  description: string;
  /** Pattern-specific detail about what matched. */
  detail: string;
  /** Short snippet from the script around the match. */
  excerpt: string;
  /** True when the pattern ships a cleanse() that can remove the threat automatically. */
  cleansable: boolean;
  /** Worm-only: meaningful code remains outside the worm payload → "WORM + EXTRA CODE". */
  extraCodeOutsidePayload: boolean;
}

/**
 * A group of findings keyed by a unique script (SHA-256 hash). Every object that
 * carries this exact script is listed in `occurrences`, so identical scripts are
 * reported once with an aggregated object list rather than repeated per object.
 */
export interface ScriptGroup {
  /** SHA-256 of the full script — also the trusted-signature key. */
  scriptHash: string;
  scriptLength: number;
  /** Highest severity among the group's findings (drives the card colour). */
  severity: Severity;
  /** Patterns that matched this script. */
  findings: Finding[];
  /** Every object in the save carrying this exact script. */
  occurrences: Occurrence[];
  /** A node whose script can be fetched to populate the viewer (any occurrence works). */
  representativeNodeId: number;
  /** Hash is in the user's local trusted-signature store. */
  trusted: boolean;
  /** Any finding is auto-cleansable. */
  cleansable: boolean;
  /** Any finding leaves extra code after cleansing. */
  extraCodeOutsidePayload: boolean;
  /** SHA-256 of the leftover code after cleansing — set only for worm+extra groups. */
  cleansedScriptHash?: string;
  /** The leftover code has been reviewed & approved (its cleansed hash is trusted). */
  approvedExtra: boolean;
}

export interface AnalysisResult {
  fileName: string;
  saveName?: string;
  totalObjects: number;
  scriptedObjects: number;
  /** Findings grouped by unique script. */
  groups: ScriptGroup[];
  /** Scripted objects with no findings at all. */
  cleanScripted: number;
  /** Distinct objects carrying at least one critical finding. */
  infectedObjects: number;
  durationMs: number;
  byteSize: number;
}

export interface CleanseOutcome {
  json: string;
  /** Number of scripts (objects) that had a worm payload removed. */
  cleansedCount: number;
  /** Paths of objects where code remains after cleansing — user must verify manually. */
  extraCodePaths: string[][];
}

export interface AnalysisProgress {
  processed: number;
  total: number;
}

/* ─── Web Worker protocol ─────────────────────────────────────────── */

export type WorkerRequest =
  | { type: 'analyze'; requestId: number; jsonText: string; fileName: string; safeHashes: string[] }
  | { type: 'cleanse'; requestId: number }
  | { type: 'getScript'; requestId: number; nodeId: number };

export type WorkerResponse =
  | { type: 'progress'; processed: number; total: number }
  | { type: 'result'; requestId: number; result: AnalysisResult }
  | { type: 'cleansed'; requestId: number; outcome: CleanseOutcome }
  | { type: 'script'; requestId: number; nodeId: number; script: string }
  | { type: 'error'; requestId: number; message: string };

/** A script signature the user has marked as trusted (stored locally in IndexedDB). */
export interface SafeSignature {
  hash: string;
  label: string;
  excerpt: string;
  addedAt: number;
}
