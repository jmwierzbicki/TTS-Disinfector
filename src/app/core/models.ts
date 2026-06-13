import type { Severity } from './threat-patterns';

/** One uploaded file (a TTS save or saved object). */
export interface DocumentInfo {
  fileName: string;
  /** Best-effort name of the save / saved object (SaveName or the root object's nickname). */
  saveName?: string;
  objectCount: number;
  scriptedCount: number;
}

/** One object, in one document, that carries a particular script. */
export interface Occurrence {
  /** Index into AnalysisResult.documents. */
  docId: number;
  /** Node index within that document (used to fetch the full script / apply cleanse). */
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
  detail: string;
  excerpt: string;
  cleansable: boolean;
  extraCodeOutsidePayload: boolean;
}

/**
 * A group of findings keyed by a unique script (SHA-256 hash). Every object that
 * carries this exact script — across every uploaded file — is listed in
 * `occurrences`, so identical scripts are reported once with an aggregated list.
 */
export interface ScriptGroup {
  scriptHash: string;
  scriptLength: number;
  severity: Severity;
  findings: Finding[];
  occurrences: Occurrence[];
  /** A doc+node whose script can be fetched to populate the viewer. */
  representativeDocId: number;
  representativeNodeId: number;
  trusted: boolean;
  cleansable: boolean;
  extraCodeOutsidePayload: boolean;
  cleansedScriptHash?: string;
  approvedExtra: boolean;
}

export interface AnalysisResult {
  /** One entry per successfully parsed file. */
  documents: DocumentInfo[];
  /** Files that couldn't be parsed (skipped, not fatal in batch mode). */
  skippedFiles: { fileName: string; reason: string }[];
  totalObjects: number;
  scriptedObjects: number;
  groups: ScriptGroup[];
  cleanScripted: number;
  infectedObjects: number;
  durationMs: number;
  byteSize: number;
}

/** One cleaned file produced by a cleanse pass. */
export interface CleansedFile {
  fileName: string;
  json: string;
  cleansedCount: number;
}

export interface CleanseOutcome {
  files: CleansedFile[];
  /** Total scripts cleansed across all files. */
  cleansedCount: number;
  /** Objects where code remains after cleansing — user must verify manually. */
  extraCodePaths: { fileName: string; pathSegments: string[] }[];
}

export interface AnalysisProgress {
  processed: number;
  total: number;
}

/* ─── Web Worker protocol ─────────────────────────────────────────── */

export interface InputFile {
  name: string;
  text: string;
}

export type WorkerRequest =
  | { type: 'analyze'; requestId: number; files: InputFile[]; safeHashes: string[] }
  | { type: 'cleanse'; requestId: number }
  | { type: 'getScript'; requestId: number; docId: number; nodeId: number };

export type WorkerResponse =
  | { type: 'progress'; processed: number; total: number }
  | { type: 'result'; requestId: number; result: AnalysisResult }
  | { type: 'cleansed'; requestId: number; outcome: CleanseOutcome }
  | { type: 'script'; requestId: number; script: string }
  | { type: 'error'; requestId: number; message: string };

/** A script signature the user has marked as trusted (stored locally in IndexedDB). */
export interface SafeSignature {
  hash: string;
  label: string;
  excerpt: string;
  addedAt: number;
}
