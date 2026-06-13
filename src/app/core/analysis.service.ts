import { Injectable, inject, signal } from '@angular/core';
import type {
  AnalysisProgress,
  AnalysisResult,
  CleanseOutcome,
  InputFile,
  WorkerRequest,
  WorkerResponse,
} from './models';
import { SignatureStoreService } from './signature-store.service';

export type AppPhase = 'idle' | 'analyzing' | 'results';

/** Omit that distributes over union members (plain Omit collapses the union). */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** `My Save.json` → `My Save.cleaned` (caller appends the extension). */
function cleanedName(fileName: string): string {
  return fileName.replace(/\.json$/i, '') + '.cleaned';
}

/**
 * Owns the analysis Web Worker and exposes the app's state as signals.
 * All file content stays between the main thread and the worker — there is no
 * network involvement anywhere in this pipeline.
 */
@Injectable({ providedIn: 'root' })
export class AnalysisService {
  private readonly signatureStore = inject(SignatureStoreService);

  readonly phase = signal<AppPhase>('idle');
  readonly progress = signal<AnalysisProgress | null>(null);
  readonly result = signal<AnalysisResult | null>(null);
  readonly error = signal<string | null>(null);

  private worker: Worker | null = null;
  private nextRequestId = 1;
  private pending = new Map<number, { resolve: (msg: WorkerResponse) => void; reject: (err: Error) => void }>();

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    this.worker = new Worker(new URL('./analysis.worker', import.meta.url), { type: 'module' });
    this.worker.onmessage = ({ data }: MessageEvent<WorkerResponse>) => {
      if (data.type === 'progress') {
        this.progress.set({ processed: data.processed, total: data.total });
        return;
      }
      const waiter = this.pending.get(data.requestId);
      if (!waiter) return;
      this.pending.delete(data.requestId);
      if (data.type === 'error') waiter.reject(new Error(data.message));
      else waiter.resolve(data);
    };
    this.worker.onerror = (e) => {
      const err = new Error(e.message || 'The analysis worker crashed.');
      for (const waiter of this.pending.values()) waiter.reject(err);
      this.pending.clear();
      this.worker?.terminate();
      this.worker = null;
    };
    return this.worker;
  }

  private request(msg: DistributiveOmit<WorkerRequest, 'requestId'>): Promise<WorkerResponse> {
    const requestId = this.nextRequestId++;
    const worker = this.ensureWorker();
    return new Promise((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject });
      worker.postMessage({ ...msg, requestId } as WorkerRequest);
    });
  }

  async analyze(files: InputFile[]): Promise<void> {
    this.phase.set('analyzing');
    this.progress.set(null);
    this.error.set(null);
    this.result.set(null);
    this.cleanseOutcome.set(null);
    try {
      const response = await this.request({
        type: 'analyze',
        files,
        safeHashes: this.signatureStore.safeHashes(),
      });
      if (response.type === 'result') {
        this.result.set(response.result);
        this.phase.set('results');
      }
    } catch (e) {
      this.error.set((e as Error).message);
      this.phase.set('idle');
    }
  }

  /** The cleansed result, produced by cleanse() and consumed by download(). */
  readonly cleanseOutcome = signal<CleanseOutcome | null>(null);

  /** Step 1: run the cleanse in the worker and hold the result in memory. */
  async cleanse(): Promise<CleanseOutcome> {
    const response = await this.request({ type: 'cleanse' });
    if (response.type !== 'cleansed') throw new Error('Unexpected worker response.');
    this.cleanseOutcome.set(response.outcome);
    return response.outcome;
  }

  /** Step 2: download the cleaned output — one JSON for a single file, a ZIP for a batch. */
  async download(): Promise<void> {
    const outcome = this.cleanseOutcome();
    if (!outcome || outcome.files.length === 0) return;

    if (outcome.files.length === 1) {
      const file = outcome.files[0];
      this.saveBlob(new Blob([file.json], { type: 'application/json' }), `${cleanedName(file.fileName)}.json`);
      return;
    }

    // Batch → ZIP (jszip is lazy-loaded so it isn't in the initial bundle).
    const { default: JSZip } = await import('jszip');
    const zip = new JSZip();
    const used = new Map<string, number>();
    for (const file of outcome.files) {
      let name = `${cleanedName(file.fileName)}.json`;
      // Avoid collisions if two uploads share a name.
      const n = used.get(name) ?? 0;
      used.set(name, n + 1);
      if (n > 0) name = name.replace(/\.json$/i, `(${n}).json`);
      zip.file(name, file.json);
    }
    const blob = await zip.generateAsync({ type: 'blob' });
    this.saveBlob(blob, 'tts-disinfected.zip');
  }

  private saveBlob(blob: Blob, fileName: string): void {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async getScript(docId: number, nodeId: number): Promise<string> {
    const response = await this.request({ type: 'getScript', docId, nodeId });
    return response.type === 'script' ? response.script : '';
  }

  /** Re-flag groups after the user trusts/revokes a signature (no re-scan needed). */
  applyTrust(hash: string, trusted: boolean): void {
    const current = this.result();
    if (!current) return;
    this.result.set({
      ...current,
      groups: current.groups.map((g) =>
        g.scriptHash === hash && g.severity !== 'critical' ? { ...g, trusted } : g,
      ),
    });
  }

  /** Flag a worm+extra group's leftover code as reviewed & approved. */
  applyExtraApproval(groupHash: string, approved: boolean): void {
    const current = this.result();
    if (!current) return;
    this.result.set({
      ...current,
      groups: current.groups.map((g) =>
        g.scriptHash === groupHash ? { ...g, approvedExtra: approved } : g,
      ),
    });
  }

  reset(): void {
    this.phase.set('idle');
    this.progress.set(null);
    this.result.set(null);
    this.error.set(null);
    this.cleanseOutcome.set(null);
    // Drop the worker so the parsed save's memory is released immediately.
    this.worker?.terminate();
    this.worker = null;
    this.pending.clear();
  }
}
