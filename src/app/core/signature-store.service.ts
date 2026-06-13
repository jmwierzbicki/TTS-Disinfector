import { Injectable, signal } from '@angular/core';
import { openDB, type IDBPDatabase } from 'idb';
import type { SafeSignature } from './models';

/**
 * Local-only store of script signatures the user has marked as trusted.
 * Lives entirely in the browser's IndexedDB — never synced, never uploaded.
 */
@Injectable({ providedIn: 'root' })
export class SignatureStoreService {
  private dbPromise: Promise<IDBPDatabase> | null = null;

  readonly signatures = signal<SafeSignature[]>([]);
  /** True when IndexedDB is unavailable (private browsing edge cases) — trusting is disabled. */
  readonly unavailable = signal(false);

  constructor() {
    void this.refresh();
  }

  private db(): Promise<IDBPDatabase> {
    this.dbPromise ??= openDB('tts-disinfector', 1, {
      upgrade(db) {
        db.createObjectStore('safeSignatures', { keyPath: 'hash' });
      },
    });
    return this.dbPromise;
  }

  async refresh(): Promise<void> {
    try {
      const db = await this.db();
      const all = (await db.getAll('safeSignatures')) as SafeSignature[];
      this.signatures.set(all.sort((a, b) => b.addedAt - a.addedAt));
      this.unavailable.set(false);
    } catch {
      this.unavailable.set(true);
      this.signatures.set([]);
    }
  }

  safeHashes(): string[] {
    return this.signatures().map((s) => s.hash);
  }

  async trust(sig: Omit<SafeSignature, 'addedAt'>): Promise<void> {
    try {
      const db = await this.db();
      await db.put('safeSignatures', { ...sig, addedAt: Date.now() } satisfies SafeSignature);
      await this.refresh();
    } catch {
      this.unavailable.set(true);
    }
  }

  async revoke(hash: string): Promise<void> {
    try {
      const db = await this.db();
      await db.delete('safeSignatures', hash);
      await this.refresh();
    } catch {
      this.unavailable.set(true);
    }
  }

  async clearAll(): Promise<void> {
    try {
      const db = await this.db();
      await db.clear('safeSignatures');
      await this.refresh();
    } catch {
      this.unavailable.set(true);
    }
  }
}
