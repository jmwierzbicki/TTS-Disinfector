import { Injectable, signal } from '@angular/core';

export interface Toast {
  id: number;
  title: string;
  message: string;
  /** Set true just before removal so the view can play the dissolve animation. */
  leaving: boolean;
  /** How long (ms) the toast stays before it begins dissolving. */
  duration: number;
}

/** Duration of the CSS dissolve animation — keep in sync with `.toast-leaving`. */
const DISSOLVE_MS = 650;

/**
 * App-wide transient toast. Only one is shown at a time; a new toast replaces
 * the current one. Rendered once at the app shell so it floats above modals.
 */
@Injectable({ providedIn: 'root' })
export class ToastService {
  readonly toast = signal<Toast | null>(null);

  private counter = 0;
  private hideTimer: ReturnType<typeof setTimeout> | null = null;
  private removeTimer: ReturnType<typeof setTimeout> | null = null;

  show(title: string, message: string, duration = 8000): void {
    if (this.hideTimer) clearTimeout(this.hideTimer);
    if (this.removeTimer) clearTimeout(this.removeTimer);

    const id = ++this.counter;
    this.toast.set({ id, title, message, leaving: false, duration });
    this.hideTimer = setTimeout(() => this.dismiss(id), duration);
  }

  dismiss(id?: number): void {
    const current = this.toast();
    if (!current || (id !== undefined && current.id !== id)) return;
    this.toast.set({ ...current, leaving: true });
    this.removeTimer = setTimeout(() => {
      const c = this.toast();
      if (c && c.id === current.id) this.toast.set(null);
    }, DISSOLVE_MS);
  }
}
