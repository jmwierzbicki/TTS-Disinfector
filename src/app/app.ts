import { Component, inject, signal } from '@angular/core';
import { DatePipe, DecimalPipe } from '@angular/common';
import { AnalysisService } from './core/analysis.service';
import { SignatureStoreService } from './core/signature-store.service';
import { ToastService } from './core/toast.service';
import { Upload } from './components/upload';
import { Results } from './components/results';

@Component({
  selector: 'app-root',
  imports: [Upload, Results, DatePipe, DecimalPipe],
  templateUrl: './app.html',
})
export class App {
  protected readonly analysis = inject(AnalysisService);
  protected readonly signatures = inject(SignatureStoreService);
  protected readonly toasts = inject(ToastService);
  protected readonly showTrustedPanel = signal(false);

  protected progressPercent(): number {
    const p = this.analysis.progress();
    if (!p || p.total === 0) return 0;
    return Math.round((p.processed / p.total) * 100);
  }
}
