import { Component, HostListener, inject, signal } from '@angular/core';
import { AnalysisService } from '../core/analysis.service';
import { THREAT_PATTERNS } from '../core/threat-patterns';

const MAX_FILE_BYTES = 250 * 1024 * 1024; // refuse absurd inputs with a clear message

@Component({
  selector: 'app-upload',
  templateUrl: './upload.html',
})
export class Upload {
  protected readonly analysis = inject(AnalysisService);
  protected readonly dragOver = signal(false);
  protected readonly localError = signal<string | null>(null);
  protected readonly patterns = THREAT_PATTERNS;

  protected onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.dragOver.set(true);
  }

  protected onDragLeave(event: DragEvent): void {
    event.preventDefault();
    this.dragOver.set(false);
  }

  protected async onDrop(event: DragEvent): Promise<void> {
    event.preventDefault();
    this.dragOver.set(false);
    const file = event.dataTransfer?.files?.[0];
    if (file) {
      await this.readFile(file);
      return;
    }
    const text = event.dataTransfer?.getData('text');
    if (text) await this.submitText(text, 'dropped-save.json');
  }

  protected async onFilePicked(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file) await this.readFile(file);
    input.value = '';
  }

  @HostListener('window:paste', ['$event'])
  protected async onPaste(event: ClipboardEvent): Promise<void> {
    if (this.analysis.phase() !== 'idle') return;
    const file = event.clipboardData?.files?.[0];
    if (file) {
      await this.readFile(file);
      return;
    }
    const text = event.clipboardData?.getData('text');
    if (text?.trim()) await this.submitText(text, 'pasted-save.json');
  }

  private async readFile(file: File): Promise<void> {
    this.localError.set(null);
    if (file.size > MAX_FILE_BYTES) {
      this.localError.set(
        `"${file.name}" is ${(file.size / 1024 / 1024).toFixed(0)} MB — larger than the ${MAX_FILE_BYTES / 1024 / 1024} MB limit. TTS saves don't get this big; this is probably not a save file.`,
      );
      return;
    }
    try {
      const text = await file.text();
      await this.submitText(text, file.name);
    } catch {
      this.localError.set(`Couldn't read "${file.name}". Is it a regular text file?`);
    }
  }

  private async submitText(text: string, fileName: string): Promise<void> {
    this.localError.set(null);
    await this.analysis.analyze(text, fileName);
  }
}
