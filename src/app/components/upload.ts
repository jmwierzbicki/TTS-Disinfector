import { Component, HostListener, inject, signal } from '@angular/core';
import { AnalysisService } from '../core/analysis.service';
import { THREAT_PATTERNS } from '../core/threat-patterns';
import type { InputFile } from '../core/models';

const MAX_FILE_BYTES = 250 * 1024 * 1024; // refuse absurd inputs with a clear message
const MAX_FILES = 500; // sanity cap for a single batch

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
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      await this.readFiles([...files]);
      return;
    }
    const text = event.dataTransfer?.getData('text');
    if (text) await this.submit([{ name: 'dropped-save.json', text }]);
  }

  protected async onFilePicked(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) await this.readFiles([...input.files]);
    input.value = '';
  }

  @HostListener('window:paste', ['$event'])
  protected async onPaste(event: ClipboardEvent): Promise<void> {
    if (this.analysis.phase() !== 'idle') return;
    const files = event.clipboardData?.files;
    if (files && files.length > 0) {
      await this.readFiles([...files]);
      return;
    }
    const text = event.clipboardData?.getData('text');
    if (text?.trim()) await this.submit([{ name: 'pasted-save.json', text }]);
  }

  private async readFiles(fileList: File[]): Promise<void> {
    this.localError.set(null);
    const files = fileList.filter((f) => /\.json$/i.test(f.name) || f.type === 'application/json' || fileList.length === 1);
    if (files.length === 0) {
      this.localError.set('No .json files found. Drop Tabletop Simulator save or saved-object .json files.');
      return;
    }
    if (files.length > MAX_FILES) {
      this.localError.set(`That's ${files.length} files — please scan at most ${MAX_FILES} at a time.`);
      return;
    }

    const inputs: InputFile[] = [];
    for (const file of files) {
      if (file.size > MAX_FILE_BYTES) {
        this.localError.set(
          `"${file.name}" is ${(file.size / 1024 / 1024).toFixed(0)} MB — larger than the ${MAX_FILE_BYTES / 1024 / 1024} MB limit, so it's probably not a save file.`,
        );
        return;
      }
      try {
        inputs.push({ name: file.name, text: await file.text() });
      } catch {
        this.localError.set(`Couldn't read "${file.name}". Is it a regular text file?`);
        return;
      }
    }
    await this.submit(inputs);
  }

  private async submit(files: InputFile[]): Promise<void> {
    this.localError.set(null);
    await this.analysis.analyze(files);
  }
}
