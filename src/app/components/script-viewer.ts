import { Component, computed, inject, input, output, signal, effect } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser';
import { AnalysisService } from '../core/analysis.service';
import { SignatureStoreService } from '../core/signature-store.service';
import { cleanseScript } from '../core/analyzer';
import { highlightLua } from '../core/lua-highlight';
import { buildPromptForGroup } from '../core/prompt-builder';
import { copyToClipboard } from '../core/clipboard.util';
import { resolveGroup } from '../core/resolution';
import { ToastService } from '../core/toast.service';
import { patternById, type CodeSpan } from '../core/threat-patterns';
import type { ScriptGroup } from '../core/models';

type Tab = 'original' | 'cleansed' | 'objects';

/**
 * Full-screen modal that shows a script with Lua syntax highlighting.
 * - "Original" tab paints the worm payload / matched ranges red.
 * - "Cleansed" tab shows what the script becomes after auto-cleansing.
 * Also lists every object carrying the script and exposes the trust action.
 */
@Component({
  selector: 'app-script-viewer',
  imports: [DecimalPipe],
  templateUrl: './script-viewer.html',
})
export class ScriptViewer {
  readonly group = input.required<ScriptGroup>();
  readonly close = output<void>();
  readonly trustChange = output<{ hash: string; trusted: boolean }>();
  readonly approveExtra = output<{ hash: string }>();

  private readonly analysis = inject(AnalysisService);
  private readonly sanitizer = inject(DomSanitizer);
  private readonly toasts = inject(ToastService);
  protected readonly signatures = inject(SignatureStoreService);

  protected readonly tab = signal<Tab>('original');
  private readonly script = signal<string>('');
  protected readonly loading = signal(true);

  constructor() {
    effect(() => {
      const g = this.group();
      this.loading.set(true);
      void this.analysis.getScript(g.representativeNodeId).then((s) => {
        this.script.set(s);
        this.loading.set(false);
        // Once the save has been cleansed, open straight to the Cleansed view —
        // that's the code the player keeps. (reading cleanseOutcome in this async
        // callback intentionally doesn't make the effect depend on it.)
        const showCleansed = !!this.analysis.cleanseOutcome() && cleanseScript(s) !== s;
        this.tab.set(showCleansed ? 'cleansed' : 'original');
      });
    });
  }

  protected readonly cleansed = computed(() => cleanseScript(this.script()));
  protected readonly cleansedDiffers = computed(() => this.cleansed() !== this.script());

  /** Combined malicious ranges from every pattern that matched this script. */
  private readonly spans = computed<CodeSpan[]>(() => {
    const src = this.script();
    const out: CodeSpan[] = [];
    for (const f of this.group().findings) {
      const p = patternById(f.patternId);
      if (p?.maliciousSpans) out.push(...p.maliciousSpans(src));
    }
    return out;
  });

  protected readonly originalHtml = computed<SafeHtml>(() =>
    this.sanitizer.bypassSecurityTrustHtml(highlightLua(this.script(), this.spans())),
  );
  protected readonly cleansedHtml = computed<SafeHtml>(() =>
    this.sanitizer.bypassSecurityTrustHtml(highlightLua(this.cleansed())),
  );

  protected readonly markedCount = computed(() => this.spans().filter((s) => s.end > s.start).length);

  protected readonly copied = signal(false);

  /** The section's current resolution (drives which prompt to copy). */
  protected readonly resolution = computed(() =>
    resolveGroup(this.group(), { cleansed: !!this.analysis.cleanseOutcome(), dismissed: false }),
  );

  protected async copyPrompt(): Promise<void> {
    const focus = this.resolution().prompt;
    if (!focus) return;
    const ok = await copyToClipboard(buildPromptForGroup(this.group(), this.script(), focus));
    if (!ok) return;
    this.copied.set(true);
    this.toasts.show(
      'Prompt copied to clipboard',
      'Open your favourite AI — ChatGPT, Claude, Gemini — and paste it in for a clear, plain-language explanation.',
    );
    setTimeout(() => this.copied.set(false), 2000);
  }

  protected async trust(): Promise<void> {
    const g = this.group();
    const last = g.occurrences[0]?.pathSegments;
    await this.signatures.trust({
      hash: g.scriptHash,
      label: last?.[last.length - 1] ?? 'Script',
      excerpt: g.findings[0]?.excerpt.slice(0, 120) ?? '',
    });
    this.trustChange.emit({ hash: g.scriptHash, trusted: true });
  }

  /** Offer "approve remaining code" for an unapproved worm+extra group. */
  protected readonly canApproveExtra = computed(() => {
    const g = this.group();
    return g.cleansable && g.extraCodeOutsidePayload && !g.approvedExtra && !this.signatures.unavailable();
  });

  protected async approve(): Promise<void> {
    const g = this.group();
    if (!g.cleansedScriptHash) return;
    const last = g.occurrences[0]?.pathSegments;
    await this.signatures.trust({
      hash: g.cleansedScriptHash,
      label: `Reviewed leftover · ${last?.[last.length - 1] ?? 'Script'}`,
      excerpt: this.cleansed().slice(0, 120),
    });
    this.approveExtra.emit({ hash: g.scriptHash });
  }

  protected async revoke(): Promise<void> {
    const g = this.group();
    await this.signatures.revoke(g.scriptHash);
    this.trustChange.emit({ hash: g.scriptHash, trusted: false });
  }
}
