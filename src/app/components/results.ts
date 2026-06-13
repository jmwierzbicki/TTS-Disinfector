import { Component, computed, inject, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { AnalysisService } from '../core/analysis.service';
import { SignatureStoreService } from '../core/signature-store.service';
import { ToastService } from '../core/toast.service';
import { ScriptViewer } from './script-viewer';
import { buildPromptForGroup } from '../core/prompt-builder';
import { copyToClipboard } from '../core/clipboard.util';
import { cleanseScript } from '../core/analyzer';
import { resolveGroup, hasResidualToDismiss, type Resolution } from '../core/resolution';
import type { Occurrence, ScriptGroup } from '../core/models';
import type { Severity } from '../core/threat-patterns';

type SeverityFilter = Severity | 'all';

@Component({
  selector: 'app-results',
  imports: [DecimalPipe, ScriptViewer],
  templateUrl: './results.html',
})
export class Results {
  protected readonly analysis = inject(AnalysisService);
  protected readonly signatures = inject(SignatureStoreService);
  private readonly toasts = inject(ToastService);

  protected readonly showTrusted = signal(false);
  protected readonly cleansing = signal(false);
  protected readonly extraPathsExpanded = signal(false);
  /** Worm sections whose residual non-worm concerns the user has dismissed. */
  protected readonly dismissedResidual = signal<ReadonlySet<string>>(new Set());

  /** Number of extra-code paths shown before the list collapses behind a toggle. */
  protected readonly EXTRA_PATH_PREVIEW = 5;
  protected readonly severityFilter = signal<SeverityFilter>('all');
  protected readonly patternFilter = signal<string | null>(null);
  protected readonly viewing = signal<ScriptGroup | null>(null);

  protected readonly result = this.analysis.result;
  protected readonly cleanseOutcome = this.analysis.cleanseOutcome;

  /** Batch mode: more than one file was scanned. */
  protected readonly multiFile = computed(() => (this.result()?.documents.length ?? 0) > 1);

  /** File name for an occurrence (used to show where each detection lives in batch mode). */
  protected fileNameOf(occ: Occurrence): string {
    return this.result()?.documents[occ.docId]?.fileName ?? '';
  }

  /** Groups the user hasn't trusted away. */
  protected readonly activeGroups = computed(() => this.result()?.groups.filter((g) => !g.trusted) ?? []);
  protected readonly trustedGroups = computed(() => this.result()?.groups.filter((g) => g.trusted) ?? []);

  protected readonly criticalCount = computed(
    () => this.activeGroups().filter((g) => g.severity === 'critical').reduce((n, g) => n + g.occurrences.length, 0),
  );
  protected readonly warningCount = computed(
    () => this.activeGroups().filter((g) => g.severity === 'warning').length,
  );
  protected readonly infoCount = computed(
    () => this.activeGroups().filter((g) => g.severity === 'info').length,
  );

  /** Distinct pattern types present across active groups, for the filter bar. */
  protected readonly patternTypes = computed(() => {
    const map = new Map<string, { id: string; name: string; severity: Severity; count: number }>();
    for (const g of this.activeGroups()) {
      for (const f of g.findings) {
        const existing = map.get(f.patternId);
        if (existing) existing.count++;
        else map.set(f.patternId, { id: f.patternId, name: f.patternName, severity: f.severity, count: 1 });
      }
    }
    return [...map.values()];
  });

  /** Active groups after applying the severity + pattern filters. */
  protected readonly filteredGroups = computed(() => {
    const sev = this.severityFilter();
    const pat = this.patternFilter();
    return this.activeGroups().filter((g) => {
      if (sev !== 'all' && g.severity !== sev) return false;
      if (pat && !g.findings.some((f) => f.patternId === pat)) return false;
      return true;
    });
  });

  protected readonly verdict = computed<'infected' | 'suspicious' | 'clean'>(() => {
    if (this.criticalCount() > 0) return 'infected';
    if (this.warningCount() > 0) return 'suspicious';
    return 'clean';
  });

  protected readonly filtersActive = computed(() => this.severityFilter() !== 'all' || this.patternFilter() !== null);

  protected setSeverityFilter(sev: SeverityFilter): void {
    this.severityFilter.set(this.severityFilter() === sev ? 'all' : sev);
  }

  protected togglePatternFilter(id: string): void {
    this.patternFilter.set(this.patternFilter() === id ? null : id);
  }

  protected clearFilters(): void {
    this.severityFilter.set('all');
    this.patternFilter.set(null);
  }

  protected readonly copiedHash = signal<string | null>(null);

  protected open(group: ScriptGroup): void {
    this.viewing.set(group);
  }

  /** Build the state-tailored LLM prompt for this section and copy it to the clipboard. */
  protected async copyPrompt(group: ScriptGroup): Promise<void> {
    const focus = this.resolution(group).prompt;
    if (!focus) return;
    const script = await this.analysis.getScript(group.representativeDocId, group.representativeNodeId);
    const ok = await copyToClipboard(buildPromptForGroup(group, script, focus));
    if (!ok) return;
    this.copiedHash.set(group.scriptHash);
    this.toasts.show(
      'Prompt copied to clipboard',
      'Open your favourite AI — ChatGPT, Claude, Gemini — and paste it in for a clear, plain-language explanation.',
    );
    setTimeout(() => {
      if (this.copiedHash() === group.scriptHash) this.copiedHash.set(null);
    }, 2000);
  }

  /**
   * The live status of a section, reflecting what's still wrong with it *right
   * now* and turning green once the user has resolved it. Drives the card's
   * colour, so the list always shows the current outstanding problems.
   */
  protected resolution(group: ScriptGroup): Resolution {
    return resolveGroup(group, {
      cleansed: !!this.cleanseOutcome(),
      dismissed: this.dismissedResidual().has(group.scriptHash),
    });
  }

  /** A worm section whose worm is handled but which still carries residual concerns. */
  protected canDismissResidual(group: ScriptGroup): boolean {
    return (
      !this.signatures.unavailable() &&
      hasResidualToDismiss(group, {
        cleansed: !!this.cleanseOutcome(),
        dismissed: this.dismissedResidual().has(group.scriptHash),
      })
    );
  }

  /** Mark a worm section's residual concerns as reviewed → it turns green (Healed). */
  protected dismissResidual(group: ScriptGroup): void {
    const next = new Set(this.dismissedResidual());
    next.add(group.scriptHash);
    this.dismissedResidual.set(next);
  }

  /** Whether to offer the "approve remaining code" action for this group. */
  protected canApproveExtra(group: ScriptGroup): boolean {
    return (
      group.cleansable &&
      group.extraCodeOutsidePayload &&
      !group.approvedExtra &&
      !this.signatures.unavailable()
    );
  }

  /** Trust the leftover code's signature and mark the group's remaining code approved. */
  protected async approveExtraCode(group: ScriptGroup): Promise<void> {
    if (!group.cleansedScriptHash) return;
    const original = await this.analysis.getScript(group.representativeDocId, group.representativeNodeId);
    const leftover = cleanseScript(original);
    const label = group.occurrences[0]?.pathSegments.at(-1) ?? 'Script';
    await this.signatures.trust({
      hash: group.cleansedScriptHash,
      label: `Reviewed leftover · ${label}`,
      excerpt: leftover.slice(0, 120),
    });
    this.analysis.applyExtraApproval(group.scriptHash, true);
    if (this.viewing()?.scriptHash === group.scriptHash) {
      this.viewing.set(this.result()?.groups.find((g) => g.scriptHash === group.scriptHash) ?? null);
    }
  }

  protected onTrustChange(e: { hash: string; trusted: boolean }): void {
    this.analysis.applyTrust(e.hash, e.trusted);
    // Keep the modal's group reference in sync so its button flips.
    const updated = this.result()?.groups.find((g) => g.scriptHash === e.hash) ?? null;
    if (this.viewing()) this.viewing.set(updated);
  }

  /** The modal approved a worm+extra group's leftover code. */
  protected onApproveExtra(e: { hash: string }): void {
    this.analysis.applyExtraApproval(e.hash, true);
    const updated = this.result()?.groups.find((g) => g.scriptHash === e.hash) ?? null;
    if (this.viewing()) this.viewing.set(updated);
  }

  protected async cleanse(): Promise<void> {
    if (this.cleansing()) return;
    this.cleansing.set(true);
    try {
      await this.analysis.cleanse();
    } finally {
      this.cleansing.set(false);
    }
  }

  protected async download(): Promise<void> {
    await this.analysis.download();
  }

  protected scanAgain(): void {
    this.analysis.reset();
  }

  protected formatBytes(bytes: number): string {
    if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
    return bytes + ' B';
  }
}
