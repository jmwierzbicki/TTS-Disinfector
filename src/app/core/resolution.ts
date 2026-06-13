/**
 * Pure resolution logic — given a finding group and the current cleanse/dismiss
 * state, decide what's still wrong with it *right now*. Shared by the results
 * cards and the script-viewer modal so both show the same status and offer the
 * same state-tailored AI prompt.
 */
import type { ScriptGroup } from './models';

export const WORM_ID = 'worm-object-base-code';
export const DANGEROUS_IDS = new Set(['webrequest-usage', 'script-injection', 'dynamic-code-load']);

/** What the "Copy AI prompt" button should ask about, given the current state. */
export type PromptFocus =
  | { kind: 'worm' } //      explain the worm payload itself
  | { kind: 'leftover' } //  is the code left after removing the worm safe?
  | { kind: 'pattern'; patternId: string }; // a specific non-worm concern

export interface Resolution {
  tone: 'critical' | 'warning' | 'info' | 'clean';
  label: string;
  icon: 'alert' | 'check' | 'info';
  /** Pulse the chip to draw the eye to an outstanding action. */
  pulse: boolean;
  /** True once the section needs no further attention. */
  resolved: boolean;
  /** The tailored prompt for this state, or null when there's nothing to ask (Healed). */
  prompt: PromptFocus | null;
}

export interface ResolutionContext {
  /** The save has been cleansed (worm payloads removed). */
  cleansed: boolean;
  /** The user dismissed this worm section's residual non-worm concerns. */
  dismissed: boolean;
}

/** The most pressing non-worm concern in a group, as a prompt focus. */
function residualFocus(group: ScriptGroup): PromptFocus | null {
  const dangerous = group.findings.find((f) => DANGEROUS_IDS.has(f.patternId));
  if (dangerous) return { kind: 'pattern', patternId: dangerous.patternId };
  if (group.findings.some((f) => f.patternId === 'worm-fragment')) {
    return { kind: 'pattern', patternId: 'worm-fragment' };
  }
  if (group.findings.some((f) => f.patternId === 'on-update-handler')) {
    return { kind: 'pattern', patternId: 'on-update-handler' };
  }
  return null;
}

/** Turn a non-worm concern into its category status. */
function categoryResolution(focus: PromptFocus & { kind: 'pattern' }): Resolution {
  if (DANGEROUS_IDS.has(focus.patternId)) {
    return { tone: 'warning', label: 'Dangerous methods', icon: 'alert', pulse: false, resolved: false, prompt: focus };
  }
  if (focus.patternId === 'worm-fragment') {
    return { tone: 'warning', label: 'Suspicious', icon: 'alert', pulse: false, resolved: false, prompt: focus };
  }
  return { tone: 'info', label: 'Performance', icon: 'info', pulse: false, resolved: false, prompt: focus };
}

export function resolveGroup(group: ScriptGroup, ctx: ResolutionContext): Resolution {
  // Explicitly trusted (non-worm) → resolved, but still answerable about its kind.
  if (group.trusted) {
    return { tone: 'clean', label: 'Marked safe', icon: 'check', pulse: false, resolved: true, prompt: residualFocus(group) };
  }

  const hasWorm = group.findings.some((f) => f.patternId === WORM_ID);
  if (hasWorm) {
    if (!ctx.cleansed) {
      return { tone: 'critical', label: 'Infected', icon: 'alert', pulse: false, resolved: false, prompt: { kind: 'worm' } };
    }
    // Worm payload removed.
    if (group.extraCodeOutsidePayload && !group.approvedExtra) {
      return { tone: 'warning', label: 'Verification needed', icon: 'alert', pulse: true, resolved: false, prompt: { kind: 'leftover' } };
    }
    // Worm handled. Surface any dangerous methods etc. that lived in the kept code,
    // so the user can still ask about them before finally dismissing the section.
    const residual = ctx.dismissed ? null : residualFocus(group);
    if (residual && residual.kind === 'pattern') return categoryResolution(residual);
    return { tone: 'clean', label: 'Healed', icon: 'check', pulse: false, resolved: true, prompt: null };
  }

  // Uninfected scripts: categorise by what they contain.
  const focus = residualFocus(group);
  if (focus && focus.kind === 'pattern') return categoryResolution(focus);
  // No recognised concern (shouldn't happen — a group always has ≥1 finding).
  return { tone: 'info', label: 'Performance', icon: 'info', pulse: false, resolved: false, prompt: null };
}

/** Worm section whose worm is handled but which still carries residual concerns to dismiss. */
export function hasResidualToDismiss(group: ScriptGroup, ctx: ResolutionContext): boolean {
  const hasWorm = group.findings.some((f) => f.patternId === WORM_ID);
  if (!hasWorm || !ctx.cleansed || ctx.dismissed) return false;
  if (group.extraCodeOutsidePayload && !group.approvedExtra) return false;
  return residualFocus(group) !== null;
}
