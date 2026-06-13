/**
 * Builds a copy-paste-ready prompt for a general-purpose chatbot (ChatGPT,
 * Claude, Gemini, …) tailored to one finding. The goal: a non-technical player
 * can paste it into any AI and get a short, plain-language answer about the
 * script the disinfector flagged.
 *
 * Each prompt always contains the script in its current state plus a
 * case-specific instruction. The case-specific part comes from the matching
 * pattern's `aiInstruction()` (see threat-patterns.ts) — so adding a tailored
 * prompt for a new threat is just one more field on its pattern definition.
 */
import { patternById, type AiInstruction, type PromptContext } from './threat-patterns';
import { cleanseScript } from './analyzer';
import { WORM_ID, type PromptFocus } from './resolution';
import type { ScriptGroup } from './models';

const DEFAULT_TASK =
  'Briefly explain, in simple terms, what this script does and whether it looks safe or potentially dangerous.';

/** Appended to every prompt so the model answers for a non-technical audience. */
const STYLE_RULES = [
  'Reply in plain language for a non-technical Tabletop Simulator player who does not know how to code.',
  'Keep it short: at most 10 sentences.',
  'Avoid technical jargon; if a technical word is unavoidable, explain it in a few words.',
  'Do not rewrite the script or give coding instructions — just explain it and say whether it is safe.',
].join(' ');

/**
 * Builds the prompt for the section's *current* concern (`focus`), not just its
 * top finding — so a "Dangerous methods" section asks about those methods, a
 * "Verification needed" section asks whether the leftover code is safe, etc.
 *
 * @param group   the finding group the user clicked
 * @param script  the script as it currently exists in the save (fetched from the worker)
 * @param focus   which concern to ask about (from the section's resolution)
 */
export function buildPromptForGroup(group: ScriptGroup, script: string, focus: PromptFocus): string {
  const ctx: PromptContext = {
    script,
    cleansedScript: cleanseScript(script),
    extraCodeOutsidePayload: group.extraCodeOutsidePayload,
  };

  // Pick the pattern + instruction that matches the focus.
  let focusPatternId: string;
  let instruction: AiInstruction;
  if (focus.kind === 'worm') {
    focusPatternId = WORM_ID;
    // Force the "explain the worm" branch (not the leftover branch).
    instruction = patternById(WORM_ID)?.aiInstruction?.({ ...ctx, extraCodeOutsidePayload: false }) ?? { task: DEFAULT_TASK };
  } else if (focus.kind === 'leftover') {
    focusPatternId = WORM_ID;
    instruction = patternById(WORM_ID)?.aiInstruction?.({ ...ctx, extraCodeOutsidePayload: true }) ?? { task: DEFAULT_TASK };
  } else {
    focusPatternId = focus.patternId;
    instruction = patternById(focus.patternId)?.aiInstruction?.(ctx) ?? { task: DEFAULT_TASK };
  }

  // Only the "explain the worm" prompt embeds the worm itself. Every other focus
  // is about the code the player keeps, so it embeds the cleansed script — never
  // re-including a worm payload that has already been removed. (For a script with
  // no worm, the cleansed form equals the original, so nothing changes.)
  const useCleansed = focus.kind !== 'worm';
  const body = (useCleansed ? ctx.cleansedScript : ctx.script).trim();
  const wormRemoved = useCleansed && body !== ctx.script.trim();
  const label = wormRemoved ? 'CODE REMAINING AFTER THE WORM WAS REMOVED' : 'SCRIPT';

  const focusName = patternById(focusPatternId)?.name ?? group.findings[0].patternName;
  // Note the other things this script was flagged for, so the answer is complete.
  const others = group.findings.filter((f) => f.patternId !== focusPatternId).map((f) => f.patternName);
  const alsoFlagged = others.length > 0 ? `\nThis script was also flagged for: ${others.join(', ')}.` : '';

  return [
    `A security scan of a Tabletop Simulator save file flagged this script for "${focusName}".${alsoFlagged}`,
    '',
    instruction.task,
    '',
    STYLE_RULES,
    '',
    `----- ${label} START -----`,
    body || '(After removing the worm, nothing is left — the script was entirely worm code.)',
    `----- ${label} END -----`,
  ].join('\n');
}
