# TTS Save Disinfector

A fully client-side web app that scans **Tabletop Simulator** save files for the
self-replicating Lua worm and removes it — without touching your own scripts.

> **Privacy:** everything happens locally in your browser. Save files are parsed
> and analyzed in a Web Worker on your machine; **no file data is ever sent over
> the network**. The only thing persisted is your local list of trusted script
> signatures (SHA-256 hashes), stored in this browser's IndexedDB.

> **Always keep a backup of your save.** The cleaned file downloads as a separate
> copy and your original is never modified, but no automated cleaner is perfect —
> keep the original until you've confirmed the cleaned save loads correctly in
> Tabletop Simulator.

## Features

- **Three input methods** — drag & drop `.json` file(s), click to pick files (multi-select), or paste raw JSON with `Ctrl+V`.
- **Saves and saved objects, one or many** — works on both TTS save files and saved-object `.json` files. Drop a single file or a whole batch at once: identical scripts aggregate across files, each detection shows its file name, and a batch cleanse downloads a ZIP of all cleaned files. Unreadable files are skipped and reported, not fatal.
- **Deep recursive scan** — walks `ObjectStates`, `ContainedObjects` (bags in bags in decks, to any depth), object `States`, and the Global script.
- **Web Worker analysis** — multi-megabyte saves with thousands of objects never freeze the UI; a progress bar tracks the scan.
- **Identical-script aggregation** — when the same script appears on many objects (the worm copies itself everywhere), it is reported **once** with an expandable ×N list of every object that carries it, instead of repeating the same finding per object.
- **Separate cleanse & download** — *Cleanse worm* removes the payload in memory and lets you preview the result; *Download cleaned save* then writes the copy. Your original save is never modified.
- **Precise cleansing** — removes exactly the worm payload (first `--[[Object base code]]` through the last `--[[Spawning object]]`, including the whitespace padding the worm adds) and preserves your original code. Objects that still contain code after cleansing are flagged **WORM + EXTRA CODE** for manual review, because the worm's remote-update channel can inject extra code.
- **Script viewer with Lua syntax highlighting** — open any finding in a modal with an **Original** tab (worm payload / matched code painted **red**) and a **Cleansed** tab showing what the script becomes after auto-cleansing. Mark-as-safe lives here too.
- **Filtering** — filter findings by severity (worm / suspicious / info) and by specific pattern type.
- **Copy AI prompt** — every finding has a button that copies a ready-made, case-specific question (with the script embedded) to paste into any chatbot. The prompt is tailored per threat — e.g. for *worm + extra code* it embeds only the leftover code and asks the AI whether it is dangerous — and always demands a short, plain-language answer for non-technical players. Copying pops a toast pointing the user to paste it into their favourite AI, which then dissolves on its own.
- **Per-section status after cleansing** — once you cleanse, each section shows where it stands: a green **Worm removed** badge when the script was nothing but worm, or an amber **Verify remaining code** badge (demanding a manual look) when your own code remained. Scripts you mark as safe get a green **Marked safe** badge.
- **Full object paths** — every finding shows where the object lives, e.g. `Bag "Player Red's Stuff" › Deck "Spells" › Card "Fireball"`.
- **Trusted scripts** — mark a flagged-but-legitimate script as trusted; its hash is remembered locally and suppressed on future scans. Critical (worm) findings can never be trusted away.
- **Severity language** — red = worm/infected · amber = suspicious pattern · blue = info (e.g. `onUpdate`) · green = clean/safe.

## Running locally

```bash
npm install
npm start          # dev server on http://localhost:4200
npm run build      # production build into dist/
```

Smoke-test the analysis engine (runs against the real worm source in Node):

```bash
npx -y tsx tools/analyzer.test.ts
```

## Deploying to GitHub Pages

A workflow at [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) builds the
app and publishes it to GitHub Pages on every push to `main`. It sets the base href to
`/<repo>/` automatically, so it works for any repository name.

One-time setup: in the repository, go to **Settings → Pages → Build and deployment**
and set the **Source** to **GitHub Actions**. The site then publishes to
`https://<user>.github.io/<repo>/`. Because everything runs client-side, the static
host never sees any save-file data.

`samples/infected-save.json` is a demo save containing the worm (as inert JSON
text — it only does anything if loaded into Tabletop Simulator). Drop it onto
the app to see detection, cleansing, and the WORM + EXTRA CODE flow.

## Adding a new threat pattern

All detectors live in **one file**:
[`src/app/core/threat-patterns.ts`](src/app/core/threat-patterns.ts).
Each threat is a self-contained object; adding a new worm is a small, isolated
pull request — no other file needs to change.

```ts
// in THREAT_PATTERNS (src/app/core/threat-patterns.ts):
{
  id: 'my-new-worm',                       // stable, never reused
  name: 'My new worm',
  description: 'What it does and how it spreads.',
  severity: 'critical',                    // 'critical' | 'warning' | 'info'
  detect(lua) {
    const idx = lua.indexOf('--[[evil marker]]');
    if (idx === -1) return null;           // null = no match
    return { detail: 'Marker found.', excerpt: lua.slice(idx, idx + 160) };
  },
  // OPTIONAL — only when removal is precise and safe; enables auto-cleansing
  // for this pattern:
  cleanse(lua) {
    return lua.replace(/--\[\[evil marker\]\][\s\S]*?--\[\[end\]\]/g, '');
  },
  // OPTIONAL — character ranges of the matched/malicious code. The script
  // viewer paints these red in the "Original" tab:
  maliciousSpans(lua) {
    const i = lua.indexOf('--[[evil marker]]');
    return i === -1 ? [] : [{ start: i, end: lua.indexOf('--[[end]]', i) + 9 }];
  },
  // OPTIONAL — the case-specific question for the "Copy AI prompt" button.
  // `include: 'cleansed'` embeds only the leftover code (after cleanse) instead
  // of the full script. The shared builder adds the plain-language style rules.
  aiInstruction: (ctx) => ({
    task: 'In simple terms, tell the player whether this looks dangerous and what it does.',
    include: ctx.extraCodeOutsidePayload ? 'cleansed' : 'original',
  }),
},
```

Rules of the registry:

1. `detect()` must be **pure and fast** — it runs on every script in the save, inside the worker.
2. **Order matters**: cleansable critical patterns come first. Later patterns are evaluated against the *cleansed* script, so a worm's own internals (its `WebRequest`, `setLuaScript`, …) don't double-report on infected objects — any additional finding genuinely belongs to the user's residual code.
3. Add a verification case to [`tools/analyzer.test.ts`](tools/analyzer.test.ts).

The registry is pure TypeScript with no Angular/DOM dependencies — it is shared
verbatim between the UI (the "What gets detected" cards) and the analysis worker.

## Shipped detectors

| Pattern | Severity | Auto-cleanse |
| --- | --- | --- |
| Self-replicating Lua worm (`--[[Object base code]]`) | critical | ✔ |
| Worm fragment / variant markers | warning | — |
| Network request (`WebRequest.*`) | warning | — |
| Rewrites other objects' scripts (`setLuaScript`) | warning | — |
| Dynamic code execution (`load`/`loadstring`) | warning | — |
| `onUpdate` handler (per-frame, performance note) | info | — |

## About the worm

The known worm spans from the first `--[[Object base code]]` marker to the end
of the last `--[[Spawning object]]` marker. It re-infects every object in the
save once per load (`getObjects()` sweep + `onObjectSpawn` hook), pads its
payload onto victims with `string.rep(" ", 100)`, and polls a remote URL for
payload updates which it splices in before its closing marker. That remote
channel is why cleansed objects that still contain code are flagged for manual
review.

## Stack

Angular (standalone components + signals, zoneless) · Tailwind CSS v4 ·
Web Worker analysis · [`idb`](https://github.com/jakearchibald/idb) for the
local trusted-signature store.
