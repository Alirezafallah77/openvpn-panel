const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const code='const deviceGuide='+fs.readFileSync('static/ui.js','utf8').split('const deviceGuide=')[1];
function harness(agent,platform='',touch=0) {
 const clicks=[];let open;
 const select={value:'android'};
 const guide={querySelector:s=>s==='[data-device-select]'?select:{addEventListener:(t,fn)=>open=fn}};
 vm.runInNewContext(code,{navigator:{userAgent:agent,platform,maxTouchPoints:touch},document:{querySelector:()=>guide,getElementById:id=>({click:()=>clicks.push(id),focus:()=>clicks.push('focus'),scrollIntoView(){}})}});
 return {select,clicks,open:()=>open({preventDefault(){}})};
}
test('device detection is a hint and manual choice controls instructions',()=>{
 const h=harness('Windows');assert.equal(h.select.value,'windows');h.select.value='android';h.open();assert.deepEqual(h.clicks,['tab-guide','tab-android','focus']);
});
test('iPhone and desktop-mode iPad choose iOS instructions',()=>{
 assert.equal(harness('iPhone').select.value,'ios');assert.equal(harness('Safari','MacIntel',5).select.value,'ios');
});
