const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const code=fs.readFileSync(require('node:path').join(__dirname,'../static/theme.js'),'utf8');
function setup({dark=false,saved=null,unavailable=false,blocked=false}={}){
  let changed,ready,click;
  const button={setAttribute(){},addEventListener(type,fn){click=fn;}};
  const media={matches:dark,addEventListener(type,fn){changed=fn;}};
  const document={documentElement:{dataset:{}},body:null,querySelector(){return button;},addEventListener(type,fn){ready=fn;}};
  const storage={getItem(){if(blocked)throw Error('blocked');return saved;},setItem(k,v){if(blocked)throw Error('blocked');saved=v;}};
  vm.runInNewContext(code,{document,localStorage:storage,window:{matchMedia:unavailable?undefined:()=>media}});
  const initial=document.documentElement.dataset.theme;
  document.body={dataset:{}};ready();
  return {initial,theme:()=>document.documentElement.dataset.theme,click:()=>click(),saved:()=>saved,change(value){media.matches=value;changed?.();}};
}
test('automatic light and dark device settings',()=>{assert.equal(setup().initial,'light');assert.equal(setup({dark:true}).initial,'dark');});
test('light fallback without matchMedia and with blocked storage',()=>{assert.equal(setup({unavailable:true,blocked:true}).theme(),'light');});
test('invalid stored preference follows device',()=>{assert.equal(setup({saved:'invalid',dark:true}).theme(),'dark');});
test('saved manual preference overrides device',()=>{assert.equal(setup({saved:'light',dark:true}).theme(),'light');assert.equal(setup({saved:'dark'}).theme(),'dark');});
test('automatic mode follows device changes',()=>{const s=setup();s.change(true);assert.equal(s.theme(),'dark');s.change(false);assert.equal(s.theme(),'light');});
test('button persists choice and prevents device override',()=>{const s=setup();s.click();assert.equal(s.theme(),'dark');assert.equal(s.saved(),'dark');s.change(true);s.change(false);assert.equal(s.theme(),'dark');s.click();assert.equal(s.theme(),'light');});
test('manual selection works even if storage blocked',()=>{const s=setup({blocked:true});s.click();s.change(true);s.change(false);assert.equal(s.theme(),'dark');});
