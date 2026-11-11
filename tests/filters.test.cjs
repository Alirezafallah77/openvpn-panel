const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync('static/ui.js','utf8').split('// Keep explicit search/Enter')[1];
function harness({present=true,dialog=false}={}) {
  const keys={},events={},selects=[{},{}];let submitted=0,focused=0,selected=0,prevented=0;
  const search={focus(){focused++;},select(){selected++;}};
  const form={querySelector:()=>search,querySelectorAll:()=>selects,requestSubmit(){submitted++;},setAttribute(k,v){this[k]=v;},removeAttribute(k){delete this[k];},addEventListener(k,v){events[k]=v;}};
  selects.forEach(s=>s.addEventListener=(k,v)=>s[k]=v);
  const context={window:{addEventListener(k,v){events[k]=v;}},document:{querySelector:s=>s==='[data-user-filters]'?(present?form:null):(dialog?{}:null),addEventListener(k,v){keys[k]=v;}}};
  vm.runInNewContext('// Keep explicit search/Enter'+source,context);
  return {form,events,selects,counts:()=>({submitted,focused,selected,prevented}),key(overrides={}){keys.keydown?.({key:'/',target:{closest:()=>null},preventDefault(){prevented++;},...overrides});}};
}
test('status and page-size apply GET filters; loading state resets on history navigation',()=>{
 const h=harness();h.selects[0].change();h.selects[1].change();assert.equal(h.counts().submitted,2);
 h.events.submit();assert.equal(h.form['aria-busy'],'true');h.events.pageshow();assert.equal(h.form['aria-busy'],undefined);
});
test('slash focuses/selects search without submitting',()=>{
 const h=harness();h.key();assert.deepEqual(h.counts(),{submitted:0,focused:1,selected:1,prevented:1});
});
test('slash never steals input, shortcuts, IME or an open dialog',()=>{
 const h=harness();for(const override of [{ctrlKey:true},{metaKey:true},{altKey:true},{isComposing:true},{target:{closest:()=>({})}},{key:'a'}])h.key(override);
 assert.equal(h.counts().focused,0);const modal=harness({dialog:true});modal.key();assert.equal(modal.counts().focused,0);
});
test('other pages need no filter form',()=>assert.doesNotThrow(()=>harness({present:false})));
