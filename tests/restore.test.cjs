const {test}=require('node:test');const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');
const source=fs.readFileSync('static/ui.js','utf8').split('const restoreProgress = ')[1];
function harness(responses) {
 const timers=[],redirects=[],message={};
 const element={dataset:{job:'abc',statusUrl:'/admin/backups/restore/status',dashboardUrl:'/admin/'},querySelector:()=>message};
 const context={Date,document:{documentElement:{lang:'en'},querySelector:selector=>selector==='[data-restore-progress]'?element:null,querySelectorAll:()=>[]},window:{location:{replace:u=>redirects.push(u)}},setTimeout:fn=>timers.push(fn),fetch:async()=>{
  const next=responses.shift();if(next instanceof Error)throw next;
  return {ok:true,redirected:false,headers:{get:()=> 'application/json'},json:async()=>next};
 }};
 vm.runInNewContext('const restoreProgress = '+source,context);
 return {timers,redirects,message,tick:async()=>{const next=timers.shift();assert.ok(next);await next();}};
}
test('restore tolerates downtime and only redirects on matching completion',async()=>{
 const h=harness([new Error('offline'),{job_id:'abc',status:'running'},{job_id:'abc',status:'completed'}]);
 await h.tick();assert.equal(h.redirects.length,0);await h.tick();assert.equal(h.redirects.length,0);await h.tick();assert.deepEqual(h.redirects,['/admin/']);assert.equal(h.timers.length,0);
});
test('different job never triggers a success refresh',async()=>{
 const h=harness([{job_id:'other',status:'completed'}]);await h.tick();assert.equal(h.redirects.length,0);assert.equal(h.timers.length,1);
});
test('failure stops polling and never reports success',async()=>{
 const h=harness([{job_id:'abc',status:'failed'}]);await h.tick();assert.equal(h.redirects.length,0);assert.equal(h.timers.length,0);assert.match(h.message.textContent,/Restore failed/);
});
