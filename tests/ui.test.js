'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {JSDOM,VirtualConsole}=require('jsdom');
const C=require('../src/content.js');
const E=require('../src/engine.js');
const html=fs.readFileSync(path.join(__dirname,'../wazuhroom.html'),'utf8');
function setup(lang='en',saved){
 const errors=[];const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e));
 const dom=new JSDOM(html,{runScripts:'dangerously',url:'https://example.test/wazuhroom/',virtualConsole:vc,beforeParse(w){
  Object.defineProperty(w.navigator,'language',{value:lang});w.scrollTo=()=>{};w.HTMLElement.prototype.scrollIntoView=()=>{};
  w.HTMLDialogElement.prototype.showModal=function(){this.open=true;};w.HTMLDialogElement.prototype.close=function(){this.open=false;};
  w.URL.createObjectURL=()=> 'blob:mock';w.URL.revokeObjectURL=()=>{};w.HTMLAnchorElement.prototype.click=()=>{};
  if(saved)w.localStorage.setItem('wazuhroom.progress.v1',JSON.stringify(saved));
 }});
 const w=dom.window,d=w.document;
 const click=(selector)=>{const x=d.querySelector(selector);assert.ok(x,selector);assert.ok(!x.disabled,selector+' enabled');x.click();};
 const fill=(selector,value)=>{const x=d.querySelector(selector);assert.ok(x,selector);x.value=value;x.dispatchEvent(new w.Event('input',{bubbles:true}));x.dispatchEvent(new w.Event('change',{bubbles:true}));};
 const submit=id=>d.getElementById(id).dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));
 const savedState=()=>JSON.parse(w.localStorage.getItem('wazuhroom.progress.v1'));
 return {dom,w,d,click,fill,submit,savedState,errors};
}
for(const lang of ['ja','en'])test('all investigations can be completed through the '+lang+' UI',()=>{
 const u=setup(lang);const {click,fill,submit,d,savedState}=u;
 try{
 assert.equal(d.documentElement.lang,lang);assert.equal(d.querySelectorAll('.case-card').length,C.cases.length);
 for(const c of C.cases){
  click(`[data-action="case"][data-id="${c.id}"]`);
  click('[data-action="view"][data-view="events"]');submit('time-range');
  fill('#event-query','rule.level >= 3');submit('event-search');
  for(const id of c.answer.evidenceGroups.map(g=>g[0])){
   fill('#event-query',`id: "${id}"`);submit('event-search');
   assert.equal(d.getElementById('hit-count').textContent,'1');click(`[data-action="expand"][data-id="${id}"]`);click(`[data-action="evidence-add"][data-id="${id}"]`);
  }
  click('[data-action="coach-tab"][data-tab="refs"]');
  for(const id of c.answer.documentIds){click(`[data-action="document"][data-id="${id}"]`);assert.equal(d.getElementById('dialog').open,true);click('[data-action="close-dialog"]');}
  click('[data-action="coach-tab"][data-tab="report"]');
  submit('report-form');assert.equal(savedState().records[c.id].feedback.passed,false);
  for(const key of ['verdict','priority','action','target'])fill('#report-'+key,c.answer[key]);
  for(const q of c.questions||[])fill('#answer-'+q.id,q.acceptedAnswers[0]);
  fill('#report-facts',c.answer.facts[lang]);fill('#report-nextStep',c.answer.nextStep[lang]);submit('report-form');
  const r=savedState().records[c.id];assert.equal(r.completed,true,c.id);assert.equal(r.feedback.passed,true,c.id);assert.ok(r.completion);click('[data-action="home"]');
 }
 const restored=setup(lang,savedState());assert.equal(restored.d.querySelectorAll('.case-card .tag.green').length,C.cases.length);assert.equal(restored.errors.length,0);restored.dom.window.close();
 assert.equal(u.errors.length,0,u.errors.map(e=>e.message).join('\n'));
 }finally{u.dom.window.close();}
});
test('invalid search keeps applied rows; numeric chips and language changes preserve work',()=>{
 const u=setup('ja');const {click,fill,submit,d,savedState}=u;
 try{
 click('[data-action="case"][data-id="tutorial"]');click('[data-view="events"]');
 fill('#event-query','id: "tutorial-failure"');submit('event-search');click('[data-action="expand"][data-id="tutorial-failure"]');
 click('[data-action="field-filter"][data-field="rule.level"]');assert.equal(typeof savedState().records.tutorial.filters[0].value,'number');assert.equal(d.getElementById('hit-count').textContent,'1');
 fill('#event-query','rule.level >= nope');submit('event-search');assert.ok(d.querySelector('.error'));assert.equal(d.getElementById('hit-count').textContent,'1');
 fill('#range-from','2026-10-14T09:10');fill('#language','en');assert.equal(d.querySelector('#event-query').value,'rule.level >= nope');assert.equal(d.querySelector('#range-from').value,'2026-10-14T09:10');
 click('[data-action="coach-tab"][data-tab="report"]');fill('#report-facts','手入力した事実は言語変更で翻訳しません。');fill('#language','ja');assert.equal(d.querySelector('#report-facts').value,'手入力した事実は言語変更で翻訳しません。');
 assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});
test('agent WQL, empty search, FIM, column controls, and help work',()=>{
 const u=setup();const {click,fill,submit,d}=u;
 try{
 click('[data-action="case"][data-id="collection-gap"]');click('[data-view="agents"]');fill('#agent-query','status=disconnected');submit('agent-search');assert.equal(d.querySelectorAll('tbody tr').length,1);
 click('[data-action="agent-events"]');assert.ok(d.querySelector('.filter-chip'));assert.ok(Number(d.getElementById('hit-count').textContent)>0);
 fill('#event-query','agent.name: "does-not-exist"');submit('event-search');assert.equal(d.getElementById('hit-count').textContent,'0');assert.ok(d.querySelector('.empty'));
 click('[data-action="clear-search"]');click('[data-action="columns"]');d.querySelector('[data-column="rule.id"]').click();assert.equal(d.querySelectorAll('thead th').length,5);
 click('[data-action="search-help"]');assert.match(d.getElementById('dialog-body').textContent,/DQL/);click('[data-action="close-dialog"]');click('[data-action="home"]');
 click('[data-action="case"][data-id="fim-change"]');click('[data-view="fim"]');assert.equal(d.querySelectorAll('tbody tr[data-event]').length,2);assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});
test('distribution is identical, self-contained, and forbids network connections',()=>{
 assert.equal(html,fs.readFileSync(path.join(__dirname,'../docs/index.html'),'utf8'));
 assert.equal(html,fs.readFileSync(path.join(__dirname,'../docs/wazuhroom.html'),'utf8'));
 assert.match(html,/connect-src 'none'/);assert.doesNotMatch(html,/<script[^>]+src=|<link[^>]+href=|@import\s|url\(\s*https?:|\bfetch\(/i);
});

for(const lang of ['ja','en'])test('old seven-case completion loads with the new case unstarted in '+lang,()=>{
 const prior={...C,cases:C.cases.filter(c=>c.id!=='crypto-compromise')};
 assert.equal(prior.cases.length,7);
 const saved=E.createProgress(prior);saved.language=lang;
 for(const c of prior.cases){
  const r=saved.records[c.id];
  r.evidence=c.answer.evidenceGroups.map(g=>g[0]);r.documents=[...c.answer.documentIds];
  r.operations=c.steps.filter(s=>s.kind!=='report').map(s=>s.kind);
  for(const key of ['verdict','priority','action','target'])r.report[key]=c.answer[key];
  r.report.facts=c.answer.facts[lang];r.report.nextStep=c.answer.nextStep[lang];
  r.feedback=E.assess(c,r);assert.equal(r.feedback.passed,true);r.completed=true;
  r.completion=JSON.parse(JSON.stringify(r));
 }
 const u=setup(lang,saved);
 try{
  assert.equal(u.d.querySelectorAll('.case-card').length,8);
  assert.equal(u.d.querySelectorAll('.case-card .tag.green').length,7);
  const progress=u.d.querySelector('[role="progressbar"]');
  assert.equal(progress.getAttribute('aria-valuenow'),'7');assert.equal(progress.getAttribute('aria-valuemax'),'8');
  assert.ok(u.d.body.textContent.includes(lang==='ja'?'全8件':'8 exercises'));
  u.click('[data-action="case"][data-id="crypto-compromise"]');
  const updated=u.savedState();assert.equal(Object.keys(updated.records).length,8);
  assert.equal(updated.records['crypto-compromise'].completed,false);
  assert.equal(Object.values(updated.records).filter(r=>r.completed).length,7);
  assert.equal(u.errors.length,0);
  const restored=setup(lang,updated);
  try{assert.equal(restored.d.querySelectorAll('.case-card .tag.green').length,7);assert.equal(restored.errors.length,0);}finally{restored.dom.window.close();}
 }finally{u.dom.window.close();}
});

for(const lang of ['ja','en'])test('instructions reveal mixed-case requirements without hints in '+lang,()=>{
 const u=setup(lang);const {click,submit,d,savedState}=u;
 try{
 const c=C.cases.find(c=>c.id==='mixed-auth');
 click('[data-action="case"][data-id="mixed-auth"]');
 const instructions=[...d.querySelectorAll('.step-instruction')];
 assert.equal(instructions.length,c.steps.length);
 for(const step of c.steps)assert.ok(instructions.some(el=>el.textContent.includes(step.body[lang])));
 assert.match(d.querySelector('.coach-body').textContent,/web-01/);
 assert.match(d.querySelector('.coach-body').textContent,/EX-12/);
 assert.equal(savedState().records[c.id].hint,0);
 click('[data-action="coach-tab"][data-tab="refs"]');
 const requiredText=lang==='ja'?'提出に必要':'Required for submission';
 const required=[...d.querySelectorAll('.doc-button')].filter(el=>el.querySelector('.tag').textContent===requiredText);
 assert.deepEqual(required.map(el=>el.dataset.id).sort(),[...c.answer.documentIds].sort());
 click('[data-action="coach-tab"][data-tab="report"]');
 assert.match(d.querySelector('.coach-body h3').textContent,lang==='ja'?/選択 0 件 \/ 上限 5 件/:/Selected 0 \/ limit 5/);
 submit('report-form');
 assert.equal(savedState().records[c.id].feedback.passed,false);
 for(const id of c.answer.documentIds)assert.ok(d.querySelector('.missing-docs').textContent.includes(c.documents.find(doc=>doc.id===id).title[lang]));
 click('[data-action="show-model"]');
 assert.ok(d.querySelector('.coach-body').textContent.includes(c.answer.facts[lang]));
 assert.equal(savedState().records[c.id].completed,false);
 assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});

for(const lang of ['ja','en'])test('policy uses report labels and documented DQL examples work in '+lang,()=>{
 const u=setup(lang);const {click,d}=u;
 try{
 click('[data-action="case"][data-id="tutorial"]');
 click('[data-action="coach-tab"][data-tab="report"]');
 const labels=['verdict','priority','action'].flatMap(key=>[...d.querySelectorAll('#report-'+key+' option')].filter(option=>option.value).map(option=>option.textContent));
 for(const c of C.cases){
  const policy=c.documents.find(doc=>doc.id===c.id+'-runbook').body[lang];
  for(const label of labels)assert.ok(policy.includes(label),c.id+': '+label);
 }
 click('[data-action="help"]');
 const body=d.querySelector('#dialog-body');
 const allEvents=C.cases.flatMap(c=>c.events);
 for(const query of body.querySelector('.query-examples').textContent.split('\n'))assert.doesNotThrow(()=>E.search(allEvents,{query}));
 for(const query of body.querySelector('.path-examples').textContent.split('\n'))assert.ok(E.search(allEvents,{query}).length>0,query);
 assert.match(body.textContent,/data\.win\.eventdata\.logonType/);
 assert.match(body.textContent,/data\.srcport/);
 assert.match(body.textContent,lang==='ja'?/合否にかかわらず/:/whether it passes or fails/);
 assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});

for(const lang of ['ja','en'])test('webshell findings and offline decoding are usable and persisted in '+lang,()=>{
 const u=setup(lang);const {click,fill,submit,d,savedState}=u;
 try{
  const c=C.cases.find(c=>c.id==='crypto-compromise');
  const encodedEvent=c.events.find(e=>e.data.artifact?.encoded_content);
  assert.ok(encodedEvent);
  click('[data-action="case"][data-id="crypto-compromise"]');
  click('[data-action="view"][data-view="events"]');
  fill('#event-query',`id: "${encodedEvent.id}"`);submit('event-search');
  click(`[data-action="expand"][data-id="${encodedEvent.id}"]`);
  click('[data-action="decode-event"]');
  assert.equal(d.getElementById('base64-input').value,encodedEvent.data.artifact.encoded_content);
  assert.equal(d.getElementById('base64-output').textContent,'','decode requires a deliberate action');
  submit('base64-form');
  const decoded=E.decodeBase64Text(encodedEvent.data.artifact.encoded_content);
  assert.equal(d.getElementById('base64-output').textContent,decoded);
  assert.equal(d.getElementById('base64-error').hidden,true);
  assert.equal(savedState().records[c.id].report.answers.decodedText,'','utility does not answer for the learner');
  fill('#base64-input','%%% invalid');submit('base64-form');
  assert.equal(d.getElementById('base64-error').hidden,false);
  assert.equal(d.getElementById('base64-output').textContent,'','a failed decode clears stale output');
  const markup='<img src="x" onerror="window.decodeExecuted=true"><script>window.decodeExecuted=true</script>';
  fill('#base64-input',Buffer.from(markup).toString('base64'));submit('base64-form');
  assert.equal(d.getElementById('base64-output').textContent,markup);
  assert.equal(d.getElementById('base64-output').children.length,0,'decoded content stays inert text');
  assert.equal(u.w.decodeExecuted,undefined);
  click('[data-action="close-dialog"]');
  click('[data-action="coach-tab"][data-tab="report"]');
  for(const q of c.questions){assert.ok(d.querySelector('label[for="answer-'+q.id+'"]').textContent.includes(q.label[lang]));fill('#answer-'+q.id,q.acceptedAnswers[0]);}
  fill('#language',lang==='ja'?'en':'ja');
  for(const q of c.questions)assert.equal(d.getElementById('answer-'+q.id).value,q.acceptedAnswers[0]);
  const restored=setup(lang,savedState());
  try{
   restored.click('[data-action="case"][data-id="crypto-compromise"]');
   restored.click('[data-action="coach-tab"][data-tab="report"]');
   for(const q of c.questions)assert.equal(restored.d.getElementById('answer-'+q.id).value,q.acceptedAnswers[0]);
   restored.fill('#answer-webshellPath','/incorrect/path.php');restored.submit('report-form');
   const state=restored.savedState().records[c.id];
   assert.equal(state.feedback.checks.find(x=>x.key==='question:webshellPath').passed,false);
   assert.equal(state.feedback.checks.find(x=>x.key==='question:webshellUri').passed,true);
   assert.equal(state.completed,false);
   assert.ok(restored.d.querySelector('.checks .no'));
   assert.equal(restored.errors.length,0);
  }finally{restored.dom.window.close();}
  assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});

test('revised crypto case preserves an earlier submission visibly without claiming completion',()=>{
 const legacy=JSON.parse(JSON.stringify(C));
 const c=legacy.cases.find(c=>c.id==='crypto-compromise');
 delete c.revision;delete c.questions;
 c.answer.evidenceGroups=c.answer.evidenceGroups.filter(g=>!g.some(id=>id.endsWith('-webpost')||id.endsWith('-file')));
 c.answer.documentIds=c.answer.documentIds.filter(id=>!id.endsWith('-webroot'));
 const saved=E.createProgress(legacy);saved.language='en';
 const r=saved.records[c.id];r.evidence=c.answer.evidenceGroups.map(g=>g[0]);r.documents=[...c.answer.documentIds];
 r.operations=c.steps.map(s=>s.kind);
 for(const key of ['verdict','priority','action','target'])r.report[key]=c.answer[key];
 r.report.facts='Earlier review submission retained for comparison.';r.report.nextStep='Earlier next checks and handover retained.';
 r.feedback=E.assess(c,r);assert.equal(r.feedback.passed,true);r.completed=true;r.completion=JSON.parse(JSON.stringify(r));
 const u=setup('en',saved);
 try{
  u.click('[data-action="case"][data-id="crypto-compromise"]');
  assert.ok(u.d.querySelector('.coach-body').textContent.includes('Webshell and Base64 questions have been added'));
  assert.equal(u.savedState().records[c.id].completed,false);
  u.click('[data-action="coach-tab"][data-tab="report"]');
  assert.ok(u.d.querySelector('.previous-submission').textContent.includes(r.report.facts));
  assert.equal(u.d.getElementById('report-facts').value,r.report.facts);
  assert.equal(u.d.getElementById('answer-decodedText').value,'');
  assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});


test('view navigation focuses content and search rerenders preserve input and caret',()=>{
 const u=setup('ja');
 try{
  u.click('[data-action="case"][data-id="tutorial"]');
  const view=u.d.querySelector('[data-view="events"]');view.focus();view.click();
  assert.ok(u.d.querySelector('main').contains(u.d.activeElement));
  const input=u.d.querySelector('#event-query');input.focus();u.fill('#event-query','rule.level >= 3');input.setSelectionRange(4,7);
  u.submit('event-search');
  assert.equal(u.d.activeElement.id,'event-query');
  assert.equal(u.d.activeElement.selectionStart,4);assert.equal(u.d.activeElement.selectionEnd,7);
  u.click('[data-action="search-help"]');
  const dialog=u.d.querySelector('dialog');
  assert.ok(u.d.getElementById(dialog.getAttribute('aria-labelledby')).textContent.trim());
  assert.equal(u.errors.length,0);
 }finally{u.dom.window.close();}
});
