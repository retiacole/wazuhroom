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
for(const lang of ['ja','en'])test('all seven investigations can be completed through the '+lang+' UI',()=>{
 const u=setup(lang);const {click,fill,submit,d,savedState}=u;
 try{
 assert.equal(d.documentElement.lang,lang);assert.equal(d.querySelectorAll('.case-card').length,7);
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
  fill('#report-facts',c.answer.facts[lang]);fill('#report-nextStep',c.answer.nextStep[lang]);submit('report-form');
  const r=savedState().records[c.id];assert.equal(r.completed,true,c.id);assert.equal(r.feedback.passed,true,c.id);assert.ok(r.completion);click('[data-action="home"]');
 }
 const restored=setup(lang,savedState());assert.equal(restored.d.querySelectorAll('.case-card .tag.green').length,7);assert.equal(restored.errors.length,0);restored.dom.window.close();
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
