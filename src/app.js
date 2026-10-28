(function () {
  'use strict';
  const C = window.WazuhContent, E = window.WazuhEngine;
  const STORE = 'wazuhroom.progress.v1';
  const app = document.getElementById('app'), dialog = document.getElementById('dialog');
  const UI = {
    concept:['WazuhをつかったSOC業務の基本フローと操作方法を体験するコンテンツ','Experience the basic SOC workflow and operations using Wazuh'],
    intro:['アラートを確認し、ログを調べ、根拠をもとに判断して報告する。Wazuhに近い画面で、SOCの一次調査を一つずつ練習します。','Review alerts, investigate logs, make evidence-based decisions, and report your findings. Practice initial SOC investigations in a Wazuh-style workspace.'],
    simulation:['非公式の学習シミュレーター','Unofficial learning simulator'],
    offline:['ブラウザだけ・オフライン対応','Browser only · Works offline'],
    home:['演習一覧','Exercises'],save:['保存','Save'],load:['読込','Load'],help:['使い方','Help'],close:['閉じる','Close'],cancel:['キャンセル','Cancel'],apply:['適用','Apply'],clear:['解除','Clear'],start:['始める','Start'],resume:['続きから','Continue'],review:['復習する','Review'],completed:['完了','Complete'],notStarted:['未開始','Not started'],progress:['学習の進み具合','Your progress'],
    tutorial:['操作チュートリアル','Interface tutorial'],guided:['ガイド付き調査','Guided investigation'],checklist:['チェックリスト調査','Checklist investigation'],independent:['自力で調査','Independent investigation'],
    workflow:['SOCの基本フロー','The SOC workflow'],triage:['アラート確認','Triage'],investigate:['調査','Investigate'],decide:['判断','Decide'],report:['報告','Report'],
    homeNote:['全7件・時間制限なし。どの演習からでも始められます。ヒントによる減点はありません。','7 exercises, no time limits. Start anywhere. Hints do not reduce your score.'],
    limit:['Wazuh 4.14系の画面・用語を参考にした独自教材です。実際のWazuhや端末には接続しません。画面と検索は学習用の範囲に限定しており、実機との完全な一致は保証しません。','An original educational simulation based on Wazuh 4.14 interface concepts. It does not connect to Wazuh or real endpoints. Screens and search support a teaching subset, not complete product compatibility.'],
    synthetic:['合成ログ・教材用カスタムルール・演習時刻はUTC','Synthetic logs · Custom teaching rules · Exercise time: UTC'],
    optional:['roomシリーズの任意教材です。メインの学習順には含めません。','An optional room-series project, outside the main learning path.'],
    overview:['概要','Overview'],agents:['エージェント','Agents'],threat:['脅威の調査','Threat hunting'],fim:['ファイル変更の調査','File changes'],
    exercise:['演習','Exercise'],training:['学習パネル','Learning panel'],task:['依頼','Task'],refs:['資料','References'],evidence:['証拠','Evidence'],
    events:['イベント','Events'],hits:['件のイベント','events'],allEvents:['演習内の全イベント','All exercise events'],highAlerts:['レベル10以上','Level 10 or above'],activeAgents:['接続中のエージェント','Active agents'],
    overviewSub:['演習データの状況を確認し、調査する画面へ進みます。','Review this exercise environment, then open an investigation view.'],
    eventsSub:['期間・検索式・フィルターを組み合わせて調べます。','Investigate using the time range, search query, and filters.'],
    agentsSub:['状態と最終通信を確認し、その端末のイベントへ進みます。','Check status and last keep-alive, then investigate the endpoint events.'],
    fimSub:['監視対象ファイルの変更イベント。すべてのファイルを監視しているわけではありません。','Change events for monitored files. Not every file is monitored.'],
    from:['開始（UTC）','From (UTC)'],to:['終了（UTC）','To (UTC)'],fullRange:['演習の全期間','Full exercise range'],search:['検索','Search'],searchHelp:['検索の対応範囲','Search reference'],addFilter:['フィルターを追加','Add filter'],removeFilters:['条件をすべて解除','Clear all conditions'],
    field:['フィールド','Field'],value:['値','Value'],exclude:['除外する','Exclude matches'],filter:['絞り込む','Filter for value'],filterOut:['除外する','Filter out value'],toggle:['有効・無効の切替','Enable or disable'],remove:['削除','Remove'],
    time:['時刻','Time'],agent:['エージェント','Agent'],description:['説明','Description'],level:['レベル','Level'],details:['詳細','Details'],original:['元のログ','Original log'],addEvidence:['証拠に追加','Add evidence'],added:['証拠に登録済み','Evidence added'],
    columns:['表示する列','Displayed columns'],prev:['前へ','Previous'],next:['次へ','Next'],empty:['該当するイベントはありません。期間や条件を確認してください。','No matching events. Check the time range and filters.'],
    agentEmpty:['一致するエージェントはありません。検索条件を確認してください。','No matching agents. Check your query.'],
    searchError:['検索式を適用できません。フィールド名、演算子、引用符、対応構文を確認してください。直前の適用済み結果を表示しています。','Unable to apply the query. Check field names, operators, quotes, and supported syntax. The previous results are preserved.'],
    rangeError:['正しいUTCの開始・終了日時を指定してください。開始は終了より前にします。','Enter valid UTC start and end times. Start must be before end.'],
    chart:['時間ごとのイベント数','Events over time'],chartHint:['棒を押すとその期間に絞ります。','Select a bar to narrow the time range.'],
    status:['状態','Status'],os:['OS','Operating system'],keepAlive:['最終通信（UTC）','Last keep-alive (UTC)'],viewEvents:['イベントを調べる','Investigate events'],
    learnNext:['次の操作','Next operation'],goStep:['操作する場所へ','Go to this control'],checked:['実施済み','Performed'],notChecked:['未実施','Not performed'],
    checkNote:['チェックは操作の実施を表します。判断の正しさは報告提出時に確認します。','Checks record performed operations. Decisions are checked when you submit the report.'],
    hint:['ヒント','Hint'],nextHint:['次のヒント','Next hint'],noHints:['ヒントはここまでです。資料と証拠を見直しましょう。','No more hints. Review the references and evidence.'],
    refNote:['資料を開き、収集範囲や承認内容をログと照合してください。','Open references and compare collection coverage and approved changes with the logs.'],
    read:['確認済み','Opened'],unread:['未確認','Not opened'],evidenceNote:['必要なイベントを絞って残します。資料は「資料」タブで確認します。','Keep a focused selection of events. Review documents in the References tab.'],
    noEvidence:['まだ証拠がありません。イベントの詳細を開いて追加できます。','No evidence yet. Expand an event to add it.'],
    verdict:['判定','Verdict'],priority:['優先度','Priority'],action:['次の対応','Next action'],target:['主な対象','Primary target'],select:['選択してください','Choose an option'],
    incident:['インシデント','Incident'],benign:['正当な活動','Benign activity'],unknown:['判断保留','Insufficient evidence'],high:['高','High'],medium:['中','Medium'],low:['低','Low'],escalate:['担当へエスカレーション','Escalate to the responsible team'],monitor:['監視を継続','Continue monitoring'],verify:['追加確認を依頼','Request verification'],
    facts:['確認した事実と根拠','Observed facts and evidence'],nextStep:['未確認事項・引継ぎ先・次の確認','Unknowns, recipient, and next checks'],factsPlaceholder:['対象・時刻・証拠IDを挙げて、分かったことを記録します。','Record findings with the target, time, and evidence IDs.'],nextPlaceholder:['分からないこと、誰に何を確認してもらうかを書きます。','State unknowns and who should check what next.'],
    structural:['自由記述は10〜4000文字で、文字数のみ確認します。意味・正確さは自動採点しません。提出後に報告例と比較してください。','Free text requires 10–4,000 characters and is checked for length only, not meaning or accuracy. Compare your writing with the example after submission.'],
    submit:['調査報告を提出','Submit investigation report'],passed:['調査を完了しました','Investigation complete'],tryAgain:['確認が必要な項目があります','Some items need another look'],
    evidenceLimit:['証拠を絞る','Focused evidence selection'],documents:['必要な資料の確認','Required references'],operations:['調査操作の実施','Investigation operations'],
    result:['提出結果','Submission result'],model:['報告例と振り返り','Example report and reflection'],showModel:['報告例を開く','Open example report'],modelNote:['自分の報告と比べ、事実・推測・未確認事項を区別してください。','Compare your report, distinguishing facts, inferences, and unknowns.'],exportReport:['報告を書き出す','Export report'],nextCase:['次の演習へ','Next exercise'],
    saved:['進捗を保存しました。','Progress exported.'],autosaveFail:['自動保存を利用できません。「保存」で進捗ファイルを残してください。','Auto-save is unavailable. Use Save to export your progress.'],
    savedBad:['保存済みデータを読み込めませんでした。元のデータは変更していません。「読込」でバックアップを復元できます。','Saved data could not be loaded. It was left unchanged. Use Load to restore a backup.'],
    loaded:['進捗を読み込みました。','Progress imported.'],invalidFile:['この進捗ファイルは読み込めません。Wazuhroomの有効な保存ファイルを選んでください。現在の進捗は変更していません。','Unable to import this file. Choose a valid Wazuhroom save. Current progress is unchanged.'],
    importTitle:['進捗を置き換えますか','Replace current progress?'],importNote:['現在の進捗をバックアップしてから、選んだファイルに置き換えます。ブラウザのダウンロード許可を確認してください。','Export a backup of your current progress, then replace it with the selected file. Check your browser download permissions.'],backup:['現在の進捗をバックアップ','Back up current progress'],replace:['読み込んで置き換える','Import and replace'],
    helpIntro:['まず操作チュートリアルから始めます。左のメニューで画面を移動し、右の学習パネルで依頼・資料・報告を確認します。','Start with the interface tutorial. Use the left menu for investigation views and the right learning panel for the task, references, and report.'],
    helpSave:['言語変更や演習の移動で進捗は失われません。保存先が変わる場合は「保存」でJSONを出力し、「読込」で復元します。ローカルHTMLの自動保存はブラウザにより異なります。','Switching language or exercises preserves progress. Export JSON with Save and restore with Load when changing location or browser. Auto-save for local HTML varies by browser.'],
    helpScope:['この教材の目的は一次調査の操作と考え方です。Wazuhの導入、エージェント登録、任意ルールの評価、実端末への対応は実行しません。','This lab teaches initial investigation operations and reasoning. It does not install Wazuh, enroll agents, evaluate arbitrary rules, or perform actions on real endpoints.'],
    helpDql:['イベント検索はフィールド指定のDQLサブセットです。:、数値比較、AND / OR / NOT、括弧、存在確認、キーワードの * に対応します。自由文検索・Lucene・正規表現・入れ子構文は未対応です。text型は学習用の部分一致で、実機の全文解析とは異なります。','Event search supports a field-based DQL subset: :, numeric comparisons, AND / OR / NOT, parentheses, existence, and keyword wildcards *. Free-text, Lucene, regex, and nested syntax are not supported. Text fields use teaching substring matching, not the real full-text analyzer.'],
    helpWql:['エージェント検索はWQLの =、!=、~、>、<、and / or、括弧に対応します。and / or は小文字です。ワイルドカードは使いません。','Agent search supports WQL =, !=, ~, >, <, and / or, and parentheses. Use lowercase and / or. Wildcards are not supported.'],
    localTime:['演習のログ時刻は固定です。「全期間」で教材の時間帯へ戻れます。端末の現在時刻とは連動しません。','Exercise timestamps are fixed. Full exercise range restores the scenario window; it does not follow your current device time.'],
    noTimer:['時間制限なし','No time limit'],completedAll:['全演習を完了しました。別の条件でも検索し、調査の手順を復習できます。','All exercises complete. Try different searches and revisit the investigation workflow.'],
    fieldCount:['フィールド一覧','Available fields'],openReport:['報告をまとめる','Prepare report'],agentScope:['このエージェントで絞り込みました。','Filtered by this agent.'],evidenceMax:['証拠は必要なものに絞ってください。','Keep evidence focused on what is needed.'],download:['オフライン用HTML','Offline HTML'],source:['ソース・説明','Source & guide'],utc:['すべてUTC','All times UTC']
  };
  let progress = E.createProgress(C), home = true, tab = 'task', page = 0, agentQuery = '', agentDraft = '', queryDraft = '', fromDraft = '', toDraft = '', searchError = '', modelOpen = false, columnsOpen = false;
  const detailOpen = {};
  let cols = ['timestamp','agent.name','rule.description','rule.level','rule.id'];
  let noticeTimer, pendingImport = null, importBackedUp = false, startupWarning = '', storageBlocked = false;
  const esc = value => String(value == null ? '' : value).replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
  const t = key => UI[key] ? UI[key][progress.language === 'ja' ? 0 : 1] : key;
  const tx = value => typeof value === 'string' ? value : value?.[progress.language] || '';
  const active = () => C.cases.find(x => x.id === progress.activeCaseId);
  const record = () => progress.records[progress.activeCaseId];
  const clone = value => JSON.parse(JSON.stringify(value));
  const time = value => value.replace('T',' ').replace(/\.\d{3}Z$/,'').replace(/Z$/,'');
  const dt = value => value.slice(0,19);
  const btn = (action, label, cls='', attrs='') => `<button type="button" class="${cls}" data-action="${action}" ${attrs}>${esc(label)}</button>`;
  const completedCount = () => C.cases.filter(c => progress.records[c.id].completed).length;
  function saveLocal() {
    if (storageBlocked) return;
    try { localStorage.setItem(STORE, JSON.stringify(progress)); }
    catch (_) { storageBlocked = true; notify(t('autosaveFail')); }
  }
  try {
    const saved = localStorage.getItem(STORE);
    if (saved) progress = E.validateProgress(JSON.parse(saved), C);
    else progress.language = (navigator.language || 'en').toLowerCase().startsWith('ja') ? 'ja' : 'en';
  } catch (_) { startupWarning = 'savedBad'; storageBlocked = true; progress.language = (navigator.language || '').startsWith('ja') ? 'ja' : 'en'; }
  queryDraft = record().query;fromDraft=dt(record().from);toDraft=dt(record().to);
  function notify(message) { const el=document.getElementById('notice');el.textContent=message;el.classList.add('show');clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>el.classList.remove('show'),6000); }
  function op(kind) { const r=record(); if (!r.operations.includes(kind)) r.operations.push(kind); }
  function syncDraft() {
    const q=document.getElementById('event-query'); if(q) queryDraft=q.value;
    const a=document.getElementById('agent-query'); if(a) agentDraft=a.value;
    const f=document.getElementById('range-from'),z=document.getElementById('range-to');if(f)fromDraft=f.value;if(z)toDraft=z.value;
    document.querySelectorAll('[data-detail-key]').forEach(el=>{detailOpen[el.dataset.detailKey]=el.open;});
    document.querySelectorAll('[data-report]').forEach(el=>{record().report[el.dataset.report]=el.value;});
  }
  function header() {
    return `<header class="topbar">${btn('home','', 'brand', 'aria-label="Wazuhroom"').replace('</button>', '<span class="brand-icon" aria-hidden="true">W</span><span><strong>Wazuhroom</strong><br><span class="version">v'+esc(document.body.dataset.version)+' · '+esc(t('simulation'))+'</span></span></button>')}<div class="top-actions"><label for="language" class="sr-only" hidden>Language</label><select id="language" aria-label="Language"><option value="ja" ${progress.language==='ja'?'selected':''}>日本語</option><option value="en" ${progress.language==='en'?'selected':''}>English</option></select>${btn('save',t('save'),'small')}${btn('load',t('load'),'small')}${btn('help',t('help'),'small')}</div></header>`;
  }
  function renderHome() {
    const count=completedCount();
    return `<main class="home" id="main" tabindex="-1"><section class="hero"><div><div class="eyebrow">WAZUHROOM / SOC WORKFLOW LAB</div><h1>${esc(t('concept'))}</h1><p>${esc(t('intro'))}</p><div class="flow"><span class="tag blue">${esc(t('offline'))}</span><span class="tag">日本語 / English</span><span class="tag">${esc(t('noTimer'))}</span></div></div><aside class="hero-note"><strong>${esc(t('workflow'))}</strong><div class="flow"><span>01 ${esc(t('triage'))}</span>→<span>02 ${esc(t('investigate'))}</span>→<span>03 ${esc(t('decide'))}</span>→<span>04 ${esc(t('report'))}</span></div></aside></section><div class="section-line"><h2>${esc(t('exercise'))}</h2><span class="muted">${esc(t('progress'))} <strong>${count} / ${C.cases.length}</strong></span></div><div class="progressline" role="progressbar" aria-label="${esc(t('progress'))}" aria-valuenow="${count}" aria-valuemax="${C.cases.length}" aria-valuemin="0"><i style="width:${count/C.cases.length*100}%"></i></div><p class="footer-note">${esc(t('homeNote'))}</p>${count===C.cases.length?`<div class="success">${esc(t('completedAll'))}</div>`:''}<div class="case-grid">${C.cases.map((c,i)=>{const r=progress.records[c.id],begun=r.operations.length>0;return `<article class="case-card ${c.stage==='tutorial'?'tutorial':''}"><div><div class="card-meta"><span class="tag ${c.stage==='tutorial'?'blue':''}">${String(i).padStart(2,'0')} · ${esc(t(c.stage))}</span>${r.completed?`<span class="tag green">✓ ${esc(t('completed'))}</span>`:''}</div><h3>${esc(tx(c.title))}</h3><p>${esc(tx(c.brief))}</p></div>${btn('case',t(r.completed?'review':begun?'resume':'start'),'primary',`data-id="${esc(c.id)}"`)}</article>`;}).join('')}</div><footer class="home-footer"><p>${esc(t('limit'))}</p><p>${esc(t('optional'))}</p><a href="https://github.com/retiacole/wazuhroom" target="_blank" rel="noopener">${esc(t('source'))}</a><a href="https://github.com/retiacole/wazuhroom/blob/main/wazuhroom.html" target="_blank" rel="noopener">${esc(t('download'))}</a><p class="footer-note">Created with AI assistance from OpenAI Codex. · MIT License</p></footer></main>`;
  }
  const viewNames={overview:'Overview',agents:'Endpoints',events:'Threat Hunting',fim:'File Integrity Monitoring'};
  function renderLab() {
    const c=active(),r=record();
    return `<div class="lab-layout"><nav class="sidebar" aria-label="Wazuh-style navigation"><div class="sidebar-label">Dashboards</div>${[['overview','◫','Overview'],['agents','▤','Endpoints'],['events','⌕','Threat Hunting'],['fim','▧','File Integrity Monitoring']].map(([v,icon,label])=>btn('view',label,`nav-btn ${r.view===v?'active':''}`,`data-view="${v}" ${r.view===v?'aria-current="page"':''}`).replace(esc(label),`<span class="nav-icon" aria-hidden="true">${icon}</span>${esc(label)}`)).join('')}<div class="sidebar-label">Wazuhroom</div>${btn('home',t('home'),'nav-btn')}<div class="sidebar-bottom">${esc(t('simulation'))}<br>Wazuh 4.14 reference<br>${esc(t('synthetic'))}</div></nav><div class="workspace"><div class="crumb">Wazuhroom <span>›</span> <strong>${esc(viewNames[r.view])}</strong><span> / ${esc(t('exercise'))} ${C.cases.indexOf(c)}</span></div><div class="mobile-note"><a href="#learning-panel">${esc(t('training'))} ↓</a><a href="#main">${esc(t('investigate'))}</a></div><div class="work-grid"><main class="analysis" id="main" tabindex="-1">${r.view==='overview'?renderOverview():r.view==='agents'?renderAgents():renderEvents()}</main>${renderCoach()}</div></div></div>`;
  }
  function renderOverview() {
    const c=active(),high=c.events.filter(e=>e.rule.level>=10).length,connected=c.agents.filter(a=>a.status==='active').length;
    return `<div class="page-head"><div><h1>Overview</h1><p>${esc(t('overviewSub'))}</p></div><span class="tag">${esc(t('utc'))}</span></div><div class="stats"><div class="stat"><span>${esc(t('allEvents'))}</span><strong>${c.events.length}</strong></div><div class="stat alert"><span>${esc(t('highAlerts'))}</span><strong>${high}</strong></div><div class="stat good"><span>${esc(t('activeAgents'))}</span><strong>${connected} / ${c.agents.length}</strong></div></div><section class="panel"><div class="panel-head"><h2>Agents status</h2>${btn('view','Endpoints →','quiet small','data-view="agents"')}</div><div class="panel-content donut-row"><div class="donut" style="background:conic-gradient(#00847c 0 ${connected/c.agents.length*100}%,#bd3b39 ${connected/c.agents.length*100}% 100%)"><i>${c.agents.length}</i></div><div class="legend"><span class="status">Active <b>${connected}</b></span><br><span class="status disconnected">Disconnected <b>${c.agents.length-connected}</b></span><br><small>${esc(time(c.timeRange.to))} UTC</small></div></div></section><div class="module-grid"><button class="module-card" data-action="view" data-view="events"><strong>Threat Hunting →</strong><span>${esc(t('eventsSub'))}</span></button><button class="module-card" data-action="view" data-view="fim"><strong>File Integrity Monitoring →</strong><span>${esc(t('fimSub'))}</span></button></div><div class="info" style="margin-top:18px">${esc(t('localTime'))}</div><p class="footer-note">${esc(t('synthetic'))}</p>`;
  }
  function renderAgents() {
    const c=active();let list;try{list=E.searchAgents(c.agents,agentQuery);}catch(_){list=c.agents;}
    return `<div class="page-head"><div><h1>Endpoints</h1><p>${esc(t('agentsSub'))}</p></div></div><section class="panel"><div class="panel-head"><h2>Agents (${list.length})</h2>${btn('search-help','WQL ?','quiet small')}</div><div class="panel-content"><form id="agent-search" class="searchbar"><input id="agent-query" aria-label="WQL query" placeholder="status=active" value="${esc(agentDraft)}" maxlength="2000"><span class="search-type">WQL</span><button class="primary" type="submit">${esc(t('search'))}</button></form>${searchError?`<div class="error" role="alert">${esc(t(searchError))}</div>`:''}<div class="table-scroll"><table><thead><tr><th>ID</th><th>Name</th><th>IP address</th><th>${esc(t('os'))}</th><th>${esc(t('status'))}</th><th>${esc(t('keepAlive'))}</th><th></th></tr></thead><tbody>${list.map(a=>`<tr><td>${esc(a.id)}</td><td><strong>${esc(a.name)}</strong></td><td class="mono">${esc(a.ip)}</td><td>${esc(a.os.name)} ${esc(a.os.version)}</td><td><span class="status ${a.status==='disconnected'?'disconnected':''}">${esc(a.status)}</span></td><td class="mono">${esc(time(a.lastKeepAlive))}</td><td>${btn('agent-events',t('viewEvents'),'quiet small',`data-id="${esc(a.id)}"`)}</td></tr>`).join('')}</tbody></table>${!list.length?`<div class="empty">${esc(t('agentEmpty'))}</div>`:''}</div></div></section><p class="footer-note">${esc(t('helpWql'))}</p>`;
  }
  function filtered() { const r=record();return E.search(active().events,{query:r.query,filters:r.filters,from:r.from,to:r.to,module:r.view==='fim'?'fim':'events'}); }
  function chartHtml(events) {
    const r=record(),start=Date.parse(r.from),end=Date.parse(r.to),width=Math.max(1,(end-start)/12),bins=Array(12).fill(0);
    events.forEach(e=>{const i=Math.min(11,Math.max(0,Math.floor((Date.parse(e.timestamp)-start)/width)));bins[i]++;});
    const max=Math.max(1,...bins);
    return `<div class="chart-title"><h3>${esc(t('chart'))}</h3><small>${esc(t('chartHint'))}</small></div><div class="chart">${bins.map((n,i)=>`<button type="button" data-action="chart-range" data-from="${new Date(start+i*width).toISOString()}" data-to="${new Date(i===11?end:start+(i+1)*width-1).toISOString()}" style="height:${Math.max(2,n/max*77)}px" aria-label="${esc(time(new Date(start+i*width).toISOString()))} UTC: ${n}"><span>${n||''}</span></button>`).join('')}</div><div class="chart-axis"><span>${esc(time(r.from))}</span><span>${esc(time(r.to))} UTC</span></div>`;
  }
  function fieldRows(event) {
    const rows=[];
    function flatten(obj,prefix=''){Object.entries(obj).forEach(([k,v])=>{const key=prefix?prefix+'.'+k:k;if(v&&typeof v==='object'&&!Array.isArray(v))flatten(v,key);else rows.push([key,Array.isArray(v)?v.join(', '):v]);});}flatten(event);
    return rows.filter(([k])=>k!=='full_log').map(([k,v])=>`<div>${esc(k)}</div><div>${esc(v)}</div><div>${E.FIELD_TYPES[k]&& !Array.isArray(E.get(event,k))?`${btn('field-filter','+','','data-field="'+esc(k)+'" data-value="'+esc(v)+'" title="'+esc(t('filter'))+'" aria-label="'+esc(t('filter')+' '+k)+'"')}${btn('field-exclude','−','','data-field="'+esc(k)+'" data-value="'+esc(v)+'" title="'+esc(t('filterOut'))+'" aria-label="'+esc(t('filterOut')+' '+k)+'"')}`:''}</div>`).join('');
  }
  function detailHtml(e) {
    const has=record().evidence.includes(e.id);
    return `<div class="event-detail"><div class="detail-tabs"><h3>${esc(t('details'))} <code>${esc(e.id)}</code></h3>${btn('evidence-add',t(has?'added':'addEvidence'),has?'small':'primary small',`data-id="${esc(e.id)}" ${has?'disabled':''}`)}</div><div class="fields">${fieldRows(e)}</div><details data-detail-key="${esc(e.id)}:json" ${detailOpen[e.id+':json']?'open':''}><summary>JSON</summary><pre>${esc(JSON.stringify(e,null,2))}</pre></details><details data-detail-key="${esc(e.id)}:raw" ${detailOpen[e.id+':raw']?'open':''}><summary>${esc(t('original'))} · full_log</summary><pre>${esc(e.full_log)}</pre></details></div>`;
  }
  function renderEvents() {
    const c=active(),r=record(),events=filtered().sort((a,b)=>b.timestamp.localeCompare(a.timestamp)||a.id.localeCompare(b.id));
    const pageSize=15,pages=Math.max(1,Math.ceil(events.length/pageSize));page=Math.min(page,pages-1);
    const current=events.slice(page*pageSize,(page+1)*pageSize),fim=r.view==='fim';
    const labels={'timestamp':t('time'),'agent.name':t('agent'),'rule.description':t('description'),'rule.level':t('level'),'rule.id':'Rule ID','syscheck.path':'Path'};
    const activeCols=fim?[...cols.filter(x=>x!=='rule.description'),'syscheck.path']:cols;
    return `<div class="page-head"><div><h1>${fim?'File Integrity Monitoring':'Threat Hunting'}</h1><p>${esc(t(fim?'fimSub':'eventsSub'))}</p></div>${btn('search-help',t('searchHelp'),'quiet small')}</div><form id="event-search" class="searchbar"><input id="event-query" aria-label="DQL query" placeholder='agent.name: "web-01" and rule.level >= 5' maxlength="2000" value="${esc(queryDraft)}"><span class="search-type">DQL</span><button type="submit" class="primary">${esc(t('search'))}</button></form><form id="time-range" class="timebar"><div><label for="range-from">${esc(t('from'))}</label><input id="range-from" type="datetime-local" step="1" value="${esc(fromDraft)}" required></div><div><label for="range-to">${esc(t('to'))}</label><input id="range-to" type="datetime-local" step="1" value="${esc(toDraft)}" required></div><button type="submit">${esc(t('apply'))}</button>${btn('full-range',t('fullRange'),'small')}</form><div class="filterbar">${btn('add-filter','+ '+t('addFilter'),'quiet small')}${r.filters.map((f,i)=>`<div class="filter-chip ${f.negate?'excluded':''} ${f.disabled?'disabled':''}"><code>${f.negate?'NOT ':''}${esc(f.field)}: ${esc(f.value)}</code>${btn('toggle-filter',f.disabled?'○':'●','',`data-index="${i}" aria-label="${esc(t('toggle'))}"`)}${btn('remove-filter','×','',`data-index="${i}" aria-label="${esc(t('remove'))}"`)}</div>`).join('')}${r.filters.length||r.query?btn('clear-search',t('removeFilters'),'quiet small'):''}</div>${searchError?`<div class="error" role="alert">${esc(t(searchError))}</div>`:''}<section class="panel"><div class="panel-content">${chartHtml(events)}</div></section><section class="panel"><div class="panel-head"><h2><span id="hit-count">${events.length}</span> ${esc(t('hits'))}</h2>${btn('columns',t('columns'),'quiet small')}</div>${columnsOpen?`<div class="columns">${['timestamp','agent.name','rule.description','rule.level','rule.id'].map(x=>`<label><input type="checkbox" data-column="${x}" ${cols.includes(x)?'checked':''}> ${esc(labels[x])}</label>`).join('')}</div>`:''}<div class="table-scroll"><table><thead><tr><th aria-label="${esc(t('details'))}"></th>${activeCols.map(k=>`<th>${esc(labels[k])}</th>`).join('')}</tr></thead><tbody>${current.map(e=>`<tr data-event="${esc(e.id)}"><td>${btn('expand',r.expanded===e.id?'▾':'▸','expand-btn',`data-id="${esc(e.id)}" aria-expanded="${r.expanded===e.id}" aria-label="${esc(t('details')+' '+e.id)}"`)}</td>${activeCols.map(k=>`<td class="${k==='rule.description'?'event-description':''}">${k==='timestamp'?`<span class="mono">${esc(time(e.timestamp))}</span><span class="row-id">${esc(e.id)}</span>`:k==='rule.level'?`<span class="level ${e.rule.level>=10?'high':e.rule.level>=7?'medium':''}">${e.rule.level}</span>`:k==='agent.name'?btn('field-filter',E.get(e,k),'quiet',`data-field="agent.name" data-value="${esc(E.get(e,k))}"`):esc(E.get(e,k)||'—')}</td>`).join('')}</tr>${r.expanded===e.id?`<tr><td colspan="${activeCols.length+1}" style="padding:0">${detailHtml(e)}</td></tr>`:''}`).join('')}</tbody></table>${!events.length?`<div class="empty">${esc(t('empty'))}</div>`:''}</div><div class="pagination"><span>${events.length?page*pageSize+1:0}–${Math.min((page+1)*pageSize,events.length)} / ${events.length}</span><div>${btn('prev-page','‹ '+t('prev'),'small',page===0?'disabled':'')} <span>${page+1} / ${pages}</span> ${btn('next-page',t('next')+' ›','small',page>=pages-1?'disabled':'')}</div></div></section><p class="footer-note">${esc(t('synthetic'))}</p>`;
  }
  function renderCoach() {
    const c=active(),r=record();return `<aside class="coach" id="learning-panel" aria-label="${esc(t('training'))}"><div class="coach-header"><div class="eyebrow">${esc(t('training'))} / ${esc(t(c.stage))}</div><h2>${esc(tx(c.title))}</h2><div class="progressline"><i style="width:${(c.steps.filter(s=>s.kind==='report'?r.completed:r.operations.includes(s.kind)).length/c.steps.length)*100}%"></i></div></div><nav class="coach-tabs" aria-label="${esc(t('training'))}">${['task','refs','report'].map(x=>btn('coach-tab',t(x),tab===x?'active':'',`data-tab="${x}" aria-current="${tab===x?'page':'false'}"`)).join('')}</nav><div class="coach-body">${tab==='task'?renderTask():tab==='refs'?renderRefs():renderReport()}</div></aside>`;
  }
  function renderTask() {
    const c=active(),r=record(),first=c.steps.find(s=>s.kind==='report'?!r.completed:!r.operations.includes(s.kind));
    return `<p>${esc(tx(c.brief))}</p><ul class="inline-list">${c.objectives.map(o=>`<li>${esc(tx(o))}</li>`).join('')}</ul><ol class="steps">${c.steps.map((s,i)=>{const done=s.kind==='report'?r.completed:r.operations.includes(s.kind),current=first?.id===s.id;return `<li class="${done?'done':current?'current':''}"><span class="step-number">${done?'✓':i+1}</span><div><strong>${esc(tx(s.title))}</strong>${(c.stage==='tutorial'||c.stage==='guided')&&current?`<p>${esc(tx(s.body))}</p>${btn('go-step',t('goStep'),'small',`data-kind="${s.kind}"`)}`:''}</div></li>`;}).join('')}</ol><p class="footer-note">${esc(t('checkNote'))}</p>${r.hint?`<div class="step-help"><strong>${esc(t('hint'))} ${r.hint}/3</strong><p>${esc(tx(c.hints[r.hint-1]))}</p></div>`:''}${r.hint<3?btn('hint',t(r.hint?'nextHint':'hint'),'small'): `<p class="muted">${esc(t('noHints'))}</p>`}<div style="margin-top:16px">${btn('coach-tab',t('openReport'),'primary small','data-tab="report"')}</div>`;
  }
  function renderRefs() { const c=active(),r=record();return `<p>${esc(t('refNote'))}</p>${c.documents.map(d=>`<button class="doc-button" data-action="document" data-id="${esc(d.id)}"><strong>${esc(tx(d.title))}</strong><br><small>${esc(d.id)} · ${esc(t(r.documents.includes(d.id)?'read':'unread'))}</small></button>`).join('')}`; }
  function options(values,selected) {return `<option value="">${esc(t('select'))}</option>`+values.map(v=>`<option value="${v}" ${v===selected?'selected':''}>${esc(t(v))}</option>`).join('');}
  function renderReport() {
    const c=active(),r=record(),a=r.report;
    return `<h3>${esc(t('evidence'))} <span class="muted">${r.evidence.length} / ${c.answer.evidenceGroups.length+2}</span></h3><p class="footer-note">${esc(t('evidenceNote'))}</p><div id="evidence-list">${r.evidence.length?r.evidence.map(id=>{const e=c.events.find(x=>x.id===id);return `<div class="evidence-item"><span><code>${esc(id)}</code><br>${esc(e.rule.description)}</span>${btn('evidence-remove','×','small',`data-id="${esc(id)}" aria-label="${esc(t('remove')+' '+id)}"`)}</div>`;}).join(''):`<p class="muted">${esc(t('noEvidence'))}</p>`}</div><form id="report-form" style="margin-top:18px"><div class="report-grid">${[['verdict',['incident','benign','unknown']],['priority',['high','medium','low']],['action',['escalate','monitor','verify']]].map(([key,choices])=>`<div><label for="report-${key}">${esc(t(key))}</label><select id="report-${key}" data-report="${key}">${options(choices,a[key])}</select></div>`).join('')}<div><label for="report-target">${esc(t('target'))}</label><select id="report-target" data-report="target"><option value="">${esc(t('select'))}</option>${c.agents.map(x=>`<option value="${esc(x.id)}" ${a.target===x.id?'selected':''}>${esc(x.name)} (${esc(x.id)})</option>`).join('')}</select></div></div><div class="report-field"><label for="report-facts">${esc(t('facts'))}</label><textarea id="report-facts" data-report="facts" maxlength="4000" placeholder="${esc(t('factsPlaceholder'))}">${esc(a.facts)}</textarea></div><div class="report-field"><label for="report-nextStep">${esc(t('nextStep'))}</label><textarea id="report-nextStep" data-report="nextStep" maxlength="4000" placeholder="${esc(t('nextPlaceholder'))}">${esc(a.nextStep)}</textarea></div><p class="footer-note">${esc(t('structural'))}</p><button type="submit" class="primary">${esc(t('submit'))}</button></form>${r.feedback?`<div class="review"><h3>${esc(t(r.feedback.passed?'passed':'tryAgain'))}</h3><ul class="checks">${r.feedback.checks.map(x=>`<li class="${x.passed?'yes':'no'}">${x.passed?'✓':'○'} ${esc(t(x.key))}</li>`).join('')}</ul>${r.feedback.passed?`<div class="success">${esc(t('modelNote'))}</div>`:''}${btn('show-model',t('showModel'),'small')} ${btn('export-report',t('exportReport'),'quiet small')}${modelOpen?`<div class="review"><h3>${esc(t('model'))}</h3><p><strong>${esc(t('verdict'))}:</strong> ${esc(t(c.answer.verdict))}<br><strong>${esc(t('priority'))}:</strong> ${esc(t(c.answer.priority))}<br><strong>${esc(t('action'))}:</strong> ${esc(t(c.answer.action))}</p><h3>${esc(t('facts'))}</h3><p>${esc(tx(c.answer.facts))}</p><h3>${esc(t('nextStep'))}</h3><p>${esc(tx(c.answer.nextStep))}</p><p>${esc(tx(c.answer.explanation))}</p></div>`:''}${r.completed?`<div style="margin-top:18px">${C.cases.indexOf(c)<C.cases.length-1?btn('next-case',t('nextCase'),'primary small'):btn('home',t('home'),'primary small')}</div>`:''}</div>`:''}`;
  }
  function render() {
    document.documentElement.lang=progress.language;document.title='Wazuhroom — '+t('workflow');
    app.innerHTML=header()+(home?renderHome():renderLab());
    if(!home && (active().stage==='tutorial'||active().stage==='guided') && tab==='task') highlight();
  }
  function highlight() {const r=record(),step=active().steps.find(s=>s.kind==='report'?!r.completed:!r.operations.includes(s.kind));if(!step)return;const selectors={events:'[data-view="events"]',range:'#time-range',search:'#event-search',detail:'.expand-btn',evidence:'[data-action="evidence-add"]',document:'[data-tab="refs"]',report:'[data-tab="report"]'};document.querySelector(selectors[step.kind])?.classList.add('guide-target');}
  function setCase(id) { syncDraft();progress.activeCaseId=id;home=false;tab='task';page=0;agentQuery='';agentDraft='';queryDraft=record().query;fromDraft=dt(record().from);toDraft=dt(record().to);searchError='';modelOpen=false;saveLocal();render();window.scrollTo(0,0); }
  function setView(view) {syncDraft();record().view=view;page=0;searchError='';if(view==='events'||view==='fim')op('events');saveLocal();render();}
  function modal(title,body,actions='') {document.getElementById('dialog-body').innerHTML=`<div class="dialog-head"><h2>${esc(title)}</h2>${btn('close-dialog','×','quiet','aria-label="'+esc(t('close'))+'"')}</div>${body}${actions?'<div class="dialog-actions">'+actions+'</div>':''}`;if(!dialog.open)dialog.showModal();}
  function help(searchOnly=false) {
    modal(t(searchOnly?'searchHelp':'help'),`${!searchOnly?`<p>${esc(t('helpIntro'))}</p><p>${esc(t('helpSave'))}</p><p>${esc(t('helpScope'))}</p>`:''}<h3>DQL</h3><p>${esc(t('helpDql'))}</p><pre>agent.name: "web-01" and rule.level >= 5\nrule.groups: "authentication_failed"\nnot data.srcip: *\n(syscheck.event: "modified" or rule.level >= 10)</pre><h3>WQL</h3><p>${esc(t('helpWql'))}</p><pre>status=disconnected and os.platform=ubuntu\nname~web</pre><details><summary>${esc(t('fieldCount'))}</summary><pre>${Object.keys(E.FIELD_TYPES).map(esc).join('\n')}</pre></details><p class="footer-note">${esc(t('limit'))}</p>`);
  }
  function download(filename,body,type='application/json') {const url=URL.createObjectURL(new Blob([body],{type})),a=document.createElement('a');a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
  function exportSave(prefix='wazuhroom-progress') {syncDraft();download(prefix+'.json',JSON.stringify(progress,null,2));}
  function addFilter(field,value,negate=false) {
    if(E.FIELD_TYPES[field]==='number'){if(String(value).trim()===''||!Number.isFinite(Number(value))){notify(t('searchError'));return;}value=Number(value);}
    const r=record(),filters=[...r.filters,{field,value,negate,disabled:false}];
    try{E.search(active().events,{query:r.query,filters,from:r.from,to:r.to});}catch(_){notify(t('searchError'));return;}
    r.filters=filters;op('search');page=0;searchError='';saveLocal();render();
  }
  function applyRange(from,to) {if(!Number.isFinite(Date.parse(from))||!Number.isFinite(Date.parse(to))||Date.parse(from)>=Date.parse(to)){searchError='rangeError';render();return;}record().from=new Date(from).toISOString();record().to=new Date(to).toISOString();fromDraft=dt(record().from);toDraft=dt(record().to);op('range');searchError='';page=0;saveLocal();render();}
  function reportText() {const c=active(),r=record(),a=r.report;return ['Wazuhroom '+document.body.dataset.version,tx(c.title),'',...['verdict','priority','action'].map(k=>t(k)+': '+t(a[k]||'select')),t('target')+': '+a.target,'',t('evidence')+': '+r.evidence.join(', '),t('documents')+': '+r.documents.join(', '),'',t('facts'),a.facts,'',t('nextStep'),a.nextStep,'',t('structural')].join('\n');}
  function handle(action,el) {
    syncDraft();const r=record(),c=active();
    switch(action){
      case 'home':home=true;saveLocal();render();window.scrollTo(0,0);break;
      case 'case':setCase(el.dataset.id);break;
      case 'view':setView(el.dataset.view);break;
      case 'coach-tab':tab=el.dataset.tab;render();if(innerWidth<=680)document.querySelector('.coach').scrollIntoView();break;
      case 'save':exportSave();notify(t('saved'));break;
      case 'load':document.getElementById('import-file').click();break;
      case 'help':help();break;case 'search-help':help(true);break;
      case 'close-dialog':dialog.close();pendingImport=null;break;
      case 'full-range':applyRange(c.timeRange.from,c.timeRange.to);break;
      case 'chart-range':applyRange(el.dataset.from,el.dataset.to);break;
      case 'clear-search':r.query='';r.filters=[];queryDraft='';searchError='';page=0;saveLocal();render();break;
      case 'add-filter':modal(t('addFilter'),`<form id="filter-form"><label for="filter-field">${esc(t('field'))}</label><select id="filter-field">${Object.keys(E.FIELD_TYPES).filter(x=>x!=='full_log').map(k=>`<option>${esc(k)}</option>`).join('')}</select><label for="filter-value" style="margin-top:14px">${esc(t('value'))}</label><input id="filter-value" required maxlength="500"><label style="margin-top:12px"><input id="filter-negate" type="checkbox" style="width:auto"> ${esc(t('exclude'))}</label><div class="dialog-actions"><button type="submit" class="primary">${esc(t('apply'))}</button></div></form>`);break;
      case 'field-filter':case 'field-exclude':addFilter(el.dataset.field,el.dataset.value,action==='field-exclude');break;
      case 'toggle-filter':r.filters[Number(el.dataset.index)].disabled=!r.filters[Number(el.dataset.index)].disabled;page=0;saveLocal();render();break;
      case 'remove-filter':r.filters.splice(Number(el.dataset.index),1);page=0;saveLocal();render();break;
      case 'columns':columnsOpen=!columnsOpen;render();break;
      case 'prev-page':page=Math.max(0,page-1);render();break;case 'next-page':page++;render();break;
      case 'expand':r.expanded=r.expanded===el.dataset.id?null:el.dataset.id;if(r.expanded)op('detail');saveLocal();render();break;
      case 'evidence-add':if(!r.evidence.includes(el.dataset.id)){r.evidence.push(el.dataset.id);op('evidence');saveLocal();render();notify(t('added'));}break;
      case 'evidence-remove':r.evidence=r.evidence.filter(x=>x!==el.dataset.id);saveLocal();render();break;
      case 'agent-events':r.view='events';r.filters=[{field:'agent.id',value:el.dataset.id,negate:false,disabled:false}];r.query='';queryDraft='';op('events');op('search');page=0;searchError='';saveLocal();render();notify(t('agentScope'));break;
      case 'document':{const d=c.documents.find(x=>x.id===el.dataset.id);if(!r.documents.includes(d.id))r.documents.push(d.id);op('document');saveLocal();render();modal(tx(d.title),`<p class="muted mono">${esc(d.id)}</p><div class="doc-body">${esc(tx(d.body))}</div>`);break;}
      case 'hint':r.hint=Math.min(3,r.hint+1);saveLocal();render();break;
      case 'go-step':{const kind=el.dataset.kind;if(kind==='document'){tab='refs';render();}else if(kind==='report'){tab='report';render();}else{setView('events');const map={range:'#range-from',search:'#event-query',detail:'.expand-btn',evidence:'[data-action="evidence-add"]'};document.querySelector(map[kind])?.focus();}break;}
      case 'show-model':modelOpen=!modelOpen;render();break;
      case 'export-report':download('wazuhroom-'+c.id+'-'+progress.language+'.txt',reportText(),'text/plain');break;
      case 'next-case':setCase(C.cases[C.cases.indexOf(c)+1].id);break;
      case 'backup-import':exportSave('wazuhroom-before-import');importBackedUp=true;document.querySelector('[data-action="confirm-import"]').disabled=false;notify(t('saved'));break;
      case 'confirm-import':if(pendingImport&&importBackedUp){progress=pendingImport;pendingImport=null;storageBlocked=false;home=true;queryDraft=record().query;fromDraft=dt(record().from);toDraft=dt(record().to);saveLocal();dialog.close();render();notify(t('loaded'));}break;
    }
  }
  document.addEventListener('click',ev=>{const el=ev.target.closest('[data-action]');if(el){ev.preventDefault();handle(el.dataset.action,el);}});
  document.addEventListener('input',ev=>{if(ev.target.dataset.report){record().report[ev.target.dataset.report]=ev.target.value;saveLocal();}});
  document.addEventListener('change',ev=>{
    const el=ev.target;
    if(el.id==='language'){syncDraft();progress.language=el.value;saveLocal();render();}
    if(el.dataset.report){record().report[el.dataset.report]=el.value;saveLocal();}
    if(el.dataset.column){if(el.checked)cols.push(el.dataset.column);else if(cols.length>1)cols=cols.filter(x=>x!==el.dataset.column);render();}
  });
  document.addEventListener('submit',ev=>{
    ev.preventDefault();syncDraft();const r=record();
    if(ev.target.id==='event-search'){
      try{E.search(active().events,{query:queryDraft,filters:r.filters,from:r.from,to:r.to});r.query=queryDraft;if(r.query.trim()||r.filters.some(x=>!x.disabled))op('search');searchError='';page=0;saveLocal();}catch(_){searchError='searchError';}render();
    }else if(ev.target.id==='agent-search'){
      try{E.searchAgents(active().agents,agentDraft);agentQuery=agentDraft;searchError='';}catch(_){searchError='searchError';}render();
    }else if(ev.target.id==='time-range'){
      applyRange(document.getElementById('range-from').value+'Z',document.getElementById('range-to').value+'Z');
    }else if(ev.target.id==='filter-form'){
      const field=document.getElementById('filter-field').value,value=document.getElementById('filter-value').value,negate=document.getElementById('filter-negate').checked;dialog.close();addFilter(field,value,negate);
    }else if(ev.target.id==='report-form'){
      op('report');r.feedback=E.assess(active(),r);
      if(r.feedback.passed){r.completed=true;const snapshot=clone(r);delete snapshot.completion;r.completion=snapshot;modelOpen=true;}
      saveLocal();render();document.querySelector('.review')?.scrollIntoView({block:'nearest'});
    }
  });
  document.getElementById('import-file').addEventListener('change',async ev=>{
    const file=ev.target.files[0];ev.target.value='';if(!file)return;
    try{if(file.size>2*1024*1024)throw new Error('large');const parsed=JSON.parse(await file.text());pendingImport=E.validateProgress(parsed,C);importBackedUp=false;const count=C.cases.filter(c=>pendingImport.records[c.id].completed).length;modal(t('importTitle'),`<p>${esc(t('importNote'))}</p><p>${esc(t('completed'))}: ${count} / ${C.cases.length}</p>`,btn('backup-import',t('backup'))+btn('confirm-import',t('replace'),'primary','disabled'));}
    catch(_){pendingImport=null;notify(t('invalidFile'));}
  });
  render();if(startupWarning)notify(t(startupWarning));
}());
