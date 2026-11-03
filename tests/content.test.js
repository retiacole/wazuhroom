'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const content = require('../src/content.js');
const byId = Object.fromEntries(content.cases.map(item => [item.id, item]));

function bilingual(value, label) {
  assert.ok(value && typeof value === 'object', `${label}: bilingual object`);
  assert.deepEqual(Object.keys(value).sort(), ['en', 'ja'], `${label}: exact language keys`);
  assert.ok(typeof value.ja === 'string' && value.ja.trim().length > 0, `${label}: Japanese`);
  assert.ok(typeof value.en === 'string' && value.en.trim().length > 0, `${label}: English`);
  assert.match(value.ja, /[\u3040-\u30ff\u3400-\u9fff]/, `${label}: Japanese prose`);
  assert.doesNotMatch(value.en, /[\u3040-\u30ff\u3400-\u9fff]/, `${label}: English prose`);
}

test('dataset provides one tutorial and seven investigations with gradual support', () => {
  assert.equal(content.version, 'wazuhroom-1');
  assert.equal(content.referenceVersion, '4.14');
  assert.equal(content.cases.length, 8);
  assert.deepEqual(content.cases.map(item => item.stage), ['tutorial', 'guided', 'guided', 'checklist', 'checklist', 'independent', 'independent', 'independent']);
  assert.equal(new Set(content.cases.map(item => item.id)).size, content.cases.length);
});

test('all learner-authored prose has complete Japanese and English counterparts', () => {
  for (const item of content.cases) {
    bilingual(item.title, `${item.id}.title`);
    bilingual(item.brief, `${item.id}.brief`);
    assert.ok(item.objectives.length >= 2);
    item.objectives.forEach((value, index) => bilingual(value, `${item.id}.objective.${index}`));
    assert.equal(item.hints.length, 3);
    item.hints.forEach((value, index) => bilingual(value, `${item.id}.hint.${index}`));
    for (const doc of item.documents) {
      bilingual(doc.title, `${doc.id}.title`);
      bilingual(doc.body, `${doc.id}.body`);
    }
    for (const step of item.steps) {
      bilingual(step.title, `${step.id}.title`);
      bilingual(step.body, `${step.id}.body`);
    }
    for (const question of item.questions || []) {
      bilingual(question.label, `${item.id}.${question.id}.label`);
      bilingual(question.prompt, `${item.id}.${question.id}.prompt`);
    }
    for (const key of ['facts', 'nextStep', 'explanation']) bilingual(item.answer[key], `${item.id}.answer.${key}`);
  }
});

test('each case has a useful amount of background activity and stable globally unique event IDs', () => {
  const ids = new Set();
  for (const item of content.cases) {
    const bg = item.events.filter(event => event.id.startsWith(`${item.id}-bg-`));
    assert.ok(bg.length >= 40 && bg.length <= 80, `${item.id}: background count`);
    for (const event of item.events) {
      assert.ok(!ids.has(event.id), `duplicate ${event.id}`);
      ids.add(event.id);
      assert.ok(event.id.startsWith(item.id + '-'));
      assert.ok(event.rule.level >= 3 && event.rule.level <= 16, 'alert levels match declared collection');
    }
  }
  assert.equal(ids.size, content.cases.reduce((total, item) => total + item.events.length, 0));
});

test('timestamps are UTC, chronological, and in the declared investigation window', () => {
  for (const item of content.cases) {
    assert.match(item.timeRange.from, /Z$/);
    assert.match(item.timeRange.to, /Z$/);
    assert.ok(Date.parse(item.timeRange.from) < Date.parse(item.timeRange.to));
    let previous = -Infinity;
    for (const event of item.events) {
      assert.match(event.timestamp, /Z$/);
      const time = Date.parse(event.timestamp);
      assert.ok(Number.isFinite(time));
      assert.ok(time >= Date.parse(item.timeRange.from) && time <= Date.parse(item.timeRange.to), event.id);
      assert.ok(time >= previous, `out of order: ${event.id}`);
      previous = time;
    }
  }
});

test('agent identity and operating-system-specific telemetry are consistent', () => {
  for (const item of content.cases) {
    assert.ok(item.agents.length >= 3 && item.agents.length <= 5);
    const agents = Object.fromEntries(item.agents.map(agent => [agent.id, agent]));
    assert.equal(new Set(item.agents.map(agent => agent.id)).size, item.agents.length);
    for (const agent of item.agents) {
      assert.ok(['active', 'disconnected'].includes(agent.status));
      assert.ok(Number.isFinite(Date.parse(agent.lastKeepAlive)));
      assert.ok(Date.parse(agent.lastKeepAlive) <= Date.parse(item.timeRange.to));
    }
    for (const event of item.events) {
      const agent = agents[event.agent.id];
      assert.ok(agent, `${event.id}: existing agent`);
      assert.equal(event.agent.name, agent.name);
      assert.equal(event.agent.ip, agent.ip);
      if (event.data.win) {
        assert.equal(agent.os.platform, 'windows');
        assert.equal(event.data.win.system.computer, agent.name);
        assert.equal(typeof event.data.win.system.eventID, 'string');
      }
      if (event.decoder.name === 'wazuhroom-sshd' || event.syscheck) assert.notEqual(agent.os.platform, 'windows');
    }
  }
});

test('events retain necessary structured fields and original logs without translated payloads', () => {
  for (const item of content.cases) for (const event of item.events) {
    assert.equal(typeof event.rule.id, 'string');
    assert.ok(Array.isArray(event.rule.groups) && event.rule.groups.includes('wazuhroom'));
    assert.ok(event.decoder.name.startsWith('wazuhroom-'));
    assert.equal(typeof event.full_log, 'string');
    assert.ok(event.full_log.length > 20);
    assert.doesNotMatch(event.full_log, /[\u3040-\u30ff\u3400-\u9fff]/);
    assert.equal(typeof event.rule.description, 'string');
    if (event.data.srcport !== undefined) assert.equal(typeof event.data.srcport, 'number');
    if (event.data.win && event.data.win.eventdata.logonType !== undefined) assert.equal(typeof event.data.win.eventdata.logonType, 'number');
  }
});

test('training-rule provenance and observation limits are disclosed in both languages', () => {
  const rules = new Map();
  for (const item of content.cases) {
    const scope = item.documents.find(doc => doc.id === `${item.id}-scope`);
    assert.ok(scope);
    for (const event of item.events) {
      assert.ok(Number(event.rule.id) >= 100001 && Number(event.rule.id) <= 100099);
      const signature = [event.rule.level, event.rule.description];
      if (rules.has(event.rule.id)) assert.deepEqual(signature, rules.get(event.rule.id), `consistent training rule ${event.rule.id}`);
      rules.set(event.rule.id, signature);
    }
    assert.match(scope.body.ja, /教材専用/);
    assert.match(scope.body.ja, /実機で検証したものではありません/);
    assert.match(scope.body.en, /not outputs verified against a live Wazuh/);
    assert.match(scope.body.en, /level 3/);
    assert.match(scope.body.en, /empty search does not prove/);
  }
});

test('answer evidence and documents exist, are selectable, and fit the declared evidence budget', () => {
  for (const item of content.cases) {
    const eventIds = new Set(item.events.map(event => event.id));
    const docIds = new Set(item.documents.map(doc => doc.id));
    assert.equal(docIds.size, item.documents.length);
    assert.ok(['incident', 'benign', 'unknown'].includes(item.answer.verdict));
    assert.ok(['high', 'medium', 'low'].includes(item.answer.priority));
    assert.ok(['escalate', 'monitor', 'verify'].includes(item.answer.action));
    assert.ok(item.agents.some(agent => agent.id === item.answer.target));
    assert.ok(item.answer.evidenceGroups.length >= 1);
    const minimum = new Set();
    for (const group of item.answer.evidenceGroups) {
      assert.ok(Array.isArray(group) && group.length > 0);
      for (const id of group) {
        assert.ok(eventIds.has(id), `${item.id}: missing event ${id}`);
        assert.ok(!id.includes('-bg-'), `${item.id}: background is not required evidence`);
      }
      minimum.add(group[0]);
    }
    assert.ok(minimum.size <= item.answer.evidenceGroups.length + 2);
    for (const id of item.answer.documentIds) assert.ok(docIds.has(id), `${item.id}: missing document ${id}`);
    assert.ok(item.answer.documentIds.includes(`${item.id}-scope`));
    assert.ok(item.answer.documentIds.includes(`${item.id}-change`));
  }
});

test('all investigations join actual interface actions to evidence, documents, and reporting', () => {
  const allowed = new Set(['events', 'range', 'search', 'detail', 'evidence', 'document', 'report']);
  for (const item of content.cases) {
    const kinds = new Set(item.steps.map(step => step.kind));
    assert.equal(kinds.size, item.steps.length, `${item.id}: no redundant required operations`);
    assert.equal(new Set(item.steps.map(step => step.id)).size, item.steps.length);
    for (const kind of kinds) assert.ok(allowed.has(kind));
    for (const kind of ['search', 'detail', 'evidence', 'document', 'report']) assert.ok(kinds.has(kind), `${item.id}: ${kind}`);
  }
  assert.deepEqual(new Set(byId.tutorial.steps.map(step => step.kind)), allowed);
});

test('collection-gap evidence distinguishes manager notification from endpoint delivery', () => {
  const item = byId['collection-gap'];
  const agent = item.agents.find(agent => agent.id === '003');
  assert.equal(agent.status, 'disconnected');
  assert.equal(agent.lastKeepAlive, '2026-10-18T13:16:00.000Z');
  const after = item.events.filter(event => event.agent.id === '003' && event.timestamp > agent.lastKeepAlive);
  assert.equal(after.length, 1);
  assert.equal(after[0].id, 'collection-gap-disconnected');
  assert.equal(after[0].decoder.name, 'wazuhroom-agent-health');
  assert.equal(after[0].data.lastKeepAlive, agent.lastKeepAlive);
  assert.match(after[0].full_log, /manager room-health-collector/);
  const normal = item.events.filter(event => event.agent.id === '003' && event.decoder.name !== 'wazuhroom-agent-health');
  assert.equal(normal[normal.length - 1].id, 'collection-gap-last');
});

test('administrator and service cases do not confuse actor, member, group, or service account', () => {
  const addition = byId['approved-admin'].events.find(event => event.id === 'approved-admin-added');
  assert.equal(addition.data.win.eventdata.subjectUserName, 'admin.mori');
  assert.equal(addition.data.win.eventdata.memberName, 'WIN-FIN-01\\maint-fin');
  assert.equal(addition.data.win.eventdata.targetUserName, 'Administrators');
  const service = byId['service-persistence'].events.find(event => event.id === 'service-persistence-installed');
  assert.equal(service.data.win.eventdata.accountName, 'LocalSystem');
  assert.equal(service.data.win.eventdata.subjectUserName, undefined);
  const process = byId['service-persistence'].events.find(event => event.id === 'service-persistence-process');
  assert.equal(process.data.win.system.eventID, '4688');
  assert.equal(process.data.win.eventdata.newProcessName, 'C:\\Windows\\System32\\sc.exe');
  assert.equal(process.data.win.eventdata.parentProcessName, 'C:\\Windows\\System32\\cmd.exe');
  assert.equal(process.data.win.eventdata.image, undefined, '4688 uses its own field names, not Sysmon Image');
  const mixed = byId['mixed-auth'];
  assert.ok(mixed.answer.documentIds.includes('mixed-auth-exercise'));
  assert.equal(mixed.answer.target, '002');
  assert.match(mixed.answer.facts.en, /registration actor.*unconfirmed/);
});

test('FIM evidence records changed content without inventing file contents or actor attribution', () => {
  const item = byId['fim-change'];
  const fim = item.events.filter(event => event.syscheck);
  assert.equal(fim.length, 2);
  assert.deepEqual(fim.map(event => event.syscheck.path), ['/etc/ssh/sshd_config', '/var/www/html/index.html']);
  for (const event of fim) {
    assert.equal(event.syscheck.event, 'modified');
    assert.match(event.syscheck.sha256_before, /^[a-f0-9]{64}$/);
    assert.match(event.syscheck.sha256_after, /^[a-f0-9]{64}$/);
    assert.notEqual(event.syscheck.sha256_before, event.syscheck.sha256_after);
    assert.equal(event.data.srcuser, undefined);
    assert.equal(event.syscheck.diff, undefined);
  }
  assert.match(item.answer.facts.en, /Settings, activation state, person, and impact remain unconfirmed/);
});

test('standalone browser UMD export matches CommonJS dataset', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/content.js'), 'utf8');
  const context = vm.createContext({});
  vm.runInContext(source, context);
  assert.equal(JSON.stringify(context.WazuhContent), JSON.stringify(content));
});

test('password-failure investigation ends with password success without changing routine public-key logins', () => {
  const success = byId['auth-chain'].events.find(event => event.id === 'auth-chain-success');
  assert.match(success.full_log, /Accepted password for ops from 203\.0\.113\.77/);
  for (const item of content.cases) for (const event of item.events) {
    if (event.decoder.name !== 'wazuhroom-sshd') continue;
    if (event.data.action === 'authentication_failed') assert.match(event.full_log, /Failed password for /);
    else if (event.id !== 'auth-chain-success') assert.match(event.full_log, /Accepted publickey for /, event.id);
  }
  assert.match(byId['fim-change'].events.find(event => event.id === 'fim-change-logon').full_log, /Accepted publickey for ops\.kai/);
});

test('form guidance uses the exact visible localized choices and field labels', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/app.js'), 'utf8');
  const labels = key => {
    const match = source.match(new RegExp(`\\b${key}:\\['([^']+)','([^']+)'\\]`));
    assert.ok(match, `visible UI labels exist for ${key}`);
    return { ja: match[1], en: match[2] };
  };
  const choices = ['incident', 'benign', 'unknown', 'high', 'medium', 'low', 'escalate', 'monitor', 'verify'];
  const fields = ['verdict', 'priority', 'action', 'target', 'facts', 'nextStep'];
  const tutorialReport = byId.tutorial.steps.find(step => step.kind === 'report');
  for (const language of ['ja', 'en']) {
    for (const item of content.cases) {
      const policy = item.documents.find(doc => doc.id === `${item.id}-runbook`).body[language];
      for (const key of [...choices, ...fields]) assert.ok(policy.includes(labels(key)[language]), `${item.id}: ${language} ${key}`);
    }
    for (const key of [...fields, 'unknown', 'low', 'verify', 'submit']) {
      assert.ok(tutorialReport.body[language].includes(labels(key)[language]), `tutorial report: ${language} ${key}`);
    }
    for (const [id, keys] of [['tutorial', ['unknown', 'low', 'verify']], ['approved-admin', ['benign', 'low', 'monitor']], ['collection-gap', ['unknown', 'medium', 'verify']]]) {
      for (const key of keys) assert.ok(byId[id].hints[2][language].includes(labels(key)[language]), `${id} hint: ${language} ${key}`);
    }
  }
});

test('every document instruction names the actual scope, change, runbook, and any additional required reference', () => {
  for (const item of content.cases) {
    const instruction = item.steps.find(step => step.kind === 'document').body;
    for (const doc of item.documents) for (const language of ['ja', 'en']) {
      assert.ok(instruction[language].includes(doc.title[language]), `${item.id}: explicit ${doc.id} in ${language}`);
    }
    assert.match(instruction.ja, /「資料」タブ/);
    assert.match(instruction.en, /References tab/);
  }
});

test('instruction improvements preserve the original seven completion requirements and dataset identity', () => {
  assert.equal(content.version, 'wazuhroom-1');
  for (const item of content.cases.filter(item => item.id !== 'crypto-compromise')) {
    const required = [`${item.id}-scope`, `${item.id}-change`];
    if (item.id === 'mixed-auth') required.push('mixed-auth-exercise');
    assert.deepEqual(item.answer.documentIds, required, `${item.id}: existing saves must not gain a runbook requirement`);
  }
  assert.deepEqual(byId['mixed-auth'].answer.evidenceGroups, [
    ['mixed-auth-logon'], ['mixed-auth-service'], ['mixed-auth-failure-1', 'mixed-auth-failure-2', 'mixed-auth-failure-3']
  ]);
});

test('mixed investigation asks for comparison evidence and EX-12 before hints are opened', () => {
  const item = byId['mixed-auth'];
  const evidence = item.steps.find(step => step.kind === 'evidence').body;
  const instructions = item.steps.find(step => step.kind === 'document').body;
  const exercise = item.documents.find(doc => doc.id === 'mixed-auth-exercise');
  for (const text of [item.brief.ja, evidence.ja]) {
    assert.match(text, /web-01/);
    assert.match(text, /認証失敗/);
    assert.match(text, /少なくとも1件/);
    assert.match(text, /証拠/);
  }
  for (const text of [item.brief.en, evidence.en]) {
    assert.match(text, /web-01/);
    assert.match(text, /authentication failure/);
    assert.match(text, /at least one/);
    assert.match(text, /evidence/);
  }
  for (const language of ['ja', 'en']) {
    assert.ok(item.brief[language].includes(exercise.title[language]));
    assert.ok(instructions[language].includes(exercise.title[language]));
    assert.ok(item.hints[2][language].includes(exercise.title[language]));
  }
});

test('collection scope covers all common background sources while preserving the disconnection limit', () => {
  for (const item of content.cases) {
    const scope = item.documents.find(doc => doc.id === `${item.id}-scope`).body;
    for (const language of ['ja', 'en']) for (const term of ['web-01', 'db-01', 'win-fin-01', '10.20.0.5', 'svc.inventory', 'logrotate', 'root', '4624', 'logonType 3', '7036', 'Windows Event Log']) {
      assert.ok(scope[language].includes(term), `${item.id}: ${language} background ${term}`);
    }
    assert.match(scope.ja, /切断後のdb-01から背景ログは届きません/);
    assert.match(scope.en, /no db-01 background telemetry arrives after disconnection/);
  }
  const gap = byId['collection-gap'];
  const cutoff = gap.agents.find(agent => agent.id === '003').lastKeepAlive;
  assert.equal(gap.events.filter(event => event.id.includes('-bg-') && event.agent.id === '003' && event.timestamp > cutoff).length, 0);
});

test('finance role and group-membership removal are explained without asserting unobserved technical impossibility', () => {
  const role = byId['service-persistence'].documents.find(doc => doc.id === 'service-persistence-change').body;
  assert.match(role.ja, /fin\.userは経理部門の通常業務用アカウント/);
  assert.match(role.ja, /サービス導入の権限利用や作業は承認されていません/);
  assert.match(role.ja, /実効権限や昇格の有無は判断できません/);
  assert.match(role.en, /fin\.user is an ordinary finance-business account/);
  assert.match(role.en, /neither use of installation privileges nor this installation work is approved/);
  assert.match(role.en, /does not establish the account’s effective privileges/);
  const scope = byId['approved-admin'].documents.find(doc => doc.id === 'approved-admin-scope').body;
  assert.match(scope.ja, /4733（ローカルグループからのメンバー削除）/);
  assert.match(scope.en, /4733 \(member removal from a local group\)/);
  assert.match(scope.ja, /アカウントやグループ自体の削除ではありません/);
  assert.match(scope.en, /does not mean the account or group itself was deleted/);
});

test('navigation guidance points to Endpoints and the Threat Hunting event list', () => {
  for (const item of content.cases) {
    const prose = JSON.stringify([item.brief, item.hints, item.steps]);
    assert.doesNotMatch(prose, /\bAgents\b|\bEvents\b/, `${item.id}: no unavailable navigation label`);
  }
  const search = byId.tutorial.steps.find(step => step.kind === 'search').body;
  for (const language of ['ja', 'en']) assert.ok(search[language].includes('Endpoints'));
  const events = byId.tutorial.steps.find(step => step.kind === 'events').body;
  assert.match(events.ja, /Threat Hunting.*イベント一覧/);
  assert.match(events.en, /Threat Hunting.*event list/);
});

test('crypto revision 2 requires all seven disclosed evidence categories and three contextual documents', () => {
  const item = byId['crypto-compromise'];
  assert.equal(item.revision, 2);
  assert.equal(item.stage, 'independent');
  assert.equal(item.answer.target, '001');
  assert.equal(item.answer.verdict, 'incident');
  assert.equal(item.answer.priority, 'high');
  assert.equal(item.answer.action, 'escalate');
  assert.deepEqual(item.answer.evidenceGroups, [
    ['crypto-compromise-http'], ['crypto-compromise-process'], ['crypto-compromise-connection'], ['crypto-compromise-cron'], ['crypto-compromise-recurrence'], ['crypto-compromise-webpost'], ['crypto-compromise-file']
  ]);
  assert.deepEqual(item.answer.documentIds, ['crypto-compromise-scope', 'crypto-compromise-change', 'crypto-compromise-webroot']);
  const evidence = item.steps.find(step => step.kind === 'evidence').body;
  for (const text of [item.brief.ja, evidence.ja]) {
    for (const term of ['HTTP', '停止前', 'PID', '外部接続', '定期実行', '再出現', '7', 'POST', 'Base64', '読取り専用レビュー', 'WEB-219', '3つの設問']) assert.ok(text.includes(term), `explicit evidence request: ${term}`);
  }
  for (const text of [item.brief.en, evidence.en]) {
    for (const term of ['HTTP', 'pre-stop', 'PID', 'outbound connection', 'scheduled', 'seven', 'POST', 'Base64', 'read-only PHP-file review', 'WEB-219', 'three case questions']) assert.ok(text.includes(term), `explicit evidence request: ${term}`);
  }
});

test('HTTP 200 is paired with a body error and cannot explain an already observed process', () => {
  const events = Object.fromEntries(byId['crypto-compromise'].events.map(event => [event.id, event]));
  const http = events['crypto-compromise-http'];
  const process = events['crypto-compromise-process'];
  assert.equal(http.data.http.method, 'POST');
  assert.equal(http.data.http.status_code, 200);
  assert.equal(http.data.path, undefined, 'HTTP URI does not establish a server filesystem path');
  assert.match(http.data.http.response_summary, /Permission denied/);
  assert.match(http.data.http.response_summary, /placement and execution are not confirmed/);
  assert.match(http.data.http.body_summary, /executable bytes omitted/);
  assert.ok(http.timestamp > process.timestamp);
  assert.match(byId['crypto-compromise'].answer.facts.ja, /最初のプロセス観測より後/);
  assert.match(byId['crypto-compromise'].answer.facts.en, /followed the initial process observation/);
});

test('crypto snapshots correlate by endpoint and nearby PID without turning recurrence into a proved launch mechanism', () => {
  const item = byId['crypto-compromise'];
  const events = Object.fromEntries(item.events.map(event => [event.id, event]));
  const first = events['crypto-compromise-process'];
  const flow = events['crypto-compromise-connection'];
  const again = events['crypto-compromise-recurrence'];
  const reconnect = events['crypto-compromise-reconnection'];
  const absent = events['crypto-compromise-absent'];
  const cron = events['crypto-compromise-cron'];
  assert.equal(first.agent.id, flow.agent.id);
  assert.equal(first.data.process.pid, flow.data.process.pid);
  assert.ok(Date.parse(flow.timestamp) - Date.parse(first.timestamp) <= 60_000);
  assert.equal(again.data.process.pid, reconnect.data.process.pid);
  assert.notEqual(first.data.process.pid, again.data.process.pid);
  assert.equal(first.data.process.cmd, again.data.process.cmd);
  assert.equal(first.data.process.args, again.data.process.args);
  assert.equal(first.data.process.euser, 'svc.web-lab');
  assert.equal(again.data.process.euser, first.data.process.euser);
  assert.ok(first.timestamp < absent.timestamp && absent.timestamp < again.timestamp);
  assert.ok(first.data.process.start_time < first.timestamp);
  assert.ok(again.data.process.start_time > absent.timestamp && again.data.process.start_time < again.timestamp);
  assert.equal(cron.data.action, 'scheduled_entry_observed');
  assert.equal(cron.data.user, first.data.process.euser);
  assert.equal(cron.data.path, first.data.process.cmd);
  assert.match(cron.full_log, /observation=read_only author=unknown added_at=unknown/);
  assert.match(item.answer.explanation.en, /possible restart mechanism, not proof/);
});

test('crypto case distinguishes synthetic HTTP summaries from supplementary endpoint and operations observations', () => {
  const item = byId['crypto-compromise'];
  const scope = item.documents.find(doc => doc.id === 'crypto-compromise-scope').body;
  assert.match(scope.ja, /実際のパケットキャプチャをWazuhログへ変換したものではありません/);
  assert.match(scope.ja, /通信記録だけでは得られない情報.*合成観測/);
  assert.match(scope.en, /not a conversion of real packet captures into Wazuh logs/);
  assert.match(scope.en, /synthetic supplementary observations/);
  assert.match(scope.en, /FIM, complete process ancestry, privilege escalation, and mining rewards are unavailable/);
  assert.match(scope.ja, /Base64には独自に作成した非実行の英語疑似コードだけ/);
  assert.match(scope.en, /Base64 contains only independently written, non-executable English pseudocode/);
  assert.match(scope.en, /represents a POST body sent to the webshell/);
  assert.doesNotMatch(JSON.stringify(item), /大量送信|bulk email|spam campaign/, 'one mail-request description is not a bulk-mail campaign');
  assert.match(item.answer.nextStep.en, /HTTP activity and the existing process/);
  const operations = item.documents.find(doc => doc.id === 'crypto-compromise-change').body;
  assert.match(operations.ja, /架空の運用記録/);
  assert.match(operations.en, /Fictional operations record/);
  assert.match(operations.ja, /復旧判定は未完了/);
  assert.match(operations.en, /recovery validation remain incomplete/);
  assert.equal(item.events.filter(event => event.syscheck).length, 0, 'no invented FIM evidence');
});

test('crypto indicators are deliberately fictional and the case contains descriptions, not executable payloads', () => {
  const item = byId['crypto-compromise'];
  const keyEvents = item.events.filter(event => !event.id.includes('-bg-'));
  for (const event of keyEvents) {
    assert.equal(event.agent.id, '001');
    for (const field of ['srcip', 'dstip']) {
      const ip = event.data[field];
      if (ip) assert.ok(ip === event.agent.ip || /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/.test(ip), `documentation IP: ${field}`);
    }
    for (const value of [event.data.path, event.data.process && event.data.process.cmd].filter(Boolean)) {
      assert.match(value, /^\/(?:opt|srv|var\/tmp)\/room-lab\//, 'dedicated fictional filesystem path');
    }
    if (event.data.http) {
      assert.match(event.data.http.host, /\.invalid$/);
      assert.match(event.data.http.uri, /^\/room-lab\//);
      assert.match(event.data.http.request_id, /^ROOM-HTTP-/);
    }
    if (event.data.process && event.data.process.args) {
      assert.match(event.data.process.args, /pool-07\.room\.invalid/);
      assert.match(event.data.process.args, /TRAINING-WALLET-07-NOT-A-REAL-ADDRESS/);
    }
    const text = JSON.stringify(event);
    assert.doesNotMatch(text, /<\?php|\u007fELF|eval\s*\(|base64_decode\s*\(/, 'no web-shell source, ELF bytes, or encoded payload execution');
  }
  assert.equal(item.timeRange.from, '2026-10-21T16:00:00.000Z');
  assert.equal(item.timeRange.to, '2026-10-21T16:40:00.000Z');
  for (const language of ['ja', 'en']) {
    const policy = item.documents.find(doc => doc.id === 'crypto-compromise-runbook').body[language];
    assert.ok(policy.includes(language === 'ja' ? '承認外の採掘用途' : 'suspected unauthorized mining'));
  }
});

test('webshell questions are grounded in separate HTTP, filesystem, and publication evidence', () => {
  const item = byId['crypto-compromise'];
  const events = Object.fromEntries(item.events.map(event => [event.id, event]));
  const post = events['crypto-compromise-webpost'];
  const upload = events['crypto-compromise-http'];
  const file = events['crypto-compromise-file'];
  const mapping = item.documents.find(doc => doc.id === 'crypto-compromise-webroot');
  const questions = Object.fromEntries(item.questions.map(question => [question.id, question]));
  assert.deepEqual(Object.keys(questions), ['webshellUri', 'webshellPath', 'decodedText']);
  assert.equal(post.data.http.method, 'POST');
  assert.equal(post.data.http.status_code, 200);
  assert.equal(post.data.http.uri, upload.data.http.uri);
  assert.notEqual(post.data.http.request_id, upload.data.http.request_id);
  assert.ok(upload.timestamp < post.timestamp && post.timestamp < file.timestamp);
  assert.equal(post.data.path, undefined, 'HTTP summary does not invent a server path');
  assert.equal(file.data.action, 'file_inspection_observed');
  assert.match(file.data.artifact.content_summary, /Read-only static review/);
  assert.match(file.data.artifact.content_summary, /passes POST input to server-side code processing/);
  assert.match(file.data.artifact.content_summary, /Installation time and actor are unknown/);
  assert.equal(file.data.artifact.encoded_content, undefined, 'encoded text came from the POST, not the file review');
  assert.deepEqual(questions.webshellUri.acceptedAnswers, [post.data.http.uri]);
  assert.deepEqual(questions.webshellPath.acceptedAnswers, [file.data.path]);
  const prefix = '/room-lab/';
  const webroot = '/srv/room-lab/www/';
  assert.equal(file.data.path, webroot + post.data.http.uri.slice(prefix.length));
  for (const language of ['ja', 'en']) {
    assert.ok(mapping.body[language].includes(prefix));
    assert.ok(mapping.body[language].includes(webroot));
    assert.ok(mapping.body[language].includes(file.data.path));
    assert.ok(item.steps.find(step => step.kind === 'document').body[language].includes(mapping.title[language]));
  }
  assert.match(mapping.body.ja, /シンボリックリンク.*ありません/);
  assert.match(mapping.body.en, /no URL rewrites, aliases to other directories, symbolic links/);
  assert.match(mapping.body.en, /not recovered as content embedded in the file/);
  assert.ok(item.answer.documentIds.includes(mapping.id));
});

test('POST Base64 decodes to the complete inert six-line exercise answer', () => {
  const item = byId['crypto-compromise'];
  const post = item.events.find(event => event.id === 'crypto-compromise-webpost');
  const question = item.questions.find(question => question.id === 'decodedText');
  const artifact = post.data.artifact;
  assert.equal(artifact.encoding, 'base64');
  assert.match(artifact.encoded_content, /^[A-Za-z0-9+/]+={0,2}$/);
  const decoded = Buffer.from(artifact.encoded_content, 'base64').toString('utf8');
  assert.equal(Buffer.from(decoded, 'utf8').toString('base64'), artifact.encoded_content);
  assert.deepEqual(decoded.split('\n'), [
    'TRAINING PSEUDOCODE - NOT EXECUTABLE',
    'SET display_errors = off',
    'SET request.REMOTE_ADDR = 192.0.2.73',
    'SET request.SCRIPT_NAME = /room-lab/forms/contact.php',
    'REQUEST MAIL TO mailbox-07@room.invalid',
    'DISPLAY mail_request_result'
  ]);
  assert.deepEqual(question.acceptedAnswers, [decoded]);
  assert.equal(question.multiline, true);
  assert.ok(decoded.length < 4096);
  assert.doesNotMatch(decoded, /<\?php|\$[_A-Za-z]|\b(?:eval|mail|system|exec|base64_decode)\s*\(/);
  assert.ok(post.full_log.includes(artifact.encoded_content));
  for (const language of ['ja', 'en']) assert.ok(item.hints[2][language].includes(decoded), 'self-study hint retains the complete answer');
});

test('decoded mail behavior is interpreted without treating forged request variables as host evidence', () => {
  const item = byId['crypto-compromise'];
  const post = item.events.find(event => event.id === 'crypto-compromise-webpost');
  const questions = Object.fromEntries(item.questions.map(question => [question.id, question]));
  const decoded = questions.decodedText.acceptedAnswers[0];
  const overrideSource = decoded.match(/REMOTE_ADDR = (.+)/)[1];
  const overridePath = decoded.match(/SCRIPT_NAME = (.+)/)[1];
  assert.notEqual(overrideSource, post.data.srcip);
  assert.notEqual(overridePath, questions.webshellUri.acceptedAnswers[0]);
  assert.notEqual(overridePath, questions.webshellPath.acceptedAnswers[0]);
  assert.match(post.data.http.response_summary, /mail delivery are not confirmed/);
  assert.match(item.answer.explanation.ja, /要求変数の書換え先.*実際の設置パスではありません/);
  assert.match(item.answer.explanation.en, /request-variable override, not the installed path/);
  assert.match(item.answer.explanation.en, /does not replace the HTTP source/);
  assert.match(item.answer.explanation.en, /does not establish successful delivery or installation of the mining process/);
  const reportStep = item.steps.find(step => step.kind === 'report').body;
  assert.match(reportStep.ja, /3設問/);
  assert.match(reportStep.en, /all three case questions/);
});
