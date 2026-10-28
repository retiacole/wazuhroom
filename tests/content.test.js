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

test('dataset provides one tutorial and six investigations with gradual support', () => {
  assert.equal(content.version, 'wazuhroom-1');
  assert.equal(content.referenceVersion, '4.14');
  assert.equal(content.cases.length, 7);
  assert.deepEqual(content.cases.map(item => item.stage), ['tutorial', 'guided', 'guided', 'checklist', 'checklist', 'independent', 'independent']);
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
