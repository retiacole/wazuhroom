'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const C = require('../src/content.js');
const E = require('../src/engine.js');
const clone = value => JSON.parse(JSON.stringify(value));
const ids = list => list.map(item => item.id);
const byId = Object.fromEntries(C.cases.map(item => [item.id, item]));

function successfulRecord(item, language = 'ja') {
  const record = E.createProgress(C).records[item.id];
  record.view = item.id === 'fim-change' ? 'fim' : 'events';
  record.query = `agent.id: ${JSON.stringify(item.answer.target)}`;
  record.evidence = [...new Set(item.answer.evidenceGroups.map(group => group[0]))];
  record.documents = item.answer.documentIds.slice();
  record.operations = [...new Set(item.steps.map(step => step.kind))];
  record.expanded = record.evidence[0];
  record.report = {
    verdict: item.answer.verdict, priority: item.answer.priority, action: item.answer.action,
    target: item.answer.target, facts: item.answer.facts[language], nextStep: item.answer.nextStep[language]
  };
  return record;
}
function submit(record, item) {
  record.feedback = E.assess(item, record);
  if (record.feedback.passed) {
    record.completed = true;
    const snapshot = clone(record);
    delete snapshot.completion;
    record.completion = snapshot;
  }
}
function leaves(object, prefix = '', result = []) {
  for (const [key, value] of Object.entries(object)) {
    const field = prefix ? `${prefix}.${key}` : key;
    if (Array.isArray(value)) for (const member of value) result.push([field, member]);
    else if (value !== null && typeof value === 'object') leaves(value, field, result);
    else result.push([field, value]);
  }
  return result;
}

test('all authored event fields have supported query mappings and typed filter behavior', () => {
  for (const item of C.cases) for (const event of item.events) {
    for (const [field, value] of leaves(event)) {
      assert.ok(Object.prototype.hasOwnProperty.call(E.FIELD_TYPES, field), `${event.id}: missing mapping ${field}`);
      assert.equal(typeof value, E.FIELD_TYPES[field] === 'number' ? 'number' : 'string', `${event.id}: ${field} type`);
      const query = `${field}: ${typeof value === 'number' ? value : JSON.stringify(value)}`;
      assert.equal(E.search([event], { query }).length, 1, `${event.id}: ${query}`);
      assert.equal(E.search([event], { filters: [{ field, value }] }).length, 1, `${event.id}: typed filter ${field}`);
      assert.equal(E.search([event], { filters: [{ field, value, negate: true }] }).length, 0, `${event.id}: excluded ${field}`);
    }
  }
});

test('every case opens with all its events and retains exact timestamps through a progress roundtrip', () => {
  const progress = E.createProgress(C);
  assert.deepEqual(E.validateProgress(clone(progress), C), progress);
  for (const item of C.cases) {
    const record = progress.records[item.id];
    assert.deepEqual(ids(E.search(item.events, { from: record.from, to: record.to })), ids(item.events));
    assert.equal(record.from, item.timeRange.from);
    assert.equal(record.to, item.timeRange.to);
    for (const agent of item.agents) {
      assert.deepEqual(ids(E.searchAgents(item.agents, `id=${agent.id}`)), [agent.id]);
      const rows = E.search(item.events, { filters: [{ field: 'agent.id', value: agent.id }] });
      assert.deepEqual(ids(rows), ids(item.events.filter(event => event.agent.id === agent.id)));
    }
  }
});

test('the queries taught in hints and tutorial lead to the intended evidence', () => {
  const searches = [
    ['tutorial', 'agent.name: "web-01" AND data.action: "authentication_failed"', ['tutorial-failure']],
    ['auth-chain', 'agent.name: "web-01" AND data.action: "authentication_failed"', ['auth-chain-fail-1', 'auth-chain-fail-2']],
    ['auth-chain', 'data.srcip: "203.0.113.77"', ['auth-chain-fail-1', 'auth-chain-fail-2', 'auth-chain-success']],
    ['approved-admin', 'agent.name: "win-fin-01" AND (data.win.system.eventID: "4720" OR data.win.system.eventID: "4732" OR data.win.system.eventID: "4733")', ['approved-admin-created', 'approved-admin-added', 'approved-admin-removed']],
    ['service-persistence', 'data.win.system.eventID: "7045" OR data.win.system.eventID: "4688"', ['service-persistence-installed', 'service-persistence-process']],
    ['fim-change', 'syscheck.path: "/etc/ssh/sshd_config"', ['fim-change-config']]
  ];
  for (const [caseId, query, required] of searches) {
    const hits = new Set(ids(E.search(byId[caseId].events, { query })));
    for (const id of required) assert.ok(hits.has(id), `${caseId}: ${query} should include ${id}`);
  }
  assert.deepEqual(ids(E.searchAgents(byId['collection-gap'].agents, 'status=disconnected')), ['003']);
  assert.deepEqual(ids(E.search(byId['fim-change'].events, { module: 'fim' })), ids(byId['fim-change'].events.filter(event => event.syscheck)));
  assert.deepEqual(E.search(byId.tutorial.events, { query: 'syscheck.path:*' }), []);
});

for (const language of ['ja', 'en']) {
  test(`all seven authored answers pass, snapshot and restore in ${language}`, () => {
    const progress = E.createProgress(C);
    progress.language = language;
    for (const item of C.cases) {
      const record = successfulRecord(item, language);
      assert.deepEqual(E.assess(item, record).checks.filter(check => !check.passed), [], item.id);
      submit(record, item);
      assert.equal(record.completed, true, item.id);
      progress.records[item.id] = record;
    }
    progress.activeCaseId = C.cases[C.cases.length - 1].id;
    const restored = E.validateProgress(clone(progress), C);
    assert.equal(restored.language, language);
    assert.equal(restored.activeCaseId, progress.activeCaseId);
    assert.equal(Object.values(restored.records).filter(record => record.completed).length, C.cases.length);
    for (const item of C.cases) {
      const before = progress.records[item.id], after = restored.records[item.id];
      assert.deepEqual(after.report, before.report);
      assert.deepEqual(after.evidence, before.evidence);
      assert.equal(after.expanded, before.expanded);
      assert.equal(after.feedback.passed, true);
      assert.equal(after.completion.feedback.passed, true);
      assert.equal(Object.hasOwn(after.feedback, 'score'), false);
      assert.equal(Object.hasOwn(after.completion.feedback, 'score'), false);
    }
    assert.deepEqual(E.validateProgress(clone(restored), C), restored);
  });
}

test('each case rejects wrong decisions, omitted evidence or documents, and selecting all events', () => {
  for (const item of C.cases) {
    for (const [field, options] of Object.entries({ verdict: ['incident', 'benign', 'unknown'], priority: ['high', 'medium', 'low'], action: ['escalate', 'monitor', 'verify'] })) {
      const record = successfulRecord(item);
      record.report[field] = options.find(value => value !== item.answer[field]);
      assert.equal(E.assess(item, record).passed, false, `${item.id}: wrong ${field}`);
    }
    const wrongTarget = successfulRecord(item);
    wrongTarget.report.target = item.agents.find(agent => agent.id !== item.answer.target).id;
    assert.equal(E.assess(item, wrongTarget).passed, false, `${item.id}: wrong target`);
    for (const group of item.answer.evidenceGroups) {
      const record = successfulRecord(item);
      record.evidence = record.evidence.filter(id => !group.includes(id));
      assert.equal(E.assess(item, record).passed, false, `${item.id}: omitted evidence group`);
    }
    for (const doc of item.answer.documentIds) {
      const record = successfulRecord(item);
      record.documents = record.documents.filter(id => id !== doc);
      assert.equal(E.assess(item, record).passed, false, `${item.id}: omitted ${doc}`);
    }
    const all = successfulRecord(item);
    all.evidence = item.events.map(event => event.id);
    assert.equal(E.assess(item, all).passed, false, `${item.id}: select all`);
    const noActions = successfulRecord(item);
    noActions.operations = [];
    assert.equal(E.assess(item, noActions).passed, false, `${item.id}: no operations`);
  }
});

test('cross-case evidence cannot be imported and failed validation leaves the input unchanged', () => {
  for (let index = 0; index < C.cases.length; index++) {
    const item = C.cases[index], other = C.cases[(index + 1) % C.cases.length];
    const progress = E.createProgress(C);
    progress.records[item.id] = successfulRecord(item);
    progress.records[item.id].evidence.push(other.answer.evidenceGroups[0][0]);
    const before = clone(progress);
    assert.throws(() => E.validateProgress(progress, C), /evidence/, item.id);
    assert.deepEqual(progress, before);
  }
});

test('completed actual cases retain valid snapshots after a failed review attempt and language change', () => {
  const progress = E.createProgress(C);
  for (const item of C.cases) {
    const record = successfulRecord(item);
    submit(record, item);
    record.report.verdict = item.answer.verdict === 'unknown' ? 'benign' : 'unknown';
    record.report.facts = '復習中の下書きを保存します。';
    record.evidence = [];
    submit(record, item);
    assert.equal(record.feedback.passed, false);
    progress.records[item.id] = record;
  }
  progress.language = 'en';
  const restored = E.validateProgress(clone(progress), C);
  for (const item of C.cases) {
    const record = restored.records[item.id];
    assert.equal(record.completed, true);
    assert.equal(record.feedback.passed, false);
    assert.equal(record.completion.report.verdict, item.answer.verdict);
    assert.equal(record.completion.feedback.passed, true);
    assert.equal(record.report.facts, '復習中の下書きを保存します。');
  }
});

test('v0.1.0 scored completion saves still restore and discard legacy scores', () => {
  // Frozen legacy decisions and evidence IDs deliberately do not use the current answer data.
  const oldCases = [
    ['tutorial', 'unknown', 'low', 'verify', '001', ['tutorial-failure'], '2026-10-14T09:00:00.000Z', '2026-10-14T09:30:00.000Z'],
    ['auth-chain', 'incident', 'high', 'escalate', '001', ['auth-chain-fail-1', 'auth-chain-success', 'auth-chain-sudo'], '2026-10-15T10:00:00.000Z', '2026-10-15T10:40:00.000Z'],
    ['approved-admin', 'benign', 'low', 'monitor', '002', ['approved-admin-created', 'approved-admin-added', 'approved-admin-removed'], '2026-10-16T11:00:00.000Z', '2026-10-16T11:40:00.000Z'],
    ['service-persistence', 'incident', 'high', 'escalate', '002', ['service-persistence-process', 'service-persistence-installed'], '2026-10-17T12:00:00.000Z', '2026-10-17T12:40:00.000Z'],
    ['collection-gap', 'unknown', 'medium', 'verify', '003', ['collection-gap-last', 'collection-gap-disconnected'], '2026-10-18T13:00:00.000Z', '2026-10-18T13:40:00.000Z'],
    ['mixed-auth', 'benign', 'low', 'monitor', '002', ['mixed-auth-logon', 'mixed-auth-service', 'mixed-auth-failure-1'], '2026-10-19T14:00:00.000Z', '2026-10-19T14:40:00.000Z'],
    ['fim-change', 'incident', 'high', 'escalate', '001', ['fim-change-command', 'fim-change-config', 'fim-change-web'], '2026-10-20T15:00:00.000Z', '2026-10-20T15:40:00.000Z']
  ];
  const legacy = { format: 'wazuhroom-save', version: 1, dataset: 'wazuhroom-1', language: 'en', activeCaseId: 'fim-change', records: {} };
  for (const [id, verdict, priority, action, target, evidence, from, to] of oldCases) {
    const record = {
      query: 'rule.level >= 3 AND (data.srcport > 41000 OR data.win.eventdata.logonType:3)',
      filters: [{ field: 'data.srcport', value: 42022, negate: false, disabled: true }, { field: 'data.win.eventdata.logonType', value: 3, negate: false, disabled: true }],
      from, to, view: id === 'fim-change' ? 'fim' : 'events', evidence,
      documents: [id + '-scope', id + '-change', ...(id === 'mixed-auth' ? ['mixed-auth-exercise'] : [])],
      operations: ['events', 'range', 'search', 'detail', 'evidence', 'document', 'report'],
      report: { verdict, priority, action, target, facts: 'The original saved findings remain available.', nextStep: 'The original saved handoff remains available.' },
      completed: true,
      feedback: { passed: true, checks: ['verdict', 'priority', 'action', 'target', 'evidence', 'evidenceLimit', 'documents', 'operations', 'facts', 'nextStep'].map(key => ({ key, passed: true })), score: 100 },
      hint: 1, expanded: evidence[0]
    };
    record.completion = clone(record);
    legacy.records[id] = record;
  }
  // A later unsuccessful review must not erase an earlier valid completion.
  legacy.records.tutorial.report.verdict = 'incident';
  legacy.records.tutorial.report.facts = 'A later review draft, still saved by the old version.';
  legacy.records.tutorial.feedback = { passed: false, checks: [], score: 90 };
  // Older completed records without the optional snapshot are validated against their current report.
  delete legacy.records['fim-change'].completion;
  const original = clone(legacy);
  const restored = E.validateProgress(clone(legacy), C);
  assert.equal(restored.format, legacy.format);
  assert.equal(restored.version, legacy.version);
  assert.equal(restored.dataset, legacy.dataset);
  assert.equal(restored.language, 'en');
  assert.equal(restored.activeCaseId, 'fim-change');
  assert.equal(Object.values(restored.records).filter(record => record.completed).length, 7);
  assert.equal(JSON.stringify(restored).includes('"score"'), false);
  assert.equal(restored.records.tutorial.report.verdict, 'incident');
  assert.equal(restored.records.tutorial.feedback.passed, false);
  assert.equal(restored.records.tutorial.completion.report.verdict, 'unknown');
  assert.equal(restored.records.tutorial.completion.feedback.passed, true);
  for (const [id] of oldCases) {
    assert.deepEqual(restored.records[id].filters, original.records[id].filters, id);
    assert.equal(restored.records[id].query, original.records[id].query, id);
    assert.deepEqual(restored.records[id].evidence, original.records[id].evidence, id);
    assert.deepEqual(restored.records[id].documents, original.records[id].documents, id);
    assert.deepEqual(restored.records[id].report, original.records[id].report, id);
  }
  assert.deepEqual(legacy, original);
  const again = E.validateProgress(clone(restored), C);
  assert.equal(Object.values(again.records).filter(record => record.completed).length, 7);
  assert.equal(JSON.stringify(again).includes('"score"'), false);
});

test('UMD content and engine cooperate without CommonJS, browser APIs or network', () => {
  const context = vm.createContext({});
  for (const filename of ['content.js', 'engine.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '../src', filename), 'utf8'), context);
  const summary = vm.runInContext(`(() => {
    const p = WazuhEngine.createProgress(WazuhContent);
    const restored = WazuhEngine.validateProgress(JSON.parse(JSON.stringify(p)), WazuhContent);
    return JSON.stringify({ cases: Object.keys(restored.records).length, counts: WazuhContent.cases.map(c => WazuhEngine.search(c.events, {from:c.timeRange.from,to:c.timeRange.to}).length) });
  })()`, context);
  assert.deepEqual(JSON.parse(summary), { cases: C.cases.length, counts: C.cases.map(item => item.events.length) });
});
