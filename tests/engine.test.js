'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../src/engine.js');

const agents = [
  { id: '001', name: 'web-01', ip: '192.0.2.1', status: 'active', os: { name: 'Ubuntu Linux', platform: 'ubuntu', version: '24.04' }, lastKeepAlive: '2026-10-20T09:00:00Z' },
  { id: '002', name: 'win-01', ip: '192.0.2.2', status: 'disconnected', os: { name: 'Microsoft Windows', platform: 'windows', version: '11' }, lastKeepAlive: '2026-10-20T08:00:00Z' },
  { id: '010', name: 'web-02', ip: '192.0.2.10', status: 'active', os: { name: 'Debian Linux', platform: 'debian', version: '12' }, lastKeepAlive: '2026-10-20T09:00:00Z' }
];
const events = [
  { id: 'a', timestamp: '2026-10-20T09:00:00Z', agent: { id: '001', name: 'web-01', ip: '192.0.2.1' }, rule: { id: '100001', level: 3, description: 'Routine session accepted', groups: ['authentication', 'sshd'] }, decoder: { name: 'sshd' }, data: { srcip: '198.51.100.8', srcport: 22001, dstuser: 'alice' }, full_log: 'Accepted publickey for alice' },
  { id: 'b', timestamp: '2026-10-20T09:05:00Z', agent: { id: '002', name: 'win-01', ip: '192.0.2.2' }, rule: { id: '100002', level: 12, description: 'Local account added', groups: ['windows', 'account'], mitre: { id: ['T1136'], technique: ['Create Account'] } }, decoder: { name: 'windows_eventchannel' }, data: { win: { system: { eventID: '4720', computer: 'win-01' }, eventdata: { targetUserName: 'new-user', logonType: 3 } } }, full_log: 'A new user account was created' },
  { id: 'c', timestamp: '2026-10-20T09:10:00Z', agent: { id: '001', name: 'web-01', ip: '192.0.2.1' }, rule: { id: '100003', level: 7, description: 'File checksum changed', groups: ['syscheck'] }, decoder: { name: 'syscheck_integrity_changed' }, data: {}, full_log: 'File /etc/ssh/sshd_config checksum changed', syscheck: { path: '/etc/ssh/sshd_config', event: 'modified', sha256_before: 'a'.repeat(64), sha256_after: 'b'.repeat(64) } },
  { id: 'd', timestamp: '2026-10-20T09:15:00Z', agent: { id: '010', name: 'web-02', ip: '192.0.2.10' }, rule: { id: '100004', level: 10, description: 'Service started', groups: ['service'] }, decoder: { name: 'json' }, data: { action: 'start', srcip: null }, full_log: 'Service started (approved)' }
];
const lesson = {
  id: 'lesson-1', agents, events, documents: [{ id: 'doc-1' }, { id: 'doc-2' }],
  timeRange: { from: '2026-10-20T09:00:00Z', to: '2026-10-20T09:15:00Z' },
  steps: ['events', 'range', 'search', 'detail', 'evidence', 'document', 'report'].map(kind => ({ id: kind, kind })),
  answer: { verdict: 'incident', priority: 'high', action: 'escalate', target: '002', evidenceGroups: [['b'], ['c', 'd']], documentIds: ['doc-1'] }
};
const content = { version: 'wazuhroom-1', cases: [lesson] };
const ids = list => list.map(item => item.id);
const search = (query, extra = {}) => E.search(events, { query, ...extra });
const clone = value => JSON.parse(JSON.stringify(value));
const revisedCase = {
  ...clone(lesson), id: 'crypto-compromise', revision: 2,
  questions: [
    { id: 'webshellUri', acceptedAnswers: ['/room-lab/ops/inspect.php'] },
    { id: 'webshellPath', acceptedAnswers: ['/srv/training-web/room-lab/ops/inspect.php'] },
    { id: 'decodedText', acceptedAnswers: ['ROOM_OFFLINE_MARKER_ONLY'] }
  ]
};
const revisedContent = { version: 'wazuhroom-1', cases: [revisedCase] };
function passingRecord() {
  const record = E.createProgress(content).records[lesson.id];
  Object.assign(record, { evidence: ['b', 'c'], documents: ['doc-1'], operations: ['events', 'range', 'search', 'detail', 'evidence', 'document'], report: { verdict: 'incident', priority: 'high', action: 'escalate', target: '002', facts: 'The new account was observed on win-01.', nextStep: 'SOC should verify the recorded change scope.' } });
  return record;
}

test('dotted getters read only own data and never prototype properties', () => {
  assert.equal(E.get(events[1], 'data.win.system.eventID'), '4720');
  assert.equal(E.get(events[0], 'data.win.system.eventID'), undefined);
  assert.equal(E.get({}, 'toString'), undefined);
  assert.equal(E.get({}, '__proto__.polluted'), undefined);
  assert.equal(E.get({ value: Object.create({ secret: 1 }) }, 'value.secret'), undefined);
  assert.equal(E.get({ value: 0 }, 'value'), 0);
});

test('Base64 decoding returns inert UTF-8 text without browser or execution APIs', () => {
  assert.equal(E.decodeBase64Text('SGVsbG8='), 'Hello');
  assert.equal(E.decodeBase64Text(' Zm9v\nYmFy\t '), 'foobar');
  assert.equal(E.decodeBase64Text('44OG44K544OI'), 'テスト');
  assert.equal(E.decodeBase64Text(Buffer.from('ROOM_OFFLINE_MARKER_ONLY').toString('base64')), 'ROOM_OFFLINE_MARKER_ONLY');
  const codeLikeText = '<script>globalThis.__decodedExecution=true</script>';
  assert.equal(E.decodeBase64Text(Buffer.from(codeLikeText).toString('base64')), codeLikeText);
  assert.equal(globalThis.__decodedExecution, undefined);
  assert.equal(E.decodeBase64Text('YQ=='.repeat(1)), 'a');
  assert.equal(E.decodeBase64Text('YWFh'.repeat(1024)).length, 3072);
});

test('Base64 decoding rejects malformed padding, alternate alphabets, invalid UTF-8 and oversized input', () => {
  for (const input of ['', ' ', 'SGVsbG8', 'SGVsbG8===', 'SGVs=bG8', 'SGVsbG8_', 'SGVsbG8-', 'Zh==', 'Zm9=', 'AA==', '/w==', 'wyg=', 'data:text/plain;base64,SGVsbG8=', 'SGVs\u200bbG8=']) assert.throws(() => E.decodeBase64Text(input), Error, input);
  assert.throws(() => E.decodeBase64Text('YWFh'.repeat(1024) + ' '), /input/);
  assert.throws(() => E.decodeBase64Text(null), /input/);
  assert.equal(E.decodeBase64Text(Buffer.from('one\ntwo\tthree\r\n').toString('base64')), 'one\ntwo\tthree\r\n');
});

test('DQL typed equality, quoted phrases, nested fields and array memberships', () => {
  assert.deepEqual(ids(search('agent.id:001')), ['a', 'c']);
  assert.deepEqual(ids(search('rule.level:10')), ['d']);
  assert.deepEqual(ids(search('data.win.system.eventID:"4720"')), ['b']);
  assert.deepEqual(ids(search('rule.groups:sshd')), ['a']);
  assert.deepEqual(ids(search('rule.mitre.id:T1136')), ['b']);
  assert.deepEqual(ids(search('full_log:"new USER account"')), ['b']);
  assert.deepEqual(ids(search('rule.description:"checksum changed"')), ['c']);
  assert.deepEqual(ids(search('agent.name:WEB-01')), []);
  assert.throws(() => search('rule.level:"10"'), /unquoted number/);
  assert.throws(() => search('rule.level:high'), /numeric/);
  assert.throws(() => search('data.win.system.eventID > 4000'), /numeric fields/);
});

test('DQL uses NOT then AND then OR precedence and honors parentheses', () => {
  assert.deepEqual(ids(search('agent.id:001 OR agent.id:002 AND rule.level >= 10')), ['a', 'b', 'c']);
  assert.deepEqual(ids(search('(agent.id:001 OR agent.id:002) AND rule.level >= 10')), ['b']);
  assert.deepEqual(ids(search('NOT agent.id:001 AND rule.level >= 10')), ['b', 'd']);
  assert.deepEqual(ids(search('NOT (agent.id:001 OR agent.id:002)')), ['d']);
  assert.deepEqual(ids(search('NOT NOT agent.id:001')), ['a', 'c']);
  assert.deepEqual(ids(search('agent.id:001 and rule.level > 3 or agent.id:002')), ['b', 'c']);
});

test('DQL range endpoints, existence and absence are distinct', () => {
  assert.deepEqual(ids(search('rule.level >= 7 AND rule.level <= 10')), ['c', 'd']);
  assert.deepEqual(ids(search('rule.level > 7 AND rule.level < 12')), ['d']);
  assert.deepEqual(ids(search('syscheck.path:*')), ['c']);
  assert.deepEqual(ids(search('data.srcip:*')), ['a']);
  assert.deepEqual(ids(search('NOT data.srcip:198.51.100.8')), ['b', 'c', 'd']);
  assert.deepEqual(ids(search('data.srcip:* AND NOT data.srcip:198.51.100.8')), []);
  assert.deepEqual(ids(search('data.win.eventdata.subjectUserName:*')), []);
  assert.deepEqual(ids(search('data.win.eventdata.logonType:3')), ['b']);
});

test('process and HTTP teaching fields retain typed comparisons and distinct observations', () => {
  const telemetry = [
    { ...events[0], id: 'process-parent', data: { process: { pid: 1200, ppid: 1, name: 'web-worker', cmd: '/usr/sbin/web-worker', args: '--foreground', euser: 'www-data', cpu_pct: 1.5, start_time: '2026-10-20T08:59:00Z' } } },
    { ...events[0], id: 'process-child', data: { process: { pid: 1300, ppid: 1200, name: 'helper', cmd: '/tmp/lab-helper', args: '--pool pool.example.test:4444 --worker lab-1', euser: 'www-data', cpu_pct: 96.5, start_time: '2026-10-20T09:00:00Z' } } },
    { ...events[0], id: 'http-response', data: { http: { method: 'POST', status_code: 200, host: 'app.example.test', uri: '/upload?mode=preview', request_id: 'req-example-01', upload_name: 'sample.txt', body_summary: 'An upload request was recorded; request content is summarized.', response_summary: 'The HTTP response included Permission denied.' } } },
    { ...events[0], id: 'cron-entry', data: { schedule: '*/5 * * * *', command: '/tmp/lab-helper --worker lab-1', user: 'www-data' } }
  ];
  assert.deepEqual(ids(E.search(telemetry, { query: 'data.process.ppid:1200 AND data.process.cpu_pct >= 90' })), ['process-child']);
  assert.deepEqual(ids(E.search(telemetry, { query: 'data.process.cmd:/tmp/* AND data.process.args:"pool.example.test"' })), ['process-child']);
  assert.deepEqual(ids(E.search(telemetry, { query: 'data.http.status_code:200 AND data.http.response_summary:"permission denied"' })), ['http-response']);
  assert.deepEqual(ids(E.search(telemetry, { query: 'data.http.uri:"/upload?mode=preview"' })), ['http-response']);
  assert.deepEqual(ids(E.search(telemetry, { query: 'data.schedule:"*/5 * * * *"' })), ['cron-entry']);
  assert.deepEqual(ids(E.search(telemetry, { filters: [{ field: 'data.process.pid', value: 1300 }] })), ['process-child']);
  assert.throws(() => E.search(telemetry, { query: 'data.process.pid:"1300"' }), /unquoted number/);
  assert.throws(() => E.search(telemetry, { query: 'data.http.status_code:"200"' }), /unquoted number/);
  assert.throws(() => E.search(telemetry, { query: 'data.process.args:*pool*' }), /keyword/);
  assert.throws(() => E.search(telemetry, { filters: [{ field: 'data.http.status_code', value: '200' }] }), /typed/);
});

test('keyword wildcards are anchored and escaped punctuation stays literal', () => {
  assert.deepEqual(ids(search('agent.name:web-*')), ['a', 'c', 'd']);
  assert.deepEqual(ids(search('agent.name:*01')), ['a', 'b', 'c']);
  assert.deepEqual(ids(search('agent.ip:192.0.2.*')), ['a', 'b', 'c', 'd']);
  assert.deepEqual(ids(search('syscheck.path:/etc/*')), ['c']);
  assert.deepEqual(ids(search('agent.name:"web-*"')), []);
  assert.throws(() => search('full_log:*account*'), /keyword/);
  assert.deepEqual(ids(E.search([{ ...events[0], agent: { ...events[0].agent, name: 'web.+01' } }], { query: 'agent.name:web.+*' })), ['a']);
  assert.deepEqual(ids(search('agent.name:**web**01**')), ['a', 'c']);
  const longName = [{ ...events[0], agent: { ...events[0].agent, name: 'a'.repeat(2000) } }];
  assert.deepEqual(E.search(longName, { query: 'agent.name:' + '*a'.repeat(100) + '*b' }), []);
});

test('Windows paths in quoted DQL decode escaped backslashes exactly once', () => {
  const windowsPath = String.raw`C:\Program Files\Acme\agent.exe`;
  const windowsEvent = {
    ...events[1],
    data: { win: { eventdata: {
      imagePath: windowsPath,
      commandLine: '"' + windowsPath + '" --config "C:\\ProgramData\\Acme\\settings.json"'
    } } }
  };
  const query = String.raw`data.win.eventdata.imagePath: "C:\\Program Files\\Acme\\agent.exe"`;
  assert.deepEqual(ids(E.search([windowsEvent], { query })), ['b']);
  assert.deepEqual(ids(E.search([windowsEvent], { query: String.raw`data.win.eventdata.commandLine: "\"C:\\Program Files\\Acme\\agent.exe\""` })), ['b']);
  assert.deepEqual(ids(E.search([windowsEvent], { filters: [{ field: 'data.win.eventdata.imagePath', value: windowsPath }] })), ['b']);
  const overEscaped = { ...windowsEvent, data: { win: { eventdata: { imagePath: windowsPath.replaceAll('\\', '\\\\') } } } };
  assert.deepEqual(E.search([overEscaped], { query }), []);
  assert.throws(() => E.search([windowsEvent], { query: String.raw`data.win.eventdata.imagePath: "C:\Program Files\Acme\agent.exe"` }), /escapes/);
  assert.throws(() => E.search([windowsEvent], { query: String.raw`data.win.eventdata.imagePath: C:\Program Files\Acme\agent.exe` }), /syntax|character|token/i);
});

test('invalid, unsupported and excessively nested queries throw instead of returning all', () => {
  for (const query of ['rule.leevl:10', 'unknown:foo', 'agent.name=', 'agent.name:web-01 agent.id:001', 'rule.level >=', '(agent.id:001', 'agent.id:001)', 'agent.name:"unclosed', 'agent.name:/web/i', 'rule.level:[1 TO 9]', 'agent.name:web?', 'rule.level!=10', 'agent.name:web-01 XOR agent.id:001', 'rule.level:Infinity', 'rule.level:1e2', 'agent.name:AND', 'full_log:""', 'agent.name:"bad\\nvalue"', 'rule.level >= 9 && agent.id:001', 'agent.id:001 OR']) {
    if (query === 'agent.name:/web/i') {
      // Slash characters are legitimate keyword data, never executable regex syntax.
      assert.deepEqual(search(query), []);
    } else assert.throws(() => search(query), Error, query);
  }
  assert.throws(() => search('('.repeat(25) + 'agent.id:001' + ')'.repeat(25)), /nesting/);
  assert.throws(() => search('NOT '.repeat(25) + 'agent.id:001'), /nesting/);
  assert.throws(() => search('x'.repeat(2001)), /query/);
  assert.deepEqual(ids(search('')), ['a', 'b', 'c', 'd']);
});

test('typed filter chips support include, exclude, disable and array values', () => {
  assert.deepEqual(ids(search('', { filters: [{ field: 'rule.level', value: 12 }] })), ['b']);
  assert.deepEqual(ids(search('', { filters: [{ field: 'rule.groups', value: 'sshd' }] })), ['a']);
  assert.deepEqual(ids(search('', { filters: [{ field: 'agent.id', value: '001', negate: true }] })), ['b', 'd']);
  assert.deepEqual(ids(search('', { filters: [{ field: 'agent.id', value: '001', disabled: true }] })), ['a', 'b', 'c', 'd']);
  assert.deepEqual(ids(search('', { filters: [{ field: 'data.srcip', value: '198.51.100.8', negate: true }] })), ['b', 'c', 'd']);
  assert.throws(() => search('', { filters: [{ field: 'rule.level', value: '12' }] }), /typed/);
  assert.throws(() => search('', { filters: [{ field: 'agent.id', value: 1 }] }), /typed/);
  assert.throws(() => search('', { filters: [{ field: 'missing', value: 'x', disabled: true }] }), /field/);
  assert.throws(() => search('', { filters: [{ field: 'agent.id', value: '001', negate: 'false' }] }), /flag/);
});

test('time filtering is inclusive, UTC-based and independent of query and FIM module', () => {
  assert.deepEqual(ids(search('', { from: '2026-10-20T09:05:00Z', to: '2026-10-20T09:10:00Z' })), ['b', 'c']);
  assert.deepEqual(ids(search('', { from: '2026-10-20T09:05:00.001Z', to: '2026-10-20T09:10:00Z' })), ['c']);
  assert.deepEqual(ids(search('', { module: 'fim' })), ['c']);
  assert.deepEqual(ids(search('rule.level:3', { module: 'fim' })), []);
  assert.throws(() => search('', { from: '2026-10-20T09:15:00Z', to: '2026-10-20T09:00:00Z' }), /start time/);
  assert.throws(() => search('', { from: '2026-02-30T09:00:00Z' }), /start time/);
  assert.throws(() => search('', { from: '2026-10-20T09:00:00+09:00' }), /UTC/);
  assert.throws(() => search('', { module: 'agents' }), /module/);
});

test('WQL agent subset uses explicit fields, operators, substring matching and precedence', () => {
  assert.deepEqual(ids(E.searchAgents(agents, 'status=disconnected')), ['002']);
  assert.deepEqual(ids(E.searchAgents(agents, 'name~web')), ['001', '010']);
  assert.deepEqual(ids(E.searchAgents(agents, 'os.name~Windows')), ['002']);
  assert.deepEqual(ids(E.searchAgents(agents, 'os.name~windows')), []);
  assert.deepEqual(ids(E.searchAgents(agents, 'name!="web-01"')), ['002', '010']);
  assert.deepEqual(ids(E.searchAgents(agents, 'id>002')), ['010']);
  assert.deepEqual(ids(E.searchAgents(agents, 'id<010')), ['001', '002']);
  assert.deepEqual(ids(E.searchAgents(agents, 'name~web or status=disconnected and os.platform=debian')), ['001', '010']);
  assert.deepEqual(ids(E.searchAgents(agents, '(name~web or status=disconnected) and os.platform=debian')), ['010']);
  for (const query of ['os.version=11', 'status:active', 'name=*web*', 'id>=001', 'NOT status=active', 'status=active;name~web', 'status=active,name~web', 'status=active AND name~web', 'status=active OR name~web']) assert.throws(() => E.searchAgents(agents, query), Error, query);
  assert.deepEqual(ids(E.searchAgents([{ id: '001' }], 'status!=active')), []);
});

test('assessment requires decisions, AND-of-OR evidence, documentation and actual operations', () => {
  const record = passingRecord();
  assert.deepEqual(E.assess(lesson, record), { passed: true, checks: ['verdict', 'priority', 'action', 'target', 'evidence', 'evidenceLimit', 'documents', 'operations', 'facts', 'nextStep'].map(key => ({ key, passed: true })) });
  record.evidence = ['b', 'd'];
  assert.equal(E.assess(lesson, record).passed, true);
  for (const mutation of [r => r.report.verdict = 'unknown', r => r.report.target = '001', r => r.evidence = ['a', 'c'], r => r.evidence = ['b', 'b', 'c'], r => r.evidence = ['b', 'c', 'foreign'], r => r.documents = [], r => r.operations = ['report'], r => r.report.facts = 'short', r => r.report.nextStep = ' '.repeat(12)]) {
    const changed = passingRecord(); mutation(changed); assert.equal(E.assess(lesson, changed).passed, false);
  }
  // Training text is checked structurally, never claimed to be semantically correct.
  const structural = passingRecord(); structural.report.facts = 'x'.repeat(10); assert.equal(E.assess(lesson, structural).passed, true);
});

test('case-specific investigation answers are separate exact checks with case-sensitive paths', () => {
  const record = passingRecord();
  record.caseRevision = 2;
  record.report.answers = Object.fromEntries(revisedCase.questions.map(question => [question.id, question.acceptedAnswers[0]]));
  assert.equal(E.assess(revisedCase, record).passed, true);
  assert.equal(E.assess(revisedCase, record).checks.filter(check => check.key.startsWith('question:')).length, 3);
  record.report.answers.webshellUri = '  /room-lab/ops/inspect.php \n';
  assert.equal(E.assess(revisedCase, record).passed, true);
  for (const question of revisedCase.questions) {
    const wrong = clone(record);
    wrong.report.answers[question.id] = '';
    assert.equal(E.assess(revisedCase, wrong).checks.find(check => check.key === 'question:' + question.id).passed, false);
    assert.equal(E.assess(revisedCase, wrong).passed, false);
  }
  record.report.answers.webshellPath = '/srv/training-web/room-lab/ops/INSPECT.php';
  assert.equal(E.assess(revisedCase, record).passed, false);
  record.report.answers.webshellPath = '/srv/training-web/room-lab/ops/inspect.php?mode=upload';
  assert.equal(E.assess(revisedCase, record).passed, false);
  const multilineCase = clone(revisedCase);
  multilineCase.questions[2] = { ...multilineCase.questions[2], multiline: true, acceptedAnswers: ['MARKER\nNO_EXECUTION'] };
  record.report.answers.webshellPath = '/srv/training-web/room-lab/ops/inspect.php';
  record.report.answers.decodedText = '  MARKER\r\nNO_EXECUTION\r\n';
  assert.equal(E.assess(multilineCase, record).passed, true);
  record.report.answers.decodedText = 'MARKER\nno_execution';
  assert.equal(E.assess(multilineCase, record).passed, false);
});

test('revision-two saves require complete known answer fields and revalidate successful snapshots', () => {
  const fresh = E.createProgress(revisedContent);
  assert.equal(fresh.records['crypto-compromise'].caseRevision, 2);
  assert.deepEqual(fresh.records['crypto-compromise'].report.answers, { webshellUri: '', webshellPath: '', decodedText: '' });
  assert.deepEqual(E.validateProgress(clone(fresh), revisedContent), fresh);
  for (const mutation of [
    record => delete record.report.answers,
    record => delete record.report.answers.decodedText,
    record => record.report.answers.extra = 'invented',
    record => record.report.answers.webshellUri = 42,
    record => record.report.answers.decodedText = 'x'.repeat(4097),
    record => delete record.caseRevision,
    record => record.caseRevision = 1,
    record => record.caseRevision = 3,
    record => record.completed = true
  ]) {
    const changed = clone(fresh); mutation(changed.records['crypto-compromise']);
    assert.throws(() => E.validateProgress(changed, revisedContent));
  }
  const good = passingRecord();
  good.caseRevision = 2;
  good.report.answers = Object.fromEntries(revisedCase.questions.map(question => [question.id, question.acceptedAnswers[0]]));
  good.completed = true; good.feedback = E.assess(revisedCase, good); good.completion = clone(good);
  good.report.answers.decodedText = 'Unfinished review answer'; good.feedback = E.assess(revisedCase, good);
  fresh.records['crypto-compromise'] = good;
  const restored = E.validateProgress(clone(fresh), revisedContent).records['crypto-compromise'];
  assert.equal(restored.completed, true);
  assert.equal(restored.feedback.passed, false);
  assert.equal(restored.completion.feedback.passed, true);
  assert.equal(restored.report.answers.decodedText, 'Unfinished review answer');
  const tampered = clone(fresh); tampered.records['crypto-compromise'].completion.report.answers.webshellPath = '/wrong/path';
  assert.throws(() => E.validateProgress(tampered, revisedContent), /does not pass/);
});

test('legacy crypto completion reopens only revised questions and preserves both historical submission and review draft', () => {
  const old = passingRecord();
  old.completed = true; old.feedback = { passed: true, checks: [], score: 100 }; old.completion = clone(old);
  old.report.facts = 'My later review notes are still unfinished.';
  old.report.verdict = 'unknown'; old.evidence = ['b'];
  const progress = { format: 'wazuhroom-save', version: 1, dataset: 'wazuhroom-1', language: 'en', activeCaseId: 'crypto-compromise', records: { 'crypto-compromise': old } };
  const before = clone(progress);
  const restored = E.validateProgress(progress, revisedContent);
  const record = restored.records['crypto-compromise'];
  assert.equal(record.caseRevision, 2);
  assert.equal(record.completed, false);
  assert.equal(Object.hasOwn(record, 'completion'), false);
  assert.equal(record.report.facts, old.report.facts);
  assert.equal(record.report.verdict, 'unknown');
  assert.deepEqual(record.evidence, ['b']);
  assert.deepEqual(record.report.answers, { webshellUri: '', webshellPath: '', decodedText: '' });
  assert.deepEqual(record.previousSubmission, { caseRevision: 1, report: old.completion.report, evidence: old.completion.evidence, documents: old.completion.documents });
  assert.equal(Object.hasOwn(record.previousSubmission, 'completed'), false);
  assert.equal(record.feedback.passed, false);
  assert.deepEqual(progress, before);
  assert.deepEqual(E.validateProgress(clone(restored), revisedContent), restored);
  const missingSnapshot = clone(progress); delete missingSnapshot.records['crypto-compromise'].completion;
  const fallback = E.validateProgress(missingSnapshot, revisedContent).records['crypto-compromise'];
  assert.equal(fallback.previousSubmission.report.facts, old.report.facts);
  const unfinished = clone(progress); delete unfinished.records['crypto-compromise'].completion; unfinished.records['crypto-compromise'].completed = false;
  assert.equal(Object.hasOwn(E.validateProgress(unfinished, revisedContent).records['crypto-compromise'], 'previousSubmission'), false);
  const wrongArchive = clone(restored); wrongArchive.records['crypto-compromise'].previousSubmission.evidence = ['foreign'];
  assert.throws(() => E.validateProgress(wrongArchive, revisedContent), /previous evidence/);
  const nestedArchive = clone(restored); nestedArchive.records['crypto-compromise'].previousSubmission.completion = {};
  assert.throws(() => E.validateProgress(nestedArchive, revisedContent), /previous submission/);
});

test('evidence budget prevents select-all completion in a larger case', () => {
  const bigger = { ...lesson, events: [...events, { ...events[0], id: 'e' }] };
  const record = passingRecord(); record.evidence = ['a', 'b', 'c', 'd', 'e'];
  const result = E.assess(bigger, record);
  assert.equal(result.passed, false);
  assert.equal(result.checks.find(check => check.key === 'evidence').passed, true);
  assert.equal(result.checks.find(check => check.key === 'evidenceLimit').passed, false);
});

test('progress defaults roundtrip and validated saves are deep clones', () => {
  const original = E.createProgress(content);
  const restored = E.validateProgress(clone(original), content);
  assert.deepEqual(restored, original);
  restored.records[lesson.id].report.facts = 'independent';
  assert.equal(original.records[lesson.id].report.facts, '');
  assert.equal(original.language, 'ja');
  assert.equal(original.records[lesson.id].view, 'overview');
});

test('completed saves re-assess snapshots while preserving later unsuccessful drafts', () => {
  const progress = E.createProgress(content), record = passingRecord();
  record.completed = true; record.feedback = { score: -5, passed: false };
  record.completion = clone({ ...record, feedback: null });
  record.report.verdict = 'unknown'; record.evidence = [];
  progress.records[lesson.id] = record;
  const restored = E.validateProgress(progress, content).records[lesson.id];
  assert.equal(restored.completed, true);
  assert.equal(restored.feedback.passed, false);
  assert.equal(restored.completion.feedback.passed, true);
  assert.equal(Object.hasOwn(restored.completion.feedback, 'score'), false);
  assert.equal(restored.completion.report.verdict, 'incident');
  assert.equal(restored.report.verdict, 'unknown');
  restored.completion.evidence.length = 0;
  assert.equal(record.completion.evidence.length, 2);
});

test('forged completion, score and foreign IDs do not produce a passing import', () => {
  const baseline = E.createProgress(content);
  for (const mutation of [
    p => p.records[lesson.id].completed = true,
    p => p.records[lesson.id].evidence = ['foreign'],
    p => p.records[lesson.id].documents = ['foreign'],
    p => p.records[lesson.id].report.target = '999',
    p => p.records[lesson.id].expanded = 'foreign',
    p => p.records[lesson.id].operations = ['events', 'events'],
    p => p.records[lesson.id].query = 'unknown:field',
    p => p.records[lesson.id].hint = 4,
    p => p.records[lesson.id].view = 'rules',
    p => p.records[lesson.id].completion = clone(p.records[lesson.id]),
    p => p.activeCaseId = 'other',
    p => p.dataset = 'socroom-3',
    p => p.language = 'xx',
    p => p.records.extra = clone(p.records[lesson.id]),
    p => delete p.records[lesson.id].report.facts
  ]) {
    const changed = clone(baseline); mutation(changed); assert.throws(() => E.validateProgress(changed, content));
  }
  baseline.records[lesson.id].feedback = { passed: true, score: 100, checks: [] };
  const sanitized = E.validateProgress(baseline, content);
  assert.equal(sanitized.records[lesson.id].completed, false);
  assert.equal(sanitized.records[lesson.id].feedback.passed, false);
  assert.equal(Object.hasOwn(sanitized.records[lesson.id].feedback, 'score'), false);
});

test('tampered successful snapshots are rejected even when draft passes', () => {
  const progress = E.createProgress(content), record = passingRecord();
  record.completed = true; record.completion = clone(record); record.completion.report.target = '001';
  progress.records[lesson.id] = record;
  assert.throws(() => E.validateProgress(progress, content), /does not pass/);
  record.completion = clone(passingRecord()); record.completion.completion = clone(passingRecord());
  assert.throws(() => E.validateProgress(progress, content), /Nested/);
});

test('prototype injection, cycles and invalid object types are rejected without mutation', () => {
  const baseline = E.createProgress(content), before = clone(baseline);
  const injected = JSON.parse(JSON.stringify(baseline).replace('"query":""', '"query":"","__proto__":{"polluted":true}'));
  assert.throws(() => E.validateProgress(injected, content), /Unsafe/);
  const nested = clone(baseline); nested.records[lesson.id].feedback = { constructor: { prototype: { polluted: true } } };
  assert.throws(() => E.validateProgress(nested, content), /Unsafe/);
  const cyclic = clone(baseline); cyclic.records[lesson.id].feedback = cyclic;
  assert.throws(() => E.validateProgress(cyclic, content), /object/);
  const strange = clone(baseline); strange.records[lesson.id].feedback = new Date();
  assert.throws(() => E.validateProgress(strange, content), /object/);
  assert.deepEqual(baseline, before);
  assert.equal({}.polluted, undefined);
});

test('only a complete original seven-case save can receive the new eighth case', () => {
  const originalIds = ['tutorial', 'auth-chain', 'approved-admin', 'service-persistence', 'collection-gap', 'mixed-auth', 'fim-change'];
  const priorContent = { version: 'wazuhroom-1', cases: originalIds.map(id => ({ ...clone(lesson), id })) };
  const expandedContent = { ...priorContent, cases: [...priorContent.cases, { ...clone(lesson), id: 'crypto-compromise' }] };
  const previous = E.createProgress(priorContent);
  previous.language = 'en';
  previous.activeCaseId = 'fim-change';
  const complete = passingRecord();
  complete.completed = true;
  complete.feedback = E.assess(priorContent.cases[0], complete);
  complete.completion = clone(complete);
  complete.report.verdict = 'unknown';
  complete.report.facts = 'A review draft after earlier completion.';
  complete.feedback = E.assess(priorContent.cases[0], complete);
  previous.records.tutorial = complete;
  previous.records['fim-change'].query = 'rule.level >= 7';
  previous.records['fim-change'].filters = [{ field: 'agent.id', value: '001', negate: false, disabled: false }];
  previous.records['fim-change'].evidence = ['c'];
  previous.records['fim-change'].documents = ['doc-1'];
  previous.records['fim-change'].operations = ['events', 'search', 'detail', 'evidence', 'document'];
  previous.records['fim-change'].report.facts = 'Unfinished observations to continue later.';
  const before = clone(previous);
  const restored = E.validateProgress(previous, expandedContent);
  assert.equal(restored.dataset, 'wazuhroom-1');
  assert.equal(restored.version, 1);
  assert.equal(restored.language, 'en');
  assert.equal(restored.activeCaseId, 'fim-change');
  assert.equal(Object.keys(restored.records).length, 8);
  assert.deepEqual(restored.records['crypto-compromise'], E.createProgress(expandedContent).records['crypto-compromise']);
  assert.equal(restored.records.tutorial.completed, true);
  assert.equal(restored.records.tutorial.feedback.passed, false);
  assert.equal(restored.records.tutorial.completion.feedback.passed, true);
  assert.equal(restored.records.tutorial.report.facts, complete.report.facts);
  assert.deepEqual(restored.records['fim-change'], previous.records['fim-change']);
  assert.deepEqual(previous, before);
  assert.deepEqual(E.validateProgress(clone(restored), expandedContent), restored);

  for (const id of originalIds) {
    const missing = clone(previous);
    delete missing.records[id];
    assert.throws(() => E.validateProgress(missing, expandedContent), /records/, id);
  }
  const unknown = clone(previous);
  unknown.records['unknown-case'] = clone(previous.records['auth-chain']);
  assert.throws(() => E.validateProgress(unknown, expandedContent), /records/);
  const absentActive = clone(previous);
  absentActive.activeCaseId = 'crypto-compromise';
  assert.throws(() => E.validateProgress(absentActive, expandedContent), /active case/);
  const corruptNew = clone(restored);
  corruptNew.records['crypto-compromise'].completed = true;
  assert.throws(() => E.validateProgress(corruptNew, expandedContent), /does not pass/);
  const sparse = { ...content, cases: [...content.cases, { ...clone(lesson), id: 'crypto-compromise' }] };
  assert.throws(() => E.validateProgress(E.createProgress(content), sparse), /records/);
});
