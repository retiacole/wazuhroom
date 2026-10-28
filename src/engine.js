(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WazuhEngine = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const UNSAFE = new Set(['__proto__', 'prototype', 'constructor']);
  const MAX_QUERY = 2000;
  const STEPS = ['events', 'range', 'search', 'detail', 'evidence', 'document', 'report'];
  const VIEWS = ['overview', 'agents', 'events', 'fim'];
  const CHOICES = {
    verdict: ['', 'incident', 'benign', 'unknown'],
    priority: ['', 'high', 'medium', 'low'],
    action: ['', 'escalate', 'monitor', 'verify']
  };
  const FIELD_TYPES = Object.freeze(Object.assign(Object.create(null), {
    id: 'keyword', timestamp: 'keyword',
    'agent.id': 'keyword', 'agent.name': 'keyword', 'agent.ip': 'keyword',
    'rule.id': 'keyword', 'rule.level': 'number', 'rule.description': 'text',
    'rule.groups': 'keyword', 'rule.mitre.id': 'keyword', 'rule.mitre.technique': 'keyword',
    'decoder.name': 'keyword', full_log: 'text',
    'syscheck.path': 'keyword', 'syscheck.event': 'keyword',
    'syscheck.sha256_before': 'keyword', 'syscheck.sha256_after': 'keyword',
    // These are the room's established teaching types, not a claim about every Wazuh index mapping.
    // Keep them stable so v0.1 numeric query/filter saves remain executable.
    'data.srcip': 'keyword', 'data.dstip': 'keyword', 'data.srcport': 'number', 'data.dstport': 'number',
    'data.srcuser': 'keyword', 'data.dstuser': 'keyword', 'data.user': 'keyword',
    'data.action': 'keyword', 'data.status': 'keyword', 'data.lastKeepAlive': 'keyword',
    'data.service': 'keyword', 'data.path': 'keyword', 'data.sha256': 'keyword', 'data.command': 'text',
    'data.win.system.eventID': 'keyword', 'data.win.system.providerName': 'keyword',
    'data.win.system.computer': 'keyword', 'data.win.system.channel': 'keyword',
    'data.win.eventdata.subjectUserName': 'keyword', 'data.win.eventdata.targetUserName': 'keyword',
    'data.win.eventdata.memberName': 'keyword', 'data.win.eventdata.targetSid': 'keyword',
    'data.win.eventdata.targetDomainName': 'keyword', 'data.win.eventdata.ipAddress': 'keyword',
    'data.win.eventdata.image': 'keyword', 'data.win.eventdata.commandLine': 'text',
    'data.win.eventdata.parentImage': 'keyword', 'data.win.eventdata.user': 'keyword',
    'data.win.eventdata.newProcessName': 'keyword', 'data.win.eventdata.parentProcessName': 'keyword',
    'data.win.eventdata.serviceName': 'keyword', 'data.win.eventdata.imagePath': 'keyword',
    'data.win.eventdata.startType': 'keyword', 'data.win.eventdata.accountName': 'keyword',
    'data.win.eventdata.logonType': 'number', 'data.win.eventdata.processId': 'number', 'data.win.eventdata.action': 'keyword'
  }));
  const AGENT_TYPES = Object.freeze({ id: 'keyword', name: 'keyword', ip: 'keyword', status: 'keyword', 'os.name': 'keyword', 'os.platform': 'keyword' });

  function fail(message) { throw new Error(message); }
  function own(object, key) { return Object.prototype.hasOwnProperty.call(object, key); }
  function plain(value) { return !!value && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)); }
  function get(object, dottedPath) {
    if (typeof dottedPath !== 'string' || !dottedPath || dottedPath.split('.').some(part => !part || UNSAFE.has(part))) return undefined;
    let value = object;
    for (const part of dottedPath.split('.')) {
      if (value == null || typeof value !== 'object' || !own(value, part)) return undefined;
      value = value[part];
    }
    return value;
  }
  function values(value) { return (Array.isArray(value) ? value.flat(2) : [value]).filter(v => v !== null && v !== undefined); }
  function queryError(message, at) { fail('Query: ' + message + (at === undefined ? '' : ' (position ' + (at + 1) + ')')); }
  function scalarString(value, label, maximum = MAX_QUERY) {
    if (typeof value !== 'string' || value.length > maximum) fail('Invalid ' + label + '.');
    return value;
  }
  function tokenize(query) {
    scalarString(query, 'query');
    const tokens = [];
    let i = 0;
    while (i < query.length) {
      if (/\s/.test(query[i])) { i++; continue; }
      const at = i, character = query[i];
      if ('():'.includes(character)) { tokens.push({ type: character, value: character, at }); i++; }
      else if ('><=!~'.includes(character)) {
        let value = query[i++];
        if (query[i] === '=') value += query[i++];
        tokens.push({ type: 'operator', value, at });
      } else if (character === '"') {
        i++;
        let value = '', closed = false;
        while (i < query.length) {
          const current = query[i++];
          if (current === '"') { closed = true; break; }
          if (current === '\\') {
            const next = query[i++];
            if (next !== '"' && next !== '\\') queryError('Only \\" and \\\\ escapes are supported inside quotes.', i - 2);
            value += next;
          } else value += current;
        }
        if (!closed) queryError('Unclosed quoted value.', at);
        tokens.push({ type: 'string', value, at });
      } else {
        let value = '';
        while (i < query.length && !/[\s():><=!~"]/.test(query[i])) value += query[i++];
        if (!value || /[\[\]{}?,;|&\\]/.test(value)) queryError('Unsupported character or syntax. Quote literal punctuation.', at);
        tokens.push({ type: 'word', value, at });
      }
      if (tokens.length > 256) queryError('Too many query terms.');
    }
    return tokens;
  }
  function fieldType(field, mapping) {
    if (typeof field !== 'string' || !own(mapping, field)) queryError('Unsupported field: ' + field);
    return mapping[field];
  }
  function numberValue(value, at) {
    if (!/^-?(?:\d+(?:\.\d+)?|\.\d+)$/.test(String(value))) queryError('A numeric value is required.', at);
    const result = Number(value);
    if (!Number.isFinite(result)) queryError('A finite numeric value is required.', at);
    return result;
  }
  function wildcardMatches(value, pattern) {
    // Match only literal characters and *, without compiling user input as a regex.
    let position = 0, cursor = 0, star = -1, retry = 0;
    while (position < value.length) {
      if (pattern[cursor] === '*') { star = cursor++; retry = position; }
      else if (pattern[cursor] === value[position]) { cursor++; position++; }
      else if (star !== -1) { cursor = star + 1; position = ++retry; }
      else return false;
    }
    while (pattern[cursor] === '*') cursor++;
    return cursor === pattern.length;
  }
  function dqlPredicate(field, operator, token) {
    const type = fieldType(field, FIELD_TYPES), expected = token.value;
    if (operator === ':' && token.type === 'word' && expected === '*') return object => values(get(object, field)).length > 0;
    if (operator !== ':' && type !== 'number') queryError('Range comparisons are supported only for numeric fields.', token.at);
    if (type === 'number') {
      if (token.type === 'string') queryError('Numeric fields require an unquoted number.', token.at);
      const n = numberValue(expected, token.at);
      return object => values(get(object, field)).some(value => typeof value === 'number' && Number.isFinite(value) && ({ ':': () => value === n, '>': () => value > n, '>=': () => value >= n, '<': () => value < n, '<=': () => value <= n }[operator])());
    }
    if (token.type === 'word' && expected.includes('*')) {
      if (type !== 'keyword') queryError('Wildcards are supported only for keyword fields.', token.at);
      return object => values(get(object, field)).some(value => typeof value === 'string' && wildcardMatches(value, expected));
    }
    if (type === 'text') {
      const phrase = expected.toLowerCase();
      if (!phrase) queryError('A text search value must not be empty.', token.at);
      return object => values(get(object, field)).some(value => typeof value === 'string' && value.toLowerCase().includes(phrase));
    }
    return object => values(get(object, field)).some(value => typeof value === 'string' && value === expected);
  }
  function wqlPredicate(field, operator, token) {
    fieldType(field, AGENT_TYPES);
    if (token.type === 'word' && token.value.includes('*')) queryError('WQL wildcards are unsupported; use ~ for substring matching.', token.at);
    const expected = token.value;
    if (operator === '~') return object => values(get(object, field)).some(value => typeof value === 'string' && value.includes(expected));
    return object => {
      const present = values(get(object, field));
      if (!present.length) return false;
      if (operator === '!=') return present.every(value => typeof value === 'string' && value !== expected);
      return present.some(value => typeof value === 'string' && ({ '=': () => value === expected, '>': () => value > expected, '<': () => value < expected }[operator])());
    };
  }
  function parse(query, mode) {
    const tokens = tokenize(query);
    if (!tokens.length) return () => true;
    let index = 0, depth = 0;
    const peek = () => tokens[index];
    const isWord = value => peek()?.type === 'word' && (mode === 'wql' ? peek().value === value.toLowerCase() : peek().value.toUpperCase() === value);
    const accept = type => { if (peek()?.type !== type) return null; return tokens[index++]; };
    function primary() {
      if (++depth > 24) queryError('Query nesting is too deep.');
      let result;
      if (accept('(')) {
        result = or();
        if (!accept(')')) queryError('Expected a closing parenthesis.', peek()?.at);
      } else {
        const field = accept('word');
        if (!field) queryError('Expected a field name.', peek()?.at);
        const operator = mode === 'dql' ? (accept(':') || accept('operator')) : accept('operator');
        const valid = mode === 'dql' ? [':', '>', '>=', '<', '<='] : ['=', '!=', '~', '>', '<'];
        if (!operator || !valid.includes(operator.value)) queryError('Unsupported or missing ' + mode.toUpperCase() + ' operator.', operator?.at ?? peek()?.at);
        const value = peek();
        if (!value || !['word', 'string'].includes(value.type) || (value.type === 'word' && /^(AND|OR|NOT)$/i.test(value.value))) queryError('Expected a value. Quote words such as AND.', value?.at);
        index++;
        result = mode === 'dql' ? dqlPredicate(field.value, operator.value, value) : wqlPredicate(field.value, operator.value, value);
      }
      depth--;
      return result;
    }
    function unary() {
      if (mode === 'dql' && isWord('NOT')) {
        index++;
        if (++depth > 24) queryError('Query nesting is too deep.');
        const predicate = unary();
        depth--;
        return object => !predicate(object);
      }
      return primary();
    }
    function and() {
      let result = unary();
      while (isWord('AND')) { index++; const left = result, right = unary(); result = object => left(object) && right(object); }
      return result;
    }
    function or() {
      let result = and();
      while (isWord('OR')) { index++; const left = result, right = and(); result = object => left(object) || right(object); }
      return result;
    }
    const predicate = or();
    if (index !== tokens.length) queryError('Unexpected token. Use an explicit AND or OR between conditions.', peek().at);
    return predicate;
  }
  function dateValue(value, label) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) fail('Invalid ' + label + '; use an ISO UTC timestamp.');
    const milliseconds = Date.parse(value);
    if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 19) !== value.slice(0, 19)) fail('Invalid ' + label + '.');
    return milliseconds;
  }
  function timeBounds(from, to) {
    const lower = from === '' || from === undefined ? -Infinity : dateValue(from, 'start time');
    const upper = to === '' || to === undefined ? Infinity : dateValue(to, 'end time');
    if (lower > upper) fail('The start time must be before or equal to the end time.');
    return [lower, upper];
  }
  function filterShape(filter) {
    if (!plain(filter) || Object.keys(filter).some(key => !['field', 'value', 'negate', 'disabled'].includes(key))) fail('Invalid filter.');
    const type = fieldType(filter.field, FIELD_TYPES);
    if (typeof filter.value !== (type === 'number' ? 'number' : 'string') || (type === 'number' && !Number.isFinite(filter.value)) || (type !== 'number' && filter.value.length > 2000)) fail('Invalid typed filter value.');
    if ((own(filter, 'negate') && typeof filter.negate !== 'boolean') || (own(filter, 'disabled') && typeof filter.disabled !== 'boolean')) fail('Invalid filter flag.');
    return { field: filter.field, value: filter.value, negate: filter.negate ?? false, disabled: filter.disabled ?? false };
  }
  function filterPredicate(filter) {
    const parsed = filterShape(filter);
    return object => {
      if (parsed.disabled) return true;
      const matches = values(get(object, parsed.field)).some(value => value === parsed.value);
      return parsed.negate ? !matches : matches;
    };
  }
  function search(events, options = {}) {
    if (!Array.isArray(events) || !plain(options)) fail('Invalid search input.');
    if (Object.keys(options).some(key => !['query', 'filters', 'from', 'to', 'module'].includes(key))) fail('Unsupported search option.');
    const { query = '', filters = [], from = '', to = '', module = 'events' } = options;
    if (!['events', 'fim'].includes(module)) fail('Unsupported event module.');
    if (!Array.isArray(filters) || filters.length > 30) fail('Invalid filters.');
    const predicate = parse(query, 'dql'), filterTests = filters.map(filterPredicate), [lower, upper] = timeBounds(from, to);
    return events.filter(event => {
      const at = Date.parse(event.timestamp);
      return Number.isFinite(at) && at >= lower && at <= upper && (module !== 'fim' || (plain(event.syscheck) && typeof event.syscheck.path === 'string')) && predicate(event) && filterTests.every(test => test(event));
    });
  }
  function searchAgents(agents, query = '') {
    if (!Array.isArray(agents)) fail('Invalid agents.');
    const predicate = parse(query, 'wql');
    return agents.filter(predicate);
  }
  function createProgress(content) {
    if (!plain(content) || !Array.isArray(content.cases) || !content.cases.length) fail('Invalid content.');
    const records = {};
    for (const item of content.cases) {
      if (UNSAFE.has(item.id) || own(records, item.id)) fail('Invalid or duplicate case ID.');
      records[item.id] = { query: '', filters: [], from: item.timeRange.from, to: item.timeRange.to, view: 'overview', evidence: [], documents: [], operations: [], report: { verdict: '', priority: '', action: '', target: '', facts: '', nextStep: '' }, completed: false, feedback: null, hint: 0, expanded: null };
    }
    return { format: 'wazuhroom-save', version: 1, dataset: content.version, language: 'ja', activeCaseId: content.cases[0].id, records };
  }
  function assess(caseData, record) {
    const answer = caseData.answer, report = record?.report || {}, evidence = Array.isArray(record?.evidence) ? record.evidence : [], documents = Array.isArray(record?.documents) ? record.documents : [], operations = Array.isArray(record?.operations) ? record.operations : [];
    const eventIds = new Set(caseData.events.map(item => item.id)), selected = new Set(evidence);
    const validEvidence = selected.size === evidence.length && evidence.every(id => eventIds.has(id));
    const groups = answer.evidenceGroups || [], limit = groups.length + 2;
    const prose = value => typeof value === 'string' && value.trim().length >= 10 && value.length <= 4000;
    const checks = [
      { key: 'verdict', passed: report.verdict === answer.verdict },
      { key: 'priority', passed: report.priority === answer.priority },
      { key: 'action', passed: report.action === answer.action },
      { key: 'target', passed: report.target === answer.target },
      { key: 'evidence', passed: validEvidence && groups.length > 0 && groups.every(group => group.length > 0 && group.some(id => selected.has(id))) },
      { key: 'evidenceLimit', passed: validEvidence && evidence.length > 0 && evidence.length <= limit },
      { key: 'documents', passed: (answer.documentIds || []).every(id => documents.includes(id)) },
      { key: 'operations', passed: [...new Set(caseData.steps.map(step => step.kind).filter(kind => kind !== 'report'))].every(kind => operations.includes(kind)) },
      { key: 'facts', passed: prose(report.facts) },
      { key: 'nextStep', passed: prose(report.nextStep) }
    ];
    return { passed: checks.every(check => check.passed), checks };
  }
  function safeTree(value, seen = new Set(), depth = 0, budget = { count: 0 }) {
    if (++budget.count > 100000 || depth > 20) fail('Save data is too large or deeply nested.');
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (typeof value === 'number') { if (!Number.isFinite(value)) fail('Invalid number in save.'); return; }
    if (typeof value !== 'object' || (!Array.isArray(value) && !plain(value)) || seen.has(value)) fail('Invalid object in save.');
    seen.add(value);
    for (const key of Object.keys(value)) {
      if (UNSAFE.has(key)) fail('Unsafe property in save.');
      safeTree(value[key], seen, depth + 1, budget);
    }
    seen.delete(value);
  }
  function exactKeys(object, allowed, required, label) {
    if (!plain(object) || Object.keys(object).some(key => !allowed.includes(key)) || required.some(key => !own(object, key))) fail('Invalid ' + label + ' fields.');
  }
  function idList(value, allowed, maximum, label) {
    if (!Array.isArray(value) || value.length > maximum || value.some(id => typeof id !== 'string' || !allowed.has(id)) || new Set(value).size !== value.length) fail('Invalid ' + label + '.');
    return value.slice();
  }
  function validateRecord(raw, item, snapshot = false) {
    const required = ['query', 'filters', 'from', 'to', 'view', 'evidence', 'documents', 'operations', 'report', 'completed', 'feedback', 'hint', 'expanded'];
    exactKeys(raw, [...required, 'completion'], required, 'record');
    if (snapshot && own(raw, 'completion') && raw.completion !== null) fail('Nested completion snapshots are invalid.');
    scalarString(raw.query, 'query');
    if (!Array.isArray(raw.filters) || raw.filters.length > 30) fail('Invalid saved filters.');
    const filters = raw.filters.map(filterShape);
    // A saved search must be executable: invalid or unsupported queries are never imported silently.
    search([], { query: raw.query, filters, from: raw.from, to: raw.to, module: 'events' });
    if (!VIEWS.includes(raw.view) || typeof raw.completed !== 'boolean' || !Number.isInteger(raw.hint) || raw.hint < 0 || raw.hint > 3) fail('Invalid saved view, completion or hint.');
    const eventIds = new Set(item.events.map(event => event.id)), documentIds = new Set(item.documents.map(document => document.id)), agentIds = new Set(item.agents.map(agent => agent.id));
    if (raw.expanded !== null && !eventIds.has(raw.expanded)) fail('Invalid expanded event.');
    const reportKeys = ['verdict', 'priority', 'action', 'target', 'facts', 'nextStep'];
    exactKeys(raw.report, reportKeys, reportKeys, 'report');
    for (const key of Object.keys(CHOICES)) if (!CHOICES[key].includes(raw.report[key])) fail('Invalid report choice.');
    if (raw.report.target !== '' && !agentIds.has(raw.report.target)) fail('Invalid report target.');
    scalarString(raw.report.facts, 'facts', 4000);
    scalarString(raw.report.nextStep, 'next step', 4000);
    if (raw.feedback !== null && !plain(raw.feedback)) fail('Invalid feedback.');
    const result = {
      query: raw.query, filters, from: raw.from, to: raw.to, view: raw.view,
      evidence: idList(raw.evidence, eventIds, eventIds.size, 'evidence'),
      documents: idList(raw.documents, documentIds, documentIds.size, 'documents'),
      operations: idList(raw.operations, new Set(STEPS), STEPS.length, 'operations'),
      report: { ...raw.report }, completed: false, feedback: null, hint: raw.hint, expanded: raw.expanded
    };
    if (!snapshot && raw.completion !== undefined && raw.completion !== null) {
      const completion = validateRecord(raw.completion, item, true);
      if (!assess(item, completion).passed) fail('Completion snapshot does not pass assessment.');
      completion.completed = true;
      completion.feedback = assess(item, completion);
      result.completion = completion;
      result.completed = true;
    } else if (raw.completed) {
      if (!assess(item, result).passed) fail('Completed record does not pass assessment.');
      result.completed = true;
      if (!snapshot) result.completion = JSON.parse(JSON.stringify(result));
    }
    if (raw.feedback !== null) result.feedback = assess(item, result);
    return result;
  }
  function validateProgress(input, content) {
    safeTree(input);
    const keys = ['format', 'version', 'dataset', 'language', 'activeCaseId', 'records'];
    exactKeys(input, keys, keys, 'save');
    if (input.format !== 'wazuhroom-save' || input.version !== 1 || input.dataset !== content.version) fail('Unsupported save format or dataset version.');
    if (!['ja', 'en'].includes(input.language)) fail('Invalid saved language.');
    const caseIds = content.cases.map(item => item.id);
    if (!caseIds.includes(input.activeCaseId)) fail('Invalid active case.');
    exactKeys(input.records, caseIds, caseIds, 'records');
    const records = {};
    for (const item of content.cases) records[item.id] = validateRecord(input.records[item.id], item);
    return { format: 'wazuhroom-save', version: 1, dataset: content.version, language: input.language, activeCaseId: input.activeCaseId, records };
  }
  return Object.freeze({ get, search, searchAgents, createProgress, assess, validateProgress, FIELD_TYPES, AGENT_TYPES });
}));
