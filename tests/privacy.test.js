'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const content = require('../src/content.js');
const engine = require('../src/engine.js');

// Check the public synthetic case without storing any original incident identifiers here.
const scenario = () => content.cases.find(item => item.id === 'crypto-compromise');
function strings(value) {
  if (typeof value === 'string') return [value];
  if (!value || typeof value !== 'object') return [];
  return Object.values(value).flatMap(strings);
}

test('incident-inspired case uses only documented example addresses and fictional room endpoints', () => {
  const item = scenario();
  assert.ok(item, 'the synthetic case exists');
  const text = strings(item).join('\n');
  const ips = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])];
  assert.ok(ips.length >= 3, 'the investigation includes endpoints and external peers');
  const roomIPs = new Set(['10.20.0.5', '10.20.0.8', '10.20.1.11', '10.20.2.21', '10.20.3.31']);
  for (const ip of ips) {
    assert.ok(ip.split('.').every(part => Number(part) <= 255), 'valid IPv4 representation');
    assert.ok(roomIPs.has(ip) || /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip), 'only fictional room IPs or TEST-NET addresses');
  }
  const urls = text.match(/\b(?:https?|stratum\+tcp):\/\/[^\s"'\\<>]+/g) || [];
  for (const raw of urls) {
    const url = new URL(raw.replace(/[),.;]+$/, ''));
    assert.ok(url.hostname.endsWith('.invalid'), 'network indicators use reserved invalid domains');
    assert.equal(url.username, '', 'no URL credentials');
    assert.equal(url.password, '', 'no URL credentials');
  }
  const domains = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [];
  const externalNames = domains.filter(name => name.includes('.room.'));
  assert.ok(externalNames.length > 0, 'fictional network hostnames are present');
  for (const name of externalNames) assert.ok(name.endsWith('.invalid'), 'fictional network names are reserved invalid domains');
  for (const event of item.events) {
    if (event.data.http?.host) assert.ok(event.data.http.host.endsWith('.invalid'), 'HTTP host is not a real destination');
    if (event.data.process?.args) {
      const pool = event.data.process.args.match(/--pool\s+(\S+)/);
      if (pool) assert.match(pool[1], /\.invalid:\d+$/, 'configured pool uses an invalid domain');
    }
  }
});

test('synthetic case contains only authored inert Base64 and omits source captures and live wallets', () => {
  const item = scenario();
  const text = strings(item).join('\n');
  const encodedEvents = item.events.filter(event => event.data.artifact?.encoded_content);
  assert.equal(encodedEvents.length, 1, 'one deliberately authored decoding exercise');
  const encoded = encodedEvents[0].data.artifact.encoded_content;
  const decoded = engine.decodeBase64Text(encoded);
  assert.equal(decoded, item.questions.find(q => q.id === 'decodedText').acceptedAnswers[0]);
  assert.match(decoded, /^TRAINING PSEUDOCODE - NOT EXECUTABLE\n/);
  assert.match(decoded, /mailbox-07@room\.invalid/);
  assert.doesNotMatch(decoded, /<\?php|eval\s*\(|system\s*\(|mail\s*\(/i, 'no functioning PHP or shell payload');
  assert.doesNotMatch(text.split(encoded).join(''), /[A-Za-z0-9+/]{180,}={0,2}/, 'no additional encoded source payload or binary');
  assert.doesNotMatch(text, /\b[48][1-9A-HJ-NP-Za-km-z]{94}\b/, 'no Monero-shaped wallet address');
  assert.doesNotMatch(text, /data:(?:application|image)\//i, 'no source files or screenshots in the case');
  const foreground = item.events.filter(event => !event.id.startsWith(item.id + '-bg-'));
  assert.ok(foreground.length > 0);
  for (const event of foreground) {
    assert.ok(event.timestamp.startsWith('2026-10-21T'), 'new fictional investigation date');
  }
});
