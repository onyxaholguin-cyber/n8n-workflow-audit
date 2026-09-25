'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync, spawnSync } = require('child_process');
const { auditWorkflow, extractWorkflows, RULES } = require('../src/audit');

const CLI = path.join(__dirname, '..', 'bin', 'n8n-audit.js');
const ex = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'examples', f), 'utf8'));
const rules = (fs_) => fs_.map((f) => f.rule).sort();
const node = (name, type, extra = {}) => ({ id: name, name, type, typeVersion: 1, position: [0, 0], parameters: {}, ...extra });
const wf = (nodes, connections = {}, extra = {}) => ({ name: 't', nodes, connections, ...extra });
const chain = (...names) => Object.fromEntries(names.slice(0, -1).map((n, i) => [n, { main: [[{ node: names[i + 1], type: 'main', index: 0 }]] }]));

test('risky example: every expected rule fires', () => {
  const got = new Set(rules(auditWorkflow(ex('risky-workflow.json'))));
  for (const r of ['secret-in-header', 'hardcoded-secret', 'webhook-no-auth', 'no-error-workflow', 'error-swallowed', 'pinned-data', 'save-errors-off',
    'insecure-tls', 'http-no-retry', 'plain-http', 'disabled-node', 'orphan-node']) assert.ok(got.has(r), `missing ${r}`);
});

test('clean example: no findings', () => {
  assert.deepEqual(auditWorkflow(ex('clean-workflow.json')), []);
});

test('secret patterns detected, and redacted in output', () => {
  const secrets = {
    github: 'ghp_' + 'a1B2c3D4e5'.repeat(4),
    slackHook: 'https://hooks.slack.com/services/T0' + 'ABCDEFG/B0ABCDEFG/' + 'x'.repeat(24),
    stripe: 'sk_' + 'live_' + 'Z'.repeat(24),
    aws: 'AKIA' + 'ABCDEFGHIJKLMNOP',
    telegram: '123456789:AA' + 'b'.repeat(33),
    pk: '-----BEGIN ' + 'PRIVATE KEY-----\nMIIE...',
    url: 'postgres://admin:' + 'hunter2hunter2@db.example.com/app',
  };
  for (const [k, s] of Object.entries(secrets)) {
    const f = auditWorkflow(wf([node('Set', 'n8n-nodes-base.set', { parameters: { value: `x ${s} y` } })], {}, {}));
    const hit = f.find((x) => x.rule === 'hardcoded-secret');
    assert.ok(hit, `not detected: ${k}`);
    assert.ok(!hit.detail.includes(s.slice(6, 20)), `not redacted: ${k}`);
  }
});

test('expressions, credentials and placeholders are not flagged as secrets', () => {
  const n = node('HTTP', 'n8n-nodes-base.httpRequest', { retryOnFail: true, parameters: {
    url: 'https://api.example.com', headerParameters: { parameters: [
      { name: 'Authorization', value: '=Bearer {{ $env.API_TOKEN }}' }, { name: 'X-API-Key', value: 'YOUR_API_KEY' }, { name: 'Accept', value: 'application/json' },
      { name: 'Proxy-Authorization', value: 'Bearer $REPLICATE_API_TOKEN' }, { name: 'apikey', value: 'DUBLAB_API_KEY' }, { name: 'Token', value: 'Bearer [REDACTED_TOKEN]' }] } } });
  const code = node('Code', 'n8n-nodes-base.code', { parameters: { jsCode: "// token = 'abcdefghijklmnopqrstuvwxyz'\nconst apiKey = $env.KEY;\nconst password = 'changeme-changeme-123';" } });
  const f = auditWorkflow(wf([node('Go', 'n8n-nodes-base.manualTrigger'), n, code], chain('Go', 'HTTP', 'Code')));
  assert.deepEqual(f.filter((x) => x.level === 'error'), []);
});

test('error workflow: not required for manual-only, error-trigger, or sub-workflows; required for schedules', () => {
  assert.equal(auditWorkflow(wf([node('Go', 'n8n-nodes-base.manualTrigger')])).filter((f) => f.rule === 'no-error-workflow').length, 0);
  assert.equal(auditWorkflow(wf([node('E', 'n8n-nodes-base.errorTrigger')])).filter((f) => f.rule === 'no-error-workflow').length, 0);
  assert.equal(auditWorkflow(wf([node('S', 'n8n-nodes-base.executeWorkflowTrigger')])).filter((f) => f.rule === 'no-error-workflow').length, 0);
  assert.equal(auditWorkflow(wf([node('Cron', 'n8n-nodes-base.scheduleTrigger')])).filter((f) => f.rule === 'no-error-workflow').length, 1);
  assert.equal(auditWorkflow(wf([node('Cron', 'n8n-nodes-base.scheduleTrigger')], {}, { settings: { errorWorkflow: '7' } })).filter((f) => f.rule === 'no-error-workflow').length, 0);
});

test('error output: connected is fine, unconnected is flagged', () => {
  const mk = (conn) => auditWorkflow(wf([node('Go', 'n8n-nodes-base.manualTrigger'), node('H', 'n8n-nodes-base.httpRequest', { retryOnFail: true, onError: 'continueErrorOutput', parameters: { url: 'https://x.io' } }), node('Alert', 'n8n-nodes-base.noOp')],
    { Go: { main: [[{ node: 'H', type: 'main', index: 0 }]] }, ...conn }));
  assert.equal(mk({ H: { main: [[], [{ node: 'Alert', type: 'main', index: 0 }]] } }).filter((f) => f.rule.startsWith('error-')).length, 0);
  assert.equal(mk({ H: { main: [[{ node: 'Alert', type: 'main', index: 0 }]] } }).filter((f) => f.rule === 'error-output-unconnected').length, 1);
});

test('AI sub-nodes connected via ai_* outputs are not orphans; sticky notes ignored', () => {
  const f = auditWorkflow(wf([node('Chat', '@n8n/n8n-nodes-langchain.chatTrigger'), node('Agent', '@n8n/n8n-nodes-langchain.agent'), node('Model', '@n8n/n8n-nodes-langchain.lmChatOpenAi'), node('Note', 'n8n-nodes-base.stickyNote')],
    { Chat: { main: [[{ node: 'Agent', type: 'main', index: 0 }]] }, Model: { ai_languageModel: [[{ node: 'Agent', type: 'ai_languageModel', index: 0 }]] } }));
  assert.equal(f.filter((x) => x.rule === 'orphan-node').length, 0);
});

test('per-node audit-ignore note and global ignore', () => {
  const w = wf([node('Hook', 'n8n-nodes-base.webhook', { notes: 'Public form endpoint. audit-ignore: webhook-no-auth' })], {}, { settings: { errorWorkflow: '1' } });
  assert.equal(auditWorkflow(w).length, 0);
  const w2 = wf([node('Hook', 'n8n-nodes-base.webhook')], {}, { settings: { errorWorkflow: '1' } });
  assert.equal(auditWorkflow(w2, { ignore: ['webhook-no-auth'] }).length, 0);
});

test('plain-http ignores private hosts', () => {
  for (const [u, n] of [['http://localhost:5678/x', 0], ['http://192.168.1.5/x', 0], ['http://n8n:5678', 0], ['http://api.example.com', 1], ['=http://api.example.com/{{ $json.id }}', 1]]) {
    const f = auditWorkflow(wf([node('Go', 'n8n-nodes-base.manualTrigger'), node('H', 'n8n-nodes-base.httpRequest', { retryOnFail: true, parameters: { url: u } })], chain('Go', 'H')));
    assert.equal(f.filter((x) => x.rule === 'plain-http').length, n, u);
  }
});

test('extractWorkflows handles single, array, API list, template wrapper, non-workflow', () => {
  const w = ex('clean-workflow.json');
  assert.equal(extractWorkflows(w).length, 1);
  assert.equal(extractWorkflows([w, w]).length, 2);
  assert.equal(extractWorkflows({ data: [w] }).length, 1);
  assert.equal(extractWorkflows({ id: 1, workflow: w }).length, 1);
  assert.equal(extractWorkflows({ workflow: { name: 'outer', workflow: w } }).length, 1);
  assert.equal(extractWorkflows({ name: 'pkg', version: '1' }).length, 0);
});

test('every rule has level, title and fix', () => {
  for (const [id, r] of Object.entries(RULES)) assert.ok(['error', 'warn', 'info'].includes(r.level) && r.title && r.fix, id);
});

test('CLI: exit codes, formats, directory scan, non-workflow files skipped', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n8na-'));
  fs.copyFileSync(path.join(__dirname, '..', 'examples', 'clean-workflow.json'), path.join(dir, 'clean.json'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x"}');
  fs.writeFileSync(path.join(dir, 'broken.json'), '{nope');
  let r = spawnSync(process.execPath, [CLI, dir], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /1 workflow\(s\) in 3 file\(s\) \(2 skipped\)/);
  r = spawnSync(process.execPath, [CLI, path.join(__dirname, '..', 'examples', 'risky-workflow.json')], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes('demo0not0a0real0token0abcdefghij'), 'secret leaked to output');
  r = spawnSync(process.execPath, [CLI, '--format', 'json', '--fail-on', 'none', path.join(__dirname, '..', 'examples')], { encoding: 'utf8' });
  assert.equal(r.status, 0); const j = JSON.parse(r.stdout); assert.equal(j.workflows, 2); assert.ok(j.summary.error >= 2);
  r = spawnSync(process.execPath, [CLI, '--format', 'github', '--min-level', 'warn', path.join(__dirname, '..', 'examples', 'risky-workflow.json')], { encoding: 'utf8' });
  assert.match(r.stdout, /^::error file=.*title=secret-in-header/m); assert.ok(!/::notice/.test(r.stdout));
  r = spawnSync(process.execPath, [CLI, '--ignore', 'nope', dir], { encoding: 'utf8' }); assert.equal(r.status, 2);
  assert.match(execFileSync(process.execPath, [CLI, '--list-rules'], { encoding: 'utf8' }), /hardcoded-secret/);
});
