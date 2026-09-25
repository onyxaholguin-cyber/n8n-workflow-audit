'use strict';
// n8n-workflow-audit: static checks for exported n8n workflow JSON. Zero dependencies.

const LEVELS = { error: 3, warn: 2, info: 1 };

const RULES = {
  'hardcoded-secret': { level: 'error', title: 'Secret or token pasted into a node', fix: 'Move it into an n8n credential (or an environment variable read with $env) and rotate the exposed value. Exported workflows, Git backups and shared templates carry parameters in plain text.' },
  'secret-in-header': { level: 'error', title: 'Auth header with a literal value', fix: 'Use a Header Auth / Bearer credential instead of a literal header value.' },
  'webhook-no-auth': { level: 'warn', title: 'Webhook without authentication', fix: 'Set Authentication (Header Auth, Basic Auth or JWT) on the Webhook node, or verify a signature in the first step and reject unsigned calls.' },
  'no-error-workflow': { level: 'warn', title: 'No error workflow set', fix: 'Workflow settings > Error Workflow: pick a workflow that starts with an Error Trigger and alerts you (Slack, email, etc.). Without it, failed production runs are silent.' },
  'error-swallowed': { level: 'warn', title: 'Node errors are swallowed', fix: 'Use "On Error: Continue (using error output)" and connect the error output, or let the node fail so the error workflow fires. If the next node deliberately checks for the error, add "audit-ignore: error-swallowed" to this node\'s Notes.' },
  'error-output-unconnected': { level: 'warn', title: 'Error output is not connected', fix: 'Connect the node\'s error output to handling/alerting nodes, or switch On Error back to "Stop Workflow".' },
  'pinned-data': { level: 'warn', title: 'Pinned test data left in the workflow', fix: 'Unpin the data before exporting or activating. Pinned data is used instead of live data in manual runs and often contains real records.' },
  'orphan-node': { level: 'warn', title: 'Node is not connected to anything', fix: 'Connect it or delete it.' },
  'save-errors-off': { level: 'warn', title: 'Failed executions are not saved', fix: 'Workflow settings > Save failed production executions: set to Save, otherwise you cannot debug failures.' },
  'insecure-tls': { level: 'warn', title: 'TLS certificate checks disabled', fix: 'Turn off "Ignore SSL Issues" unless the target is a known internal host with a self-signed certificate.' },
  'http-no-retry': { level: 'info', title: 'HTTP Request without Retry On Fail', fix: 'Node settings > Retry On Fail (e.g., 3 tries, 5000 ms wait) handles transient 429/5xx errors.' },
  'plain-http': { level: 'info', title: 'Request to a non-HTTPS URL', fix: 'Use https:// for anything outside localhost / your private network.' },
  'disabled-node': { level: 'info', title: 'Disabled node', fix: 'Delete it if it is no longer needed; disabled nodes still ship in exports.' },
};

const TRIGGER_TYPES = new Set(['n8n-nodes-base.webhook', 'n8n-nodes-base.start', 'n8n-nodes-base.cron', 'n8n-nodes-base.interval',
  'n8n-nodes-base.emailReadImap', 'n8n-nodes-base.manualTrigger']);
const isTrigger = (n) => TRIGGER_TYPES.has(n.type) || /trigger$/i.test(n.type || '');
const isManual = (n) => n.type === 'n8n-nodes-base.manualTrigger' || n.type === 'n8n-nodes-base.start';
const isSticky = (n) => n.type === 'n8n-nodes-base.stickyNote';

// Token formats with distinctive prefixes: low false-positive rate.
const SECRET_PATTERNS = [
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/],
  ['GitLab token', /\bglpat-[A-Za-z0-9_-]{20,}\b/],
  ['Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/],
  ['Slack webhook URL', /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/],
  ['Discord webhook URL', /discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{30,}/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI-style API key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['Stripe key', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Telegram bot token', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/],
  ['SendGrid key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/],
  ['Private key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----/],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ['Bearer token', /\bBearer\s+(?!\{\{)[A-Za-z0-9._~+/-]{24,}=*/],
  ['Password in URL', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:(?!\{\{)[^\s@/'"]{6,}@/i],
];
// key = "long literal" assignments inside Code nodes.
const CODE_ASSIGN = /\b(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|auth)\w*\s*[:=]\s*(['"`])([^'"`\s]{16,})\2/i;
const PLACEHOLDER_WORDS = /(your|enter|insert|replace|here|example|placeholder|xxx|changeme|dummy|sample|redacted|[<>\[\]{}]|\$\{|\$\(|^\$[A-Za-z_]|\*{3})/i;
function isPlaceholder(v) {
  v = String(v).trim().replace(/^(Bearer|Basic|Token)\s+/i, '');
  if (!v || PLACEHOLDER_WORDS.test(v)) return true;
  if (/^[A-Z0-9_-]+$/.test(v) && /[A-Z]/.test(v) && /[_-]/.test(v)) return true; // MY_API_KEY style
  if (/^_{2}.*_{2}$/.test(v) || /^(.)\1+$/.test(v)) return true;               // __TOKEN_0__, aaaaaaa
  return false;
}
const SENSITIVE_HEADER = /^(authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie|x-api-token|token)$/i;

function redact(s) {
  s = String(s);
  return s.length <= 8 ? '****' : s.slice(0, 4) + '…' + s.slice(-2) + ` (${s.length} chars)`;
}

function walkStrings(value, path, out) {
  if (typeof value === 'string') out.push([path, value]);
  else if (Array.isArray(value)) value.forEach((v, i) => walkStrings(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) walkStrings(v, path ? `${path}.${k}` : k, out);
  return out;
}

function ignoredRules(node) {
  const m = String(node.notes || '').match(/audit-ignore:\s*([a-z0-9,\s-]+)/i);
  return new Set(m ? m[1].split(/[\s,]+/).filter(Boolean) : []);
}

function looksLikeWorkflow(x) { return x && typeof x === 'object' && Array.isArray(x.nodes) && x.connections && typeof x.connections === 'object'; }

function extractWorkflows(json) {
  if (looksLikeWorkflow(json)) return [json];
  if (Array.isArray(json)) return json.filter(looksLikeWorkflow);
  if (json && Array.isArray(json.data)) return json.data.filter(looksLikeWorkflow); // n8n public API list response
  if (json && json.workflow && typeof json.workflow === 'object') return extractWorkflows(json.workflow).map((w) => ({ name: json.name, ...w })); // n8n.io template API wrapper(s)
  return [];
}

function auditWorkflow(wf, opts = {}) {
  const findings = [];
  const wfName = wf.name || '(unnamed workflow)';
  const nodes = (wf.nodes || []).filter((n) => n && typeof n === 'object');
  const conns = wf.connections || {};
  const settings = wf.settings || {};
  const skip = new Set(opts.ignore || []);
  const add = (rule, node, detail) => {
    if (skip.has(rule) || (node && ignoredRules(node).has(rule))) return;
    findings.push({ rule, level: RULES[rule].level, title: RULES[rule].title, workflow: wfName, node: node ? node.name : null, detail: detail || '', fix: RULES[rule].fix });
  };

  // Connection graph (all connection types, incl. AI sub-node types).
  const incoming = new Map(), outgoing = new Map();
  for (const [src, types] of Object.entries(conns)) {
    for (const [type, outputs] of Object.entries(types || {})) {
      (outputs || []).forEach((list, outIdx) => (list || []).forEach((c) => {
        if (!c || !c.node) return;
        incoming.set(c.node, (incoming.get(c.node) || 0) + 1);
        const o = outgoing.get(src) || []; o.push({ type, outIdx, to: c.node }); outgoing.set(src, o);
      }));
    }
  }

  const real = nodes.filter((n) => !isSticky(n));
  const triggers = real.filter(isTrigger);
  const hasErrorTrigger = real.some((n) => n.type === 'n8n-nodes-base.errorTrigger');
  const autoTriggers = triggers.filter((n) => !isManual(n) && !n.disabled && n.type !== 'n8n-nodes-base.errorTrigger' && n.type !== 'n8n-nodes-base.executeWorkflowTrigger');

  if (autoTriggers.length && !hasErrorTrigger && !settings.errorWorkflow)
    add('no-error-workflow', null, `Triggers: ${autoTriggers.map((n) => n.name).join(', ')}`);
  if (settings.saveDataErrorExecution === 'none') add('save-errors-off', null, 'settings.saveDataErrorExecution = "none"');
  const pinned = Object.keys(wf.pinData || {}).filter((k) => Array.isArray(wf.pinData[k]) ? wf.pinData[k].length : wf.pinData[k]);
  if (pinned.length) add('pinned-data', null, `Pinned on: ${pinned.join(', ')}`);

  for (const n of real) {
    const p = n.parameters || {};
    if (n.disabled) add('disabled-node', n, n.type);

    // Secrets anywhere in parameters (Code node source included).
    const seen = new Set();
    for (const [path, s] of walkStrings(p, '', [])) {
      for (const [label, re] of SECRET_PATTERNS) {
        const m = s.match(re);
        if (m && !seen.has(m[0]) && !(label === 'Bearer token' && isPlaceholder(m[0]))) { seen.add(m[0]); add('hardcoded-secret', n, `${label} in parameters.${path}: ${redact(m[0])}`); }
      }
      if (/jsCode|pythonCode|functionCode|code$/i.test(path)) {
        const lines = s.split('\n');
        lines.forEach((line) => {
          if (/^\s*(\/\/|#)/.test(line)) return;
          const m = line.match(CODE_ASSIGN);
          if (m && !isPlaceholder(m[3]) && !seen.has(m[3]) && !/^(true|false|null|undefined)$/i.test(m[3])) {
            seen.add(m[3]); add('hardcoded-secret', n, `Literal "${m[1]}" value in parameters.${path}: ${redact(m[3])}`);
          }
        });
      }
    }
    // Literal auth headers (HTTP Request v3+: headerParameters.parameters[{name,value}]).
    const headers = ((p.headerParameters || {}).parameters || []).concat(((p.options || {}).headers || {}).parameters || []);
    for (const h of headers) {
      if (!h || !SENSITIVE_HEADER.test(String(h.name || '').trim())) continue;
      const v = String(h.value || '').trim();
      if (!v || v.startsWith('=') || v.includes('{{') || isPlaceholder(v)) continue;
      if (![...seen].some((x) => v.includes(x))) add('secret-in-header', n, `Header "${h.name}": ${redact(v)}`);
    }

    if (n.type === 'n8n-nodes-base.webhook' && !n.disabled && (!p.authentication || p.authentication === 'none'))
      add('webhook-no-auth', n, `path: ${p.path || '(auto)'}${p.httpMethod ? ', method: ' + p.httpMethod : ''}`);

    const outs = outgoing.get(n.name) || [];
    if (n.continueOnFail === true || n.onError === 'continueRegularOutput')
      add('error-swallowed', n, n.onError ? `onError = "${n.onError}"` : 'continueOnFail = true');
    if (n.onError === 'continueErrorOutput') {
      // The error output is the last main output; with a single regular output it is index 1.
      const mainOuts = ((conns[n.name] || {}).main || []);
      const errIdx = n.type === 'n8n-nodes-base.if' ? 2 : (n.type === 'n8n-nodes-base.switch' ? null : 1);
      if (errIdx !== null && !((mainOuts[errIdx] || []).length)) add('error-output-unconnected', n, `output #${errIdx} has no connection`);
    }

    const opt = p.options || {};
    if (opt.allowUnauthorizedCerts === true || p.allowUnauthorizedCerts === true) add('insecure-tls', n, 'allowUnauthorizedCerts = true');

    if (n.type === 'n8n-nodes-base.httpRequest') {
      if (!n.retryOnFail) add('http-no-retry', n, '');
      const url = typeof p.url === 'string' ? p.url : '';
      const mm = url.replace(/^=/, '').match(/^http:\/\/([^/:?#]+)/i);
      if (mm && !/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|host\.docker\.internal$|\[?::1)/i.test(mm[1]) && !/\.(local|internal|lan)$/i.test(mm[1]) && !/^[a-z0-9-]+$/i.test(mm[1]))
        add('plain-http', n, url.replace(/^=/, ''));
    }

    if (!isTrigger(n) && !incoming.get(n.name) && !outs.some((o) => o.type !== 'main')) add('orphan-node', n, n.type);
  }
  return findings;
}

function summarize(findings) {
  const s = { error: 0, warn: 0, info: 0 };
  findings.forEach((f) => { s[f.level]++; });
  return s;
}

module.exports = { RULES, LEVELS, auditWorkflow, extractWorkflows, looksLikeWorkflow, summarize, redact };
