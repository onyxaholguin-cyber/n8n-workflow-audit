#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { RULES, LEVELS, auditWorkflow, extractWorkflows, summarize } = require('../src/audit');
const VERSION = require('../package.json').version;

const HELP = `n8n-workflow-audit ${VERSION}
Static checks for exported n8n workflow JSON: pasted secrets, unauthenticated webhooks,
missing error workflows, swallowed errors, pinned data, orphan nodes and more.

Usage: n8n-audit [options] <file-or-directory> [...]

Options:
  --format <text|json|github>  Output format (default: text; "github" = Actions annotations)
  --fail-on <error|warn|info|none>  Exit 1 if a finding at or above this level exists (default: error)
  --min-level <error|warn|info>     Only report findings at or above this level (default: info)
  --ignore <rule,rule>         Skip rules everywhere (per node: put "audit-ignore: rule" in the node's Notes)
  --list-rules                 Print all rules and exit
  -h, --help / -v, --version

Directories are scanned recursively for *.json (node_modules and .git are skipped).
Files that are not n8n workflows are skipped. Accepts single workflows, arrays
(n8n export:workflow --all) and n8n API list responses ({"data": [...]}).`;

function parseArgs(argv) {
  const o = { format: 'text', failOn: 'error', minLevel: 'info', ignore: [], paths: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a === '--list-rules') o.listRules = true;
    else if (a === '--format') o.format = next();
    else if (a === '--fail-on') o.failOn = next();
    else if (a === '--min-level') o.minLevel = next();
    else if (a === '--ignore') o.ignore.push(...next().split(',').map((s) => s.trim()).filter(Boolean));
    else if (a.startsWith('--')) throw new Error(`Unknown option ${a}`);
    else o.paths.push(a);
  }
  if (!['text', 'json', 'github'].includes(o.format)) throw new Error(`Bad --format ${o.format}`);
  if (!['error', 'warn', 'info', 'none'].includes(o.failOn)) throw new Error(`Bad --fail-on ${o.failOn}`);
  if (!LEVELS[o.minLevel]) throw new Error(`Bad --min-level ${o.minLevel}`);
  for (const r of o.ignore) if (!RULES[r]) throw new Error(`Unknown rule in --ignore: ${r}`);
  return o;
}

function collect(p, out) {
  const st = fs.statSync(p);
  if (st.isDirectory()) {
    for (const e of fs.readdirSync(p).sort()) {
      if (e === 'node_modules' || e === '.git') continue;
      const full = path.join(p, e);
      if (fs.statSync(full).isDirectory() || e.toLowerCase().endsWith('.json')) collect(full, out);
    }
  } else out.push(p);
  return out;
}

function main(argv) {
  let o;
  try { o = parseArgs(argv); } catch (e) { console.error(`n8n-audit: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log(VERSION); return 0; }
  if (o.listRules) {
    for (const [id, r] of Object.entries(RULES)) console.log(`${r.level.padEnd(5)} ${id.padEnd(26)} ${r.title}`);
    return 0;
  }
  if (!o.paths.length) { console.error(HELP); return 2; }

  const results = []; let scanned = 0, workflows = 0, skipped = 0;
  for (const p of o.paths) {
    let files;
    try { files = collect(p, []); } catch (e) { console.error(`n8n-audit: cannot read ${p}: ${e.message}`); return 2; }
    for (const f of files) {
      scanned++;
      let json;
      try { json = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { skipped++; continue; }
      const wfs = extractWorkflows(json);
      if (!wfs.length) { skipped++; continue; }
      for (const wf of wfs) {
        workflows++;
        const fnd = auditWorkflow(wf, { ignore: o.ignore }).filter((x) => LEVELS[x.level] >= LEVELS[o.minLevel]);
        results.push({ file: f, workflow: wf.name || '(unnamed workflow)', findings: fnd });
      }
    }
  }
  const all = results.flatMap((r) => r.findings.map((f) => ({ file: r.file, ...f })));
  const sum = summarize(all);

  if (o.format === 'json') {
    console.log(JSON.stringify({ version: VERSION, filesScanned: scanned, workflows, skippedFiles: skipped, summary: sum, findings: all }, null, 2));
  } else if (o.format === 'github') {
    const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    const cmd = { error: 'error', warn: 'warning', info: 'notice' };
    for (const f of all) console.log(`::${cmd[f.level]} file=${esc(f.file)},title=${esc(`${f.rule}: ${f.title}`)}::${esc(`[${f.workflow}${f.node ? ' > ' + f.node : ''}] ${f.detail ? f.detail + '. ' : ''}${f.fix}`)}`);
    console.log(`n8n-audit: ${workflows} workflow(s), ${sum.error} error(s), ${sum.warn} warning(s), ${sum.info} info`);
  } else {
    const tty = process.stdout.isTTY && !process.env.NO_COLOR;
    const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
    const tag = { error: c(31, 'error'), warn: c(33, 'warn '), info: c(36, 'info ') };
    for (const r of results) {
      if (!r.findings.length) { console.log(`${c(32, '✓')} ${r.file} :: ${r.workflow}`); continue; }
      console.log(`\n${c(1, r.file)} :: ${c(1, r.workflow)}`);
      for (const f of r.findings) {
        console.log(`  ${tag[f.level]} ${f.rule}${f.node ? `  [${f.node}]` : ''}  ${f.title}${f.detail ? ': ' + f.detail : ''}`);
        console.log(`        ${c(2, 'fix: ' + f.fix)}`);
      }
    }
    console.log(`\n${workflows} workflow(s) in ${scanned} file(s) (${skipped} skipped): ${sum.error} error(s), ${sum.warn} warning(s), ${sum.info} info`);
    if (!workflows) console.log('No n8n workflows found. Export them with the n8n UI (Download) or `n8n export:workflow --all --output=workflows.json`.');
  }
  if (o.failOn === 'none') return 0;
  return all.some((f) => LEVELS[f.level] >= LEVELS[o.failOn]) ? 1 : 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { main, parseArgs };
