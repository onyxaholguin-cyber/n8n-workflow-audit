# n8n-workflow-audit

Static checks for exported **n8n** workflow JSON. It catches the mistakes that bite in production:

- **Secrets pasted into nodes** (API keys, bearer tokens, webhook URLs, private keys, passwords in URLs, literal auth headers, keys hard-coded in Code nodes). Exported workflows, Git backups and shared templates carry these in plain text.
- **Webhooks with no authentication.**
- **No error workflow**, so production failures are silent.
- **Swallowed errors** (`Continue` on error) and error outputs that go nowhere.
- **Pinned test data** left in the workflow, **orphan** and **disabled** nodes.
- **TLS checks disabled**, plain-HTTP calls, HTTP Request nodes without **Retry On Fail**.

Zero dependencies, Node 18+. Runs locally, in CI, or as a GitHub Action. Secrets are **redacted** in all output.

## Quick start

```sh
# one-off, no install (runs straight from GitHub)
npx --yes github:onyxaholguin-cyber/n8n-workflow-audit ./workflows

# or clone it
git clone https://github.com/onyxaholguin-cyber/n8n-workflow-audit
node n8n-workflow-audit/bin/n8n-audit.js ./workflows
```

Get workflow JSON from the n8n editor (**⋯ > Download**) or the n8n CLI:

```sh
docker compose exec n8n n8n export:workflow --all --output=/home/node/.n8n/workflows.json
```

It reads single workflows, arrays (`export:workflow --all`), n8n API list responses (`{"data": [...]}`) and n8n.io template JSON. Directories are scanned recursively; non-workflow JSON files are skipped.

Example output (`examples/risky-workflow.json`):

```text
examples/risky-workflow.json :: Example: risky lead intake
  warn  no-error-workflow  No error workflow set: Triggers: Webhook
        fix: Workflow settings > Error Workflow: pick a workflow that starts with an Error Trigger and alerts you (Slack, email, etc.). Without it, failed production runs are silent.
  warn  save-errors-off  Failed executions are not saved: settings.saveDataErrorExecution = "none"
        fix: Workflow settings > Save failed production executions: set to Save, otherwise you cannot debug failures.
  ...
  error hardcoded-secret  [Create lead]  Secret or token pasted into a node: Bearer token in parameters.headerParameters.parameters[0].value: Bear…ij (39 chars)
        fix: Move it into an n8n credential (or an environment variable read with $env) and rotate the exposed value. Exported workflows, Git backups and shared templates carry parameters in plain text.
  ...
1 workflow(s) in 1 file(s) (0 skipped): 3 error(s), 7 warning(s), 3 info
```

## Options

```text
--format <text|json|github>       text (default), JSON, or GitHub Actions annotations
--fail-on <error|warn|info|none>  exit 1 if a finding at or above this level exists (default: error)
--min-level <error|warn|info>     only report findings at or above this level (default: info)
--ignore <rule,rule>              skip rules everywhere
--list-rules                      print all rules
```

To silence one rule on one node, put `audit-ignore: rule-id` in that node's **Notes** (node settings), e.g. `audit-ignore: webhook-no-auth` for a deliberately public form endpoint.

## GitHub Action

Keep your workflows in Git (for example with a nightly backup workflow) and audit every push:

```yaml
# .github/workflows/n8n-audit.yml
name: n8n audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: onyxaholguin-cyber/n8n-workflow-audit@v0.1.0
        with:
          path: workflows
          fail-on: error      # error | warn | info | none
          min-level: warn
```

Findings show up as annotations on the run and the pull request.

## Rules

| Rule | Level | What it flags |
|---|---|---|
| `hardcoded-secret` | error | Secret or token pasted into a node |
| `secret-in-header` | error | Auth header with a literal value |
| `webhook-no-auth` | warn | Webhook without authentication |
| `no-error-workflow` | warn | No error workflow set |
| `error-swallowed` | warn | Node errors are swallowed |
| `error-output-unconnected` | warn | Error output is not connected |
| `pinned-data` | warn | Pinned test data left in the workflow |
| `orphan-node` | warn | Node is not connected to anything |
| `save-errors-off` | warn | Failed executions are not saved |
| `insecure-tls` | warn | TLS certificate checks disabled |
| `http-no-retry` | info | HTTP Request without Retry On Fail |
| `plain-http` | info | Request to a non-HTTPS URL |
| `disabled-node` | info | Disabled node |

Every finding comes with a one-line fix. `no-error-workflow` only applies to workflows with an automatic trigger (schedule, webhook, app trigger); manual, Error Trigger and sub-workflows are exempt.

## How it was tested

- Unit and CLI tests: `node --test test/` (secret patterns, redaction, placeholders, AI sub-node connections, error outputs, exit codes, formats). CI runs them on Node 18, 20 and 22.
- Ran against 99 public workflows from the n8n.io template gallery: **0 false "secret" errors** after placeholder handling (`YOUR_TOKEN`, `$ENV_VAR`, `[REDACTED]`, `{api_key}` and similar are ignored).
- Static analysis only: it never connects to your n8n instance and never sends data anywhere.

## Fixing what it finds

Free, tested guides on the Sheet & Flow site:

- [Set up an n8n error alert workflow](https://onyxaholguin-cyber.github.io/sheet-and-flow/tutorials/n8n-error-alert-workflow/) (fixes `no-error-workflow`)
- [Back up n8n properly, including the encryption key](https://onyxaholguin-cyber.github.io/sheet-and-flow/tutorials/backup-n8n-properly/)
- [Self-host n8n with Docker Compose + Postgres](https://onyxaholguin-cyber.github.io/sheet-and-flow/tutorials/self-host-n8n-docker-compose-postgres/) and the free [n8n Docker Compose generator](https://onyxaholguin-cyber.github.io/sheet-and-flow/tools/n8n-compose-generator/)

If you'd rather not build it yourself, the paid **n8n Reliability Pack** (deduplicated error alerts, Git and disk backups, uptime/SSL monitor, weekly failure report) and **n8n Production Self-Hosting Kit** are listed [on the site](https://onyxaholguin-cyber.github.io/sheet-and-flow/#products). This tool is free and MIT-licensed either way.

## Notes

- Built with AI assistance and tested as described above. Issues and pull requests are welcome.
- Not affiliated with n8n GmbH. "n8n" is a trademark of its owner.
- MIT license.
