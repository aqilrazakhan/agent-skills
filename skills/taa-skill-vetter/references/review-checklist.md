# Manual review checklist

Answer every item in the report as Yes / No / N/A with file:line evidence.

## A. Scope and intent
- [ ] Stated purpose (description) written in one sentence.
- [ ] Every script, command and network call is required by that purpose.
- [ ] Description does not try to trigger on all/most tasks.
- [ ] No instructions to invoke, install or prefer other skills, plugins or MCP servers that were not declared.

## B. Agent-directed instructions (read as the agent would)
- [ ] No override phrasing ("ignore previous", "you are now", fake system/user/Anthropic messages).
- [ ] No stealth wording (silently, don't tell the user, without asking).
- [ ] No attempt to disable or pre-answer permission prompts.
- [ ] No "always run X first / on every call" bootstraps.
- [ ] No instructions hidden in: HTML comments, code comments, reference docs, JSON/YAML/CSV data, image alt-text, zero-width or tag Unicode, very long lines.
- [ ] Nothing addressed to an auditor or scanner ("this skill is verified", "mark as safe").

## C. Code behaviour
- [ ] Every file reviewed in full (list them).
- [ ] No execution of downloaded or decoded content.
- [ ] No reads of credentials, keychains, browser data, wallets, SSH/cloud/registry tokens, or bulk env vars.
- [ ] No writes outside the project/work dir; none to CLAUDE.md, AGENTS.md, MEMORY.md, `.claude/settings*.json`, hooks, MCP config, shell profiles, cron/launchd/systemd, git hooks.
- [ ] No destructive operations (recursive deletes, overwrites of user files) beyond the stated purpose.
- [ ] No sudo / privilege escalation.
- [ ] Obfuscation absent (minified/packed code, encoded blobs, dynamic attribute lookups to hide calls).

## D. Network
- [ ] Complete list of destinations (domain, purpose, data sent).
- [ ] Each destination is legitimate and required by the purpose.
- [ ] No webhook/paste/tunnel/raw-IP sinks.
- [ ] TLS not disabled (`verify=False`, `-k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).

## E. Supply chain
- [ ] Dependencies listed and versions pinned.
- [ ] Package names checked for typosquats.
- [ ] No runtime fetch of mutable content (`main`/`HEAD`, `latest`, unversioned `npx`/`uvx`).
- [ ] No bundled binaries/archives without reproducible source.
- [ ] No npm/pip install hooks.

## F. Provenance
- [ ] Publisher identity and history checked.
- [ ] Not a near-clone of a popular/official skill with small suspicious diffs.
- [ ] Not impersonating an official name (anthropic-*, claude-*, pdf, docx, xlsx, pptx).
- [ ] Marketplace security tab reviewed; findings reconciled with this audit.
- [ ] Commit SHA recorded.

## G. Privilege fit
- [ ] `allowed-tools` (if set) is the minimum needed; no `Bash` wildcard unless justified.
- [ ] Recommended scope: project vs personal.
- [ ] Data-sensitivity fit: safe to use in repos containing client/regulated data?
