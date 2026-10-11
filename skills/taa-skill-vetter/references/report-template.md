# Skill audit: <skill-name>

| | |
|---|---|
| **Verdict** | PASS / REVIEW / FAIL |
| **Source** | <repo URL> (path: <skills/x>) |
| **Commit audited** | <full SHA> |
| **Marketplace** | <skills.sh / other + link to its security tab> |
| **Audited on** | <date> |
| **Static risk score** | <n>/100 (critical a | high b | medium c | low d) |

## Summary
<3-5 sentences: what the skill claims to do, what it actually does, the deciding findings, and the verdict rationale.>

## Provenance
- Publisher:
- Repo signals (age, commits, contributors, stars trend, last commit):
- Name-collision / clone check:
- Marketplace scanner results and how they compare to this audit:

## Capabilities observed
| Capability | Evidence (file:line) | Explained by description? |
|---|---|---|
| Network: <domain> | | |
| Reads: <path> | | |
| Writes: <path> | | |
| Executes: <command> | | |

## Static scan triage
| Rule | Location | Triage (true positive / benign / decision) | Reason |
|---|---|---|---|

## Manual review
<Checklist sections A-G with Yes/No/N/A and evidence; list only failures and notable items in full.>

## Required changes before use (REVIEW only)
1.

## Safe-install recipe
<Pinned SHA, install path, scope, allowed-tools, re-audit trigger.>

## Limitations
Static and manual review of commit <SHA> only. Runtime-fetched content, future updates and dependencies' transitive code were <reviewed / not reviewed>.
