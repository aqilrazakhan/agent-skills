# Agent Skills by Towards Agentic AI

Agent skills by [Aqil Khan](https://github.com/aqilrazakhan), founder of
[BI Analytics Inc.](https://bianalytics.ca) and co-founder of
[Towards Agentic AI](https://towardsagenticai.com). The skills are built from
15+ years of data governance and regulatory-compliance work in Canadian
financial services.

They work with Claude Code, claude.ai, the Claude API and any agent supported
by the [`skills` CLI](https://github.com/vercel-labs/skills) / [skills.sh](https://skills.sh).

## Skills

| Skill | What it does |
|---|---|
| [`taa-skill-vetter`](skills/taa-skill-vetter/) | Security-audits a third-party agent skill **before** you install it. It quarantines the skill, checks provenance, runs a static scan (49 signatures plus hidden-Unicode, encoding and filesystem checks), does a mandatory full-file review, and writes a PASS / REVIEW / FAIL report with a pinned-install recipe. |

## Install

Pin to a release tag. Don't track `main`, which is the same advice this
repo's skill gives about everyone else's skills.

**Any agent (skills.sh CLI)**
```bash
npx skills add aqilrazakhan/agent-skills --skill taa-skill-vetter
# Claude Code only, user-wide:
npx skills add aqilrazakhan/agent-skills --skill taa-skill-vetter -a claude-code -g
```

**Claude Code plugin marketplace**
```bash
claude plugin marketplace add aqilrazakhan/agent-skills
claude plugin install taa-skills@aqilrazakhan-agent-skills
```

**Manual (recommended for regulated environments)**
Download the tagged release, review it, then copy `skills/taa-skill-vetter/`
into `~/.claude/skills/` or your project's `.claude/skills/`.

**claude.ai**
Zip the `skills/taa-skill-vetter/` folder (the folder itself, not just its
contents) and upload it in claude.ai's skill settings.

## Usage

```
Audit aqilrazakhan/some-repo --skill some-skill before I install it
Vet the skill in ./downloads/cool-skill
Re-audit every skill installed in ~/.claude/skills
```

The scanner also runs on its own (Python 3.9+, standard library only):
```bash
python3 -I skills/taa-skill-vetter/scripts/scan_skill.py <skill-dir> --md report.md --json report.json
# exit code: 0 PASS, 1 REVIEW, 2 FAIL
```

## A note for security scanners and reviewers

`skills/taa-skill-vetter/references/signatures.json` contains **detection
signatures**: regular expressions describing malicious patterns such as
reverse shells, exfiltration endpoints and prompt-injection phrasing. They
are loaded as data and matched against *other* skills' files. Nothing in this
repository executes, downloads or installs anything, and the scanner never
runs the code it inspects. Automated malware scanners may still flag the
signature file. If one does, please read the file before drawing
conclusions.

Self-scanning this skill gives FAIL on its own signature and checklist files
for the same reason. The only other match is a medium-severity hit on a
`.env` extension constant in the scanner.

## Limitations

- Static and manual review only. There is no sandboxed execution or dynamic
  analysis.
- Regex signatures catch known shapes. The mandatory manual review is what
  catches skills whose behaviour doesn't match their description.
- The reviewing agent is told to treat the target as hostile data. A
  sufficiently clever injection could still influence it. For audits near
  sensitive data, run the vetter in a session with no credentials loaded.
- A PASS applies to the audited commit only.

## Contributing

Issues and PRs welcome, especially new signatures with a benign
false-positive analysis. To report a bypass or a vulnerability, see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Aqil Khan
