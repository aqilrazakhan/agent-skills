# Installing taa-skill-vetter

`taa-skill-vetter` security-audits a third-party agent skill **before** you
install it. Current release: **v1.0.1**.

Install a tagged release, not `main`. Pinning is the same advice the skill
gives about everyone else's skills, and it means you get exactly the code that
was reviewed.

## Requirements

- An agent that supports skills (Claude Code, claude.ai, or any agent
  supported by the [`skills` CLI](https://github.com/vercel-labs/skills)).
- Python 3.9+ on the machine that runs the audit. The scanner uses the
  standard library only.
- `git` and network access to GitHub, so the skill can clone what it audits.
- Node.js, only for the `skills` CLI route.

## Choose a route

| Route | Best for |
|---|---|
| [Claude Code plugin](#1-claude-code-plugin) | Claude Code users who want updates through the plugin system |
| [skills CLI](#2-skills-cli-skillssh) | Any supported agent; installs into the agent's skills folder |
| [Manual copy](#3-manual-copy) | Regulated environments, or if you want to read everything first |
| [claude.ai upload](#4-claudeai) | Using the skill in claude.ai |

## 1. Claude Code plugin

```bash
claude plugin marketplace add aqilrazakhan/agent-skills@v1.0.1
claude plugin install taa-skills@aqilrazakhan-agent-skills
```

Check it:

```bash
claude plugin list
```

You should see `taa-skills@aqilrazakhan-agent-skills`, version `1.0.1`,
enabled. In a Claude Code session the skill runs as
`/taa-skills:taa-skill-vetter`.

## 2. skills CLI (skills.sh)

List what the repo contains without installing anything:

```bash
npx skills add aqilrazakhan/agent-skills#v1.0.1 --list
```

Install for the agents you choose:

```bash
npx skills add aqilrazakhan/agent-skills#v1.0.1 --skill taa-skill-vetter
```

Claude Code only, available in every project (user-wide):

```bash
npx skills add aqilrazakhan/agent-skills#v1.0.1 --skill taa-skill-vetter -a claude-code -g
```

Check it with `npx skills list`.

## 3. Manual copy

1. Download the
   [v1.0.1 release](https://github.com/aqilrazakhan/agent-skills/releases/tag/v1.0.1)
   or clone the tag:
   ```bash
   git clone --depth 1 --branch v1.0.1 https://github.com/aqilrazakhan/agent-skills.git
   ```
2. Read `skills/taa-skill-vetter/`. It is small: `SKILL.md`, two reference
   documents, a signatures file and one Python script.
3. Copy the folder into one of:
   - `~/.claude/skills/taa-skill-vetter/` (all your projects)
   - `<project>/.claude/skills/taa-skill-vetter/` (one project, preferred)

## 4. claude.ai

1. Zip the `skills/taa-skill-vetter/` folder. Zip the folder itself, not just
   its contents.
2. Upload the zip in claude.ai's skill settings.

## Use it

Ask your agent, in your own words:

```
Audit aqilrazakhan/some-repo --skill some-skill before I install it
Vet the skill in ./downloads/cool-skill
Re-audit every skill installed in ~/.claude/skills
```

For each audit you get a `skill-audit-<name>-<shortsha>.md` report with a
PASS / REVIEW / FAIL verdict, the exact commit audited, the scanner findings
and how each was judged.

The scanner also runs on its own:

```bash
python3 -I skills/taa-skill-vetter/scripts/scan_skill.py <skill-dir> --md report.md --json report.json
# exit code: 0 PASS, 1 REVIEW, 2 FAIL
```

A scanner PASS is not proof of safety. The skill also requires a full manual
read of every file.

## Update

Releases are listed on the
[releases page](https://github.com/aqilrazakhan/agent-skills/releases). Before
moving to a new version, read the changelog and diff it like any other
third-party skill, ideally by auditing it with this skill:

```bash
git diff v1.0.1..<new-tag> -- skills/taa-skill-vetter
```

Then repeat your install command with the new tag.

- **Claude Code plugin:** run `claude plugin marketplace remove aqilrazakhan-agent-skills`,
  then add the marketplace again with the new `@<tag>` and reinstall.
- **skills CLI:** rerun `npx skills add aqilrazakhan/agent-skills#<tag> --skill taa-skill-vetter`.
  `npx skills update` is also available, but it moves to the latest version
  rather than a tag you have reviewed.
- **Manual / claude.ai:** replace the folder with the new tagged copy.

## Uninstall

- **Claude Code plugin:**
  ```bash
  claude plugin uninstall taa-skills@aqilrazakhan-agent-skills
  claude plugin marketplace remove aqilrazakhan-agent-skills
  ```
- **skills CLI:** `npx skills remove taa-skill-vetter`
- **Manual:** delete the `taa-skill-vetter` folder you copied.

## Troubleshooting

- **`python3: command not found`, or a syntax error from the scanner.** Install
  Python 3.9 or newer.
- **Marketplace name already exists.** Claude Code allows one marketplace per
  name. Remove the old `aqilrazakhan-agent-skills` entry first
  (`claude plugin marketplace remove aqilrazakhan-agent-skills`), then add the
  pinned one.
- **The audit cannot clone the target.** The skill asks you to attach the
  folder or zip instead. Private repositories need git credentials on the
  machine.
- **A scanner hit on `references/signatures.json` or
  `references/review-checklist.md` when scanning this skill.** Expected: those
  files describe the attacks being detected. See the note in the README.
- **A false positive or a missed attack.** Please open an issue at
  https://github.com/aqilrazakhan/agent-skills/issues with the pattern and, if
  possible, a minimal inert example.
