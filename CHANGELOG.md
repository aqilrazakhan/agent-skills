# Changelog

## 1.0.1 - 2026-10-11
- Add `tests/test_hostile_fixtures.py`: inert hostile skills built in temp
  directories at test time, plus scanner robustness and CLI exit-code tests.
- Fix `DST-01` missing `rm -rf ~/`, `$HOME/` and `~/*`.
- Extend `PER-01` to prose instructions that write to agent memory or
  instruction files (CLAUDE.md, AGENTS.md, MEMORY.md and similar).
- Escalate directory symlinks that resolve outside the skill folder (`FS-01`)
  to critical, matching file symlinks.

## 1.0.0 - 2026-10-11
- Initial release of `taa-skill-vetter`: quarantine, provenance, static scan
  (49 data-driven signatures plus Unicode, encoding, filesystem and
  frontmatter checks), mandatory manual review, PASS/REVIEW/FAIL report.
- Claude Code plugin marketplace manifest (`taa-skills`).
