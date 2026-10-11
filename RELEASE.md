# Release checklist

1. `python3 -m unittest discover -s tests -v` passes.
2. Run the private malicious-fixture suite (kept out of this public repo);
   every planted technique must be detected.
3. `claude plugin validate .` passes.
4. `npx skills add . --list` shows every skill.
5. Bump `version` in `.claude-plugin/plugin.json` and each SKILL.md
   `metadata.version`; update CHANGELOG.md.
6. Commit, then tag: `git tag -s vX.Y.Z -m "vX.Y.Z"` (signed) and push the tag.
7. Create a GitHub release from the tag. Attach a zip of
   `skills/taa-skill-vetter/` for claude.ai uploads.
8. After the first installs, check the skill's security tab on skills.sh.
   If the signature file is flagged, respond with the README's scanner note.
