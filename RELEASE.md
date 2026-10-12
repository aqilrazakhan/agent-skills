# Release checklist

1. `python3 -m unittest discover -s tests -v` passes. This includes
   `test_hostile_fixtures.py`, which builds inert hostile skills at test time.
2. Run the private malicious-fixture suite (kept out of this public repo);
   every planted technique must be detected.
3. `claude plugin validate .` passes.
4. `npx skills add . --list` shows every skill.
5. Bump `version` in `.claude-plugin/plugin.json`, each SKILL.md
   `metadata.version` and `references/signatures.json`; update CHANGELOG.md.
6. Merge that change to `main` via PR, then tag the merge commit:
   `git tag -s vX.Y.Z -m "vX.Y.Z"` (signed) and push the tag.
7. Create a GitHub release from the tag. Attach a zip of
   `skills/taa-skill-vetter/` for claude.ai uploads.
8. Update the pinned version in README.md's Install section and in
   INSTALLATION.md (the intro line,
   the two `npx skills add ...#vX.Y.Z` commands, the
   `claude plugin marketplace add ...@vX.Y.Z` command and the release link)
   and merge it. Do this after the tag exists, since the snippets point at it.
   Check with `grep -n 'v[0-9]\+\.[0-9]\+\.[0-9]\+' README.md`.
9. After the first installs, check the skill's security tab on skills.sh.
   If the signature file is flagged, respond with the README's scanner note.
