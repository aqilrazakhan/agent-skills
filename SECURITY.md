# Security Policy

## Reporting a vulnerability or bypass

Please **do not open a public issue** for:
- a malicious-skill technique that `taa-skill-vetter` fails to detect,
- a prompt injection that steers the vetter into a wrong verdict,
- any vulnerability in this repository.

Use GitHub's private vulnerability reporting instead:
**Security tab → Report a vulnerability** on
https://github.com/aqilrazakhan/agent-skills.

Include a minimal, non-weaponised reproduction (a description or a
defanged sample skill is enough) and the version or commit tested.
You can expect an acknowledgement within 5 business days.

## Supported versions

Only the latest release tag is supported. Always install a pinned tag.

## Scope note

`skills/taa-skill-vetter/references/signatures.json` intentionally contains
patterns that describe malicious code. They are detection signatures loaded as
data, not executable content. Reports that only point out their presence are
out of scope.
