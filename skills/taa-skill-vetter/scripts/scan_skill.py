#!/usr/bin/env python3
"""
scan_skill.py - static security scanner for third-party agent skills.

Reads every file in a skill folder AS TEXT ONLY. It never imports, executes,
installs, or follows anything it scans. Safe to point at hostile content.

Usage:
    python3 -I scan_skill.py <skill_dir> [--json out.json] [--md out.md]

Exit codes: 0 = PASS, 1 = REVIEW, 2 = FAIL, 3 = usage error
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

MAX_FILE_BYTES = 2_000_000
TEXT_EXT = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".rb", ".go", ".rs", ".php", ".pl", ".lua",
    ".html", ".htm", ".xml", ".csv", ".sql", ".env", "",
}
EXEC_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".app", ".msi",
            ".dmg", ".pkg", ".deb", ".rpm", ".jar", ".class", ".pyc", ".wasm"}
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".whl"}

SEV_WEIGHT = {"critical": 40, "high": 15, "medium": 5, "low": 1}


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    why: str
    flags: int = re.IGNORECASE


SIGNATURES = Path(__file__).resolve().parent.parent / "references" / "signatures.json"


def load_rules(path: Path = SIGNATURES) -> list[Rule]:
    """Detection signatures live in references/signatures.json as data."""
    data = json.loads(path.read_text("utf-8"))
    rules = []
    for r in data["rules"]:
        if r["severity"] not in SEV_WEIGHT:
            raise ValueError(f"bad severity in {r['id']}")
        re.compile(r["pattern"])  # fail fast on a broken signature
        rules.append(Rule(r["id"], r["category"], r["severity"], r["pattern"], r["why"]))
    return rules


RULES: list[Rule] = load_rules()

ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff\xad]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}|[0-9a-fA-F]{240,}")


@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    file: str
    line: int
    evidence: str
    why: str


def safe_snippet(s: str, n: int = 160) -> str:
    s = s.strip().replace("\t", " ")
    s = ZERO_WIDTH.sub("<ZW>", BIDI.sub("<BIDI>", TAG_CHARS.sub("<TAG>", s)))
    return (s[:n] + "...") if len(s) > n else s


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def parse_frontmatter(text: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.S)
    if not m:
        return {}
    fm: dict = {}
    key = None
    for raw in m.group(1).splitlines():
        if re.match(r"^[A-Za-z0-9_-]+\s*:", raw):
            key, _, val = raw.partition(":")
            key = key.strip()
            fm[key] = val.strip().strip("'\"")
        elif key and raw.startswith((" ", "\t", "-")):
            fm[key] = (fm[key] + " " + raw.strip()).strip()
    return fm


def scan(skill_dir: Path) -> dict:
    findings: list[Finding] = []
    inventory: list[dict] = []
    root = skill_dir.resolve()

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # hidden dirs are scanned too, but flagged
        for d in list(dirnames):
            p = Path(dirpath) / d
            rel = str(p.relative_to(root))
            if p.is_symlink():
                resolved = (p.parent / os.readlink(p)).resolve()
                sev = "critical" if not str(resolved).startswith(str(root)) else "high"
                findings.append(Finding("FS-01", "filesystem", sev, rel, 0,
                                        f"symlink -> {os.readlink(p)}",
                                        "Symlinked directory (outside skill dir = critical)"))
                dirnames.remove(d)
            elif d == ".git":
                dirnames.remove(d)
            elif d.startswith("."):
                findings.append(Finding("FS-02", "filesystem", "low", rel, 0, d, "Hidden directory"))

        for fn in filenames:
            p = Path(dirpath) / fn
            rel = str(p.relative_to(root))
            ext = p.suffix.lower()
            if p.is_symlink():
                target = os.readlink(p)
                resolved = (p.parent / target).resolve()
                sev = "critical" if not str(resolved).startswith(str(root)) else "medium"
                findings.append(Finding("FS-01", "filesystem", sev, rel, 0,
                                        f"symlink -> {target}", "Symlink (outside skill dir = critical)"))
                inventory.append({"file": rel, "bytes": 0, "type": "symlink"})
                continue
            size = p.stat().st_size
            ftype = "text"
            if ext in EXEC_EXT:
                ftype = "executable"
                findings.append(Finding("FS-03", "filesystem", "high", rel, 0, ext,
                                        "Bundled binary/compiled artefact - cannot be reviewed as text"))
            elif ext in ARCHIVE_EXT:
                ftype = "archive"
                findings.append(Finding("FS-04", "filesystem", "high", rel, 0, ext,
                                        "Bundled archive - contents hidden from review"))
            if os.access(p, os.X_OK) and ext not in {".sh", ".py", ".bash", ".js"}:
                findings.append(Finding("FS-05", "filesystem", "medium", rel, 0, "executable bit",
                                        "Executable file with non-script extension"))
            if fn.startswith("."):
                findings.append(Finding("FS-02", "filesystem", "low", rel, 0, fn, "Hidden file"))
            inventory.append({"file": rel, "bytes": size, "type": ftype})

            if ftype != "text":
                continue
            if size > MAX_FILE_BYTES:
                findings.append(Finding("FS-06", "filesystem", "medium", rel, 0, f"{size} bytes",
                                        "Very large file - skipped, review manually"))
                continue
            raw = p.read_bytes()
            if b"\x00" in raw[:4096]:
                findings.append(Finding("FS-07", "filesystem", "high", rel, 0, "NUL bytes",
                                        "Binary content in a text-named file"))
                continue
            text = raw.decode("utf-8", errors="replace")

            for rule in RULES:
                for m in re.finditer(rule.pattern, text, rule.flags | re.MULTILINE):
                    ln = line_of(text, m.start())
                    line_txt = text.splitlines()[ln - 1] if text else ""
                    findings.append(Finding(rule.id, rule.category, rule.severity, rel, ln,
                                            safe_snippet(line_txt), rule.why))

            for rx, rid, sev, why in [
                (ZERO_WIDTH, "OBF-01", "high", "Zero-width characters (hidden text)"),
                (BIDI, "OBF-02", "critical", "Bidirectional override characters (Trojan Source)"),
                (TAG_CHARS, "OBF-03", "critical", "Unicode tag characters (invisible instructions)"),
            ]:
                for m in rx.finditer(text):
                    ln = line_of(text, m.start())
                    findings.append(Finding(rid, "obfuscation", sev, rel, ln,
                                            safe_snippet(text.splitlines()[ln - 1]), why))
                    break  # one per file per type

            for m in B64_BLOB.finditer(text):
                blob = m.group(0)
                decoded_hint = ""
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)[:200]
                    if sum(32 <= c < 127 for c in dec) / max(len(dec), 1) > 0.85:
                        decoded_hint = " | decodes to text: " + safe_snippet(dec.decode("ascii", "replace"), 100)
                except Exception:
                    pass
                findings.append(Finding("OBF-04", "obfuscation", "high" if decoded_hint else "medium",
                                        rel, line_of(text, m.start()),
                                        safe_snippet(blob, 60) + decoded_hint, "Long base64 blob"))
            for m in HEX_BLOB.finditer(text):
                findings.append(Finding("OBF-05", "obfuscation", "medium", rel, line_of(text, m.start()),
                                        safe_snippet(m.group(0), 60), "Long hex-encoded blob"))

    # --- SKILL.md structural checks ----------------------------------------
    skill_md = root / "SKILL.md"
    meta: dict = {}
    if not skill_md.exists():
        findings.append(Finding("META-01", "metadata", "high", "SKILL.md", 0, "missing",
                                "No SKILL.md at skill root"))
    else:
        txt = skill_md.read_text("utf-8", errors="replace")
        meta = parse_frontmatter(txt)
        if not meta.get("name") or not meta.get("description"):
            findings.append(Finding("META-02", "metadata", "medium", "SKILL.md", 1, str(list(meta)),
                                    "Frontmatter missing name or description"))
        desc = meta.get("description", "")
        if len(desc) > 1024:
            findings.append(Finding("META-03", "metadata", "medium", "SKILL.md", 1, f"{len(desc)} chars",
                                    "Over-long description - can be used to over-trigger the skill"))
        if re.search(r"\b(always|every|any|all)\s+(task|request|message|conversation|prompt)s?\b", desc, re.I):
            findings.append(Finding("META-04", "metadata", "medium", "SKILL.md", 1, safe_snippet(desc),
                                    "Description tries to trigger on everything"))
        at = meta.get("allowed-tools", "")
        if at and re.search(r"Bash\(\s*\*?\s*\)|Bash(?!\()|\*", at):
            findings.append(Finding("META-05", "privilege", "high", "SKILL.md", 1, at,
                                    "allowed-tools grants unrestricted Bash / wildcard"))
        lines = txt.count("\n")
        if lines > 800:
            findings.append(Finding("META-06", "metadata", "low", "SKILL.md", 0, f"{lines} lines",
                                    "Very long SKILL.md - more room to hide instructions"))

    # --- de-dupe & score ---------------------------------------------------
    seen = set()
    uniq: list[Finding] = []
    for f in findings:
        k = (f.rule, f.file, f.line)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    uniq.sort(key=lambda f: (order[f.severity], f.file, f.line))

    counts = {s: sum(1 for f in uniq if f.severity == s) for s in order}
    score = min(100, sum(SEV_WEIGHT[f.severity] for f in uniq))
    if counts["critical"] or score >= 60:
        verdict = "FAIL"
    elif counts["high"] or score >= 15:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    return {
        "scanner": "taa-skill-vetter/scan_skill.py",
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": str(root),
        "skill_name": meta.get("name", ""),
        "description": meta.get("description", ""),
        "allowed_tools": meta.get("allowed-tools", ""),
        "verdict": verdict,
        "risk_score": score,
        "counts": counts,
        "files": inventory,
        "findings": [asdict(f) for f in uniq],
    }


def to_markdown(r: dict) -> str:
    out = [
        f"# Static scan: {r['skill_name'] or Path(r['target']).name}",
        "",
        f"**Verdict:** {r['verdict']}  |  **Risk score:** {r['risk_score']}/100  |  "
        f"critical {r['counts']['critical']} | high {r['counts']['high']} | "
        f"medium {r['counts']['medium']} | low {r['counts']['low']}",
        "",
        f"- Scanned: {r['scanned_at']}",
        f"- Files: {len(r['files'])}",
        f"- allowed-tools: `{r['allowed_tools'] or '(not set)'}`",
        f"- Description: {r['description'][:300]}",
        "",
        "> Static pattern matching only. A PASS is not proof of safety; "
        "an LLM/manual review of every file is still required.",
        "",
        "## Findings",
        "",
    ]
    if not r["findings"]:
        out.append("_No pattern matches._")
    else:
        out += ["| Sev | Rule | Category | Location | Evidence | Why |",
                "|---|---|---|---|---|---|"]
        for f in r["findings"]:
            ev = f["evidence"].replace("|", "\\|").replace("`", "'")
            out.append(f"| {f['severity']} | {f['rule']} | {f['category']} | "
                       f"`{f['file']}:{f['line']}` | `{ev}` | {f['why']} |")
    out += ["", "## File inventory", "", "| File | Bytes | Type |", "|---|---|---|"]
    for i in r["files"]:
        out.append(f"| `{i['file']}` | {i['bytes']} | {i['type']} |")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Static security scan of an agent skill folder")
    ap.add_argument("skill_dir")
    ap.add_argument("--json", help="write JSON report here")
    ap.add_argument("--md", help="write Markdown report here")
    a = ap.parse_args()
    d = Path(a.skill_dir)
    if not d.is_dir():
        print(f"not a directory: {d}", file=sys.stderr)
        return 3
    r = scan(d)
    if a.json:
        Path(a.json).write_text(json.dumps(r, indent=2), "utf-8")
    md = to_markdown(r)
    if a.md:
        Path(a.md).write_text(md, "utf-8")
    print(md)
    return {"PASS": 0, "REVIEW": 1, "FAIL": 2}[r["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
