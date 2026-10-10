"""Deterministic inspection of shell commands (the ``Bash`` tool).

HARD LIMITS (documented in docs/limitations.md): regex/shlex cannot *secure*
arbitrary shell. Commands can be base64-encoded, read from files, built via
variables, or run through interpreters we don't model. This subsystem detects
*clear, well-known dangerous shapes* and flags *unparseable* commands as
uncertain so policy (not silent allow) decides.

We NEVER execute a command to find out whether it is safe.
"""

from __future__ import annotations

import re
import shlex

from ..models import SecurityFinding, Severity

# (rule_id, human message, severity, compiled regex). Applied to the raw command
# string. Patterns tolerate arbitrary internal whitespace via \s+.
_DANGEROUS: list[tuple[str, str, Severity, re.Pattern[str]]] = [
    (
        "cmd.disk_format",
        "Disk formatting / raw device write",
        Severity.CRITICAL,
        re.compile(r"\b(mkfs(\.\w+)?|format\s+[a-zA-Z]:)\b|\bdd\b[^\n]*\bof=/dev/"),
    ),
    (
        "cmd.fork_bomb",
        "Fork bomb pattern",
        Severity.CRITICAL,
        re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    ),
    (
        "cmd.download_execute",
        "Download-and-execute pipeline (curl/wget piped to a shell)",
        Severity.HIGH,
        re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|perl|node)\b"),
    ),
    (
        "cmd.remote_shell_exec",
        "Remote script fetched then executed",
        Severity.HIGH,
        re.compile(r"\b(bash|sh)\s+<\(\s*(curl|wget)\b"),
    ),
    (
        "cmd.chmod_777",
        "World-writable/exec permissions (chmod 777)",
        Severity.MEDIUM,
        re.compile(r"\bchmod\s+(-R\s+)?0?777\b"),
    ),
    (
        "cmd.disable_firewall",
        "Attempt to disable a host firewall / security control",
        Severity.HIGH,
        re.compile(r"\b(ufw\s+disable|iptables\s+-F|setenforce\s+0|systemctl\s+stop\s+(firewalld|apparmor))\b"),
    ),
    (
        "cmd.exfil_env",
        "Environment/credentials piped to a network client",
        Severity.HIGH,
        re.compile(r"\b(env|printenv|cat\s+[^\n|]*\.env[^\n|]*)\b[^\n]*\|\s*(curl|wget|nc|ncat)\b"),
    ),
    (
        "cmd.db_drop",
        "Destructive database statement",
        Severity.HIGH,
        re.compile(r"(?i)\b(drop\s+(database|table)|truncate\s+table)\b"),
    ),
    (
        "cmd.history_wipe",
        "Shell history / log wipe (anti-forensics)",
        Severity.MEDIUM,
        re.compile(r"\b(history\s+-c|rm\s+[^\n]*\.bash_history|>\s*/var/log/)"),
    ),
    (
        "cmd.obfuscated_exec",
        "Base64-decoded content piped to an interpreter (obfuscation)",
        Severity.HIGH,
        re.compile(r"\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(sh|bash|python[0-9.]*|node|perl)\b"),
    ),
]

# `rm` needs flag-aware handling: -r and -f can be fused (-rf), reordered (-fr),
# separated (-r -f), spelled long (--recursive --force), or mixed-case (-Rf). A
# single regex cannot express "r AND f appear across the option cluster", so we
# tokenize each rm invocation instead. Invocation = `rm` not preceded by a word
# char (so /bin/rm matches, but warm/confirm do not), up to a shell separator.
_RM_INVOCATION = re.compile(r"(?<!\w)rm\b([^\n;&|]*)")
# A target that *is* a root/home/system anchor (not merely a path under one).
_ROOT_TARGET = re.compile(r"^(/|~|/\*|/\.\*|\$HOME|\$\{HOME\}|%USERPROFILE%)$")


def _inspect_rm(command: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for match in _RM_INVOCATION.finditer(command):
        args = match.group(1)
        recursive = force = False
        targets: list[str] = []
        for tok in args.split():
            if tok in ("--recursive", "--recursive=true"):
                recursive = True
            elif tok == "--force":
                force = True
            elif tok == "--":
                continue
            elif tok.startswith("--"):
                continue  # some other long option
            elif tok.startswith("-") and len(tok) > 1:
                letters = tok[1:]
                recursive = recursive or any(c in "rR" for c in letters)
                force = force or "f" in letters
            else:
                targets.append(tok)
        if not (recursive and force):
            continue  # a plain `rm`, or recursive-only, is not what we flag here
        evidence = ("rm" + args).strip()[:80]
        if any(_ROOT_TARGET.match(t) for t in targets):
            findings.append(
                SecurityFinding(
                    rule_id="cmd.rm_rf_root",
                    category="command",
                    severity=Severity.CRITICAL,
                    message="Recursive force-delete targeting a root/home/system path",
                    evidence=evidence,
                )
            )
        findings.append(
            SecurityFinding(
                rule_id="cmd.rm_rf_generic",
                category="command",
                severity=Severity.HIGH,
                message="Recursive force-delete (rm -rf)",
                evidence=evidence,
            )
        )
    return findings


# Interpreters that take an inline program we cannot statically evaluate.
_OPAQUE_INTERPRETERS = {"python", "python3", "node", "perl", "ruby", "php", "osascript"}


def _looks_obfuscated(command: str) -> bool:
    # eval of a variable, or inline -c with an interpreter -> opaque payload.
    if re.search(r"\beval\b", command):
        return True
    tokens = command.split()
    for i, tok in enumerate(tokens):
        base = tok.split("/")[-1]
        if base in _OPAQUE_INTERPRETERS and i + 1 < len(tokens) and tokens[i + 1] in {"-c", "-e"}:
            return True
    return False


def inspect_command(command: str) -> list[SecurityFinding]:
    """Return findings for a Bash command string.

    Besides matching known-dangerous shapes, we try to tokenize with ``shlex``.
    A tokenization failure (unbalanced quotes, etc.) is itself reported as an
    "uncertain" finding so the engine does not silently treat it as benign.
    """
    findings: list[SecurityFinding] = []
    if not command or not command.strip():
        return findings

    findings += _inspect_rm(command)

    for rule_id, message, severity, pattern in _DANGEROUS:
        if pattern.search(command):
            match = pattern.search(command)
            evidence = match.group(0)[:80] if match else None
            findings.append(
                SecurityFinding(
                    rule_id=rule_id,
                    category="command",
                    severity=severity,
                    message=message,
                    evidence=evidence,
                )
            )

    if _looks_obfuscated(command):
        findings.append(
            SecurityFinding(
                rule_id="cmd.opaque_payload",
                category="command",
                severity=Severity.MEDIUM,
                message=(
                    "Command runs an inline/opaque program the firewall "
                    "cannot statically evaluate"
                ),
                evidence=None,
                confidence=0.6,
                inferred=True,
            )
        )

    try:
        shlex.split(command, posix=True)
    except ValueError:
        findings.append(
            SecurityFinding(
                rule_id="cmd.unparseable",
                category="command",
                severity=Severity.MEDIUM,
                message="Command could not be tokenized (unbalanced quoting); treated as uncertain",
                evidence=None,
                confidence=0.5,
                inferred=True,
            )
        )

    return findings
