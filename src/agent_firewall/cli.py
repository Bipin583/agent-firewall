"""Command-line interface: ``agent-firewall``.

Subcommands:
  evaluate         Evaluate a synthetic tool request and print the decision.
  audit verify     Verify the integrity of an audit log (hash chain).
  audit show       Print recent audit events.
  policy validate  Validate a policy YAML file against the schema.
  hook             Run the Claude Code PreToolUse hook (reads JSON from stdin).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .config import CoreConfig
from .engine import SecurityEngine
from .normalize import normalize
from .policies import PolicyLoadError, load_policy_document


def _cmd_evaluate(args: argparse.Namespace) -> int:
    try:
        tool_input: dict[str, Any] = json.loads(args.input) if args.input else {}
    except ValueError as exc:
        print(f"error: --input is not valid JSON: {exc}", file=sys.stderr)
        return 2
    config = CoreConfig.from_env()
    policy_file = args.policy or config.policy_file
    try:
        doc = load_policy_document(policy_file)
    except PolicyLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    engine = SecurityEngine(doc)
    req = normalize(
        args.tool,
        tool_input,
        environment=config.environment,
        project_root=str(config.project_root) if config.project_root else None,
    )
    decision = engine.evaluate(req)
    print(json.dumps(decision.model_dump(mode="json"), indent=2))
    return 0


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    from .audit import verify_chain

    config = CoreConfig.from_env()
    log = args.log or config.audit_log
    result = verify_chain(log)
    print(json.dumps(result.as_dict(), indent=2))
    if result.ok:
        print(f"OK: {result.total} event(s) verified.", file=sys.stderr)
        return 0
    print(f"FAIL: {len(result.errors)} integrity error(s).", file=sys.stderr)
    return 1


def _cmd_audit_show(args: argparse.Namespace) -> int:
    from .audit import read_events

    config = CoreConfig.from_env()
    log = args.log or config.audit_log
    for event in read_events(log, limit=args.limit):
        print(json.dumps(event))
    return 0


def _cmd_policy_validate(args: argparse.Namespace) -> int:
    try:
        doc = load_policy_document(args.file)
    except PolicyLoadError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: {args.file} is valid "
        f"({len(doc.policies)} policies, default={doc.default_effect.value})."
    )
    return 0


def _cmd_hook(_: argparse.Namespace) -> int:
    from .integrations.claude_code.hook import main as hook_main

    return hook_main()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-firewall", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("evaluate", help="Evaluate a synthetic tool request.")
    ev.add_argument("--tool", required=True, help="Tool name, e.g. Bash, Read, Write.")
    ev.add_argument("--input", default="{}", help="Tool input as a JSON object string.")
    ev.add_argument("--policy", default=None, help="Policy file (defaults to configured).")
    ev.set_defaults(func=_cmd_evaluate)

    audit = sub.add_parser("audit", help="Audit log operations.")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="Verify the audit hash chain.")
    verify.add_argument("--log", default=None, help="Audit log path.")
    verify.set_defaults(func=_cmd_audit_verify)
    show = audit_sub.add_parser("show", help="Print recent audit events.")
    show.add_argument("--log", default=None, help="Audit log path.")
    show.add_argument("--limit", type=int, default=20, help="Max events to show.")
    show.set_defaults(func=_cmd_audit_show)

    policy = sub.add_parser("policy", help="Policy operations.")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    validate = policy_sub.add_parser("validate", help="Validate a policy file.")
    validate.add_argument("file", help="Path to a policy YAML file.")
    validate.set_defaults(func=_cmd_policy_validate)

    hook = sub.add_parser("hook", help="Run the Claude Code PreToolUse hook (stdin).")
    hook.set_defaults(func=_cmd_hook)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
