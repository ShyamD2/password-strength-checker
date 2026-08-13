"""
Command-line interface for the Advanced Password Strength Checker.

Usage examples:
    python -m password_checker "MyP@ssw0rd123"
    python -m password_checker                      # hidden prompt
    python -m password_checker --file passwords.txt --json
    python -m password_checker --policy policy.json --min-score 60
    python -m password_checker --suggest --length 24
"""

import argparse
import getpass
import json
import sys
from dataclasses import asdict

from .analyzer import analyze
from .crack_time import estimate_crack_times
from .breach_check import check_breach
from .policy import load_policy, check_policy
from .generator import generate_password

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.text import Text
    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False

console = Console() if _HAS_RICH else None

STRENGTH_COLORS = {
    "Very Weak": "bright_red",
    "Weak": "red",
    "Fair": "yellow",
    "Good": "green",
    "Strong": "bright_green",
    "Very Strong": "bold bright_green",
}


def _print_plain(text: str):
    print(text)


def render_result(password: str, result, crack_times, breach_result, policy_result=None):
    if not _HAS_RICH:
        _render_plain(password, result, crack_times, breach_result, policy_result)
        return

    color = STRENGTH_COLORS.get(result.strength_label, "white")
    bar_len = 30
    filled = int(bar_len * result.score / 100)
    bar = "█" * filled + "░" * (bar_len - filled)

    header = Text()
    header.append(f"{bar}  ", style=color)
    header.append(f"{result.score}/100  ", style=f"bold {color}")
    header.append(result.strength_label, style=f"bold {color}")

    console.print(Panel(header, title="Password Strength", expand=False))

    info_table = Table(show_header=False, box=None, padding=(0, 1))
    info_table.add_row("Length", str(result.password_length))
    info_table.add_row("Character pool size", str(result.pool_size))
    info_table.add_row("Estimated entropy", f"{result.entropy_bits} bits")
    console.print(info_table)

    if result.pattern_matches:
        pt = Table(title="Detected Weaknesses", show_lines=False)
        pt.add_column("Type")
        pt.add_column("Detail")
        pt.add_column("Penalty", justify="right")
        for m in result.pattern_matches:
            pt.add_row(m.kind, m.detail, f"-{m.penalty}")
        console.print(pt)
    else:
        console.print("[green]No structural weaknesses detected.[/green]")

    ct = Table(title="Estimated Crack Time")
    ct.add_column("Attack Scenario")
    ct.add_column("Estimated Time")
    for est in crack_times:
        ct.add_row(est.scenario, est.human_readable)
    console.print(ct)

    if breach_result.checked:
        if breach_result.breached:
            console.print(Panel(
                f"[bold red]⚠ Found in {breach_result.times_seen:,} known data breaches.[/bold red]\n"
                "This password should not be used.",
                title="Breach Check (HaveIBeenPwned)",
            ))
        else:
            console.print(Panel(
                "[green]✓ Not found in known breach databases.[/green]",
                title="Breach Check (HaveIBeenPwned)",
            ))
    elif breach_result.error:
        console.print(f"[dim]Breach check skipped: {breach_result.error}[/dim]")

    sugg_text = "\n".join(f"• {s}" for s in result.suggestions)
    console.print(Panel(sugg_text, title="Suggestions", border_style="cyan"))

    if policy_result is not None:
        if policy_result.compliant:
            console.print(Panel("[bold green]✓ Compliant with policy.[/bold green]", title="Policy Check"))
        else:
            violations = "\n".join(f"• {v}" for v in policy_result.violations)
            console.print(Panel(f"[bold red]✗ Not compliant:[/bold red]\n{violations}", title="Policy Check", border_style="red"))


def _render_plain(password, result, crack_times, breach_result, policy_result):
    print(f"Score: {result.score}/100 ({result.strength_label})")
    print(f"Length: {result.password_length}  Pool size: {result.pool_size}  Entropy: {result.entropy_bits} bits")
    print()
    if result.pattern_matches:
        print("Detected weaknesses:")
        for m in result.pattern_matches:
            print(f"  - [{m.kind}] {m.detail} (-{m.penalty})")
    else:
        print("No structural weaknesses detected.")
    print()
    print("Estimated crack time:")
    for est in crack_times:
        print(f"  - {est.scenario}: {est.human_readable}")
    print()
    if breach_result.checked:
        if breach_result.breached:
            print(f"BREACH CHECK: Found in {breach_result.times_seen:,} known breaches!")
        else:
            print("BREACH CHECK: Not found in known breaches.")
    elif breach_result.error:
        print(f"Breach check skipped: {breach_result.error}")
    print()
    print("Suggestions:")
    for s in result.suggestions:
        print(f"  - {s}")
    if policy_result is not None:
        print()
        if policy_result.compliant:
            print("POLICY: Compliant.")
        else:
            print("POLICY: Not compliant.")
            for v in policy_result.violations:
                print(f"  - {v}")


def build_json_output(password, result, crack_times, breach_result, policy_result=None):
    output = {
        "score": result.score,
        "strength_label": result.strength_label,
        "length": result.password_length,
        "pool_size": result.pool_size,
        "entropy_bits": result.entropy_bits,
        "pattern_matches": [
            {"kind": m.kind, "detail": m.detail, "penalty": m.penalty}
            for m in result.pattern_matches
        ],
        "crack_times": [
            {"scenario": e.scenario, "human_readable": e.human_readable, "seconds": e.seconds}
            for e in crack_times
        ],
        "suggestions": result.suggestions,
        "breach_check": {
            "checked": breach_result.checked,
            "breached": breach_result.breached,
            "times_seen": breach_result.times_seen,
            "error": breach_result.error,
        },
    }
    if policy_result is not None:
        output["policy"] = {
            "compliant": policy_result.compliant,
            "violations": policy_result.violations,
        }
    return output


def process_password(password: str, args) -> tuple:
    result = analyze(password)
    crack_times = estimate_crack_times(result.pool_size, result.password_length)

    breach_result = None
    if not args.no_breach_check:
        breach_result = check_breach(password)
    else:
        from .breach_check import BreachResult
        breach_result = BreachResult(checked=False, breached=False, times_seen=0, error="Skipped by user")

    policy_result = None
    if args.policy or args.min_score is not None:
        policy = load_policy(args.policy)
        if args.min_score is not None:
            policy["min_score"] = args.min_score
        has_common = any(m.kind.startswith("common") for m in result.pattern_matches)
        policy_result = check_policy(password, policy, result.score, has_common)

    return result, crack_times, breach_result, policy_result


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Password Strength Checker — entropy analysis, "
                     "pattern detection, crack-time estimation, breach check, "
                     "and policy compliance."
    )
    parser.add_argument("password", nargs="?", help="Password to check (omit for hidden prompt)")
    parser.add_argument("--file", help="Path to a file with one password per line (batch mode)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--no-breach-check", action="store_true", help="Skip the HaveIBeenPwned online check")
    parser.add_argument("--policy", help="Path to a JSON policy file for compliance checking")
    parser.add_argument("--min-score", type=int, help="Minimum required score (overrides policy file); exits non-zero if not met")
    parser.add_argument("--suggest", action="store_true", help="Generate a strong random password instead of checking one")
    parser.add_argument("--length", type=int, default=20, help="Length for --suggest (default: 20)")
    args = parser.parse_args()

    if args.suggest:
        pw = generate_password(length=args.length)
        result, crack_times, breach_result, policy_result = process_password(pw, args)
        if args.json:
            out = build_json_output(pw, result, crack_times, breach_result, policy_result)
            out["generated_password"] = pw
            print(json.dumps(out, indent=2))
        else:
            if _HAS_RICH:
                console.print(Panel(f"[bold cyan]{pw}[/bold cyan]", title="Generated Password"))
            else:
                print(f"Generated password: {pw}")
            render_result(pw, result, crack_times, breach_result, policy_result)
        sys.exit(0)

    if args.file:
        exit_code = 0
        with open(args.file, "r", encoding="utf-8") as f:
            passwords = [line.rstrip("\n") for line in f if line.strip()]
        all_json = []
        for pw in passwords:
            result, crack_times, breach_result, policy_result = process_password(pw, args)
            if args.json:
                all_json.append(build_json_output(pw, result, crack_times, breach_result, policy_result))
            else:
                masked = pw[:2] + "*" * max(0, len(pw) - 2)
                if _HAS_RICH:
                    console.rule(f"[bold]{masked}[/bold]")
                else:
                    print(f"\n=== {masked} ===")
                render_result(pw, result, crack_times, breach_result, policy_result)
            if policy_result is not None and not policy_result.compliant:
                exit_code = 1
        if args.json:
            print(json.dumps(all_json, indent=2))
        sys.exit(exit_code)

    password = args.password
    if password is None:
        password = getpass.getpass("Enter password to check (hidden): ")

    result, crack_times, breach_result, policy_result = process_password(password, args)

    if args.json:
        print(json.dumps(build_json_output(password, result, crack_times, breach_result, policy_result), indent=2))
    else:
        render_result(password, result, crack_times, breach_result, policy_result)

    if policy_result is not None and not policy_result.compliant:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
