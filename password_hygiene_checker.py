import argparse
import getpass
import hashlib
import json
import math
import re
import sys
from pathlib import Path

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
COMMON_LIST_PATH = Path(__file__).parent / "common_passwords.txt"


def load_common_passwords(path: Path = COMMON_LIST_PATH) -> set:
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def check_strength(password: str, common_list: set) -> dict:
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    class_count = sum([has_lower, has_upper, has_digit, has_symbol])

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 33
    entropy_bits = round(length * math.log2(charset_size), 1) if charset_size else 0.0

    is_common = password.lower() in common_list

    score = 0
    if not is_common:
        score += min(length * 4, 40)
        score += class_count * 10
        score += min(int(entropy_bits / 2), 30)
    score = max(0, min(100, score))

    if is_common or score < 40:
        verdict = "Weak"
    elif score < 70:
        verdict = "Medium"
    else:
        verdict = "Strong"

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "class_count": class_count,
        "entropy_bits": entropy_bits,
        "is_common": is_common,
        "score": score,
        "verdict": verdict,
    }


def check_pwned(password: str, timeout: float = 5.0):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(HIBP_RANGE_URL.format(prefix=prefix), timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException:
        return None

    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        line_suffix, count = parts
        if line_suffix == suffix:
            return int(count)
    return 0


def render_report(strength: dict, pwned_count) -> str:
    lines = ["# Password Hygiene Report", ""]
    lines.append(f"- Length: {strength['length']}")
    classes = []
    if strength["has_lower"]:
        classes.append("lowercase")
    if strength["has_upper"]:
        classes.append("uppercase")
    if strength["has_digit"]:
        classes.append("digit")
    if strength["has_symbol"]:
        classes.append("symbol")
    lines.append(f"- Character classes used: {', '.join(classes) if classes else 'none'} ({strength['class_count']}/4)")
    lines.append(f"- Estimated entropy: ~{strength['entropy_bits']} bits")
    lines.append(f"- Found in common password list: {'yes' if strength['is_common'] else 'no'}")
    lines.append(f"- Strength score: {strength['score']}/100")
    lines.append(f"- **Verdict: {strength['verdict']}**")
    lines.append("")

    if pwned_count is None:
        lines.append("- Breach check: skipped (no network access or HIBP API unreachable)")
    elif pwned_count == 0:
        lines.append("- Breach check: not found in any known breach (Have I Been Pwned)")
    else:
        lines.append(f"- Breach check: ⚠️ found in **{pwned_count:,}** known breaches (Have I Been Pwned)")

    lines.append("")
    lines.append("> Note: your password is never stored or written to disk. Only this summary is saved.")
    return "\n".join(lines)


def render_json(strength: dict, pwned_count) -> str:
    payload = {
        "length": strength["length"],
        "character_classes": {
            "lowercase": strength["has_lower"],
            "uppercase": strength["has_upper"],
            "digit": strength["has_digit"],
            "symbol": strength["has_symbol"],
        },
        "class_count": strength["class_count"],
        "entropy_bits": strength["entropy_bits"],
        "found_in_common_list": strength["is_common"],
        "score": strength["score"],
        "verdict": strength["verdict"],
        "breach_check": {
            "status": "skipped" if pwned_count is None else "checked",
            "pwned_count": pwned_count,
        },
        "note": "The password itself is never included in this output.",
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="Check password strength and breach exposure without exposing the password itself.")
    parser.add_argument("--password", help="Password to check (omit to be prompted securely)")
    parser.add_argument("--output", default="report.md", help="Path to write the report to")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format (default: markdown)")
    parser.add_argument("--skip-pwned-check", action="store_true", help="Skip the Have I Been Pwned breach check (local strength check only)")
    parser.add_argument("--fail-on-weak", action="store_true", help="Exit with code 1 if the verdict is Weak (for CI/account-creation gating)")
    parser.add_argument("--fail-on-pwned", action="store_true", help="Exit with code 1 if the password was found in a known breach")
    args = parser.parse_args()

    password = args.password if args.password is not None else getpass.getpass("Enter password to check: ")

    common_list = load_common_passwords()
    strength = check_strength(password, common_list)

    pwned_count = None
    if not args.skip_pwned_check:
        pwned_count = check_pwned(password)

    report = render_json(strength, pwned_count) if args.format == "json" else render_report(strength, pwned_count)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report + "\n")

    print(f"Verdict: {strength['verdict']} (score {strength['score']}/100)")
    print(f"Report written to {args.output}")

    if args.fail_on_weak and strength["verdict"] == "Weak":
        return 1
    if args.fail_on_pwned and pwned_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
