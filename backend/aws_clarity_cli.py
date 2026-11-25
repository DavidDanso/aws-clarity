#!/usr/bin/env python3
"""AWS Clarity Local CLI — privacy-first, read-only AWS account scanner.

Usage:
  aws-clarity doctor --profile my-profile
  aws-clarity scan --profile my-profile --output aws-clarity-report.json
  aws-clarity scan --profile my-profile --yes --output aws-clarity-report.json
  aws-clarity scan --profile my-profile --include-s3-checks --output aws-clarity-report.json
  aws-clarity policy --zero-cost-only
"""

import argparse
import json
import os
import stat
import sys

from exceptions import RootIdentityBlockedError
from local_engine import (
    CLI_VERSION,
    S3_OPTIONAL_COST_NOTICE,
    build_policy_document,
    create_local_session,
    describe_credential_source,
    enforce_identity_guards,
    format_admin_heuristic_warning,
    mask_account_id,
    mask_caller_arn,
    run_doctor,
    run_local_scan,
    verify_identity,
)
from utils import redact_credential_strings


def _write_secure_json(path: str, payload: dict, pretty: bool = True) -> None:
    """Write report JSON locally with owner-only permissions (0600 on POSIX; user ACLs on Windows)."""
    text = json.dumps(payload, default=str, indent=2 if pretty else None) + "\n"
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    if os.name == "posix":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _prompt_s3_consent(confirm_flag: bool) -> bool:
    if confirm_flag:
        return True
    print("\n[Optional S3 Checks — Cost Disclosure]", file=sys.stderr)
    print(f"  {S3_OPTIONAL_COST_NOTICE}", file=sys.stderr)
    if not sys.stdin.isatty():
        print(
            "  Non-interactive shell detected. Pass --confirm-s3-request-costs to explicitly consent, "
            "or omit --include-s3-checks to run the 9 zero-request-charge services.",
            file=sys.stderr,
        )
        return False
    try:
        answer = input("  Enable optional S3 bucket configuration checks? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def _print_prescan_confirmation_and_prompt(
    *,
    account_id: str,
    caller_arn: str,
    credential_source: str,
    regions_arg,
    include_s3: bool,
    auto_yes: bool,
) -> bool:
    """Print transparent pre-scan scope & identity summary before any collector runs."""
    regions_display = (
        "All enabled AWS regions (auto-discovered via ec2:DescribeRegions)"
        if regions_arg == "all"
        else ", ".join(regions_arg)
    )
    scope_display = (
        "10 AWS services / 34 allowlisted read-only actions (optional S3 ENABLED)"
        if include_s3
        else "9 AWS services / 28 allowlisted read-only actions (S3 skipped by default)"
    )
    charges_display = (
        "Potential small AWS S3 LIST ($0.005/1k) & GET ($0.0004/1k) request fees outside 12-mo S3 Free Tier"
        if include_s3
        else "$0 in AWS API request charges (free control-plane Describe/List/Get APIs only)"
    )

    print(
        f"\nAWS Clarity Local Scanner v{CLI_VERSION} — Pre-Scan Confirmation (local-only; zero uploads)",
        file=sys.stderr,
    )
    print(f"  Target AWS Account  : {mask_account_id(account_id)}", file=sys.stderr)
    print(f"  Caller ARN          : {mask_caller_arn(caller_arn)}", file=sys.stderr)
    print(f"  Credential Source   : {credential_source}", file=sys.stderr)
    print(f"  Read-Only Scope     : {scope_display}", file=sys.stderr)
    print(f"  Target Regions      : {regions_display}", file=sys.stderr)
    print(f"  Optional S3 Checks  : {'ENABLED (with consent)' if include_s3 else 'OFF (default)'}", file=sys.stderr)
    print(f"  Potential AWS Cost  : {charges_display}", file=sys.stderr)
    print(
        "  Collected           : Allowlisted configuration metadata only (no resource modifications).",
        file=sys.stderr,
    )
    print(
        "  NOT Collected       : S3 object lists/contents, RDS/DynamoDB rows, Lambda code or env var values,\n"
        "                        resource tag values, free-text descriptions, CloudWatch log events, credentials.",
        file=sys.stderr,
    )
    print(
        "  Permission Note     : AWS Clarity does not inspect or claim your identity's full effective IAM permissions.",
        file=sys.stderr,
    )

    if auto_yes:
        print("  Confirmation        : Auto-confirmed via --yes.", file=sys.stderr)
        return True

    if not sys.stdin.isatty():
        print(
            "  Non-interactive shell detected. Review the target account and scope above, then re-run with --yes.",
            file=sys.stderr,
        )
        return False

    try:
        answer = input("\n  Proceed with this read-only local scan? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def cmd_doctor(args: argparse.Namespace) -> int:
    try:
        session = create_local_session(
            profile=args.profile,
            role_arn=args.role_arn,
            external_id=args.external_id,
        )
        result = run_doctor(
            session,
            include_s3_checks=args.include_s3_checks,
            allow_root=args.allow_root,
        )
    except RootIdentityBlockedError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {redact_credential_strings(str(exc))}", file=sys.stderr)
        return 1

    if result.get("admin_name_heuristic"):
        print(f"\n{format_admin_heuristic_warning(result['caller_arn'])}\n", file=sys.stderr)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "OK" else 2

    print(f"AWS Clarity Doctor v{CLI_VERSION} (local-only; zero data uploaded)")
    print(f"  AWS Account ID : {mask_account_id(result['account_id'])}")
    print(f"  Caller ARN     : {mask_caller_arn(result['caller_arn'])}")
    print(f"  Enabled Regions: {len(result['enabled_regions'])} ({result['region_discovery'].get('status')})")
    print("")
    print("Service Read-Only Permission Probes:")
    for svc, info in result["permission_checks"].items():
        status = info["status"]
        marker = "OK  " if status == "PASSED" else ("SKIP" if status == "SKIPPED_OPTIONAL" else "MISS")
        detail = f" — {info['message']}" if info.get("message") else ""
        print(f"  [{marker}] {svc:<12} {status}{detail}")

    if result["missing_services"]:
        print(
            f"\nMissing permissions for {len(result['missing_services'])} service(s): "
            + ", ".join(result["missing_services"]),
            file=sys.stderr,
        )
        print("Run `aws-clarity policy --zero-cost-only` to inspect the exact least-privilege read-only IAM policy.", file=sys.stderr)
        return 2

    print("\nAll checked permissions passed. Ready to run `aws-clarity scan`.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    include_s3 = bool(args.include_s3_checks)
    s3_confirmed = False
    if include_s3:
        s3_confirmed = _prompt_s3_consent(args.confirm_s3_request_costs)
        if not s3_confirmed:
            print(
                "Aborting: optional S3 checks were not confirmed. Re-run without --include-s3-checks "
                "for default zero-request-charge checks.",
                file=sys.stderr,
            )
            return 2

    regions_arg = "all"
    if args.regions and args.regions.strip().lower() != "all":
        regions_arg = [r.strip() for r in args.regions.split(",") if r.strip()]

    try:
        session = create_local_session(
            profile=args.profile,
            role_arn=args.role_arn,
            external_id=args.external_id,
        )
        ident = verify_identity(session)
        guard_info = enforce_identity_guards(ident, allow_root=args.allow_root)
    except RootIdentityBlockedError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {redact_credential_strings(str(exc))}", file=sys.stderr)
        return 1

    if guard_info["admin_name_heuristic"]:
        print(f"\n{format_admin_heuristic_warning(ident['caller_arn'])}", file=sys.stderr)

    cred_source = describe_credential_source(session, profile=args.profile, role_arn=args.role_arn)
    proceed = _print_prescan_confirmation_and_prompt(
        account_id=ident["account_id"],
        caller_arn=ident["caller_arn"],
        credential_source=cred_source,
        regions_arg=regions_arg,
        include_s3=include_s3,
        auto_yes=args.yes,
    )
    if not proceed:
        print("Scan cancelled before calling any AWS service collectors.", file=sys.stderr)
        return 2

    try:
        report = run_local_scan(
            session,
            regions=regions_arg,
            include_s3_checks=include_s3,
            confirm_s3_request_costs=s3_confirmed,
            allow_root=args.allow_root,
        )
    except RootIdentityBlockedError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: {redact_credential_strings(str(exc))}", file=sys.stderr)
        return 1

    output_path = args.output
    if output_path == "-":
        print(json.dumps(report, default=str, indent=2 if not args.compact else None))
    else:
        _write_secure_json(output_path, report, pretty=not args.compact)
        s = report["summary"]
        cov = report["coverage"]
        print(
            f"\nScan complete ({report['scan_duration_ms'] / 1000:.1f}s) — Coverage: {cov['status']} | "
            f"Resources: {s['total_resources']} | Critical: {s['critical_issues']} | "
            f"Warnings: {s['warnings']} | Unused: {s['unused']} | Info: {s['info_observations']}",
            file=sys.stderr,
        )
        if cov.get("services_skipped_optional"):
            print(
                f"  Skipped optional services (not marked healthy): {', '.join(cov['services_skipped_optional'])}",
                file=sys.stderr,
            )
        perm_note = "mode 0600" if os.name == "posix" else "standard Windows user directory ACLs (0600 N/A on Windows)"
        print(f"  Saved local report ({perm_note}): {os.path.abspath(output_path)}", file=sys.stderr)
        print("  Next step: Open the AWS Clarity website and drop this file to inspect it locally.", file=sys.stderr)

    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    doc = build_policy_document(include_s3=not args.zero_cost_only)
    text = json.dumps(doc, indent=2) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote read-only IAM policy ({len(doc['Statement'][0]['Action'])} actions) to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-clarity",
        description=(
            "AWS Clarity local-first, strictly read-only AWS account scanner. "
            "Runs entirely on your computer using your AWS CLI / IAM Identity Center credentials "
            "and writes a local JSON report for offline viewing in the AWS Clarity web dashboard."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ver = sub.add_parser("version", help="Print AWS Clarity CLI version and privacy guarantees")
    p_ver.set_defaults(func=lambda _a: (print(f"aws-clarity {CLI_VERSION} (local-first, read-only, zero telemetry)"), 0)[1])

    p_doc = sub.add_parser("doctor", help="Verify active AWS identity, enabled regions, and read-only permissions")
    p_doc.add_argument("--profile", help="AWS CLI / IAM Identity Center profile name")
    p_doc.add_argument("--role-arn", help="Optional customer-owned read-only IAM Role ARN to assume locally")
    p_doc.add_argument("--external-id", help="Optional External ID when using --role-arn")
    p_doc.add_argument("--include-s3-checks", action="store_true", help="Also probe optional S3 read permissions")
    p_doc.add_argument("--allow-root", action="store_true", help="Override safety refusal for AWS account root credentials (not recommended)")
    p_doc.add_argument("--json", action="store_true", help="Emit JSON output")
    p_doc.set_defaults(func=cmd_doctor)

    p_scan = sub.add_parser("scan", help="Run a local read-only assessment and save a local JSON report")
    p_scan.add_argument("--profile", help="AWS CLI / IAM Identity Center profile name")
    p_scan.add_argument("--role-arn", help="Optional customer-owned read-only IAM Role ARN to assume locally")
    p_scan.add_argument("--external-id", help="Optional External ID when using --role-arn")
    p_scan.add_argument("--regions", default="all", help="Comma-separated AWS regions or 'all' (default: all enabled regions)")
    p_scan.add_argument(
        "--include-s3-checks",
        action="store_true",
        help="Opt in to S3 bucket configuration checks (uses S3 LIST/GET API requests; requires explicit consent)",
    )
    p_scan.add_argument(
        "--confirm-s3-request-costs",
        action="store_true",
        help="Explicitly confirm potential S3 API request charges for non-interactive runs with --include-s3-checks",
    )
    p_scan.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip interactive pre-scan confirmation prompt (for non-interactive/CI use)",
    )
    p_scan.add_argument(
        "--allow-root",
        action="store_true",
        help="Override safety refusal for AWS account root credentials (not recommended)",
    )
    p_scan.add_argument(
        "--output",
        "-o",
        default="aws-clarity-report.json",
        help="Local output path for the JSON report (use '-' for stdout; default: aws-clarity-report.json)",
    )
    p_scan.add_argument("--compact", action="store_true", help="Write compact JSON instead of pretty-printed JSON")
    p_scan.set_defaults(func=cmd_scan)

    p_pol = sub.add_parser("policy", help="Print the exact least-privilege read-only IAM policy JSON")
    p_pol.add_argument("--zero-cost-only", action="store_true", help="Emit only the 28 zero-request-charge actions (excluding S3)")
    p_pol.add_argument("--output", "-o", help="Optional path to write the IAM policy JSON")
    p_pol.set_defaults(func=cmd_policy)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
