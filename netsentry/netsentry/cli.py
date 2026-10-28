"""Command-line interface for NetSentry."""
import argparse
import json
import sys

from .analyzer import analyze_capture, write_json_report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="Summarize a saved PCAP/PCAPNG file for defensive analysis.",
    )
    parser.add_argument("capture", help="Path to a saved .pcap or .pcapng file")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--top", type=int, default=10, help="Number of top items to show (default: 10)")
    parser.add_argument(
        "--connection-threshold", type=int, default=100,
        help="Flag a source/destination pair at or above this packet count (default: 100)",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        report = analyze_capture(
            args.capture,
            top_n=args.top,
            connection_threshold=args.connection_threshold,
        )
        rendered = json.dumps(report, indent=2)
        print(rendered)
        if args.json_path:
            write_json_report(report, args.json_path)
            print(f"\nJSON report written to: {args.json_path}", file=sys.stderr)
        return 0
    except (OSError, ValueError) as exc:
        print(f"netsentry: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
