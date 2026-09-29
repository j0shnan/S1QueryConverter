#!/usr/bin/env python3
"""
S1QueryConverter_Single.py

Convert a single SentinelOne S1QL v1 (Deep Visibility) query, read from a
text file, into S1QL v2 (Event Search / PowerQuery) syntax.

Usage:
    python3 S1QueryConverter_Single.py query.txt
    python3 S1QueryConverter_Single.py query.txt -o converted.txt

The actual conversion logic lives in s1ql_convert.py (shared with
S1QueryConverter_Multiple.py) so both front-ends stay in sync.

Exit codes:
    0  -- clean conversion, no warnings.
    1  -- conversion completed but needs manual review (see the printed
          warnings). This includes the one case the project's README
          already documented as a known limitation: a literal containing
          BOTH a double-quote and a single-quote can't be automatically
          re-quoted, so the clause is named and the run stops short of
          claiming success -- it does not silently produce a partially
          converted query the way the original tool did.
    2  -- couldn't read the input file.
"""

import argparse
import sys

from s1ql_convert import convert


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert a SentinelOne S1QL v1 query to S1QL v2."
    )
    parser.add_argument("input_file", help="Path to the input text file")
    parser.add_argument("-o", "--output", help="Path to the output file (optional)")
    args = parser.parse_args()

    try:
        with open(args.input_file, "r", encoding="utf-8") as f:
            input_text = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{args.input_file}' not found.", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"Error reading '{args.input_file}': {e}", file=sys.stderr)
        return 2

    if not input_text:
        print(f"Error: '{args.input_file}' is empty.", file=sys.stderr)
        return 2

    result = convert(input_text)

    print()
    print("Original Query (v1):")
    print(input_text)
    print()
    print("SentinelOne QL V2.0 Query:")
    print(result.output)
    print()

    if args.output:
        # Always write the fully-processed result (fixes the original
        # tool's bug where -o wrote a pre-escaping intermediate string
        # while stdout showed the real, final output).
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(result.output)
            print(f"Transformed text written to '{args.output}'.")
        except OSError as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            return 2

    if result.warnings:
        print()
        print("WARNINGS -- this conversion needs manual review before use:")
        for w in result.warnings:
            print(f"  - {w}")
        print()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
