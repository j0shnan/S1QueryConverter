#!/usr/bin/env python3
"""
S1QueryConverter_Multiple.py

Batch-convert SentinelOne S1QL v1 queries stored in one or more columns of
an .xlsx file into S1QL v2 syntax.

Usage:
    python3 S1QueryConverter_Multiple.py -i detections.xlsx -c Query
    python3 S1QueryConverter_Multiple.py -i detections.xlsx -s "Rules" \\
        -c Query -c Notes -o detections_converted.xlsx --suffix _v2

For each column given with -c/--column, two new columns are added:
    <column>_v2            the converted query (best-effort, even when
                            flagged -- see below)
    <column>_v2_warnings   empty if the conversion was clean; otherwise a
                            "; "-joined list of everything that needs a
                            human to look at before the row is used

Unlike the single-query script, a row that can't be fully auto-converted
does NOT stop the run -- it's flagged in its own warnings column and the
rest of the file keeps processing, so one bad row in a 200-row detection
library doesn't block the other 199.

Only the specified sheet is read and written; this does not do a
full multi-sheet passthrough copy of the workbook.

The actual conversion logic lives in s1ql_convert.py (shared with
S1QueryConverter_Single.py) so both front-ends stay in sync.
"""

import argparse
import os
import sys

import pandas as pd

from s1ql_convert import convert


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Batch-convert SentinelOne S1QL v1 queries in an xlsx file to S1QL v2."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the input .xlsx file")
    parser.add_argument(
        "-s", "--sheet", default=0,
        help="Sheet name or 0-based index to read (default: first sheet)"
    )
    parser.add_argument(
        "-c", "--column", action="append", required=True, dest="columns",
        help="Column name containing v1 queries to convert. Repeat -c for multiple columns."
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to the output .xlsx file (default: <input>_converted.xlsx)"
    )
    parser.add_argument(
        "--suffix", default="_v2",
        help="Suffix appended to a converted column's name (default: _v2)"
    )
    args = parser.parse_args()

    # Sheet arg may be a name or an index -- try to interpret bare digits as an index.
    sheet = args.sheet
    if isinstance(sheet, str) and sheet.isdigit():
        sheet = int(sheet)

    try:
        df = pd.read_excel(args.input, sheet_name=sheet)
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found.", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"Error reading sheet '{args.sheet}' from '{args.input}': {e}", file=sys.stderr)
        return 2

    missing = [c for c in args.columns if c not in df.columns]
    if missing:
        print(f"Error: column(s) not found in the sheet: {', '.join(missing)}", file=sys.stderr)
        print(f"Available columns: {', '.join(str(c) for c in df.columns)}", file=sys.stderr)
        return 2

    total_flagged = 0
    total_rows_converted = 0

    for col in args.columns:
        out_col = f"{col}{args.suffix}"
        warn_col = f"{col}{args.suffix}_warnings"

        converted_values = []
        warning_values = []

        for value in df[col]:
            if pd.isna(value) or not str(value).strip():
                converted_values.append("")
                warning_values.append("")
                continue

            result = convert(str(value))
            converted_values.append(result.output)
            warning_values.append("; ".join(result.warnings))
            total_rows_converted += 1
            if result.warnings:
                total_flagged += 1

        df[out_col] = converted_values
        df[warn_col] = warning_values

    output_path = args.output
    if not output_path:
        base, ext = os.path.splitext(args.input)
        output_path = f"{base}_converted{ext or '.xlsx'}"

    try:
        df.to_excel(output_path, index=False)
    except OSError as e:
        print(f"Error writing to '{output_path}': {e}", file=sys.stderr)
        return 2

    print(f"Converted {total_rows_converted} cell(s) across {len(args.columns)} column(s).")
    if total_flagged:
        print(
            f"{total_flagged} cell(s) need manual review -- see the "
            f"'<column>{args.suffix}_warnings' column(s) in the output file."
        )
    else:
        print("No warnings -- all conversions completed cleanly.")
    print(f"Written to '{output_path}'.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
