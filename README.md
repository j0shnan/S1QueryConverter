![Static Badge](https://img.shields.io/badge/Made%20with%20-%20Python%20-%20blue)
[![Sponsored By CyberMaxx](https://github.com/j0shnan/S1QueryConverter/blob/main/Images/cybermaxx_logo.png)](https://www.cybermaxx.com/)

Sponsored By CyberMaxx

![Visitor Count](https://visitcount.itsvg.in/api?id=j0shnan.S1QueryConverter)

# S1QL Query Converter

Converts SentinelOne S1QL v1 (Deep Visibility) queries into S1QL v2 (Event Search / PowerQuery) syntax. Works on a single query from a text file or in batch across an Excel workbook.

## Requirements

- Python 3.7+
- `pandas` and `openpyxl` (batch mode only): `pip install pandas openpyxl`

All three files must be in the same directory:

```
s1ql_convert.py              # conversion engine (shared by both scripts)
S1QueryConverter_Single.py   # single-query CLI
S1QueryConverter_Multiple.py # batch xlsx CLI
```

---

## Single query

Put your v1 query in a plain text file, then run:

```bash
python3 S1QueryConverter_Single.py query.txt
```

To also save the output to a file:

```bash
python3 S1QueryConverter_Single.py query.txt -o converted.txt
```

The original query and the converted result are both printed to stdout. If anything needs manual attention, warnings are printed below the result.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Clean conversion, no action needed |
| `1` | Converted, but one or more clauses need manual review (see printed warnings) |
| `2` | Could not read the input file |

---

## Batch mode (Excel)

Reads one or more columns of v1 queries from an `.xlsx` file and adds converted columns alongside them.

**Minimal usage** — convert the `Query` column in the first sheet:

```bash
python3 S1QueryConverter_Multiple.py -i detections.xlsx -c Query
```

**Full options:**

```bash
python3 S1QueryConverter_Multiple.py \
  -i detections.xlsx \       # input file (required)
  -s "Rules" \               # sheet name or 0-based index (default: first sheet)
  -c Query \                 # column to convert (repeat -c for multiple columns)
  -c Notes \
  -o detections_v2.xlsx \    # output file (default: <input>_converted.xlsx)
  --suffix _v2               # suffix for new columns (default: _v2)
```

For each `-c` column, two new columns are added to the output:

| Column | Contents |
|--------|----------|
| `<column>_v2` | The converted query. Always populated, even when flagged. |
| `<column>_v2_warnings` | Empty if clean. Otherwise a `;`-separated list of issues to review. |

Rows with warnings do not stop the run — they're flagged in place and the rest of the file continues processing.

> **Note:** Only the specified sheet is written to the output file. Other sheets in the workbook are not copied across.

---

## What gets converted automatically

| v1 syntax | v2 output |
|-----------|-----------|
| `Field Contains Anycase "x"` | `field contains "x"` |
| `Field ContainsCIS "x"` | `field contains "x"` |
| `Field Contains "x"` | `field contains "x"` |
| `Field Does Not ContainCIS "x"` | `NOT (field contains "x")` |
| `Field Does Not Contain "x"` | `NOT (field contains:matchcase "x")` |
| `Field In Contains Anycase (...)` | `field contains (...)` |
| `Field In Contains (...)` | `field contains:matchcase (...)` |
| `Field In Anycase (...)` | `field in:anycase (...)` |
| `Field In (...)` | `field in (...)` |
| `Field Not In (...)` | `NOT (field in (...))` |
| `Field StartsWith "x"` | `field matches "^x"` |
| `Field EndsWith "x"` | `field matches "x$"` |
| `Field RegExp "..."` | `field matches "..."` |
| `Field Is Empty` | `!(field = *)` |
| `Field Is Not Empty` | `field = *` |
| `Field Is True` | `field = true` |
| `Field Is False` | `field = false` |
| `Field Exists` | `field = *` |

All ~350 field names are mapped from v1 CamelCase to v2 dot notation (e.g. `SrcProcImagePath` → `src.process.image.path`). String literals are never rewritten — operator keywords or field names that happen to appear inside a quoted value are left exactly as written.

---

## Known limitations

**`between`** is detected and flagged but not auto-converted, because the exact v1 syntax wasn't available to verify against. The warning tells you what to write:

```
"TgtFileSize between ..." was left unconverted -- needs manual conversion to
"tgt.file.size >= a AND tgt.file.size <= b"
```

The clause is left in the output as-is (with the field name already mapped to v2), so it's easy to find and fix.

**Literals containing both `"` and `'`** can't be automatically re-quoted. The converter flags the specific literal and sets exit code 1. Wrap it manually in whichever quote character doesn't appear in the value.

**Consolidation and optimization** are out of scope. The tool converts each clause individually and preserves the structure of the original query. Grouping multiple same-field clauses into a value list, or adding `endpoint.os` / `event.category` scoping filters, is a separate authoring step.

---

### Of Note 
This is project was created and is maintained with the help of LLM.  Please check to be sure the queries you're using are running as running expected. 
