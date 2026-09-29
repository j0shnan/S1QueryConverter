#!/usr/bin/env python3
"""Unit tests for individual pieces of the conversion engine, isolating each
of the 9 issues from the GitHub issue report plus the escaping rules."""

from s1ql_convert import (
    convert, FIELD_MAP, double_backslashes, regex_escape_literal,
    plain_escape_literal, quote_literal, strip_leading_case_insensitive_flag,
)

passed = 0
failed = 0


def check(label, actual, expected):
    global passed, failed
    if actual == expected:
        passed += 1
        print(f'PASS  {label}')
    else:
        failed += 1
        print(f'FAIL  {label}')
        print(f'      expected: {expected!r}')
        print(f'      actual:   {actual!r}')


# ---------------------------------------------------------------------------
# Issue #1: string literals must not be mangled by field/operator mapping
# ---------------------------------------------------------------------------
r = convert('SrcProcCmdLine Contains "Invoke-WebRequest"')
check('issue1: "Invoke" not mangled by the In->in mapping', r.output,
      'src.process.cmdline contains "Invoke-WebRequest"')

r = convert('SrcProcDisplayName Contains "Name"')
check('issue1: literal "Name" not mangled', r.output,
      'src.process.displayName contains "Name"')

r = convert('SrcProcCmdLine Contains "IPConfig /all"')
check('issue1: literal "IPConfig" not mangled (fwd slash correctly escaped per sample evidence)', r.output,
      'src.process.cmdline contains "IPConfig \\/all"')

# ---------------------------------------------------------------------------
# Issue #2: StartsWith / EndsWith must anchor + regex-escape
# ---------------------------------------------------------------------------
r = convert('SrcProcName StartsWith "power"')
check('issue2: StartsWith anchors with ^', r.output,
      'src.process.name matches "^power"')

r = convert('SrcProcName EndsWith ".exe"')
check('issue2: EndsWith anchors with $ and escapes the metachar dot', r.output,
      'src.process.name matches "\\\\.exe$"')

# ---------------------------------------------------------------------------
# Issue #3: Does Not Contain must negate in EVERY position, not just after AND
# ---------------------------------------------------------------------------
r = convert('SrcProcCmdLine Does Not Contain "update"')
check('issue3: negates even at the start of a query (no preceding AND)', r.output,
      'NOT (src.process.cmdline contains:matchcase "update")')

r = convert('( SrcProcCmdScript Does Not ContainCIS "a" AND SrcProcCmdScript Does Not ContainCIS "b" )')
check('issue3: negates the FIRST clause in a parenthesized AND group', r.output,
      '( NOT (cmdScript.content contains "a") AND NOT (cmdScript.content contains "b") )')

# ---------------------------------------------------------------------------
# Issue #4: Is Empty must reference the actual field, not a literal "x"
# ---------------------------------------------------------------------------
r = convert('TgtProcCmdLine Is Empty')
check('issue4: Is Empty substitutes the real field name', r.output,
      '!(tgt.process.cmdline = *)')

r = convert('TgtProcCmdLine Is Not Empty')
check('issue4b: Is Not Empty', r.output, 'tgt.process.cmdline = *')

# ---------------------------------------------------------------------------
# Issue #9: mapping table corrections
# ---------------------------------------------------------------------------
check('issue9: SrcProcImageCompletenessHints not clobbered',
      FIELD_MAP['SrcProcImageCompletenessHints'], 'src.process.completeness.hints')
check('issue9: SrcProcImageSize restored',
      FIELD_MAP['SrcProcImageSize'], 'src.process.image.size')
check('issue9: driverDropperProcess (renamed from driverProcessProcess)',
      FIELD_MAP['driverDropperProcess'], 'driver.dropperProcess')
check('issue9: TgtFileSignatureInvalidReason (renamed from GroupType)',
      FIELD_MAP['TgtFileSignatureInvalidReason'], 'tgt.file.signatureInvalidReason')
check('issue9: OsSrcIndicatorGeneralCount fixed to match sibling counters',
      FIELD_MAP['OsSrcIndicatorGeneralCount'], 'osSrc.process.indicatorGeneralCount')
check('issue9: LoginAccountDomain restored (Domain corruption fix)',
      FIELD_MAP['LoginAccountDomain'], 'event.login.accountDomain')
check('issue9: LoginTgtDomainName restored',
      FIELD_MAP['LoginTgtDomainName'], 'event.login.tgt.domainName')
check('issue9: LogoutTgtDomainName restored',
      FIELD_MAP['LogoutTgtDomainName'], 'event.logout.tgt.domainName')
check('issue9: RegistryOwnerUserSID (was a v2-style dead key)',
      FIELD_MAP['RegistryOwnerUserSID'], 'registry.owner.userSid')
check('issue9: the corrupted key no longer exists',
      'GroupType' not in FIELD_MAP, True)

# ---------------------------------------------------------------------------
# Backslash escaping rules
# ---------------------------------------------------------------------------
check('escaping: double_backslashes on a regex whitespace class',
      double_backslashes('Set-StrictMode\\s+-Version\\s+2'),
      'Set-StrictMode\\\\s+-Version\\\\s+2')
check('escaping: double_backslashes quadruples an already-escaped backslash',
      double_backslashes('\\\\Device'), '\\\\\\\\Device')
check('escaping: regex_escape_literal quadruples a literal backslash from a plain string',
      regex_escape_literal('\\Program Files'), '\\\\\\\\Program\\\\ Files')
check('escaping: plain_escape_literal doubles backslash, escapes forward slash',
      plain_escape_literal('C:\\Program Files/sub'), 'C:\\\\Program Files\\/sub')

# ---------------------------------------------------------------------------
# Adaptive quoting
# ---------------------------------------------------------------------------
q, w = quote_literal('plain text')
check('quoting: default double quotes', q, '"plain text"')
q, w = quote_literal('has "a double" quote')
check('quoting: switches to single quotes to avoid collision', q, "'has \"a double\" quote'")
check('quoting: no warning for the resolvable case', w, None)
q, w = quote_literal('has "both\' kinds')
check('quoting: flags a warning when both quote types are present', w, 'quote_collision')

r = convert('SrcProcName = "it\'s a \\"trap\\""')
check('quoting: end-to-end unresolvable collision is flagged, not silently corrupted', r.ok, False)

# ---------------------------------------------------------------------------
# RegExp (already-regex) translation
# ---------------------------------------------------------------------------
r = convert('SrcProcCmdScript RegExp "Set-StrictMode\\s+-Version\\s+2"')
check('regexp: whitespace class doubled correctly', r.output,
      'cmdScript.content matches "Set-StrictMode\\\\s+-Version\\\\s+2"')

check('ci_flag: leading (?i) stripped (unit)',
      strip_leading_case_insensitive_flag('(?i)[-\\/]f(?:orce)*\\s'),
      '[-\\/]f(?:orce)*\\s')
check('ci_flag: no leading (?i) -- unchanged',
      strip_leading_case_insensitive_flag('[-\\/]f(?:orce)*\\s'),
      '[-\\/]f(?:orce)*\\s')
check('ci_flag: mid-pattern (?i) is NOT stripped (only a LEADING one is)',
      strip_leading_case_insensitive_flag('abc(?i)def'), 'abc(?i)def')

r = convert('TgtProcCmdLine RegExp "(?i)[-\\/]f(?:orce)*\\s"')
check('ci_flag: end-to-end, matches the manually-converted reference exactly', r.output,
      'tgt.process.cmdline matches "[-\\\\/]f(?:orce)*\\\\s"')

# ---------------------------------------------------------------------------
# Not In / In / In Anycase family
# ---------------------------------------------------------------------------
r = convert('EventType Not In ( "Process Creation" )')
check('not_in: negation wraps correctly, does not mistake "Not" for a field', r.output,
      'NOT (event.type in ( "Process Creation" ))')

r = convert('EventType In ( "Process Creation" )')
check('in_bare: bare In with parens', r.output,
      'event.type in ( "Process Creation" )')

print(f'\n{passed} passed, {failed} failed')
import sys
sys.exit(1 if failed else 0)
