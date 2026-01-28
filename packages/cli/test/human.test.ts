// packages/cli/test/human.test.ts
// Tests for human-readable output formatter

import { describe, expect, test } from 'bun:test';
import {
  formatHuman,
  formatMultiFileHuman,
  formatFinding,
  formatSummary,
  countSeverities,
  stripAnsi,
} from '../src/human';
import type { RuleResult } from '@sentriflow/core';

// Mock rule results for testing
const mockResults: RuleResult[] = [
  {
    ruleId: 'NET-DOC-001',
    passed: false,
    message: 'Interface "Gi0/0" is missing a description',
    level: 'warning',
    nodeId: 'interface GigabitEthernet0/0',
    loc: { startLine: 3, endLine: 3 },
  },
  {
    ruleId: 'SEC-VTY-001',
    passed: false,
    message: 'VTY line missing access-class',
    level: 'error',
    nodeId: 'line vty 0 4',
    loc: { startLine: 6, endLine: 8 },
  },
];

const mockInfoResult: RuleResult = {
  ruleId: 'INFO-001',
  passed: false,
  message: 'Informational finding',
  level: 'info',
  nodeId: 'info node',
  loc: { startLine: 10, endLine: 10 },
};

const mockPassedResult: RuleResult = {
  ruleId: 'PASS-001',
  passed: true,
  message: 'This check passed',
  level: 'info',
  nodeId: 'passed node',
  loc: { startLine: 1, endLine: 1 },
};

describe('countSeverities', () => {
  test('counts failures by severity level', () => {
    const counts = countSeverities(mockResults);
    expect(counts.error).toBe(1);
    expect(counts.warning).toBe(1);
    expect(counts.info).toBe(0);
    expect(counts.total).toBe(2);
  });

  test('ignores passed results', () => {
    const resultsWithPassed = [...mockResults, mockPassedResult];
    const counts = countSeverities(resultsWithPassed);
    expect(counts.total).toBe(2); // Only failures counted
  });

  test('returns zeros for empty results', () => {
    const counts = countSeverities([]);
    expect(counts.error).toBe(0);
    expect(counts.warning).toBe(0);
    expect(counts.info).toBe(0);
    expect(counts.total).toBe(0);
  });

  test('counts info level findings', () => {
    const counts = countSeverities([mockInfoResult]);
    expect(counts.info).toBe(1);
    expect(counts.total).toBe(1);
  });

  test('handles unknown severity levels gracefully', () => {
    const unknownResult: RuleResult = {
      ruleId: 'UNKNOWN-001',
      passed: false,
      message: 'Unknown severity',
      level: 'critical' as RuleResult['level'], // Force unknown level
      nodeId: 'test',
      loc: { startLine: 1, endLine: 1 },
    };
    const counts = countSeverities([unknownResult, mockResults[0]!]);
    // Unknown level should still count toward total but not corrupt known counts
    expect(counts.total).toBe(2);
    expect(counts.error).toBe(0);
    expect(counts.warning).toBe(1);
    expect(counts.info).toBe(0);
    // Verify no NaN values
    expect(Number.isNaN(counts.error)).toBe(false);
    expect(Number.isNaN(counts.warning)).toBe(false);
    expect(Number.isNaN(counts.info)).toBe(false);
  });
});

describe('formatFinding', () => {
  test('includes line number', () => {
    const output = formatFinding(mockResults[0]!, false);
    expect(output).toContain('3:1');
  });

  test('includes severity level', () => {
    const output = formatFinding(mockResults[0]!, false);
    expect(output).toContain('warning');
  });

  test('includes message', () => {
    const output = formatFinding(mockResults[0]!, false);
    expect(output).toContain('Interface "Gi0/0" is missing a description');
  });

  test('includes rule ID', () => {
    const output = formatFinding(mockResults[0]!, false);
    expect(output).toContain('NET-DOC-001');
  });

  test('handles missing location', () => {
    const resultWithoutLoc: RuleResult = {
      ...mockResults[0]!,
      loc: undefined,
    };
    const output = formatFinding(resultWithoutLoc, false);
    expect(output).toContain('0:1'); // Default to 0 when no location
  });
});

describe('formatSummary', () => {
  test('shows correct problem count', () => {
    const counts = { error: 1, warning: 1, info: 0, total: 2 };
    const output = formatSummary(counts, false);
    expect(output).toContain('2 problems');
  });

  test('shows singular problem for count of 1', () => {
    const counts = { error: 1, warning: 0, info: 0, total: 1 };
    const output = formatSummary(counts, false);
    expect(output).toContain('1 problem');
    expect(output).not.toContain('1 problems');
  });

  test('shows error count', () => {
    const counts = { error: 2, warning: 0, info: 0, total: 2 };
    const output = formatSummary(counts, false);
    expect(output).toContain('2 errors');
  });

  test('shows singular error for count of 1', () => {
    const counts = { error: 1, warning: 0, info: 0, total: 1 };
    const output = formatSummary(counts, false);
    expect(output).toContain('1 error');
    expect(output).not.toContain('1 errors');
  });

  test('shows warning count', () => {
    const counts = { error: 0, warning: 3, info: 0, total: 3 };
    const output = formatSummary(counts, false);
    expect(output).toContain('3 warnings');
  });

  test('shows singular warning for count of 1', () => {
    const counts = { error: 0, warning: 1, info: 0, total: 1 };
    const output = formatSummary(counts, false);
    expect(output).toContain('1 warning');
    expect(output).not.toContain('1 warnings');
  });

  test('shows info count', () => {
    const counts = { error: 0, warning: 0, info: 2, total: 2 };
    const output = formatSummary(counts, false);
    expect(output).toContain('2 info');
  });

  test('shows no problems message for zero total', () => {
    const counts = { error: 0, warning: 0, info: 0, total: 0 };
    const output = formatSummary(counts, false);
    expect(output).toContain('No problems found');
    expect(output).toContain('✔');
  });

  test('shows X mark for problems', () => {
    const counts = { error: 1, warning: 0, info: 0, total: 1 };
    const output = formatSummary(counts, false);
    expect(output).toContain('✖');
  });
});

describe('formatHuman', () => {
  test('formats results with file header', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: false });
    expect(output).toContain('router.conf');
    expect(output).toContain('NET-DOC-001');
    expect(output).toContain('SEC-VTY-001');
  });

  test('shows correct summary counts', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: false });
    expect(output).toContain('2 problems');
    expect(output).toContain('1 error');
    expect(output).toContain('1 warning');
  });

  test('includes line numbers', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: false });
    expect(output).toContain('3:1');
    expect(output).toContain('6:1');
  });

  test('adds colors when enabled', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: true });
    expect(output).toContain('\x1b[31m'); // red for error
    expect(output).toContain('\x1b[33m'); // yellow for warning
  });

  test('no colors when disabled', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: false });
    expect(output).not.toContain('\x1b[');
  });

  test('shows no problems message for empty results', () => {
    const output = formatHuman([], 'router.conf', { color: false });
    expect(output).toContain('No problems found');
  });

  test('only shows failed results (not passed)', () => {
    const resultsWithPassed = [...mockResults, mockPassedResult];
    const output = formatHuman(resultsWithPassed, 'router.conf', { color: false });
    expect(output).not.toContain('PASS-001');
    expect(output).toContain('NET-DOC-001');
    expect(output).toContain('SEC-VTY-001');
  });

  test('uses bold for file header when colors enabled', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: true });
    expect(output).toContain('\x1b[1m'); // bold
    expect(output).toContain('router.conf');
  });

  test('uses gray for rule ID when colors enabled', () => {
    const output = formatHuman(mockResults, 'router.conf', { color: true });
    expect(output).toContain('\x1b[90m'); // gray
  });
});

describe('formatMultiFileHuman', () => {
  test('groups findings by file', () => {
    const files = [
      { file: 'router.conf', results: [mockResults[0]!] },
      { file: 'switch.conf', results: [mockResults[1]!] },
    ];
    const output = formatMultiFileHuman(files, { color: false });
    expect(output).toContain('router.conf');
    expect(output).toContain('switch.conf');
  });

  test('shows aggregate summary', () => {
    const files = [
      { file: 'router.conf', results: [mockResults[0]!] },
      { file: 'switch.conf', results: [mockResults[1]!] },
    ];
    const output = formatMultiFileHuman(files, { color: false });
    expect(output).toContain('2 problems');
  });

  test('includes blank line between files', () => {
    const files = [
      { file: 'router.conf', results: [mockResults[0]!] },
      { file: 'switch.conf', results: [mockResults[1]!] },
    ];
    const output = formatMultiFileHuman(files, { color: false });
    // Check for blank line (two consecutive newlines)
    expect(output).toMatch(/\n\n/);
  });

  test('skips files with no failures', () => {
    const files = [
      { file: 'router.conf', results: [mockResults[0]!] },
      { file: 'clean.conf', results: [mockPassedResult] },
    ];
    const output = formatMultiFileHuman(files, { color: false });
    expect(output).toContain('router.conf');
    expect(output).not.toContain('clean.conf');
  });

  test('shows no problems for all passing files', () => {
    const files = [
      { file: 'clean1.conf', results: [mockPassedResult] },
      { file: 'clean2.conf', results: [mockPassedResult] },
    ];
    const output = formatMultiFileHuman(files, { color: false });
    expect(output).toContain('No problems found');
  });

  test('adds colors when enabled', () => {
    const files = [{ file: 'router.conf', results: mockResults }];
    const output = formatMultiFileHuman(files, { color: true });
    expect(output).toContain('\x1b[31m'); // red for error
    expect(output).toContain('\x1b[33m'); // yellow for warning
  });

  test('no colors when disabled', () => {
    const files = [{ file: 'router.conf', results: mockResults }];
    const output = formatMultiFileHuman(files, { color: false });
    expect(output).not.toContain('\x1b[');
  });
});

describe('stripAnsi', () => {
  test('removes ANSI color codes', () => {
    const colored = '\x1b[31merror\x1b[0m';
    expect(stripAnsi(colored)).toBe('error');
  });

  test('removes bold codes', () => {
    const bold = '\x1b[1mtext\x1b[0m';
    expect(stripAnsi(bold)).toBe('text');
  });

  test('removes gray codes', () => {
    const gray = '\x1b[90mruleId\x1b[0m';
    expect(stripAnsi(gray)).toBe('ruleId');
  });

  test('handles multiple ANSI codes', () => {
    const multiple = '\x1b[1m\x1b[31mred bold\x1b[0m normal \x1b[33myellow\x1b[0m';
    expect(stripAnsi(multiple)).toBe('red bold normal yellow');
  });

  test('returns unchanged string with no ANSI codes', () => {
    const plain = 'plain text';
    expect(stripAnsi(plain)).toBe('plain text');
  });

  test('handles empty string', () => {
    expect(stripAnsi('')).toBe('');
  });
});

describe('edge cases', () => {
  test('handles very long file paths', () => {
    const longPath = '/very/long/path/'.repeat(20) + 'config.conf';
    const output = formatHuman(mockResults, longPath, { color: false });
    expect(output).toContain(longPath);
  });

  test('handles very long messages', () => {
    const longMessage = 'A'.repeat(500);
    const resultWithLongMessage: RuleResult = {
      ...mockResults[0]!,
      message: longMessage,
    };
    const output = formatHuman([resultWithLongMessage], 'test.conf', { color: false });
    expect(output).toContain(longMessage);
  });

  test('handles special characters in message', () => {
    const specialMessage = 'Interface "eth0/0.100" has <invalid> chars & symbols';
    const resultWithSpecialChars: RuleResult = {
      ...mockResults[0]!,
      message: specialMessage,
    };
    const output = formatHuman([resultWithSpecialChars], 'test.conf', { color: false });
    expect(output).toContain(specialMessage);
  });

  test('handles unicode in file path', () => {
    const unicodePath = 'конфиг/роутер.conf';
    const output = formatHuman(mockResults, unicodePath, { color: false });
    expect(output).toContain(unicodePath);
  });
});
