// packages/cli/src/human.ts
// Human-readable output formatter for SentriFlow CLI

import type { RuleResult } from '@sentriflow/core';

// ANSI color codes for terminal output
const COLORS = {
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
} as const;

const SEVERITY_COLORS: Record<string, string> = {
  error: COLORS.red,
  warning: COLORS.yellow,
  info: COLORS.blue,
};

/**
 * Options for human-readable output formatting.
 */
export interface HumanFormatOptions {
  /** Enable ANSI color codes in output. Default: false */
  color?: boolean;
}

/**
 * Counts of findings by severity level.
 */
export interface SeverityCounts {
  error: number;
  warning: number;
  info: number;
  total: number;
}

/**
 * Results for a single file in multi-file formatting.
 */
export interface FileResults {
  file: string;
  results: RuleResult[];
}

/**
 * Counts findings by severity level.
 * Only counts failed results (passed: false).
 */
export function countSeverities(results: RuleResult[]): SeverityCounts {
  const counts: SeverityCounts = { error: 0, warning: 0, info: 0, total: 0 };
  for (const r of results) {
    if (!r.passed) {
      counts[r.level as keyof Omit<SeverityCounts, 'total'>]++;
      counts.total++;
    }
  }
  return counts;
}

/**
 * Formats a single finding as a line of output.
 * Format: "  <line>:<col>  <severity>  <message>  <ruleId>"
 */
export function formatFinding(result: RuleResult, color: boolean): string {
  const line = result.loc?.startLine ?? 0;
  const col = 1; // Column always 1 (config files don't have meaningful columns)
  const location = `${line}:${col}`.padEnd(8);

  const severityColor = color ? SEVERITY_COLORS[result.level] ?? '' : '';
  const reset = color ? COLORS.reset : '';
  // Pad severity text, accounting for ANSI codes not taking visible width
  const severityText = result.level.padEnd(7);
  const severity = `${severityColor}${severityText}${reset}`;

  const ruleColor = color ? COLORS.gray : '';
  const ruleId = `${ruleColor}${result.ruleId}${reset}`;

  return `  ${location}  ${severity}  ${result.message}  ${ruleId}`;
}

/**
 * Formats the summary line showing total counts.
 * Examples:
 * - "✔ No problems found"
 * - "✖ 2 problems (1 error, 1 warning)"
 */
export function formatSummary(counts: SeverityCounts, color: boolean): string {
  if (counts.total === 0) {
    const check = color ? `${COLORS.bold}✔${COLORS.reset}` : '✔';
    return `\n${check} No problems found\n`;
  }

  const x = color ? `${COLORS.red}✖${COLORS.reset}` : '✖';
  const parts: string[] = [];

  if (counts.error > 0) {
    parts.push(`${counts.error} error${counts.error !== 1 ? 's' : ''}`);
  }
  if (counts.warning > 0) {
    parts.push(`${counts.warning} warning${counts.warning !== 1 ? 's' : ''}`);
  }
  if (counts.info > 0) {
    parts.push(`${counts.info} info`);
  }

  const problemText = counts.total === 1 ? 'problem' : 'problems';
  return `\n${x} ${counts.total} ${problemText} (${parts.join(', ')})\n`;
}

/**
 * Formats validation results for a single file in human-readable format.
 *
 * @param results Array of rule results
 * @param filePath Path to the scanned file
 * @param options Formatting options
 * @returns Formatted string for terminal output
 */
export function formatHuman(
  results: RuleResult[],
  filePath: string,
  options?: HumanFormatOptions
): string {
  const color = options?.color ?? false;
  const failures = results.filter((r) => !r.passed);

  const lines: string[] = [];

  // File header
  const header = color ? `${COLORS.bold}${filePath}${COLORS.reset}` : filePath;
  lines.push(header);

  // Findings
  for (const result of failures) {
    lines.push(formatFinding(result, color));
  }

  // Summary
  const counts = countSeverities(results);
  lines.push(formatSummary(counts, color));

  return lines.join('\n');
}

/**
 * Formats validation results for multiple files in human-readable format.
 *
 * @param files Array of file results
 * @param options Formatting options
 * @returns Formatted string with file grouping and aggregate summary
 */
export function formatMultiFileHuman(
  files: FileResults[],
  options?: HumanFormatOptions
): string {
  const color = options?.color ?? false;
  const lines: string[] = [];
  const totalCounts: SeverityCounts = { error: 0, warning: 0, info: 0, total: 0 };

  for (const { file, results } of files) {
    const failures = results.filter((r) => !r.passed);
    if (failures.length === 0) continue;

    // File header
    const header = color ? `${COLORS.bold}${file}${COLORS.reset}` : file;
    lines.push(header);

    // Findings
    for (const result of failures) {
      lines.push(formatFinding(result, color));
    }

    lines.push(''); // Blank line between files

    // Accumulate counts
    const counts = countSeverities(results);
    totalCounts.error += counts.error;
    totalCounts.warning += counts.warning;
    totalCounts.info += counts.info;
    totalCounts.total += counts.total;
  }

  // Summary (covers all files)
  lines.push(formatSummary(totalCounts, color));

  return lines.join('\n');
}

/**
 * Strips ANSI escape codes from a string.
 * Useful for testing and comparison.
 */
export function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, '');
}
