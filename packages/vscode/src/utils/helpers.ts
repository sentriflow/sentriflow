/**
 * Pure Utility Functions
 *
 * This module contains pure functions with no side effects.
 * These functions do not import from state/context.ts and are easily unit-testable.
 */

import type { IRule, RulePack } from '@sentriflow/core';

// ============================================================================
// Configuration Constants
// ============================================================================

/** Supported language IDs for network config scanning */
export const SUPPORTED_LANGUAGES = ['network-config', 'plaintext'];

/** Debounce delay for document scanning in milliseconds */
export const DEBOUNCE_MS = 300;

/** Maximum file size for real-time scanning (500KB) */
export const MAX_FILE_SIZE = 500_000;

/** Known network configuration file extensions for bulk scanning */
export const CONFIG_EXTENSIONS = new Set([
  '.txt',
  '.cfg',
  '.conf',
  '.config',
  '.ios',
  '.junos',
  '.eos',
  '.nxos',
  '.routeros',
  '.vyos',
  '.panos',
  '.sros',
  '.vrp',
  '.exos',
  '.voss',
]);

// ============================================================================
// String Parsing Utilities
// ============================================================================

/**
 * DRY-002: Parse an array of potentially comma-separated values into individual items.
 * Handles cases where users enter "NET-001,NET-002" as a single item.
 * Exported for testing.
 *
 * @param items Array of strings that may contain comma-separated values
 * @returns Flattened array of individual items
 */
export function parseCommaSeparated(items: string[]): string[] {
  const result: string[] = [];
  for (const item of items) {
    const parts = item
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    result.push(...parts);
  }
  return result;
}

// ============================================================================
// Rule Formatting Utilities
// ============================================================================

/**
 * Format category for display in diagnostic messages.
 *
 * @param rule The rule to format category for (can be undefined)
 * @returns Formatted category string
 */
export function formatCategory(rule: IRule | undefined): string {
  if (!rule?.category) return 'general';
  return Array.isArray(rule.category)
    ? rule.category.join(', ')
    : rule.category;
}

/**
 * Get unique categories from a collection of rules.
 *
 * @param rules The rules to extract categories from
 * @returns Sorted array of unique category names
 */
export function getUniqueCategoriesFromRules(rules: Iterable<IRule>): string[] {
  const categories = new Set<string>();
  for (const rule of rules) {
    if (rule.category) {
      const cats = Array.isArray(rule.category)
        ? rule.category
        : [rule.category];
      cats.forEach((c) => categories.add(c));
    }
  }
  return [...categories].sort();
}

/**
 * Get vendor coverage for a rule pack.
 * Returns array of vendor IDs that the pack's rules apply to.
 *
 * @param pack The rule pack to analyze
 * @returns Array of vendor IDs, or ['all'] if pack has vendor-agnostic rules
 */
export function getPackVendorCoverage(pack: RulePack): string[] {
  const vendors = new Set<string>();

  for (const rule of pack.rules) {
    if (!rule.vendor) {
      // Vendor-agnostic rule - applies to all
      return ['all'];
    }

    if (Array.isArray(rule.vendor)) {
      for (const v of rule.vendor) {
        if (v === 'common') {
          return ['all'];
        }
        vendors.add(v);
      }
    } else {
      if (rule.vendor === 'common') {
        return ['all'];
      }
      vendors.add(rule.vendor);
    }
  }

  return Array.from(vendors).sort();
}

/**
 * Format rules as an ASCII table.
 *
 * @param rules Array of rules to format
 * @returns Formatted ASCII table string
 */
export function formatRulesTable(rules: IRule[]): string {
  if (rules.length === 0) {
    return '  (no rules)';
  }

  // Define column widths
  const colId = 20;
  const colLevel = 8;
  const colVendor = 18;
  const colDescription = 60;

  const lines: string[] = [];

  // Header
  const header = `| ${'Rule ID'.padEnd(colId)} | ${'Level'.padEnd(
    colLevel
  )} | ${'Vendor'.padEnd(colVendor)} | ${'Description'.padEnd(
    colDescription
  )} |`;
  const separator = `|${'-'.repeat(colId + 2)}|${'-'.repeat(
    colLevel + 2
  )}|${'-'.repeat(colVendor + 2)}|${'-'.repeat(colDescription + 2)}|`;

  lines.push(separator);
  lines.push(header);
  lines.push(separator);

  // Sort rules by ID
  const sortedRules = [...rules].sort((a, b) => a.id.localeCompare(b.id));

  for (const rule of sortedRules) {
    const id = rule.id.slice(0, colId).padEnd(colId);
    const level = rule.metadata.level.slice(0, colLevel).padEnd(colLevel);

    // Format vendor
    let vendor = 'common';
    if (rule.vendor) {
      vendor = Array.isArray(rule.vendor)
        ? rule.vendor.join(', ')
        : rule.vendor;
    }
    vendor = vendor.slice(0, colVendor).padEnd(colVendor);

    // Format description (use remediation or description, truncate if needed)
    let desc = rule.metadata.remediation ?? rule.metadata.description ?? '';
    // Remove newlines and extra spaces
    desc = desc.replace(/\s+/g, ' ').trim();
    if (desc.length > colDescription) {
      desc = desc.slice(0, colDescription - 3) + '...';
    }
    desc = desc.padEnd(colDescription);

    lines.push(`| ${id} | ${level} | ${vendor} | ${desc} |`);
  }

  lines.push(separator);

  return lines.join('\n');
}

/**
 * Format pack details for output display.
 *
 * @param pack The rule pack to format
 * @param rules The rules to include in the details (pre-resolved for the pack)
 * @returns Formatted pack details string
 */
export function formatPackDetails(pack: RulePack, rules: IRule[]): string {
  const lines: string[] = [];
  const ruleCount = rules.length;

  lines.push(`\n${'='.repeat(120)}`);
  lines.push(`Pack: ${pack.name}`);
  lines.push(`${'='.repeat(120)}`);
  lines.push(`Version:     ${pack.version}`);
  lines.push(`Publisher:   ${pack.publisher}`);
  lines.push(`Priority:    ${pack.priority}`);
  lines.push(`License:     ${pack.license ?? 'Not specified'}`);
  lines.push(`Description: ${pack.description ?? 'No description'}`);
  if (pack.homepage) {
    lines.push(`Homepage:    ${pack.homepage}`);
  }
  lines.push(`Rule Count:  ${ruleCount}`);

  // Vendor coverage
  const vendors = getPackVendorCoverage(pack);
  lines.push(`Vendors:     ${vendors.join(', ')}`);

  // Disables info
  if (pack.disables) {
    lines.push(`\nDisables:`);
    if (pack.disables.all) {
      lines.push(`  - All default rules`);
    }
    if (pack.disables.vendors?.length) {
      lines.push(`  - Vendors: ${pack.disables.vendors.join(', ')}`);
    }
    if (pack.disables.rules?.length) {
      lines.push(`  - Rules: ${pack.disables.rules.length} specific rules`);
    }
  }

  lines.push(`\nRules:`);
  lines.push(formatRulesTable(rules));

  return lines.join('\n');
}

// ============================================================================
// File Utilities
// ============================================================================

/**
 * Check if a file path has a known network configuration file extension.
 *
 * @param path The file path to check (should be lowercase)
 * @returns True if the file has a configuration extension
 */
export function isConfigFile(path: string): boolean {
  const lowerPath = path.toLowerCase();
  const lastDot = lowerPath.lastIndexOf('.');
  if (lastDot === -1) return false;
  const ext = lowerPath.substring(lastDot);
  return CONFIG_EXTENSIONS.has(ext);
}

// ============================================================================
// Logging Utilities
// ============================================================================

/**
 * Format a log message with timestamp.
 *
 * @param message The message to format
 * @returns Formatted message with ISO timestamp
 */
export function formatLogMessage(message: string): string {
  return `[${new Date().toISOString()}] ${message}`;
}

/**
 * Format a debug log message.
 *
 * @param message The message to format
 * @returns Formatted debug message with timestamp and DEBUG prefix
 */
export function formatDebugMessage(message: string): string {
  return formatLogMessage(`[DEBUG] ${message}`);
}
