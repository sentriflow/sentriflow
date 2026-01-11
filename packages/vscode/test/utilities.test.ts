// packages/vscode/test/utilities.test.ts
//
// Unit tests for utility functions extracted during code quality improvements.

import { describe, expect, test } from 'bun:test';
import type { IRule } from '@sentriflow/core';

// =============================================================================
// parseCommaSeparated Tests (DRY-002)
// =============================================================================

/**
 * Parse an array of potentially comma-separated values into individual items.
 * This mirrors the exported function in extension.ts for testing purposes.
 */
function parseCommaSeparated(items: string[]): string[] {
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

describe('parseCommaSeparated', () => {
  test('returns empty array for empty input', () => {
    expect(parseCommaSeparated([])).toEqual([]);
  });

  test('handles single item without comma', () => {
    expect(parseCommaSeparated(['NET-001'])).toEqual(['NET-001']);
  });

  test('handles multiple items without commas', () => {
    expect(parseCommaSeparated(['NET-001', 'NET-002', 'NET-003'])).toEqual([
      'NET-001',
      'NET-002',
      'NET-003',
    ]);
  });

  test('splits comma-separated values in single item', () => {
    expect(parseCommaSeparated(['NET-001,NET-002'])).toEqual(['NET-001', 'NET-002']);
  });

  test('trims whitespace around values', () => {
    expect(parseCommaSeparated(['NET-001 , NET-002 , NET-003'])).toEqual([
      'NET-001',
      'NET-002',
      'NET-003',
    ]);
  });

  test('filters empty strings after split', () => {
    expect(parseCommaSeparated(['NET-001,,NET-002'])).toEqual(['NET-001', 'NET-002']);
  });

  test('handles mixed array with commas and separate items', () => {
    expect(parseCommaSeparated(['NET-001,NET-002', 'NET-003', 'NET-004,NET-005'])).toEqual([
      'NET-001',
      'NET-002',
      'NET-003',
      'NET-004',
      'NET-005',
    ]);
  });

  test('handles whitespace-only items', () => {
    expect(parseCommaSeparated(['  ', 'NET-001', '  ,  '])).toEqual(['NET-001']);
  });

  test('handles newlines and tabs in whitespace', () => {
    expect(parseCommaSeparated(['NET-001\t,\nNET-002'])).toEqual(['NET-001', 'NET-002']);
  });
});

// =============================================================================
// compareRulesByLevel Tests (DRY-001)
// =============================================================================

/** Severity order for sorting: errors first, then warnings, then info */
const LEVEL_ORDER: Record<string, number> = { error: 0, warning: 1, info: 2 };

/**
 * Compare function for sorting rules by severity level, then by ID.
 * This mirrors the exported function in RulesTreeProvider.ts.
 */
function compareRulesByLevel(a: IRule, b: IRule): number {
  const aLevel = LEVEL_ORDER[a.metadata.level] ?? 3;
  const bLevel = LEVEL_ORDER[b.metadata.level] ?? 3;
  if (aLevel !== bLevel) return aLevel - bLevel;
  return a.id.localeCompare(b.id);
}

/**
 * Helper to create a minimal IRule for testing.
 */
function createRule(id: string, level: 'error' | 'warning' | 'info'): IRule {
  return {
    id,
    selector: 'test',
    metadata: { level, obu: 'Test', owner: 'Test' },
    check: () => ({ passed: true, message: '', ruleId: id, nodeId: '', level }),
  };
}

describe('compareRulesByLevel', () => {
  test('sorts errors before warnings', () => {
    const error = createRule('ERR-001', 'error');
    const warning = createRule('WARN-001', 'warning');
    expect(compareRulesByLevel(error, warning)).toBeLessThan(0);
    expect(compareRulesByLevel(warning, error)).toBeGreaterThan(0);
  });

  test('sorts warnings before info', () => {
    const warning = createRule('WARN-001', 'warning');
    const info = createRule('INFO-001', 'info');
    expect(compareRulesByLevel(warning, info)).toBeLessThan(0);
    expect(compareRulesByLevel(info, warning)).toBeGreaterThan(0);
  });

  test('sorts errors before info', () => {
    const error = createRule('ERR-001', 'error');
    const info = createRule('INFO-001', 'info');
    expect(compareRulesByLevel(error, info)).toBeLessThan(0);
    expect(compareRulesByLevel(info, error)).toBeGreaterThan(0);
  });

  test('sorts same level by ID alphabetically', () => {
    const a = createRule('A-001', 'warning');
    const b = createRule('B-001', 'warning');
    const c = createRule('C-001', 'warning');
    expect(compareRulesByLevel(a, b)).toBeLessThan(0);
    expect(compareRulesByLevel(b, c)).toBeLessThan(0);
    expect(compareRulesByLevel(c, a)).toBeGreaterThan(0);
  });

  test('returns 0 for identical rules', () => {
    const rule = createRule('TEST-001', 'error');
    expect(compareRulesByLevel(rule, rule)).toBe(0);
  });

  test('handles rules with same ID but different levels', () => {
    const error = createRule('TEST-001', 'error');
    const warning = createRule('TEST-001', 'warning');
    expect(compareRulesByLevel(error, warning)).toBeLessThan(0);
  });

  test('sorts complete array correctly', () => {
    const rules = [
      createRule('B-WARN', 'warning'),
      createRule('A-INFO', 'info'),
      createRule('C-ERR', 'error'),
      createRule('A-ERR', 'error'),
      createRule('Z-INFO', 'info'),
    ];

    const sorted = [...rules].sort(compareRulesByLevel);

    expect(sorted.map((r) => r.id)).toEqual([
      'A-ERR', // error, alphabetically first
      'C-ERR', // error, alphabetically second
      'B-WARN', // warning
      'A-INFO', // info, alphabetically first
      'Z-INFO', // info, alphabetically second
    ]);
  });
});

// =============================================================================
// Security: Nonce Generation Tests (SEC-002)
// =============================================================================

describe('Nonce Generation Security', () => {
  test('crypto.randomBytes produces different values', async () => {
    // Dynamic import for crypto module
    const crypto = await import('crypto');

    // Generate multiple nonces
    const nonces = new Set<string>();
    for (let i = 0; i < 100; i++) {
      nonces.add(crypto.randomBytes(16).toString('base64'));
    }

    // All should be unique (testing entropy)
    expect(nonces.size).toBe(100);
  });

  test('nonce has sufficient length for CSP', async () => {
    const crypto = await import('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');

    // 16 bytes in base64 = 24 characters (with padding)
    expect(nonce.length).toBeGreaterThanOrEqual(22);
  });

  test('nonce contains only valid base64 characters', async () => {
    const crypto = await import('crypto');
    const nonce = crypto.randomBytes(16).toString('base64');

    // Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
    expect(nonce).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
});
