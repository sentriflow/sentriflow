// packages/vscode/test/hover-provider.test.ts
//
// VS Code Extension Integration Tests
//
// NOTE: Full VS Code extension testing requires @vscode/test-electron or @vscode/test-web
// packages and a proper test runner setup. These tests validate the logic that can be
// tested independently of VS Code APIs.
//
// To set up full integration tests:
// 1. Install @vscode/test-electron: npm install --save-dev @vscode/test-electron
// 2. Create a test runner in src/test/runTest.ts
// 3. Run tests via VS Code's Extension Test Host
//
// For now, we test the core logic that doesn't depend on VS Code types.

import { describe, expect, test } from 'bun:test';
import type { IRule, Tag } from '@sentriflow/core';

/**
 * Helper to format category for display (mirrors logic in HoverProvider)
 */
function formatCategory(rule: IRule | undefined): string {
  if (!rule?.category) return 'general';
  return Array.isArray(rule.category) ? rule.category.join(', ') : rule.category;
}

/**
 * Helper to format tags for hover display (mirrors logic in HoverProvider)
 */
function formatTags(tags: Tag[] | undefined): string[] {
  if (!tags || tags.length === 0) return [];
  return tags.map((tag) => {
    const text = tag.text ? ` *(${tag.text})*` : '';
    const score = tag.score !== undefined ? ` [${tag.score}/10]` : '';
    return `- \`${tag.type}\`: **${tag.label}**${text}${score}`;
  });
}

describe('HoverProvider Logic', () => {
  describe('formatCategory', () => {
    test('returns "general" for undefined rule', () => {
      expect(formatCategory(undefined)).toBe('general');
    });

    test('returns "general" for rule without category', () => {
      const rule: IRule = {
        id: 'TEST-001',
        selector: 'test',
        metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
        check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
      };
      expect(formatCategory(rule)).toBe('general');
    });

    test('returns single category as-is', () => {
      const rule: IRule = {
        id: 'TEST-001',
        selector: 'test',
        category: 'authentication',
        metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
        check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
      };
      expect(formatCategory(rule)).toBe('authentication');
    });

    test('joins array categories with comma', () => {
      const rule: IRule = {
        id: 'TEST-001',
        selector: 'test',
        category: ['authentication', 'encryption'],
        metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
        check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
      };
      expect(formatCategory(rule)).toBe('authentication, encryption');
    });
  });

  describe('formatTags', () => {
    test('returns empty array for undefined tags', () => {
      expect(formatTags(undefined)).toEqual([]);
    });

    test('returns empty array for empty tags', () => {
      expect(formatTags([])).toEqual([]);
    });

    test('formats basic tag', () => {
      const tags: Tag[] = [{ type: 'security', label: 'credential-exposure' }];
      const result = formatTags(tags);
      expect(result).toHaveLength(1);
      expect(result[0]).toBe('- `security`: **credential-exposure**');
    });

    test('formats tag with text', () => {
      const tags: Tag[] = [
        { type: 'compliance', label: 'NIST-PR.AC', text: 'Access Control' },
      ];
      const result = formatTags(tags);
      expect(result[0]).toBe('- `compliance`: **NIST-PR.AC** *(Access Control)*');
    });

    test('formats tag with score', () => {
      const tags: Tag[] = [
        { type: 'security', label: 'weak-crypto', score: 8 },
      ];
      const result = formatTags(tags);
      expect(result[0]).toBe('- `security`: **weak-crypto** [8/10]');
    });

    test('formats tag with all properties', () => {
      const tags: Tag[] = [
        { type: 'security', label: 'credential-exposure', text: 'Password in plaintext', score: 9 },
      ];
      const result = formatTags(tags);
      expect(result[0]).toBe('- `security`: **credential-exposure** *(Password in plaintext)* [9/10]');
    });

    test('formats multiple tags', () => {
      const tags: Tag[] = [
        { type: 'security', label: 'auth-weak' },
        { type: 'compliance', label: 'PCI-8.3' },
      ];
      const result = formatTags(tags);
      expect(result).toHaveLength(2);
      expect(result[0]).toBe('- `security`: **auth-weak**');
      expect(result[1]).toBe('- `compliance`: **PCI-8.3**');
    });
  });
});

describe('Category Filter Logic', () => {
  /**
   * Check if rule matches category filter (mirrors logic in extension.ts)
   */
  function matchesCategoryFilter(
    rule: IRule | undefined,
    categoryFilter: string | undefined
  ): boolean {
    if (!categoryFilter) return true; // No filter = show all
    if (!rule?.category) return false; // Rule without category doesn't match specific filter

    const ruleCats = Array.isArray(rule.category) ? rule.category : [rule.category];
    return ruleCats.includes(categoryFilter);
  }

  test('no filter matches all rules', () => {
    const rule: IRule = {
      id: 'TEST-001',
      selector: 'test',
      category: 'authentication',
      metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
      check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
    };
    expect(matchesCategoryFilter(rule, undefined)).toBe(true);
  });

  test('filter matches single category', () => {
    const rule: IRule = {
      id: 'TEST-001',
      selector: 'test',
      category: 'authentication',
      metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
      check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
    };
    expect(matchesCategoryFilter(rule, 'authentication')).toBe(true);
    expect(matchesCategoryFilter(rule, 'routing')).toBe(false);
  });

  test('filter matches array categories', () => {
    const rule: IRule = {
      id: 'TEST-001',
      selector: 'test',
      category: ['authentication', 'encryption'],
      metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
      check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
    };
    expect(matchesCategoryFilter(rule, 'authentication')).toBe(true);
    expect(matchesCategoryFilter(rule, 'encryption')).toBe(true);
    expect(matchesCategoryFilter(rule, 'routing')).toBe(false);
  });

  test('filter rejects rules without category', () => {
    const rule: IRule = {
      id: 'TEST-001',
      selector: 'test',
      metadata: { level: 'warning', obu: 'Test', owner: 'Test' },
      check: () => ({ passed: true, message: '', ruleId: 'TEST-001', nodeId: '', level: 'info' }),
    };
    expect(matchesCategoryFilter(rule, 'authentication')).toBe(false);
  });

  test('undefined rule fails filter', () => {
    expect(matchesCategoryFilter(undefined, 'authentication')).toBe(false);
  });
});
