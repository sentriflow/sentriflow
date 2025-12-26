// packages/cli/test/sarif.test.ts

// Define __VERSION__ before importing sarif module (injected by build in production)
declare global {
  var __VERSION__: string;
}
globalThis.__VERSION__ = '0.0.0-test';

import { describe, expect, test } from 'bun:test';
import { generateSarif, generateMultiFileSarif } from '../src/sarif';
import type { IRule, RuleResult, Tag } from '@sentriflow/core';

describe('SARIF Formatter', () => {
  const mockRule: IRule = {
    id: 'TEST-001',
    selector: 'interface',
    vendor: 'common',
    category: 'authentication',
    metadata: {
      level: 'error',
      obu: 'Security',
      owner: 'Test',
      description: 'Test rule description',
      remediation: 'Fix the issue',
      tags: [
        { type: 'security', label: 'credential-exposure' },
        { type: 'compliance', label: 'NIST-PR.AC', text: 'Access Control' },
      ],
    },
    check: () => ({
      passed: false,
      message: 'Test failure',
      ruleId: 'TEST-001',
      nodeId: 'test-node',
      level: 'error',
    }),
  };

  const mockResult: RuleResult = {
    passed: false,
    message: 'Password found in plaintext',
    ruleId: 'TEST-001',
    nodeId: 'interface GigabitEthernet1',
    level: 'error',
    loc: { startLine: 10, endLine: 10 },
  };

  describe('generateSarif', () => {
    test('includes category in rule properties', () => {
      const sarifOutput = generateSarif(
        [mockResult],
        'test.cfg',
        [mockRule]
      );
      const parsed = JSON.parse(sarifOutput);

      const sarifRule = parsed.runs[0].tool.driver.rules[0];
      expect(sarifRule.id).toBe('TEST-001');
      expect(sarifRule.properties).toBeDefined();
      expect(sarifRule.properties.category).toBe('authentication');
    });

    test('includes tags in rule properties', () => {
      const sarifOutput = generateSarif(
        [mockResult],
        'test.cfg',
        [mockRule]
      );
      const parsed = JSON.parse(sarifOutput);

      const sarifRule = parsed.runs[0].tool.driver.rules[0];
      expect(sarifRule.properties.tags).toBeDefined();
      expect(sarifRule.properties.tags).toContain('credential-exposure');
      expect(sarifRule.properties.tags).toContain('NIST-PR.AC');
    });

    test('handles rules with array category', () => {
      const ruleWithArrayCategory: IRule = {
        ...mockRule,
        category: ['authentication', 'encryption'],
      };

      const sarifOutput = generateSarif(
        [mockResult],
        'test.cfg',
        [ruleWithArrayCategory]
      );
      const parsed = JSON.parse(sarifOutput);

      const sarifRule = parsed.runs[0].tool.driver.rules[0];
      expect(sarifRule.properties.category).toEqual(['authentication', 'encryption']);
    });

    test('handles rules without category', () => {
      const ruleWithoutCategory: IRule = {
        id: 'TEST-002',
        selector: 'interface',
        metadata: {
          level: 'warning',
          obu: 'Operations',
          owner: 'Test',
        },
        check: () => ({
          passed: true,
          message: 'OK',
          ruleId: 'TEST-002',
          nodeId: 'test',
          level: 'info',
        }),
      };

      const result: RuleResult = {
        passed: true,
        message: 'OK',
        ruleId: 'TEST-002',
        nodeId: 'test',
        level: 'info',
      };

      const sarifOutput = generateSarif(
        [result],
        'test.cfg',
        [ruleWithoutCategory]
      );
      const parsed = JSON.parse(sarifOutput);

      const sarifRule = parsed.runs[0].tool.driver.rules[0];
      // Rule without category or tags should not have properties
      expect(sarifRule.properties).toBeUndefined();
    });
  });

  describe('generateMultiFileSarif', () => {
    test('includes category in multi-file SARIF output', () => {
      const fileResults = [
        {
          filePath: 'config1.cfg',
          results: [mockResult],
        },
        {
          filePath: 'config2.cfg',
          results: [{ ...mockResult, nodeId: 'interface GigabitEthernet2' }],
        },
      ];

      const sarifOutput = generateMultiFileSarif(fileResults, [mockRule]);
      const parsed = JSON.parse(sarifOutput);

      const sarifRule = parsed.runs[0].tool.driver.rules[0];
      expect(sarifRule.properties.category).toBe('authentication');
      expect(sarifRule.properties.tags).toContain('credential-exposure');
    });
  });
});
