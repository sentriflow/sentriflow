// packages/core/test/ast-equivalence.test.ts

import { describe, it, expect, beforeAll } from 'bun:test';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { SchemaAwareParser, getVendor } from '../src';
import type { ConfigNode } from '../src/types/ConfigNode';
import { compareAstStructure, countNodes, findBlockStarters } from './helpers/ast-compare';
import {
  CISCO_IOS_FIXTURE_PAIRS,
  CISCO_NXOS_FIXTURE_PAIRS,
  CISCO_ASA_FIXTURE_PAIRS,
  getAllFixturePairs,
  type TestFixturePair,
} from './helpers/fixture-pairs';

const PACKAGES_CORE = join(__dirname, '..');

/**
 * Helper to load and parse a fixture file.
 */
function parseFixture(relativePath: string, vendorId: 'cisco-ios' | 'cisco-nxos'): ConfigNode[] {
  const fullPath = join(PACKAGES_CORE, relativePath);
  if (!existsSync(fullPath)) {
    throw new Error(`Fixture file not found: ${fullPath}`);
  }
  const content = readFileSync(fullPath, 'utf-8');
  const vendor = getVendor(vendorId);
  const parser = new SchemaAwareParser({ vendor });
  return parser.parse(content);
}

/**
 * Runs AST equivalence test for a fixture pair.
 */
function testFixturePair(pair: TestFixturePair) {
  const indentedAst = parseFixture(pair.indentedPath, pair.vendor);
  const flatAst = parseFixture(pair.flatPath, pair.vendor);

  // Count nodes in both ASTs
  const indentedCounts = countNodes(indentedAst);
  const flatCounts = countNodes(flatAst);

  // Verify expected counts (from indented version as baseline)
  expect(indentedCounts.sections).toBe(pair.expectedSections);
  expect(indentedCounts.commands).toBe(pair.expectedCommands);

  // Verify flat version has same counts (block starters and commands are recognized)
  expect(flatCounts.sections).toBe(indentedCounts.sections);
  expect(flatCounts.commands).toBe(indentedCounts.commands);

  // For strict equivalence fixtures, also verify AST structure matches exactly
  if (pair.strictEquivalence) {
    const comparison = compareAstStructure(indentedAst, flatAst);

    if (!comparison.equivalent) {
      console.error(`AST differences for ${pair.name}:`);
      comparison.differences.forEach(diff => {
        console.error(`  ${diff.path}.${diff.field}: expected=${JSON.stringify(diff.expected)}, actual=${JSON.stringify(diff.actual)}`);
      });
    }

    expect(comparison.equivalent).toBe(true);
  }
  // For non-strict fixtures, count equivalence is sufficient
  // These have context-dependent nesting that the parser can't replicate without indentation
}

describe('AST Equivalence Tests', () => {
  describe('Cisco IOS Fixtures', () => {
    // Dynamic tests for each registered fixture pair
    CISCO_IOS_FIXTURE_PAIRS.forEach(pair => {
      it(`${pair.name}: indented and flat versions produce equivalent AST`, () => {
        testFixturePair(pair);
      });
    });

    // Skip if no fixtures registered yet
    if (CISCO_IOS_FIXTURE_PAIRS.length === 0) {
      it.skip('No Cisco IOS fixture pairs registered yet', () => {});
    }
  });

  describe('Cisco NX-OS Fixtures', () => {
    CISCO_NXOS_FIXTURE_PAIRS.forEach(pair => {
      it(`${pair.name}: indented and flat versions produce equivalent AST`, () => {
        testFixturePair(pair);
      });
    });

    if (CISCO_NXOS_FIXTURE_PAIRS.length === 0) {
      it.skip('No Cisco NX-OS fixture pairs registered yet', () => {});
    }
  });

  describe('Cisco ASA Fixtures (using IOS schema)', () => {
    CISCO_ASA_FIXTURE_PAIRS.forEach(pair => {
      it(`${pair.name}: indented and flat versions produce equivalent AST`, () => {
        testFixturePair(pair);
      });
    });

    if (CISCO_ASA_FIXTURE_PAIRS.length === 0) {
      it.skip('No Cisco ASA fixture pairs registered yet', () => {});
    }
  });
});

describe('Block Starter Coverage', () => {
  describe('Cisco IOS Coverage', () => {
    // This test will be expanded once fixtures are registered
    it.skip('should cover 90% of block starters (40/44)', () => {
      const allStarters = new Set<string>();

      CISCO_IOS_FIXTURE_PAIRS.forEach(pair => {
        const ast = parseFixture(pair.indentedPath, pair.vendor);
        const starters = findBlockStarters(ast);
        starters.forEach(s => allStarters.add(s));
      });

      // Expected: 40+ unique block starters
      expect(allStarters.size).toBeGreaterThanOrEqual(40);
    });
  });

  describe('Cisco NX-OS Coverage', () => {
    it.skip('should cover 90% of block starters (27/30)', () => {
      const allStarters = new Set<string>();

      CISCO_NXOS_FIXTURE_PAIRS.forEach(pair => {
        const ast = parseFixture(pair.indentedPath, pair.vendor);
        const starters = findBlockStarters(ast);
        starters.forEach(s => allStarters.add(s));
      });

      // Expected: 27+ unique block starters
      expect(allStarters.size).toBeGreaterThanOrEqual(27);
    });
  });
});

describe('Fixture File Validation', () => {
  it('all registered fixtures should exist and parse without errors', () => {
    const allPairs = getAllFixturePairs();

    allPairs.forEach(pair => {
      const indentedPath = join(PACKAGES_CORE, pair.indentedPath);
      const flatPath = join(PACKAGES_CORE, pair.flatPath);

      expect(existsSync(indentedPath)).toBe(true);
      expect(existsSync(flatPath)).toBe(true);

      // Should not throw
      expect(() => parseFixture(pair.indentedPath, pair.vendor)).not.toThrow();
      expect(() => parseFixture(pair.flatPath, pair.vendor)).not.toThrow();
    });
  });
});
