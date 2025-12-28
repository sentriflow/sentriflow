// packages/core/test/helpers/ast-compare.ts

import type { ConfigNode } from '../../src/types/ConfigNode';

/**
 * Result of comparing two AST trees for structural equivalence.
 */
export interface AstComparisonResult {
  equivalent: boolean;
  differences: AstDifference[];
}

/**
 * Represents a single difference found during AST comparison.
 */
export interface AstDifference {
  path: string;
  field: 'id' | 'type' | 'params' | 'blockDepth' | 'childrenCount';
  expected: unknown;
  actual: unknown;
}

/**
 * Compares two AST trees for structural equivalence.
 *
 * Compares: id, type, params, blockDepth, children (recursive)
 * Ignores: indent, rawText, loc, source (these differ between indented/flat versions)
 *
 * @param expected - The expected AST (from indented version)
 * @param actual - The actual AST (from flat version)
 * @param path - Current path in the tree (for error reporting)
 * @returns Comparison result with any differences found
 */
export function compareAstStructure(
  expected: ConfigNode[],
  actual: ConfigNode[],
  path: string = 'root'
): AstComparisonResult {
  const differences: AstDifference[] = [];

  if (expected.length !== actual.length) {
    differences.push({
      path,
      field: 'childrenCount',
      expected: expected.length,
      actual: actual.length,
    });
    return { equivalent: false, differences };
  }

  for (let i = 0; i < expected.length; i++) {
    const exp = expected[i]!;
    const act = actual[i]!;
    const nodePath = `${path}.children[${i}]`;

    // Compare id (trimmed command text)
    if (exp.id !== act.id) {
      differences.push({
        path: nodePath,
        field: 'id',
        expected: exp.id,
        actual: act.id,
      });
    }

    // Compare type
    if (exp.type !== act.type) {
      differences.push({
        path: nodePath,
        field: 'type',
        expected: exp.type,
        actual: act.type,
      });
    }

    // Compare params (deep array comparison)
    if (!arraysEqual(exp.params, act.params)) {
      differences.push({
        path: nodePath,
        field: 'params',
        expected: exp.params,
        actual: act.params,
      });
    }

    // Compare blockDepth (for sections only)
    if (exp.blockDepth !== act.blockDepth) {
      differences.push({
        path: nodePath,
        field: 'blockDepth',
        expected: exp.blockDepth,
        actual: act.blockDepth,
      });
    }

    // Recursively compare children
    if (exp.children.length > 0 || act.children.length > 0) {
      const childResult = compareAstStructure(exp.children, act.children, nodePath);
      differences.push(...childResult.differences);
    }
  }

  return {
    equivalent: differences.length === 0,
    differences,
  };
}

/**
 * Deep array equality check for params comparison.
 * Handles null/undefined arrays safely.
 */
function arraysEqual(a: string[] | undefined, b: string[] | undefined): boolean {
  // Handle null/undefined cases
  if (!a && !b) return true;
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  return a.every((val, idx) => val === b[idx]);
}

/**
 * Counts nodes in an AST by type.
 */
export function countNodes(nodes: ConfigNode[]): { sections: number; commands: number; comments: number } {
  let sections = 0;
  let commands = 0;
  let comments = 0;

  for (const node of nodes) {
    if (node.type === 'section') sections++;
    else if (node.type === 'command') commands++;
    else if (node.type === 'comment') comments++;

    const childCounts = countNodes(node.children);
    sections += childCounts.sections;
    commands += childCounts.commands;
    comments += childCounts.comments;
  }

  return { sections, commands, comments };
}

/**
 * Finds all unique block starter patterns used in an AST.
 * Returns the first parameter of each section node (e.g., "interface", "router").
 */
export function findBlockStarters(nodes: ConfigNode[]): Set<string> {
  const starters = new Set<string>();

  for (const node of nodes) {
    if (node.type === 'section' && node.params.length > 0) {
      // Get the first word(s) that form the block starter
      // e.g., "router bgp" -> "router", "ip access-list" -> "ip access-list"
      const firstParam = node.params[0];
      if (firstParam) {
        starters.add(firstParam);
      }
    }
    // Recursively check children
    const childStarters = findBlockStarters(node.children);
    childStarters.forEach(s => starters.add(s));
  }

  return starters;
}
