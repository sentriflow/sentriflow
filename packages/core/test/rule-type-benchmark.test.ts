// packages/core/test/rule-type-benchmark.test.ts

/**
 * Benchmark comparing execution times of different rule types:
 * 1. TypeScript rule from default rules-default package
 * 2. JSON-defined rule (compiled to IRule)
 * 3. Custom TypeScript rule (inline)
 */

import { describe, test } from 'bun:test';
import { RuleEngine } from '../src/engine/Runner';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import { getVendor } from '../src/parser/vendors';
import { compileJsonRule } from '../src/json-rules';
import type { IRule, RuleResult, Context } from '../src/types/IRule';
import type { ConfigNode } from '../src/types/ConfigNode';
import type { JsonRule } from '../src/json-rules';

// Import helpers for the "default-style" rule
import { cisco, hasChildCommand, isShutdown } from '../src/helpers';

// ============================================================================
// Test Configuration
// ============================================================================

const WARMUP_ITERATIONS = 100;
const BENCHMARK_ITERATIONS = 1000;

// ============================================================================
// Test Data
// ============================================================================

/**
 * Generate a Cisco IOS config with trunk ports for testing
 */
function generateTrunkConfig(interfaceCount: number): string {
  const lines: string[] = ['!', 'hostname TestSwitch', '!'];

  for (let i = 0; i < interfaceCount; i++) {
    lines.push(`interface GigabitEthernet0/${i}`);
    lines.push(` description Trunk to Switch ${i}`);
    lines.push(` switchport mode trunk`);
    if (i % 3 === 0) {
      // Every 3rd interface has allowed vlan (passes rule)
      lines.push(` switchport trunk allowed vlan 10,20,30`);
    }
    // No shutdown - interface is active
    lines.push('!');
  }

  lines.push('end');
  return lines.join('\n');
}

// ============================================================================
// Rule Definitions (Equivalent Logic)
// ============================================================================

/**
 * Custom TypeScript rule - checks trunk ports have allowed VLAN list
 */
const customTsRule: IRule = {
  id: 'BENCH-TS-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    description: 'Trunk ports should have explicit allowed VLAN list',
    remediation: "Add 'switchport trunk allowed vlan <list>' to restrict VLANs",
  },
  check: (node: ConfigNode, _ctx: Context): RuleResult => {
    // Check if this is a trunk port
    const isTrunk = node.children.some(
      (child) => child.id.toLowerCase() === 'switchport mode trunk'
    );

    if (!isTrunk) {
      return {
        passed: true,
        message: 'Not a trunk port',
        ruleId: 'BENCH-TS-001',
        nodeId: node.id,
        level: 'warning',
      };
    }

    // Check for allowed vlan configuration
    const hasAllowedVlan = node.children.some((child) =>
      child.id.toLowerCase().startsWith('switchport trunk allowed vlan')
    );

    if (hasAllowedVlan) {
      return {
        passed: true,
        message: 'Trunk port has allowed VLAN list',
        ruleId: 'BENCH-TS-001',
        nodeId: node.id,
        level: 'warning',
      };
    }

    return {
      passed: false,
      message: `Trunk port ${node.id} should have explicit allowed VLAN list`,
      ruleId: 'BENCH-TS-001',
      nodeId: node.id,
      level: 'warning',
    };
  },
};

/**
 * JSON rule definition - same logic as TypeScript rule
 */
const jsonRuleDefinition: JsonRule = {
  id: 'BENCH-JSON-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    description: 'Trunk ports should have explicit allowed VLAN list',
    remediation: "Add 'switchport trunk allowed vlan <list>' to restrict VLANs",
  },
  check: {
    type: 'and',
    conditions: [
      {
        type: 'child_exists',
        selector: 'switchport mode trunk',
      },
      {
        type: 'child_not_exists',
        selector: 'switchport trunk allowed vlan',
      },
    ],
  },
  failureMessage: 'Trunk port {nodeId} should have explicit allowed VLAN list',
};

// Compile JSON rule to IRule
const compiledJsonRule = compileJsonRule(jsonRuleDefinition);

/**
 * TypeScript rule using helper functions (like default rules)
 * Same logic but using the helper function abstraction layer
 */
const helperBasedTsRule: IRule = {
  id: 'BENCH-HELPER-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    description: 'Trunk ports should have explicit allowed VLAN list',
    remediation: "Add 'switchport trunk allowed vlan <list>' to restrict VLANs",
  },
  check: (node: ConfigNode, _ctx: Context): RuleResult => {
    // Skip non-physical ports and shutdown interfaces (like default rules)
    if (!cisco.isPhysicalPort(node.id) || isShutdown(node)) {
      return {
        passed: true,
        message: 'Not applicable',
        ruleId: 'BENCH-HELPER-001',
        nodeId: node.id,
        level: 'info',
      };
    }

    // Use helper to check trunk status
    if (!cisco.isTrunkPort(node)) {
      return {
        passed: true,
        message: 'Not a trunk port',
        ruleId: 'BENCH-HELPER-001',
        nodeId: node.id,
        level: 'info',
      };
    }

    // Use helper to check for allowed vlan
    if (hasChildCommand(node, 'switchport trunk allowed vlan')) {
      return {
        passed: true,
        message: 'Trunk port has allowed VLAN list',
        ruleId: 'BENCH-HELPER-001',
        nodeId: node.id,
        level: 'info',
      };
    }

    return {
      passed: false,
      message: `Trunk port ${node.id} should have explicit allowed VLAN list`,
      ruleId: 'BENCH-HELPER-001',
      nodeId: node.id,
      level: 'warning',
    };
  },
};

/**
 * JSON rule using helper functions (like helper-based TS rule)
 */
const jsonRuleWithHelpers: JsonRule = {
  id: 'BENCH-JSON-HELPER-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    description: 'Trunk ports should have explicit allowed VLAN list',
    remediation: "Add 'switchport trunk allowed vlan <list>' to restrict VLANs",
  },
  check: {
    type: 'and',
    conditions: [
      {
        type: 'helper',
        helper: 'cisco.isPhysicalPort',
        args: [{ $ref: 'node.id' }],
      },
      {
        type: 'helper',
        helper: 'isShutdown',
        args: [{ $ref: 'node' }],
        negate: true,
      },
      {
        type: 'helper',
        helper: 'cisco.isTrunkPort',
        args: [{ $ref: 'node' }],
      },
      {
        type: 'child_not_exists',
        selector: 'switchport trunk allowed vlan',
      },
    ],
  },
  failureMessage: 'Trunk port {nodeId} should have explicit allowed VLAN list',
};

const compiledJsonRuleWithHelpers = compileJsonRule(jsonRuleWithHelpers);

// ============================================================================
// Benchmark Helpers
// ============================================================================

interface BenchmarkResult {
  name: string;
  totalTimeMs: number;
  avgTimeMs: number;
  minTimeMs: number;
  maxTimeMs: number;
  iterations: number;
  failedChecks: number;
}

function runBenchmark(
  name: string,
  rule: IRule,
  nodes: ConfigNode[],
  iterations: number
): BenchmarkResult {
  const engine = new RuleEngine();
  const times: number[] = [];
  let failedChecks = 0;

  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    engine.run(nodes, [rule]);
  }

  // Benchmark
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    const results = engine.run(nodes, [rule]);
    const elapsed = performance.now() - start;
    times.push(elapsed);
    failedChecks = results.filter((r) => !r.passed).length;
  }

  const totalTimeMs = times.reduce((a, b) => a + b, 0);
  const avgTimeMs = totalTimeMs / iterations;
  const minTimeMs = Math.min(...times);
  const maxTimeMs = Math.max(...times);

  return {
    name,
    totalTimeMs,
    avgTimeMs,
    minTimeMs,
    maxTimeMs,
    iterations,
    failedChecks,
  };
}

function formatResult(result: BenchmarkResult): string {
  return (
    `${result.name}: ` +
    `avg=${result.avgTimeMs.toFixed(3)}ms, ` +
    `min=${result.minTimeMs.toFixed(3)}ms, ` +
    `max=${result.maxTimeMs.toFixed(3)}ms, ` +
    `total=${result.totalTimeMs.toFixed(1)}ms, ` +
    `failed=${result.failedChecks}`
  );
}

// ============================================================================
// Tests
// ============================================================================

describe('Rule Type Performance Comparison', () => {
  test('Compare TS vs JSON rule performance (same logic)', () => {
    // Parse test configuration
    const configText = generateTrunkConfig(100); // 100 interfaces
    const parser = new SchemaAwareParser({ vendor: getVendor('cisco-ios') });
    const ast = parser.parse(configText);

    console.log(`\n--- Rule Type Performance Benchmark (SAME LOGIC) ---`);
    console.log(`Config: 100 interfaces, ${BENCHMARK_ITERATIONS} iterations`);
    console.log(`Rule: Check trunk ports have allowed VLAN list\n`);

    const results: BenchmarkResult[] = [];

    // Group 1: Simple inline logic (no helper functions)
    console.log('=== Simple Rules (inline logic) ===');
    results.push(
      runBenchmark('TS (inline)  ', customTsRule, ast, BENCHMARK_ITERATIONS)
    );
    results.push(
      runBenchmark('JSON (inline)', compiledJsonRule, ast, BENCHMARK_ITERATIONS)
    );

    // Group 2: Using helper functions (like default rules)
    console.log('\n=== Rules with Helper Functions ===');
    results.push(
      runBenchmark('TS (helpers) ', helperBasedTsRule, ast, BENCHMARK_ITERATIONS)
    );
    results.push(
      runBenchmark('JSON (helpers)', compiledJsonRuleWithHelpers, ast, BENCHMARK_ITERATIONS)
    );

    // Print all results
    console.log('\n=== All Results ===');
    for (const result of results) {
      console.log(formatResult(result));
    }

    // Calculate relative performance
    const tsInline = results[0]!.avgTimeMs;
    const jsonInline = results[1]!.avgTimeMs;
    const tsHelper = results[2]!.avgTimeMs;
    const jsonHelper = results[3]!.avgTimeMs;

    console.log('\n=== Performance Ratios ===');
    console.log(`JSON/TS (inline):  ${(jsonInline / tsInline).toFixed(2)}x`);
    console.log(`JSON/TS (helpers): ${(jsonHelper / tsHelper).toFixed(2)}x`);
    console.log(`TS helpers/inline: ${(tsHelper / tsInline).toFixed(2)}x`);
    console.log(`JSON helpers/inline: ${(jsonHelper / jsonInline).toFixed(2)}x`);
  });

  test('Benchmark with varying config sizes', () => {
    const sizes = [10, 50, 100, 200];
    const parser = new SchemaAwareParser({ vendor: getVendor('cisco-ios') });

    console.log(`\n--- Scaling Benchmark (${BENCHMARK_ITERATIONS} iterations each) ---\n`);
    console.log('Interfaces | TS inline | JSON inline | TS helper | JSON helper | JSON/TS');
    console.log('-----------|-----------|-------------|-----------|-------------|--------');

    for (const size of sizes) {
      const configText = generateTrunkConfig(size);
      const ast = parser.parse(configText);

      const tsInline = runBenchmark('TS', customTsRule, ast, BENCHMARK_ITERATIONS);
      const jsonInline = runBenchmark('JSON', compiledJsonRule, ast, BENCHMARK_ITERATIONS);
      const tsHelper = runBenchmark('TS-H', helperBasedTsRule, ast, BENCHMARK_ITERATIONS);
      const jsonHelper = runBenchmark('JSON-H', compiledJsonRuleWithHelpers, ast, BENCHMARK_ITERATIONS);

      const ratio = jsonInline.avgTimeMs / tsInline.avgTimeMs;
      console.log(
        `${String(size).padStart(10)} | ` +
        `${tsInline.avgTimeMs.toFixed(3).padStart(9)} | ` +
        `${jsonInline.avgTimeMs.toFixed(3).padStart(11)} | ` +
        `${tsHelper.avgTimeMs.toFixed(3).padStart(9)} | ` +
        `${jsonHelper.avgTimeMs.toFixed(3).padStart(11)} | ` +
        `${ratio.toFixed(2)}x`
      );
    }
  });
});
