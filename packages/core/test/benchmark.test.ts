// packages/core/test/benchmark.test.ts

import { describe, expect, test } from 'bun:test';
import { RuleEngine } from '../src/engine/Runner';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import type { IRule, RuleResult, Context } from '../src/types/IRule';
import type { ConfigNode } from '../src/types/ConfigNode';

// ============================================================================
// Test Data Generators
// ============================================================================

/**
 * Generate mock configuration with specified number of interface blocks.
 */
function generateMockConfig(interfaceCount: number): string {
  const lines: string[] = ['!', 'hostname TestRouter', '!'];

  for (let i = 0; i < interfaceCount; i++) {
    lines.push(`interface GigabitEthernet0/${i}`);
    lines.push(` description Link to Switch ${i}`);
    lines.push(` ip address 10.${Math.floor(i / 256)}.${i % 256}.1 255.255.255.0`);
    lines.push(` no shutdown`);
    lines.push('!');
  }

  lines.push('router ospf 1');
  lines.push(' router-id 1.1.1.1');
  for (let i = 0; i < Math.min(interfaceCount, 50); i++) {
    lines.push(` network 10.${Math.floor(i / 256)}.${i % 256}.0 0.0.0.255 area 0`);
  }
  lines.push('!');
  lines.push('end');

  return lines.join('\n');
}

/**
 * Generate mock rules with various selectors.
 */
function generateMockRules(count: number): IRule[] {
  const selectors = [
    'interface',
    'ip address',
    'description',
    'router ospf',
    'router bgp',
    'vlan',
    'access-list',
    'route-map',
    'prefix-list',
    'ip route',
  ];

  const rules: IRule[] = [];

  for (let i = 0; i < count; i++) {
    const selector = selectors[i % selectors.length];
    const rule: IRule = {
      id: `TEST-${String(i).padStart(4, '0')}`,
      selector,
      metadata: {
        level: i % 3 === 0 ? 'error' : i % 3 === 1 ? 'warning' : 'info',
        obu: 'benchmark',
        owner: 'test',
      },
      check: (node: ConfigNode, ctx: Context): RuleResult => {
        // Simple check that does minimal work
        return {
          passed: node.children.length > 0,
          message: `Rule ${i} checked`,
          ruleId: `TEST-${String(i).padStart(4, '0')}`,
          nodeId: node.id,
          level: 'info',
          loc: node.loc,
        };
      },
    };
    rules.push(rule);
  }

  return rules;
}

// ============================================================================
// Benchmark Tests
// ============================================================================

describe('RuleEngine', () => {
  const parser = new SchemaAwareParser();

  test('should handle global rules (no selector)', () => {
    const config = `
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
    `;
    const nodes = parser.parse(config);

    const globalRule: IRule = {
      id: 'GLOBAL-001',
      // No selector = global rule
      metadata: { level: 'info', obu: 'test', owner: 'test' },
      check: (node: ConfigNode): RuleResult => ({
        passed: true,
        message: 'Global check',
        ruleId: 'GLOBAL-001',
        nodeId: node.id,
        level: 'info',
      }),
    };

    const engine = new RuleEngine();
    engine.buildIndex([globalRule]);
    const results = engine.run(nodes);

    // Global rule runs on all nodes (interface + its children)
    expect(results.length).toBeGreaterThan(1);
  });

  test('should correctly index rules by prefix', () => {
    const engine = new RuleEngine();
    const rules: IRule[] = [
      {
        id: 'R1',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: () => ({ passed: true, message: 'OK', ruleId: 'R1', nodeId: '', level: 'info' }),
      },
      {
        id: 'R2',
        selector: 'interface GigabitEthernet',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: () => ({ passed: true, message: 'OK', ruleId: 'R2', nodeId: '', level: 'info' }),
      },
      {
        id: 'R3',
        selector: 'router bgp',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: () => ({ passed: true, message: 'OK', ruleId: 'R3', nodeId: '', level: 'info' }),
      },
    ];

    engine.buildIndex(rules);
    const stats = engine.getIndexStats();

    expect(stats.totalRules).toBe(3);
    expect(stats.globalRules).toBe(0);
    expect(stats.prefixBuckets).toBe(2); // 'interface' and 'router'
  });

  test('should provide accurate index statistics', () => {
    const engine = new RuleEngine();
    const rules = generateMockRules(100);

    engine.buildIndex(rules);
    const stats = engine.getIndexStats();

    expect(stats.totalRules).toBe(100);
    expect(stats.globalRules).toBe(0);
    expect(stats.prefixBuckets).toBeGreaterThan(0);
    expect(stats.avgRulesPerPrefix).toBeGreaterThan(0);
  });

  test('should increment index version on rebuild', () => {
    const engine = new RuleEngine();
    const rules = generateMockRules(10);

    expect(engine.getIndexVersion()).toBe(0);

    engine.buildIndex(rules);
    expect(engine.getIndexVersion()).toBe(1);

    engine.buildIndex(rules);
    expect(engine.getIndexVersion()).toBe(2);
  });

  test('should detect when reindex is needed', () => {
    const engine = new RuleEngine();
    const rules1 = generateMockRules(10);
    const rules2 = generateMockRules(20);

    engine.buildIndex(rules1);

    expect(engine.needsReindex(rules1)).toBe(false); // Same reference
    expect(engine.needsReindex(rules2)).toBe(true); // Different reference
  });

  test('should auto-rebuild index when rules change', () => {
    const config = generateMockConfig(5);
    const nodes = parser.parse(config);
    const rules1 = generateMockRules(10);
    const rules2 = generateMockRules(20);

    const engine = new RuleEngine();

    // First run builds index
    const results1 = engine.run(nodes, rules1);
    expect(engine.getIndexVersion()).toBe(1);

    // Second run with same rules uses cached index
    engine.run(nodes);
    expect(engine.getIndexVersion()).toBe(1);

    // Third run with different rules rebuilds index
    const results2 = engine.run(nodes, rules2);
    expect(engine.getIndexVersion()).toBe(2);
    expect(results2.length).toBeGreaterThanOrEqual(results1.length);
  });

  test('should handle empty rules array', () => {
    const config = generateMockConfig(5);
    const nodes = parser.parse(config);

    const engine = new RuleEngine();
    engine.buildIndex([]);

    const results = engine.run(nodes);
    expect(results).toEqual([]);
  });

  test('should handle rule execution errors gracefully', () => {
    const config = `interface Loopback0`;
    const nodes = parser.parse(config);

    const crashingRule: IRule = {
      id: 'CRASH-001',
      selector: 'interface',
      metadata: { level: 'error', obu: 'test', owner: 'test' },
      check: () => {
        throw new Error('Intentional crash');
      },
    };

    const engine = new RuleEngine();
    engine.buildIndex([crashingRule]);
    const results = engine.run(nodes);

    expect(results.length).toBe(1);
    expect(results[0]?.passed).toBe(false);
    expect(results[0]?.message).toContain('Rule execution error');
  });

  test('should clear index', () => {
    const engine = new RuleEngine();
    const rules = generateMockRules(50);

    engine.buildIndex(rules);
    expect(engine.getIndexStats().totalRules).toBe(50);

    engine.clearIndex();
    expect(engine.getIndexStats().totalRules).toBe(0);
  });
});

describe('Performance Benchmarks', () => {
  const parser = new SchemaAwareParser();

  // Test configurations
  const configs = {
    small: generateMockConfig(20), // ~100 lines
    medium: generateMockConfig(100), // ~500 lines
    large: generateMockConfig(400), // ~2000 lines
  };

  // Test rule sets
  const ruleSets = {
    few: generateMockRules(10),
    moderate: generateMockRules(100),
    many: generateMockRules(500),
  };

  for (const [configSize, config] of Object.entries(configs)) {
    for (const [ruleCount, rules] of Object.entries(ruleSets)) {
      test(`${configSize} config + ${ruleCount} rules - should complete efficiently`, () => {
        const nodes = parser.parse(config);

        const engine = new RuleEngine();
        const start = performance.now();
        engine.buildIndex(rules); // Build once
        for (let i = 0; i < 10; i++) {
          engine.run(nodes); // Run with cached index
        }
        const elapsed = (performance.now() - start) / 10;

        console.log(`[${configSize}/${ruleCount}] OptimizedEngine: ${elapsed.toFixed(2)}ms`);

        // Should be reasonably fast
        expect(elapsed).toBeLessThan(200);
      });
    }
  }

  test('large config + many rules should complete under 100ms', () => {
    const config = generateMockConfig(400); // ~2000 lines
    const rules = generateMockRules(500);
    const nodes = parser.parse(config);

    const engine = new RuleEngine();
    engine.buildIndex(rules);

    const start = performance.now();
    engine.run(nodes);
    const elapsed = performance.now() - start;

    console.log(`Large config + 500 rules: ${elapsed.toFixed(2)}ms`);

    // Should complete under 100ms for real-time linting
    expect(elapsed).toBeLessThan(100);
  });

  test('index build time should be reasonable', () => {
    const rules = generateMockRules(500);

    const engine = new RuleEngine();

    const start = performance.now();
    engine.buildIndex(rules);
    const elapsed = performance.now() - start;

    console.log(`Index build time (500 rules): ${elapsed.toFixed(2)}ms`);

    // Index build should be fast (under 10ms)
    expect(elapsed).toBeLessThan(10);
  });
});
