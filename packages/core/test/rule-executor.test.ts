// packages/core/test/rule-executor.test.ts

import { describe, expect, test, beforeEach } from 'bun:test';
import { RuleExecutor } from '../src/engine/RuleExecutor';
import { RuleEngine } from '../src/engine/Runner';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import type { IRule, RuleResult, Context } from '../src/types/IRule';
import type { ConfigNode } from '../src/types/ConfigNode';

describe('RuleExecutor', () => {
  let executor: RuleExecutor;
  let parser: SchemaAwareParser;

  beforeEach(() => {
    executor = new RuleExecutor({ timeoutMs: 50, maxTimeouts: 3 });
    parser = new SchemaAwareParser();
  });

  const createNode = (id: string): ConfigNode => ({
    id,
    type: 'command',
    rawText: id,
    params: id.split(' '),
    children: [],
    source: 'base',
    loc: { startLine: 0, endLine: 0 },
    indent: 0,
  });

  const createContext = (): Context => ({
    getAst: () => [],
  });

  describe('Basic Execution', () => {
    test('should execute a passing rule', () => {
      const rule: IRule = {
        id: 'TEST-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: true,
          message: 'OK',
          ruleId: 'TEST-001',
          nodeId: node.id,
          level: 'info',
        }),
      };

      const node = createNode('interface GigabitEthernet0/0');
      const result = executor.execute(rule, node, createContext());

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(true);
    });

    test('should execute a failing rule', () => {
      const rule: IRule = {
        id: 'TEST-002',
        selector: 'interface',
        metadata: { level: 'error', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: false,
          message: 'Missing description',
          ruleId: 'TEST-002',
          nodeId: node.id,
          level: 'error',
        }),
      };

      const node = createNode('interface GigabitEthernet0/0');
      const result = executor.execute(rule, node, createContext());

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(false);
      expect(result?.message).toBe('Missing description');
    });

    test('should handle rule exceptions gracefully', () => {
      const rule: IRule = {
        id: 'TEST-CRASH',
        selector: 'interface',
        metadata: { level: 'error', obu: 'test', owner: 'test' },
        check: () => {
          throw new Error('Intentional crash');
        },
      };

      const node = createNode('interface GigabitEthernet0/0');
      const result = executor.execute(rule, node, createContext());

      expect(result).not.toBeNull();
      expect(result?.passed).toBe(false);
      // SEC-005: Error message is now sanitized to prevent information disclosure
      // It should contain the rule ID but not the internal error details
      expect(result?.message).toContain('TEST-CRASH');
      expect(result?.message).toContain('failed to execute');
      // The actual error message should NOT be exposed
      expect(result?.message).not.toContain('Intentional crash');
    });
  });

  describe('Timeout Detection', () => {
    test('should detect slow rules', () => {
      let timeoutCalled = false;
      let timeoutRuleId = '';

      const slowExecutor = new RuleExecutor({
        timeoutMs: 5, // Very short timeout
        maxTimeouts: 3,
        onTimeout: (ruleId) => {
          timeoutCalled = true;
          timeoutRuleId = ruleId;
        },
      });

      const slowRule: IRule = {
        id: 'SLOW-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => {
          // Busy wait to simulate slow rule
          const start = performance.now();
          while (performance.now() - start < 10) {
            // Spin
          }
          return {
            passed: true,
            message: 'OK',
            ruleId: 'SLOW-001',
            nodeId: node.id,
            level: 'info',
          };
        },
      };

      const node = createNode('interface GigabitEthernet0/0');
      slowExecutor.execute(slowRule, node, createContext());

      expect(timeoutCalled).toBe(true);
      expect(timeoutRuleId).toBe('SLOW-001');
      expect(slowExecutor.getTimeoutCount('SLOW-001')).toBe(1);
    });

    test('should auto-disable rule after max timeouts', () => {
      let disabledRuleId = '';

      const slowExecutor = new RuleExecutor({
        timeoutMs: 1, // Very short timeout
        maxTimeouts: 2,
        onRuleDisabled: (ruleId) => {
          disabledRuleId = ruleId;
        },
      });

      const slowRule: IRule = {
        id: 'SLOW-002',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => {
          const start = performance.now();
          while (performance.now() - start < 5) {}
          return {
            passed: true,
            message: 'OK',
            ruleId: 'SLOW-002',
            nodeId: node.id,
            level: 'info',
          };
        },
      };

      const node = createNode('interface GigabitEthernet0/0');

      // First timeout
      slowExecutor.execute(slowRule, node, createContext());
      expect(slowExecutor.isDisabled('SLOW-002')).toBe(false);

      // Second timeout - should trigger auto-disable
      slowExecutor.execute(slowRule, node, createContext());
      expect(slowExecutor.isDisabled('SLOW-002')).toBe(true);
      expect(disabledRuleId).toBe('SLOW-002');
    });

    test('should skip disabled rules', () => {
      const rule: IRule = {
        id: 'DISABLED-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: true,
          message: 'OK',
          ruleId: 'DISABLED-001',
          nodeId: node.id,
          level: 'info',
        }),
      };

      executor.disableRule('DISABLED-001');

      const node = createNode('interface GigabitEthernet0/0');
      const result = executor.execute(rule, node, createContext());

      expect(result).toBeNull();
    });
  });

  describe('Rule Management', () => {
    test('should re-enable disabled rules', () => {
      executor.disableRule('TEST-001');
      expect(executor.isDisabled('TEST-001')).toBe(true);

      executor.enableRule('TEST-001');
      expect(executor.isDisabled('TEST-001')).toBe(false);
    });

    test('should list disabled rules', () => {
      executor.disableRule('RULE-A');
      executor.disableRule('RULE-B');
      executor.disableRule('RULE-C');

      const disabled = executor.getDisabledRules();
      expect(disabled).toContain('RULE-A');
      expect(disabled).toContain('RULE-B');
      expect(disabled).toContain('RULE-C');
      expect(disabled.length).toBe(3);
    });

    test('should reset timeout counts', () => {
      // Manually set timeout count
      executor.disableRule('TEST-001');

      executor.resetTimeoutCounts();

      // Timeout count should be reset but rule stays disabled
      expect(executor.getTimeoutCount('TEST-001')).toBe(0);
      expect(executor.isDisabled('TEST-001')).toBe(true);
    });

    test('should reset all state', () => {
      executor.disableRule('TEST-001');

      executor.resetAll();

      expect(executor.isDisabled('TEST-001')).toBe(false);
      expect(executor.getDisabledRules()).toEqual([]);
    });
  });

  describe('Execution Statistics', () => {
    test('should track execution statistics', () => {
      const rule: IRule = {
        id: 'STATS-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: true,
          message: 'OK',
          ruleId: 'STATS-001',
          nodeId: node.id,
          level: 'info',
        }),
      };

      const node = createNode('interface GigabitEthernet0/0');

      // Execute multiple times
      for (let i = 0; i < 5; i++) {
        executor.execute(rule, node, createContext());
      }

      const stats = executor.getStats();
      expect(stats.rulesExecuted).toBe(5);
      expect(stats.totalTimeMs).toBeGreaterThanOrEqual(0);
    });

    test('should calculate average execution time', () => {
      const rule: IRule = {
        id: 'AVG-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: true,
          message: 'OK',
          ruleId: 'AVG-001',
          nodeId: node.id,
          level: 'info',
        }),
      };

      const node = createNode('interface GigabitEthernet0/0');

      for (let i = 0; i < 10; i++) {
        executor.execute(rule, node, createContext());
      }

      const avgTime = executor.getAverageTime('AVG-001');
      expect(avgTime).toBeGreaterThanOrEqual(0);
    });

    test('should identify slowest rules', () => {
      // Fast rule
      const fastRule: IRule = {
        id: 'FAST-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => ({
          passed: true,
          message: 'OK',
          ruleId: 'FAST-001',
          nodeId: node.id,
          level: 'info',
        }),
      };

      // Slower rule (but still under timeout)
      const slowerRule: IRule = {
        id: 'SLOWER-001',
        selector: 'interface',
        metadata: { level: 'info', obu: 'test', owner: 'test' },
        check: (node) => {
          const start = performance.now();
          while (performance.now() - start < 2) {} // 2ms delay
          return {
            passed: true,
            message: 'OK',
            ruleId: 'SLOWER-001',
            nodeId: node.id,
            level: 'info',
          };
        },
      };

      const node = createNode('interface GigabitEthernet0/0');

      // Execute each rule multiple times
      for (let i = 0; i < 5; i++) {
        executor.execute(fastRule, node, createContext());
        executor.execute(slowerRule, node, createContext());
      }

      const slowest = executor.getSlowestRules(2);
      expect(slowest.length).toBe(2);
      // SLOWER-001 should be first (slowest)
      expect(slowest[0]?.[0]).toBe('SLOWER-001');
    });
  });
});

describe('RuleEngine with Timeout Protection', () => {
  test('should work with timeout protection enabled', () => {
    const engine = new RuleEngine({
      enableTimeoutProtection: true,
      executionOptions: { timeoutMs: 100, maxTimeouts: 3 },
    });

    const parser = new SchemaAwareParser();
    const config = `
interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
`;
    const nodes = parser.parse(config);

    const rule: IRule = {
      id: 'TEST-001',
      selector: 'interface',
      metadata: { level: 'info', obu: 'test', owner: 'test' },
      check: (node) => ({
        passed: true,
        message: 'OK',
        ruleId: 'TEST-001',
        nodeId: node.id,
        level: 'info',
      }),
    };

    engine.buildIndex([rule]);
    const results = engine.run(nodes);

    expect(results.length).toBe(1);
    expect(results[0]?.passed).toBe(true);
  });

  test('should auto-disable slow rules in engine', () => {
    const engine = new RuleEngine({
      enableTimeoutProtection: true,
      executionOptions: { timeoutMs: 1, maxTimeouts: 2 },
    });

    const parser = new SchemaAwareParser();
    const config = `
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
interface GigabitEthernet0/1
 ip address 10.0.1.1 255.255.255.0
interface GigabitEthernet0/2
 ip address 10.0.2.1 255.255.255.0
`;
    const nodes = parser.parse(config);

    const slowRule: IRule = {
      id: 'SLOW-ENGINE-001',
      selector: 'interface',
      metadata: { level: 'info', obu: 'test', owner: 'test' },
      check: (node) => {
        const start = performance.now();
        while (performance.now() - start < 5) {} // 5ms delay
        return {
          passed: true,
          message: 'OK',
          ruleId: 'SLOW-ENGINE-001',
          nodeId: node.id,
          level: 'info',
        };
      },
    };

    engine.buildIndex([slowRule]);
    engine.run(nodes);

    // Rule should be auto-disabled after 2 timeouts
    const disabled = engine.getDisabledRules();
    expect(disabled).toContain('SLOW-ENGINE-001');
  });

  test('should allow re-enabling disabled rules', () => {
    const engine = new RuleEngine({
      enableTimeoutProtection: true,
      executionOptions: { timeoutMs: 100 },
    });

    // Manually disable via executor
    engine.getExecutor()?.disableRule('TEST-001');
    expect(engine.getDisabledRules()).toContain('TEST-001');

    // Re-enable
    engine.enableRule('TEST-001');
    expect(engine.getDisabledRules()).not.toContain('TEST-001');
  });

  test('should reset executor state', () => {
    const engine = new RuleEngine({
      enableTimeoutProtection: true,
    });

    engine.getExecutor()?.disableRule('TEST-001');
    engine.resetExecutor();

    expect(engine.getDisabledRules()).toEqual([]);
  });

  test('should work without timeout protection (default)', () => {
    const engine = new RuleEngine(); // No options

    expect(engine.getExecutor()).toBeNull();
    expect(engine.getDisabledRules()).toEqual([]);

    const parser = new SchemaAwareParser();
    const nodes = parser.parse('interface Loopback0');

    const rule: IRule = {
      id: 'TEST-001',
      selector: 'interface',
      metadata: { level: 'info', obu: 'test', owner: 'test' },
      check: (node) => ({
        passed: true,
        message: 'OK',
        ruleId: 'TEST-001',
        nodeId: node.id,
        level: 'info',
      }),
    };

    engine.buildIndex([rule]);
    const results = engine.run(nodes);

    expect(results.length).toBe(1);
  });
});
