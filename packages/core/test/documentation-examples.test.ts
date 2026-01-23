// packages/core/test/documentation-examples.test.ts
// Tests to verify that documentation examples in README.md and RULE_AUTHORING_GUIDE.md work correctly

import { describe, expect, test } from 'bun:test';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import { RuleEngine } from '../src/engine/Runner';
import type { IRule, RuleResult } from '../src/types/IRule';
import type { ConfigNode } from '../src/types/ConfigNode';
import { allRules } from '@sentriflow/rules-default';

// Helper imports - testing documented import patterns
import { hasChildCommand, getChildCommand, getChildCommands } from '../src/helpers/common';
import { isPhysicalPort, isTrunkPort, isShutdown } from '../src/helpers/cisco';
import { findStanza } from '../src/helpers/juniper';

// JSON Rule functions
import {
  compileJsonRule,
  validateJsonRule,
} from '../src/json-rules';

describe('README.md Examples', () => {
  test('Programmatic Usage example works', () => {
    // This is the corrected example that should appear in README.md
    const config = `
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
`;
    const parser = new SchemaAwareParser();
    const nodes = parser.parse(config);

    const engine = new RuleEngine();
    const results = engine.run(nodes, allRules);

    expect(Array.isArray(nodes)).toBe(true);
    expect(nodes.length).toBeGreaterThan(0);
    expect(Array.isArray(results)).toBe(true);
  });

  test('Quick Example JSON rule from README compiles and validates', () => {
    // This is the JSON rule example from README.md
    const jsonRule = {
      id: 'MY-001',
      selector: 'interface',
      vendor: 'cisco-ios' as const,
      metadata: {
        level: 'warning' as const,
        obu: 'NetOps',
        owner: 'Team',
        tags: [{ type: 'operational' as const, label: 'documentation' }],
      },
      check: {
        type: 'child_not_exists' as const,
        selector: 'description',
      },
      failureMessage: 'Interface {nodeId} missing description',
    };

    const validation = validateJsonRule(jsonRule);
    expect(validation.valid).toBe(true);

    const compiledRule = compileJsonRule(jsonRule);
    expect(compiledRule.id).toBe('MY-001');
  });
});

describe('RULE_AUTHORING_GUIDE.md Examples', () => {
  describe('Helper imports are available', () => {
    test('common helpers are importable and functional', () => {
      expect(typeof hasChildCommand).toBe('function');
      expect(typeof getChildCommand).toBe('function');
      expect(typeof getChildCommands).toBe('function');
    });

    test('cisco helpers are importable and functional', () => {
      expect(typeof isPhysicalPort).toBe('function');
      expect(typeof isTrunkPort).toBe('function');
      expect(typeof isShutdown).toBe('function');

      // Verify they work as expected
      expect(isPhysicalPort('GigabitEthernet0/1')).toBe(true);
      expect(isPhysicalPort('Loopback0')).toBe(false);
      expect(isPhysicalPort('Vlan100')).toBe(false);
    });

    test('juniper helpers are importable and functional', () => {
      expect(typeof findStanza).toBe('function');
    });
  });

  describe('Testing Your Rules example', () => {
    test('corrected testing example works', () => {
      // This is the corrected example that should appear in RULE_AUTHORING_GUIDE.md
      const config = `
interface GigabitEthernet0/1
 switchport mode trunk
`;
      const parser = new SchemaAwareParser();
      const nodes = parser.parse(config);

      // Create a simple test rule
      const myRule: IRule = {
        id: 'TEST-TRUNK',
        selector: 'interface',
        vendor: 'cisco-ios',
        metadata: {
          level: 'info',
          obu: 'Test',
          owner: 'Test',
        },
        check: (node: ConfigNode): RuleResult => ({
          passed: isTrunkPort(node),
          message: isTrunkPort(node) ? 'Is trunk' : 'Not trunk',
          ruleId: 'TEST-TRUNK',
          nodeId: node.id,
          level: 'info',
          loc: node.loc,
        }),
      };

      const engine = new RuleEngine();
      const results = engine.run(nodes, [myRule]);

      expect(results.length).toBe(1);
      expect(results[0]?.passed).toBe(true);
    });
  });

  describe('JSON Rule example from guide', () => {
    test('Quick Example JSON rule compiles and runs', () => {
      const jsonRule = {
        id: 'MY-001',
        selector: 'interface',
        vendor: 'cisco-ios' as const,
        metadata: {
          level: 'warning' as const,
          obu: 'NetOps',
          owner: 'Team',
          tags: [{ type: 'operational' as const, label: 'documentation' }],
        },
        check: {
          type: 'child_not_exists' as const,
          selector: 'description',
        },
        failureMessage: 'Interface {nodeId} missing description',
      };

      const validation = validateJsonRule(jsonRule);
      expect(validation.valid).toBe(true);

      const compiledRule = compileJsonRule(jsonRule);
      expect(compiledRule.id).toBe('MY-001');

      const parser = new SchemaAwareParser();
      const config = `
interface GigabitEthernet0/1
 no shutdown
`;
      const nodes = parser.parse(config);

      const engine = new RuleEngine();
      const results = engine.run(nodes, [compiledRule]);

      // Should find the interface
      const ifResult = results.find((r) => r.nodeId.includes('GigabitEthernet'));
      expect(ifResult).toBeDefined();
      expect(ifResult?.passed).toBe(false); // Missing description = failure
    });
  });

  describe('TypeScript Rule pattern', () => {
    test('IRule check function pattern works', () => {
      const myRule: IRule = {
        id: 'TEST-001',
        selector: 'interface',
        vendor: 'cisco-ios',
        metadata: {
          level: 'warning',
          obu: 'Test',
          owner: 'Test',
        },
        check: (node: ConfigNode): RuleResult => ({
          passed: hasChildCommand(node, 'description'),
          message: hasChildCommand(node, 'description')
            ? 'Has description'
            : `Interface ${node.id} missing description`,
          ruleId: 'TEST-001',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        }),
      };

      const parser = new SchemaAwareParser();
      const config = `
interface GigabitEthernet0/1
 description Test
interface GigabitEthernet0/2
 no shutdown
`;
      const nodes = parser.parse(config);

      const engine = new RuleEngine();
      const results = engine.run(nodes, [myRule]);

      expect(results.length).toBe(2);

      const gi1 = results.find((r) => r.nodeId.includes('0/1'));
      const gi2 = results.find((r) => r.nodeId.includes('0/2'));

      expect(gi1?.passed).toBe(true); // Has description
      expect(gi2?.passed).toBe(false); // Missing description
    });
  });

  describe('Helper function usage', () => {
    test('hasChildCommand works as documented', () => {
      const parser = new SchemaAwareParser();
      const config = `
interface GigabitEthernet0/1
 description Uplink
 no shutdown
interface GigabitEthernet0/2
 shutdown
`;
      const nodes = parser.parse(config);

      const gi1 = nodes.find((n) => n.id.includes('0/1'));
      const gi2 = nodes.find((n) => n.id.includes('0/2'));

      expect(gi1).toBeDefined();
      expect(gi2).toBeDefined();

      // Test hasChildCommand
      expect(hasChildCommand(gi1!, 'description')).toBe(true);
      expect(hasChildCommand(gi2!, 'description')).toBe(false);

      // Test isShutdown (cisco helper)
      expect(isShutdown(gi1!)).toBe(false);
      expect(isShutdown(gi2!)).toBe(true);
    });

    test('findStanza helper works on node children', () => {
      const parser = new SchemaAwareParser();
      // Use Cisco-style config to test findStanza (it works on any ConfigNode hierarchy)
      const config = `
interface GigabitEthernet0/1
 description Uplink to core
 ip address 10.0.0.1 255.255.255.0
 no shutdown
`;
      const nodes = parser.parse(config);

      const interfaceNode = nodes.find((n) => n.id.includes('GigabitEthernet'));
      expect(interfaceNode).toBeDefined();

      // findStanza searches children by name (case-insensitive)
      const descChild = findStanza(interfaceNode!, 'description Uplink to core');
      expect(descChild).toBeDefined();

      // Non-existent stanza returns undefined
      const missingStanza = findStanza(interfaceNode!, 'nonexistent');
      expect(missingStanza).toBeUndefined();
    });
  });
});
