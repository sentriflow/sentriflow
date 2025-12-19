// packages/core/test/engine.test.ts

import { describe, expect, test } from 'bun:test';
import { RuleEngine } from '../src/engine/Runner';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import type { IRule, RuleResult, Context } from '../src/types/IRule';
import type { ConfigNode } from '../src/types/ConfigNode';

describe('RuleEngine', () => {
    const parser = new SchemaAwareParser();

    test('should run a simple passing rule', () => {
        const config = `
interface GigabitEthernet1
 description Uplink
        `;
        const nodes = parser.parse(config);

        const rule: IRule = {
            id: 'TEST-001',
            selector: 'interface',
            metadata: { level: 'error', obu: 'network', owner: 'me' },
            check: (node: ConfigNode, ctx: Context): RuleResult => {
                return {
                    passed: true,
                    message: 'Interface found',
                    ruleId: 'TEST-001',
                    nodeId: node.id,
                    level: 'info'
                };
            }
        };

        const engine = new RuleEngine();
        const results = engine.run(nodes, [rule]);

        expect(results).toHaveLength(1);
        expect(results[0]?.passed).toBe(true);
        expect(results[0]?.nodeId).toBe('interface GigabitEthernet1');
    });

    test('should run a simple failing rule', () => {
        const config = `
interface GigabitEthernet1
 no description
        `;
        const nodes = parser.parse(config);

        const rule: IRule = {
            id: 'TEST-002',
            selector: 'interface',
            metadata: { level: 'error', obu: 'network', owner: 'me' },
            check: (node: ConfigNode, ctx: Context): RuleResult => {
                const hasDescription = node.children.some(c => c.rawText.trim().startsWith('description'));
                if (hasDescription) {
                     return { passed: true, message: 'OK', ruleId: 'TEST-002', nodeId: node.id, level: 'info' };
                }
                return {
                    passed: false,
                    message: 'Interface missing description',
                    ruleId: 'TEST-002',
                    nodeId: node.id,
                    level: 'error'
                };
            }
        };

        const engine = new RuleEngine();
        const results = engine.run(nodes, [rule]);

        expect(results).toHaveLength(1);
        expect(results[0]?.passed).toBe(false);
        expect(results[0]?.message).toBe('Interface missing description');
    });

    test('should respect selectors', () => {
        const config = `
interface GigabitEthernet1
 description Link 1
router bgp 65000
 bgp router-id 1.1.1.1
        `;
        const nodes = parser.parse(config);

        const rule: IRule = {
            id: 'TEST-003',
            selector: 'router bgp',
            metadata: { level: 'error', obu: 'network', owner: 'me' },
            check: (node: ConfigNode, ctx: Context): RuleResult => {
                return {
                    passed: true,
                    message: 'BGP Router found',
                    ruleId: 'TEST-003',
                    nodeId: node.id,
                    level: 'info'
                };
            }
        };

        const engine = new RuleEngine();
        const results = engine.run(nodes, [rule]);

        expect(results).toHaveLength(1); // Should only match router bgp, not interface
        expect(results[0]?.nodeId).toBe('router bgp 65000');
    });

    test('should traverse children and apply rules recursively', () => {
        const config = `
interface GigabitEthernet1
 description Uplink
 ip address 10.0.0.1 255.255.255.0
        `;
        const nodes = parser.parse(config);

        const rule: IRule = {
            id: 'TEST-004',
            selector: 'ip address', // Selector matches the child command
            metadata: { level: 'error', obu: 'network', owner: 'me' },
            check: (node: ConfigNode, ctx: Context): RuleResult => {
                return {
                    passed: true,
                    message: 'IP Address found',
                    ruleId: 'TEST-004',
                    nodeId: node.id,
                    level: 'info'
                };
            }
        };

        const engine = new RuleEngine();
        const results = engine.run(nodes, [rule]);

        expect(results).toHaveLength(1);
        expect(results[0]?.nodeId).toContain('ip address 10.0.0.1');
    });

    test('should handle rule execution errors', () => {
         const config = `interface Loopback0`;
         const nodes = parser.parse(config);

         const rule: IRule = {
             id: 'TEST-CRASH',
             selector: 'interface',
             metadata: { level: 'error', obu: 'test', owner: 'me' },
             check: () => { throw new Error('Boom'); }
         };

         const engine = new RuleEngine();
         const results = engine.run(nodes, [rule]);

         expect(results).toHaveLength(1);
         expect(results[0]?.passed).toBe(false);
         expect(results[0]?.message).toContain('Rule execution error: Boom');
    });
});
