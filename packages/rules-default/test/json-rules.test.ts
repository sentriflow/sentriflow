// packages/rules-default/test/json-rules.test.ts

import { describe, expect, test } from 'bun:test';
import { SchemaAwareParser, RuleEngine, validateJsonRuleFile } from '@sentriflow/core';
import {
    allJsonRules,
    ciscoJsonRules,
    commonJsonRules,
    juniperJsonRules,
    getJsonRulesByVendor,
} from '../src/index';

// Import raw JSON files for validation testing
import ciscoJsonFile from '../src/json/cisco-json-rules.json';
import commonJsonFile from '../src/json/common-json-rules.json';
import juniperJsonFile from '../src/json/juniper-json-rules.json';

describe('JSON Rules - Validation', () => {
    test('cisco-json-rules.json is valid', () => {
        const result = validateJsonRuleFile(ciscoJsonFile);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    test('common-json-rules.json is valid', () => {
        const result = validateJsonRuleFile(commonJsonFile);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });

    test('juniper-json-rules.json is valid', () => {
        const result = validateJsonRuleFile(juniperJsonFile);
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
    });
});

describe('JSON Rules - Compilation', () => {
    test('ciscoJsonRules is compiled', () => {
        expect(ciscoJsonRules.length).toBeGreaterThan(0);
        expect(ciscoJsonRules[0]?.id).toMatch(/^JSON-CISCO-/);
    });

    test('commonJsonRules is compiled', () => {
        expect(commonJsonRules.length).toBeGreaterThan(0);
        expect(commonJsonRules[0]?.id).toMatch(/^JSON-COMMON-/);
    });

    test('juniperJsonRules is compiled', () => {
        expect(juniperJsonRules.length).toBeGreaterThan(0);
        expect(juniperJsonRules[0]?.id).toMatch(/^JSON-JUNOS-/);
    });

    test('allJsonRules contains all rules', () => {
        expect(allJsonRules.length).toBe(
            ciscoJsonRules.length + commonJsonRules.length + juniperJsonRules.length
        );
    });
});

describe('JSON Rules - getJsonRulesByVendor', () => {
    test('returns cisco rules for cisco-ios', () => {
        const rules = getJsonRulesByVendor('cisco-ios');
        expect(rules.length).toBeGreaterThan(0);
        expect(rules.some(r => r.id.startsWith('JSON-CISCO-'))).toBe(true);
        expect(rules.some(r => r.id.startsWith('JSON-COMMON-'))).toBe(true);
    });

    test('returns juniper rules for juniper-junos', () => {
        const rules = getJsonRulesByVendor('juniper-junos');
        expect(rules.length).toBeGreaterThan(0);
        expect(rules.some(r => r.id.startsWith('JSON-JUNOS-'))).toBe(true);
        expect(rules.some(r => r.id.startsWith('JSON-COMMON-'))).toBe(true);
    });

    test('returns common rules for unknown vendor', () => {
        const rules = getJsonRulesByVendor('some-unknown');
        expect(rules.length).toBeGreaterThan(0);
        expect(rules.some(r => r.id.startsWith('JSON-COMMON-'))).toBe(true);
    });
});

describe('JSON Rules - Execution', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('Cisco JSON Rules', () => {
        test('JSON-CISCO-003: Interface description required', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet0/2
 description Uplink to core
 switchport mode trunk
            `;
            const nodes = parser.parse(config);

            // Get only the description rule
            const descRule = ciscoJsonRules.find(r => r.id === 'JSON-CISCO-003');
            expect(descRule).toBeDefined();

            const results = engine.run(nodes, [descRule!]);

            // Check semantics: check defines failure condition
            // Gi0/1 has no description - failure condition met - passed=false
            // Gi0/2 has description - failure condition NOT met - passed=true
            const gi1Result = results.find(r => r.nodeId.includes('0/1'));
            const gi2Result = results.find(r => r.nodeId.includes('0/2'));

            expect(gi1Result?.passed).toBe(false); // Violation: no description
            expect(gi2Result?.passed).toBe(true); // No violation: has description
        });

        test('JSON-CISCO-005: VTY access-class required', () => {
            const config = `
line vty 0 4
 transport input ssh
 login local
line vty 5 15
 access-class 10 in
 transport input ssh
            `;
            const nodes = parser.parse(config);

            const vtyRule = ciscoJsonRules.find(r => r.id === 'JSON-CISCO-005');
            expect(vtyRule).toBeDefined();

            const results = engine.run(nodes, [vtyRule!]);

            // vty 0 4 has no access-class - should fail
            // vty 5 15 has access-class - should pass
            const vty04Result = results.find(r => r.nodeId.includes('0 4'));
            const vty515Result = results.find(r => r.nodeId.includes('5 15'));

            expect(vty04Result?.passed).toBe(false); // Violation: no access-class
            expect(vty515Result?.passed).toBe(true); // No violation: has access-class
        });
    });

    describe('Common JSON Rules', () => {
        test('JSON-COMMON-001: Interface description for active interfaces', () => {
            const config = `
interface Ethernet1
 no shutdown
interface Ethernet2
 description Server port
 no shutdown
            `;
            const nodes = parser.parse(config);

            const descRule = commonJsonRules.find(r => r.id === 'JSON-COMMON-001');
            expect(descRule).toBeDefined();

            const results = engine.run(nodes, [descRule!]);

            // Both are active (no shutdown command means active by default for common check)
            // Eth1 has no description
            // Eth2 has description
            expect(results.length).toBeGreaterThanOrEqual(2);
        });
    });
});

describe('JSON Rules - allRules Integration', () => {
    test('allJsonRules are included in allRules from main export', async () => {
        const { allRules } = await import('../src/index');

        // Check that JSON rules are included
        const jsonRuleIds = allJsonRules.map(r => r.id);
        for (const jsonId of jsonRuleIds) {
            expect(allRules.some(r => r.id === jsonId)).toBe(true);
        }
    });
});

describe('JSON Rules - Rule Properties', () => {
    test('all JSON rules have required properties', () => {
        for (const rule of allJsonRules) {
            expect(rule.id).toMatch(/^[A-Z][A-Z0-9_-]+$/);
            expect(rule.metadata).toBeDefined();
            expect(rule.metadata.level).toMatch(/^(error|warning|info)$/);
            expect(rule.metadata.obu).toBeDefined();
            expect(rule.metadata.owner).toBeDefined();
            expect(typeof rule.check).toBe('function');
        }
    });

    test('JSON rules have vendor targeting', () => {
        // Cisco rules should target cisco-ios
        for (const rule of ciscoJsonRules) {
            expect(rule.vendor).toBe('cisco-ios');
        }

        // Juniper rules should target juniper-junos
        for (const rule of juniperJsonRules) {
            expect(rule.vendor).toBe('juniper-junos');
        }

        // Common rules should target 'common'
        for (const rule of commonJsonRules) {
            expect(rule.vendor).toBe('common');
        }
    });
});
