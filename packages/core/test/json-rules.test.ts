// packages/core/test/json-rules.test.ts

import { describe, expect, test, beforeEach } from 'bun:test';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import { RuleEngine } from '../src/engine/Runner';
import type { ConfigNode } from '../src/types/ConfigNode';

// Types
import {
    isJsonCheck,
    isJsonRule,
    isJsonRuleFile,
    isJsonArgValue,
    type JsonRule,
    type JsonCheck,
    type JsonRuleFile,
} from '../src/json-rules/types';

// Helper Registry
import {
    createHelperRegistry,
    resolveHelper,
    getAvailableHelpers,
    hasHelper,
    clearHelperRegistryCache,
} from '../src/json-rules/HelperRegistry';

// Expression Evaluator
import {
    ExpressionEvaluator,
    createExpressionEvaluator,
    isValidExpression,
} from '../src/json-rules/ExpressionEvaluator';

// JSON Rule Compiler
import {
    JsonRuleCompiler,
    createJsonRuleCompiler,
    compileJsonRule,
    compileJsonRules,
    clearJsonRuleCompiler,
} from '../src/json-rules/JsonRuleCompiler';

// JSON Rule Validator
import {
    validateJsonRuleFile,
    validateJsonRule,
    formatValidationResult,
} from '../src/json-rules/JsonRuleValidator';

describe('JSON Rules - Type Guards', () => {
    describe('isJsonArgValue', () => {
        test('accepts string values', () => {
            expect(isJsonArgValue('test')).toBe(true);
        });

        test('accepts number values', () => {
            expect(isJsonArgValue(42)).toBe(true);
        });

        test('accepts boolean values', () => {
            expect(isJsonArgValue(true)).toBe(true);
            expect(isJsonArgValue(false)).toBe(true);
        });

        test('accepts null', () => {
            expect(isJsonArgValue(null)).toBe(true);
        });

        test('accepts valid $ref objects', () => {
            expect(isJsonArgValue({ $ref: 'node' })).toBe(true);
            expect(isJsonArgValue({ $ref: 'node.id' })).toBe(true);
            expect(isJsonArgValue({ $ref: 'node.children' })).toBe(true);
            expect(isJsonArgValue({ $ref: 'node.params' })).toBe(true);
        });

        test('rejects invalid $ref values', () => {
            expect(isJsonArgValue({ $ref: 'invalid' })).toBe(false);
            expect(isJsonArgValue({ $ref: 123 })).toBe(false);
        });

        test('rejects objects without $ref', () => {
            expect(isJsonArgValue({ foo: 'bar' })).toBe(false);
        });
    });

    describe('isJsonCheck', () => {
        test('accepts match check', () => {
            expect(isJsonCheck({ type: 'match', pattern: '^interface' })).toBe(true);
            expect(isJsonCheck({ type: 'match', pattern: 'test', flags: 'i' })).toBe(true);
        });

        test('accepts contains check', () => {
            expect(isJsonCheck({ type: 'contains', text: 'description' })).toBe(true);
        });

        test('accepts child_exists check', () => {
            expect(isJsonCheck({ type: 'child_exists', selector: 'switchport' })).toBe(true);
        });

        test('accepts helper check', () => {
            expect(isJsonCheck({
                type: 'helper',
                helper: 'cisco.isTrunkPort',
                args: [{ $ref: 'node' }]
            })).toBe(true);
        });

        test('accepts expr check', () => {
            expect(isJsonCheck({ type: 'expr', expr: 'node.id.includes("Gi")' })).toBe(true);
        });

        test('accepts logical combinators', () => {
            expect(isJsonCheck({
                type: 'and',
                conditions: [
                    { type: 'contains', text: 'interface' },
                    { type: 'child_exists', selector: 'description' }
                ]
            })).toBe(true);

            expect(isJsonCheck({
                type: 'or',
                conditions: [
                    { type: 'contains', text: 'interface' },
                    { type: 'contains', text: 'vlan' }
                ]
            })).toBe(true);

            expect(isJsonCheck({
                type: 'not',
                condition: { type: 'contains', text: 'shutdown' }
            })).toBe(true);
        });

        test('rejects invalid check types', () => {
            expect(isJsonCheck({ type: 'invalid' })).toBe(false);
            expect(isJsonCheck({ type: 'match' })).toBe(false); // missing pattern
            expect(isJsonCheck(null)).toBe(false);
            expect(isJsonCheck('string')).toBe(false);
        });
    });

    describe('isJsonRule', () => {
        const validRule: JsonRule = {
            id: 'TEST-001',
            selector: 'interface',
            vendor: 'cisco-ios',
            metadata: {
                level: 'warning',
                obu: 'Network',
                owner: 'NetOps',
                description: 'Test rule'
            },
            check: { type: 'contains', text: 'interface' }
        };

        test('accepts valid rule', () => {
            expect(isJsonRule(validRule)).toBe(true);
        });

        test('accepts rule without selector', () => {
            const rule = { ...validRule, selector: undefined };
            expect(isJsonRule(rule)).toBe(true);
        });

        test('accepts rule without vendor', () => {
            const rule = { ...validRule, vendor: undefined };
            expect(isJsonRule(rule)).toBe(true);
        });

        test('rejects rule without id', () => {
            const rule = { ...validRule, id: undefined };
            expect(isJsonRule(rule)).toBe(false);
        });

        test('rejects rule with invalid metadata', () => {
            const rule = { ...validRule, metadata: { level: 'invalid' } };
            expect(isJsonRule(rule)).toBe(false);
        });
    });

    describe('isJsonRuleFile', () => {
        test('accepts valid rule file', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'test' }
                }]
            };
            expect(isJsonRuleFile(file)).toBe(true);
        });

        test('accepts rule file with meta', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                meta: {
                    name: 'Test Rules',
                    description: 'Test description',
                    author: 'Test Author'
                },
                rules: []
            };
            expect(isJsonRuleFile(file)).toBe(true);
        });

        test('rejects wrong version', () => {
            expect(isJsonRuleFile({ version: '2.0', rules: [] })).toBe(false);
        });
    });
});

describe('JSON Rules - Helper Registry', () => {
    beforeEach(() => {
        clearHelperRegistryCache();
    });

    test('creates registry with common helpers', () => {
        const registry = createHelperRegistry();
        expect(typeof registry.hasChildCommand).toBe('function');
        expect(typeof registry.parseIp).toBe('function');
        expect(typeof registry.isShutdown).toBe('function');
    });

    test('creates registry with vendor namespaces', () => {
        const registry = createHelperRegistry();
        expect(typeof registry.cisco).toBe('object');
        expect(typeof registry.juniper).toBe('object');
        expect(typeof registry.cisco.isTrunkPort).toBe('function');
    });

    test('resolves common helper', () => {
        const registry = createHelperRegistry();
        const helper = resolveHelper(registry, 'hasChildCommand');
        expect(helper).toBeDefined();
        expect(typeof helper).toBe('function');
    });

    test('resolves namespaced helper', () => {
        const registry = createHelperRegistry();
        const helper = resolveHelper(registry, 'cisco.isTrunkPort');
        expect(helper).toBeDefined();
        expect(typeof helper).toBe('function');
    });

    test('returns undefined for unknown helper', () => {
        const registry = createHelperRegistry();
        expect(resolveHelper(registry, 'unknownHelper')).toBeUndefined();
        expect(resolveHelper(registry, 'cisco.unknownHelper')).toBeUndefined();
    });

    test('hasHelper returns correct values', () => {
        const registry = createHelperRegistry();
        expect(hasHelper(registry, 'hasChildCommand')).toBe(true);
        expect(hasHelper(registry, 'cisco.isTrunkPort')).toBe(true);
        expect(hasHelper(registry, 'unknownHelper')).toBe(false);
    });

    test('getAvailableHelpers returns sorted list', () => {
        const registry = createHelperRegistry();
        const helpers = getAvailableHelpers(registry);
        expect(helpers.length).toBeGreaterThan(0);
        expect(helpers).toContain('hasChildCommand');
        expect(helpers.some(h => h.startsWith('cisco.'))).toBe(true);
    });
});

describe('JSON Rules - Expression Evaluator', () => {
    describe('isValidExpression', () => {
        test('accepts valid expressions', () => {
            expect(isValidExpression('node.id')).toBe(true);
            expect(isValidExpression('node.params[0]')).toBe(true);
            expect(isValidExpression('node.id.includes("test")')).toBe(true);
        });

        test('rejects dangerous patterns', () => {
            expect(isValidExpression('require("fs")')).toBe(false);
            expect(isValidExpression('process.exit()')).toBe(false);
            expect(isValidExpression('global.something')).toBe(false);
            expect(isValidExpression('__proto__')).toBe(false);
            expect(isValidExpression('constructor')).toBe(false);
        });

        test('rejects template literals with expressions', () => {
            expect(isValidExpression('`${node.id}`')).toBe(false);
        });

        test('rejects assignment operators', () => {
            expect(isValidExpression('x = 5')).toBe(false);
        });

        test('rejects overly long expressions', () => {
            const longExpr = 'a'.repeat(1001);
            expect(isValidExpression(longExpr)).toBe(false);
        });
    });

    describe('ExpressionEvaluator', () => {
        const parser = new SchemaAwareParser();

        test('runs property access expression', () => {
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);
            const node = nodes[0]!;

            const exprEval = createExpressionEvaluator();
            expect(exprEval.evaluate('node.id.includes("Gigabit")', node)).toBe(true);
            expect(exprEval.evaluate('node.id.includes("Fast")', node)).toBe(false);
        });

        test('runs expression with helper functions', () => {
            const config = `
interface GigabitEthernet1
 switchport mode trunk
            `;
            const nodes = parser.parse(config);
            const node = nodes[0]!;

            const exprEval = createExpressionEvaluator();
            expect(exprEval.evaluate('hasChildCommand(node, "switchport mode")', node)).toBe(true);
            expect(exprEval.evaluate('hasChildCommand(node, "shutdown")', node)).toBe(false);
        });

        test('precompiles expressions', () => {
            const exprEval = createExpressionEvaluator();
            expect(exprEval.precompile('node.id')).toBe(true);
            expect(exprEval.precompile('require("fs")')).toBe(false);
        });

        test('returns false for invalid expressions', () => {
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);
            const node = nodes[0]!;

            const exprEval = createExpressionEvaluator();
            expect(exprEval.evaluate('invalid syntax {{', node)).toBe(false);
            expect(exprEval.evaluate('require("fs")', node)).toBe(false);
        });
    });
});

describe('JSON Rules - Compiler', () => {
    const parser = new SchemaAwareParser();

    beforeEach(() => {
        clearJsonRuleCompiler();
    });

    describe('basic check types', () => {
        test('compiles match check', () => {
            // Check defines failure condition: fail if node.id matches pattern
            const jsonRule: JsonRule = {
                id: 'TEST-MATCH',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: { type: 'match', pattern: '^interface Gigabit' }
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Node matches pattern → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('compiles contains check', () => {
            // Check defines failure condition: fail if node.id contains text
            const jsonRule: JsonRule = {
                id: 'TEST-CONTAINS',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: { type: 'contains', text: 'Gigabit' }
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Node contains text → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('compiles child_exists check', () => {
            // Check defines failure condition: fail if child exists
            const jsonRule: JsonRule = {
                id: 'TEST-CHILD',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: { type: 'child_exists', selector: 'description' }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 description Uplink
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Child exists → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('compiles child_not_exists check', () => {
            // Check defines failure condition: fail if child is missing
            const jsonRule: JsonRule = {
                id: 'TEST-NO-CHILD',
                selector: 'interface',
                metadata: { level: 'error', obu: 'Net', owner: 'Me' },
                check: { type: 'child_not_exists', selector: 'shutdown' }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 description Active
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Child 'shutdown' doesn't exist → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });
    });

    describe('helper check', () => {
        test('calls helper with node reference', () => {
            // Check defines failure condition: fail if helper returns true
            const jsonRule: JsonRule = {
                id: 'TEST-HELPER',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'helper',
                    helper: 'hasChildCommand',
                    args: [{ $ref: 'node' }, 'switchport mode trunk']
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 switchport mode trunk
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Helper returns true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('supports negate option', () => {
            // Check defines failure condition: fail if NOT shutdown (negate: true)
            const jsonRule: JsonRule = {
                id: 'TEST-NEGATE',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'helper',
                    helper: 'isShutdown',
                    args: [{ $ref: 'node' }],
                    negate: true
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 description Active
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // isShutdown returns false, negated → true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('returns false for unknown helper', () => {
            // Unknown helper → check returns false → no failure → passed = true
            const jsonRule: JsonRule = {
                id: 'TEST-UNKNOWN',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'helper',
                    helper: 'unknownHelper',
                    args: [{ $ref: 'node' }]
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Unknown helper → check returns false → no failure → passed = true
            expect(results[0]?.passed).toBe(true);
        });
    });

    describe('expr check', () => {
        test('runs simple expression', () => {
            // Check defines failure condition: fail if expression returns true
            const jsonRule: JsonRule = {
                id: 'TEST-EXPR',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'expr',
                    expr: 'node.id.toLowerCase().includes("gigabit")'
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Expression returns true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });
    });

    describe('logical combinators', () => {
        test('compiles AND check', () => {
            // Check: fail if contains 'Gigabit' AND has description child
            const jsonRule: JsonRule = {
                id: 'TEST-AND',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'and',
                    conditions: [
                        { type: 'contains', text: 'Gigabit' },
                        { type: 'child_exists', selector: 'description' }
                    ]
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 description Uplink
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Both conditions true → AND true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('compiles OR check', () => {
            // Check: fail if contains 'Fast' OR contains 'Gigabit'
            const jsonRule: JsonRule = {
                id: 'TEST-OR',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'or',
                    conditions: [
                        { type: 'contains', text: 'Fast' },
                        { type: 'contains', text: 'Gigabit' }
                    ]
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // Contains 'Gigabit' → OR true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });

        test('compiles NOT check', () => {
            // Check: fail if NOT has shutdown child (i.e., fail if shutdown missing)
            const jsonRule: JsonRule = {
                id: 'TEST-NOT',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: {
                    type: 'not',
                    condition: { type: 'child_exists', selector: 'shutdown' }
                }
            };

            const rule = compileJsonRule(jsonRule);
            const config = `
interface GigabitEthernet1
 description Active
            `;
            const nodes = parser.parse(config);

            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            // No shutdown → child_exists false → NOT true → failure condition met → passed = false
            expect(results[0]?.passed).toBe(false);
        });
    });

    describe('compileJsonRules', () => {
        test('compiles multiple rules', () => {
            const jsonRules: JsonRule[] = [
                {
                    id: 'TEST-001',
                    selector: 'interface',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'Gigabit' }
                },
                {
                    id: 'TEST-002',
                    selector: 'interface',
                    metadata: { level: 'error', obu: 'Net', owner: 'Me' },
                    check: { type: 'child_exists', selector: 'description' }
                }
            ];

            const rules = compileJsonRules(jsonRules);
            expect(rules).toHaveLength(2);
            expect(rules[0]?.id).toBe('TEST-001');
            expect(rules[1]?.id).toBe('TEST-002');
        });
    });
});

describe('JSON Rules - Validator', () => {
    describe('validateJsonRuleFile', () => {
        test('validates correct rule file', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'test' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        test('detects invalid version', () => {
            const file = { version: '2.0', rules: [] };
            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.path === '/version')).toBe(true);
        });

        test('detects invalid rule ID format', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'invalid-lowercase',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'test' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Invalid rule ID'))).toBe(true);
        });

        test('detects unknown vendor', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    vendor: 'unknown-vendor' as any,
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'test' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Unknown vendor'))).toBe(true);
        });

        test('detects unknown helper', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'helper', helper: 'unknownHelper' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Unknown helper'))).toBe(true);
        });

        test('detects unsafe expression', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'expr', expr: 'require("fs")' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('unsafe expression'))).toBe(true);
        });

        test('detects invalid regex', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'match', pattern: '[invalid' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Invalid regex'))).toBe(true);
        });

        test('detects duplicate rule IDs', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [
                    {
                        id: 'TEST-001',
                        metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                        check: { type: 'contains', text: 'test' }
                    },
                    {
                        id: 'TEST-001',
                        metadata: { level: 'error', obu: 'Net', owner: 'Me' },
                        check: { type: 'contains', text: 'other' }
                    }
                ]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Duplicate rule ID'))).toBe(true);
        });

        test('warns about missing description', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-001',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'contains', text: 'test' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.warnings.some(w => w.message.includes('description'))).toBe(true);
        });
    });

    describe('validateJsonRule', () => {
        test('validates single rule', () => {
            const rule: JsonRule = {
                id: 'TEST-001',
                metadata: {
                    level: 'warning',
                    obu: 'Net',
                    owner: 'Me',
                    description: 'Test rule'
                },
                check: { type: 'contains', text: 'test' }
            };

            const result = validateJsonRule(rule);
            expect(result.valid).toBe(true);
        });
    });

    describe('formatValidationResult', () => {
        test('formats passing result', () => {
            const result = { valid: true, errors: [], warnings: [] };
            const formatted = formatValidationResult(result);
            expect(formatted).toContain('Validation passed');
        });

        test('formats failing result', () => {
            const result = {
                valid: false,
                errors: [{ path: '/rules/0/id', message: 'Invalid ID', severity: 'error' as const }],
                warnings: []
            };
            const formatted = formatValidationResult(result);
            expect(formatted).toContain('Validation failed');
            expect(formatted).toContain('Invalid ID');
        });
    });
});

describe('JSON Rules - Security Hardening', () => {
    describe('ReDoS Protection', () => {
        test('rejects patterns with nested quantifiers', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-REDOS',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'match', pattern: '(a+)+$' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('ReDoS'))).toBe(true);
        });

        test('rejects patterns exceeding length limit', () => {
            const longPattern = 'a'.repeat(501);
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-LONG',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'match', pattern: longPattern }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('too long'))).toBe(true);
        });

        test('accepts safe patterns within limit', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-SAFE',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'match', pattern: '^interface\\s+\\w+$' }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(true);
        });
    });

    describe('Empty Conditions Validation', () => {
        test('rejects empty AND conditions', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-EMPTY-AND',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'and', conditions: [] }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Empty conditions'))).toBe(true);
        });

        test('rejects empty OR conditions', () => {
            const file: JsonRuleFile = {
                version: '1.0',
                rules: [{
                    id: 'TEST-EMPTY-OR',
                    metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                    check: { type: 'or', conditions: [] }
                }]
            };

            const result = validateJsonRuleFile(file);
            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.message.includes('Empty conditions'))).toBe(true);
        });
    });

    describe('Expression Blocked Patterns', () => {
        test('rejects "arguments" keyword', () => {
            expect(isValidExpression('arguments[0]')).toBe(false);
        });

        test('rejects "this" keyword', () => {
            expect(isValidExpression('this.something')).toBe(false);
        });

        test('rejects "with" keyword', () => {
            expect(isValidExpression('with(obj) { x }')).toBe(false);
        });
    });

    describe('Message Template replaceAll', () => {
        const parser = new SchemaAwareParser();

        test('replaces all occurrences of placeholders', () => {
            const jsonRule: JsonRule = {
                id: 'TEST-MSG',
                selector: 'interface',
                metadata: { level: 'warning', obu: 'Net', owner: 'Me' },
                check: { type: 'match', pattern: 'GigabitEthernet' },
                failureMessage: 'Rule {ruleId} failed for {nodeId}. See {ruleId} docs.'
            };

            const rule = compileJsonRule(jsonRule);
            const config = 'interface GigabitEthernet1';
            const nodes = parser.parse(config);
            const engine = new RuleEngine();
            const results = engine.run(nodes, [rule]);

            expect(results).toHaveLength(1);
            const message = results[0]?.message ?? '';
            // Both {ruleId} occurrences should be replaced
            expect(message).toContain('TEST-MSG');
            expect(message).not.toContain('{ruleId}');
            expect(message.match(/TEST-MSG/g)?.length).toBe(2);
        });
    });
});

describe('JSON Rules - Integration', () => {
    const parser = new SchemaAwareParser();

    test('end-to-end: JSON rule file to results', () => {
        const ruleFile: JsonRuleFile = {
            version: '1.0',
            meta: {
                name: 'Test Rules',
                author: 'Test'
            },
            rules: [
                {
                    id: 'JSON-TEST-001',
                    selector: 'interface',
                    vendor: 'cisco-ios',
                    metadata: {
                        level: 'warning',
                        obu: 'Network',
                        owner: 'NetOps',
                        description: 'Interface must have description',
                        remediation: 'Add description command'
                    },
                    check: {
                        type: 'not',
                        condition: { type: 'child_exists', selector: 'description' }
                    },
                    failureMessage: 'Interface {nodeId} is missing a description'
                }
            ]
        };

        // Validate
        const validation = validateJsonRuleFile(ruleFile);
        expect(validation.valid).toBe(true);

        // Compile
        const rules = compileJsonRules(ruleFile.rules);

        // Run
        const config = `
interface GigabitEthernet1
 no description
interface GigabitEthernet2
 description Uplink to core
        `;
        const nodes = parser.parse(config);

        const engine = new RuleEngine();
        const results = engine.run(nodes, rules);

        // Check semantics: fail if NOT(child_exists(description))
        // i.e., fail if description is missing
        expect(results).toHaveLength(2);

        const gi1Result = results.find(r => r.nodeId.includes('GigabitEthernet1'));
        const gi2Result = results.find(r => r.nodeId.includes('GigabitEthernet2'));

        // Gi1 has no description → NOT(false) = true → failure condition met → passed = false
        expect(gi1Result?.passed).toBe(false);
        // Gi2 has description → NOT(true) = false → failure condition NOT met → passed = true
        expect(gi2Result?.passed).toBe(true);
    });
});
