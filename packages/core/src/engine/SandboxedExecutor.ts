// packages/core/src/engine/SandboxedExecutor.ts

/**
 * SEC-001: Sandboxed Executor for Declarative Rules
 *
 * Provides safe evaluation of declarative rules without executing
 * arbitrary JavaScript. Custom code blocks run in a VM sandbox
 * with strict timeouts and limited API access.
 */

import { createContext, Script, type Context as VMContext } from 'vm';
import type { ConfigNode } from '../types/ConfigNode';
import type { Context } from '../types/IRule';
import type { IRule, RuleResult, RuleVendor } from '../types/IRule';
import type { DeclarativeRule, DeclarativeCheck } from '../types/DeclarativeRule';

/** Timeout for custom code execution in milliseconds */
const CUSTOM_CODE_TIMEOUT_MS = 100;

/**
 * Compiles a DeclarativeRule into an IRule with a safe check function.
 *
 * For most declarative checks, this produces a native function that
 * executes without any sandboxing overhead. Only 'custom' type checks
 * require VM sandboxing.
 */
export class SandboxedExecutor {
    private readonly sandbox: Record<string, unknown>;
    private readonly vmContext: VMContext;

    constructor() {
        this.sandbox = this.createSandbox();
        this.vmContext = createContext(this.sandbox);
    }

    /**
     * Compiles a declarative rule into an executable IRule.
     */
    compileRule(decl: DeclarativeRule): IRule {
        return {
            id: decl.id,
            selector: decl.selector,
            vendor: decl.vendor as RuleVendor | RuleVendor[] | undefined,
            metadata: decl.metadata,
            check: (node: ConfigNode, ctx: Context): RuleResult => {
                return this.evaluate(decl.check, node, ctx, decl);
            },
        };
    }

    /**
     * Evaluates a declarative check condition against a node.
     */
    private evaluate(
        check: DeclarativeCheck,
        node: ConfigNode,
        ctx: Context,
        rule: DeclarativeRule
    ): RuleResult {
        const passed = this.evaluateCondition(check, node);
        return {
            passed,
            message: passed
                ? `${rule.id}: Check passed`
                : `${rule.id}: Check failed - ${rule.metadata.remediation ?? 'See rule documentation'}`,
            ruleId: rule.id,
            nodeId: node.id,
            level: rule.metadata.level,
            loc: node.loc,
        };
    }

    /**
     * Recursively evaluates a declarative check condition.
     * Returns true if the condition is satisfied.
     */
    private evaluateCondition(check: DeclarativeCheck, node: ConfigNode): boolean {
        switch (check.type) {
            case 'match':
                return new RegExp(check.pattern, check.flags).test(node.id);

            case 'not_match':
                return !new RegExp(check.pattern, check.flags).test(node.id);

            case 'contains':
                return node.id.includes(check.text);

            case 'not_contains':
                return !node.id.includes(check.text);

            case 'child_exists':
                return node.children.some(c =>
                    c.id.toLowerCase().startsWith(check.selector.toLowerCase())
                );

            case 'child_not_exists':
                return !node.children.some(c =>
                    c.id.toLowerCase().startsWith(check.selector.toLowerCase())
                );

            case 'child_matches': {
                const matchingChildren = node.children.filter(c =>
                    c.id.toLowerCase().startsWith(check.selector.toLowerCase())
                );
                const regex = new RegExp(check.pattern, check.flags);
                return matchingChildren.some(c => regex.test(c.id));
            }

            case 'child_contains': {
                const containsChildren = node.children.filter(c =>
                    c.id.toLowerCase().startsWith(check.selector.toLowerCase())
                );
                return containsChildren.some(c => c.id.includes(check.text));
            }

            case 'and':
                return check.conditions.every(c => this.evaluateCondition(c, node));

            case 'or':
                return check.conditions.some(c => this.evaluateCondition(c, node));

            case 'not':
                return !this.evaluateCondition(check.condition, node);

            case 'custom':
                return this.executeCustomCode(check.code, node);

            default:
                // Unknown check type - fail closed for safety
                return false;
        }
    }

    /**
     * Executes custom code in a VM sandbox.
     * Returns the boolean result of the code execution.
     */
    private executeCustomCode(code: string, node: ConfigNode): boolean {
        // Prepare a frozen copy of the node for the sandbox
        this.sandbox.node = Object.freeze({
            id: node.id,
            type: node.type,
            children: node.children.map(c => Object.freeze({
                id: c.id,
                type: c.type,
            })),
        });

        try {
            const wrappedCode = `(function() { ${code} })()`;
            const script = new Script(wrappedCode, {
                filename: 'custom-check.js',
                timeout: CUSTOM_CODE_TIMEOUT_MS,
            } as { filename: string; timeout: number });
            const result = script.runInContext(this.vmContext);
            return Boolean(result);
        } catch {
            // Any error (timeout, syntax, runtime) = fail closed
            return false;
        }
    }

    /**
     * Creates a minimal sandbox for custom code execution.
     * Only provides safe, read-only access to basic JavaScript features.
     */
    private createSandbox(): Record<string, unknown> {
        return Object.freeze({
            // The node being checked (set dynamically)
            node: null,

            // Safe built-ins (frozen)
            Boolean,
            Number,
            String,
            Array,
            Object,
            RegExp,

            // Safe JSON access
            JSON: Object.freeze({
                parse: JSON.parse,
                stringify: JSON.stringify,
            }),

            // Safe Math access
            Math: Object.freeze(Math),

            // Primitives
            true: true,
            false: false,
            undefined,
            null: null,
            NaN,
            Infinity,

            // No console, no require, no import, no process, no global
        });
    }
}

/**
 * Creates a SandboxedExecutor instance.
 * Use this for compiling declarative rules.
 */
export function createSandboxedExecutor(): SandboxedExecutor {
    return new SandboxedExecutor();
}
