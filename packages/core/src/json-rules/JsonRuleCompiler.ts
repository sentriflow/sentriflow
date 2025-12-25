// packages/core/src/json-rules/JsonRuleCompiler.ts

/**
 * JSON Rule Compiler
 *
 * Compiles JSON rule definitions into executable IRule objects.
 * Supports all check types including helper invocation and expression evaluation.
 */

import type { ConfigNode } from '../types/ConfigNode';
import type { IRule, Context, RuleResult } from '../types/IRule';
import type { JsonRule, JsonCheck, JsonArgValue } from './types';
import {
    type HelperRegistry,
    type HelperFunction,
    getHelperRegistry,
    resolveHelper,
} from './HelperRegistry';
import { ExpressionEvaluator, createExpressionEvaluator } from './ExpressionEvaluator';

/**
 * Options for the JSON rule compiler.
 */
export interface JsonRuleCompilerOptions {
    /** Custom helper registry (uses default if not provided) */
    registry?: HelperRegistry;
    /** Pre-compile expressions at rule load time (default: true) */
    precompileExpressions?: boolean;
}

/**
 * Compiles JSON rules into executable IRule objects.
 */
export class JsonRuleCompiler {
    private readonly registry: HelperRegistry;
    private readonly evaluator: ExpressionEvaluator;
    private readonly precompileExpressions: boolean;
    private readonly regexCache: Map<string, RegExp> = new Map();

    constructor(options: JsonRuleCompilerOptions = {}) {
        this.registry = options.registry ?? getHelperRegistry();
        this.evaluator = createExpressionEvaluator(this.registry);
        this.precompileExpressions = options.precompileExpressions ?? true;
    }

    /**
     * Get a cached regex or create and cache a new one.
     */
    private getRegex(pattern: string, flags?: string): RegExp {
        const key = `${pattern}::${flags ?? ''}`;
        let regex = this.regexCache.get(key);
        if (!regex) {
            regex = new RegExp(pattern, flags);
            this.regexCache.set(key, regex);
        }
        return regex;
    }

    /**
     * Format a message template by replacing placeholders.
     */
    private formatMessage(template: string, nodeId: string, ruleId: string): string {
        return template.replaceAll('{nodeId}', nodeId).replaceAll('{ruleId}', ruleId);
    }

    /**
     * Get children matching a selector (case-insensitive prefix match).
     */
    private getMatchingChildren(node: ConfigNode, selector: string): ConfigNode[] {
        const selectorLower = selector.toLowerCase();
        return node.children.filter((child) =>
            child.id.toLowerCase().startsWith(selectorLower)
        );
    }

    /**
     * Compile a JSON rule into an executable IRule.
     *
     * @param jsonRule The JSON rule definition
     * @returns An executable IRule object
     */
    compile(jsonRule: JsonRule): IRule {
        // Pre-compile expressions if enabled
        if (this.precompileExpressions) {
            this.precompileCheckExpressions(jsonRule.check);
        }

        return {
            id: jsonRule.id,
            selector: jsonRule.selector,
            vendor: jsonRule.vendor,
            category: jsonRule.category,
            metadata: jsonRule.metadata,
            check: (node: ConfigNode, _ctx: Context): RuleResult => {
                // Check defines failure conditions - invert to get pass status
                const passed = !this.evaluateCheck(jsonRule.check, node);

                // Format message with placeholders
                const template = passed
                    ? (jsonRule.successMessage ?? `${jsonRule.id}: Check passed`)
                    : (jsonRule.failureMessage ?? jsonRule.metadata.description ?? `${jsonRule.id}: Check failed`);
                const message = this.formatMessage(template, node.id, jsonRule.id);

                return {
                    passed,
                    message,
                    ruleId: jsonRule.id,
                    nodeId: node.id,
                    level: passed ? 'info' : jsonRule.metadata.level,
                    loc: node.loc,
                    remediation: passed ? undefined : jsonRule.metadata.remediation,
                };
            },
        };
    }

    /**
     * Compile multiple JSON rules.
     *
     * @param jsonRules Array of JSON rule definitions
     * @returns Array of executable IRule objects
     */
    compileAll(jsonRules: JsonRule[]): IRule[] {
        return jsonRules.map((rule) => this.compile(rule));
    }

    /**
     * Pre-compile all expressions in a check tree.
     */
    private precompileCheckExpressions(check: JsonCheck): void {
        switch (check.type) {
            case 'expr':
                this.evaluator.precompile(check.expr);
                break;
            case 'and':
            case 'or':
                for (const condition of check.conditions) {
                    this.precompileCheckExpressions(condition);
                }
                break;
            case 'not':
                this.precompileCheckExpressions(check.condition);
                break;
            // Other types don't have expressions to pre-compile
        }
    }

    /**
     * Evaluate a check condition against a node.
     */
    private evaluateCheck(check: JsonCheck, node: ConfigNode): boolean {
        switch (check.type) {
            case 'match':
                return this.evaluateMatch(check.pattern, check.flags, node);

            case 'not_match':
                return !this.evaluateMatch(check.pattern, check.flags, node);

            case 'contains':
                return node.id.toLowerCase().includes(check.text.toLowerCase());

            case 'not_contains':
                return !node.id.toLowerCase().includes(check.text.toLowerCase());

            case 'child_exists':
                return this.hasMatchingChild(node, check.selector);

            case 'child_not_exists':
                return !this.hasMatchingChild(node, check.selector);

            case 'child_matches':
                return this.childMatches(node, check.selector, check.pattern, check.flags);

            case 'child_contains':
                return this.childContains(node, check.selector, check.text);

            case 'helper':
                return this.evaluateHelper(check, node);

            case 'expr':
                return this.evaluator.evaluate(check.expr, node);

            case 'and':
                return check.conditions.every((c) => this.evaluateCheck(c, node));

            case 'or':
                return check.conditions.some((c) => this.evaluateCheck(c, node));

            case 'not':
                return !this.evaluateCheck(check.condition, node);

            default:
                // Unknown check type - fail closed
                return false;
        }
    }

    /**
     * Evaluate a regex match on node.id.
     */
    private evaluateMatch(pattern: string, flags: string | undefined, node: ConfigNode): boolean {
        try {
            const regex = this.getRegex(pattern, flags);
            return regex.test(node.id);
        } catch {
            return false; // Invalid regex
        }
    }

    /**
     * Check if node has a child matching the selector (case-insensitive prefix).
     */
    private hasMatchingChild(node: ConfigNode, selector: string): boolean {
        return this.getMatchingChildren(node, selector).length > 0;
    }

    /**
     * Check if any matching child's id matches the pattern.
     */
    private childMatches(
        node: ConfigNode,
        selector: string,
        pattern: string,
        flags?: string
    ): boolean {
        const matchingChildren = this.getMatchingChildren(node, selector);
        try {
            const regex = this.getRegex(pattern, flags);
            return matchingChildren.some((child) => regex.test(child.id));
        } catch {
            return false; // Invalid regex
        }
    }

    /**
     * Check if any matching child's id contains the text.
     */
    private childContains(node: ConfigNode, selector: string, text: string): boolean {
        const textLower = text.toLowerCase();
        const matchingChildren = this.getMatchingChildren(node, selector);
        return matchingChildren.some((child) =>
            child.id.toLowerCase().includes(textLower)
        );
    }

    /**
     * Evaluate a helper function check.
     */
    private evaluateHelper(
        check: { type: 'helper'; helper: string; args?: JsonArgValue[]; negate?: boolean },
        node: ConfigNode
    ): boolean {
        const helperFn = resolveHelper(this.registry, check.helper);
        if (!helperFn) {
            // Unknown helper - fail closed
            return false;
        }

        // Resolve arguments
        const args = (check.args ?? []).map((arg) => this.resolveArg(arg, node));

        try {
            const result = (helperFn as HelperFunction)(...args);
            const boolResult = Boolean(result);
            return check.negate ? !boolResult : boolResult;
        } catch {
            return false; // Helper execution error
        }
    }

    /**
     * Resolve an argument value, handling $ref references.
     */
    private resolveArg(arg: JsonArgValue, node: ConfigNode): unknown {
        if (arg === null) return null;
        if (typeof arg !== 'object') return arg;

        if ('$ref' in arg) {
            switch (arg.$ref) {
                case 'node':
                    return node;
                case 'node.id':
                    return node.id;
                case 'node.type':
                    return node.type;
                case 'node.children':
                    return node.children;
                case 'node.params':
                    return node.params;
                case 'node.rawText':
                    return node.rawText;
                default:
                    return undefined;
            }
        }

        return arg;
    }
}

/**
 * Create a new JSON rule compiler.
 */
export function createJsonRuleCompiler(options?: JsonRuleCompilerOptions): JsonRuleCompiler {
    return new JsonRuleCompiler(options);
}

// Default singleton compiler for convenience
let defaultCompiler: JsonRuleCompiler | null = null;

/**
 * Get the default JSON rule compiler (singleton).
 */
export function getJsonRuleCompiler(): JsonRuleCompiler {
    if (!defaultCompiler) {
        defaultCompiler = new JsonRuleCompiler();
    }
    return defaultCompiler;
}

/**
 * Compile a JSON rule to IRule using the default compiler.
 */
export function compileJsonRule(jsonRule: JsonRule): IRule {
    return getJsonRuleCompiler().compile(jsonRule);
}

/**
 * Compile multiple JSON rules to IRule array using the default compiler.
 */
export function compileJsonRules(jsonRules: JsonRule[]): IRule[] {
    return getJsonRuleCompiler().compileAll(jsonRules);
}

/**
 * Clear the default compiler (useful for testing).
 */
export function clearJsonRuleCompiler(): void {
    defaultCompiler = null;
}
