// packages/core/src/json-rules/ExpressionEvaluator.ts

/**
 * Sandboxed Expression Evaluator for JSON Rules
 *
 * Evaluates simple JavaScript expressions in a secure sandbox.
 * Provides access to helper functions while blocking dangerous operations.
 */

import { createContext, Script, type Context as VMContext } from 'vm';
import type { ConfigNode } from '../types/ConfigNode';
import { type HelperRegistry, getHelperRegistry, VENDOR_NAMESPACES } from './HelperRegistry';

/** Maximum expression length to prevent DoS */
const MAX_EXPR_LENGTH = 1000;

/** Timeout for expression evaluation in milliseconds */
const EXPR_TIMEOUT_MS = 50;

/** Patterns that are blocked for security */
const BLOCKED_PATTERNS = [
    'require',
    'import',
    'eval',
    'Function',
    'process',
    'global',
    'globalThis',
    'window',
    '__proto__',
    'constructor',
    'prototype',
    'Reflect',
    'Proxy',
    'module',
    'exports',
    'Buffer',
    'setTimeout',
    'setInterval',
    'setImmediate',
    'clearTimeout',
    'clearInterval',
    'clearImmediate',
    'fetch',
    'XMLHttpRequest',
    'WebSocket',
    // Additional security patterns
    'arguments',  // Special object in functions
    'this',       // Context access
    'with',       // Scope manipulation
];

/**
 * Pre-compiled script cache for performance.
 */
const scriptCache = new Map<string, Script>();

/**
 * Freeze an object deeply to prevent modification.
 */
function deepFreeze<T>(obj: T): T {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }

    Object.freeze(obj);

    for (const key of Object.keys(obj)) {
        const value = (obj as Record<string, unknown>)[key];
        if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
            deepFreeze(value);
        }
    }

    return obj;
}

/**
 * Create a frozen, safe copy of a ConfigNode for sandbox use.
 * Only exposes safe properties, no methods or circular references.
 */
function createSafeNode(node: ConfigNode): Readonly<{
    id: string;
    type: string;
    rawText: string;
    params: readonly string[];
    children: readonly ReturnType<typeof createSafeNode>[];
}> {
    return deepFreeze({
        id: node.id,
        type: node.type,
        rawText: node.rawText,
        params: [...node.params],
        children: node.children.map(createSafeNode),
    });
}

/**
 * Validate an expression for security.
 * Returns true if the expression is safe to evaluate.
 */
export function isValidExpression(expr: string): boolean {
    // Check length
    if (expr.length > MAX_EXPR_LENGTH) {
        return false;
    }

    // Check for blocked patterns
    const exprLower = expr.toLowerCase();
    for (const pattern of BLOCKED_PATTERNS) {
        if (exprLower.includes(pattern.toLowerCase())) {
            return false;
        }
    }

    // Block template literals with expressions
    if (expr.includes('${')) {
        return false;
    }

    // Block assignment operators
    if (/[^=!<>]=[^=]/.test(expr)) {
        return false;
    }

    return true;
}

/**
 * Expression Evaluator class for sandboxed expression evaluation.
 * Provides pre-compilation and caching for performance.
 */
export class ExpressionEvaluator {
    private readonly sandbox: VMContext;
    private readonly registry: HelperRegistry;

    constructor(registry?: HelperRegistry) {
        this.registry = registry ?? getHelperRegistry();
        this.sandbox = this.createSandbox();
    }

    /**
     * Create a sandboxed VM context with helpers available.
     */
    private createSandbox(): VMContext {
        // Start with safe primitives
        const sandboxObj: Record<string, unknown> = {
            // Safe primitives
            true: true,
            false: false,
            undefined: undefined,
            null: null,
            NaN: NaN,
            Infinity: Infinity,

            // Safe built-in constructors (frozen)
            Boolean: Object.freeze(Boolean),
            Number: Object.freeze(Number),
            String: Object.freeze(String),
            Array: Object.freeze(Array),
            Object: Object.freeze(Object),
            RegExp: Object.freeze(RegExp),
            JSON: Object.freeze(JSON),
            Math: Object.freeze(Math),

            // Node placeholder (set per evaluation)
            node: null,
        };

        // Add common helpers at top level
        for (const [key, value] of Object.entries(this.registry)) {
            if (typeof value === 'function') {
                sandboxObj[key] = value;
            }
        }

        // Add vendor namespaces
        for (const namespace of VENDOR_NAMESPACES) {
            const vendorHelpers = this.registry[namespace];
            if (vendorHelpers && typeof vendorHelpers === 'object') {
                sandboxObj[namespace] = Object.freeze({ ...vendorHelpers });
            }
        }

        return createContext(Object.freeze(sandboxObj));
    }

    /**
     * Pre-compile an expression for later evaluation.
     * Call this at rule load time for performance.
     *
     * @param expr The expression to compile
     * @returns true if compilation succeeded
     */
    precompile(expr: string): boolean {
        if (!isValidExpression(expr)) {
            return false;
        }

        if (scriptCache.has(expr)) {
            return true;
        }

        try {
            const script = new Script(`(${expr})`, {
                filename: 'expr.js',
            });
            scriptCache.set(expr, script);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Evaluate an expression against a node.
     *
     * @param expr The expression to evaluate
     * @param node The ConfigNode to evaluate against
     * @returns The evaluation result as a boolean
     */
    evaluate(expr: string, node: ConfigNode): boolean {
        // Validate expression
        if (!isValidExpression(expr)) {
            return false;
        }

        // Get or compile script
        let script = scriptCache.get(expr);
        if (!script) {
            try {
                script = new Script(`(${expr})`, {
                    filename: 'expr.js',
                });
                scriptCache.set(expr, script);
            } catch {
                return false; // Compilation error
            }
        }

        // Set node in sandbox (create a new context each time for isolation)
        const evalContext = createContext({
            ...this.sandbox,
            node: createSafeNode(node),
        });

        try {
            const result = script.runInContext(evalContext, {
                timeout: EXPR_TIMEOUT_MS,
            });
            return Boolean(result);
        } catch {
            return false; // Runtime error or timeout
        }
    }

    /**
     * Clear the script cache (useful for testing).
     */
    static clearCache(): void {
        scriptCache.clear();
    }
}

/**
 * Create a new ExpressionEvaluator instance.
 * The evaluator can be reused across multiple rule evaluations.
 */
export function createExpressionEvaluator(registry?: HelperRegistry): ExpressionEvaluator {
    return new ExpressionEvaluator(registry);
}

// Default singleton evaluator for convenience
let defaultEvaluator: ExpressionEvaluator | null = null;

/**
 * Get the default expression evaluator (singleton).
 */
export function getExpressionEvaluator(): ExpressionEvaluator {
    if (!defaultEvaluator) {
        defaultEvaluator = new ExpressionEvaluator();
    }
    return defaultEvaluator;
}

/**
 * Clear the default evaluator (useful for testing).
 */
export function clearExpressionEvaluator(): void {
    defaultEvaluator = null;
    ExpressionEvaluator.clearCache();
}
