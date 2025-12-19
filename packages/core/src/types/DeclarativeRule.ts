// packages/core/src/types/DeclarativeRule.ts

/**
 * SEC-001: Declarative Rule Types
 *
 * Provides a declarative rule format that can be evaluated without
 * executing arbitrary JavaScript code. This is the preferred format
 * for external/untrusted rules as it executes natively with zero overhead.
 */

import type { RuleVendor, RuleMetadata } from './IRule';

/**
 * Declarative check conditions that can be evaluated safely.
 * These map to common pattern matching and node inspection operations.
 */
export type DeclarativeCheck =
    // Pattern matching
    | { type: 'match'; pattern: string; flags?: string }
    | { type: 'not_match'; pattern: string; flags?: string }

    // Text contains
    | { type: 'contains'; text: string }
    | { type: 'not_contains'; text: string }

    // Child node existence
    | { type: 'child_exists'; selector: string }
    | { type: 'child_not_exists'; selector: string }

    // Child text matching
    | { type: 'child_matches'; selector: string; pattern: string; flags?: string }
    | { type: 'child_contains'; selector: string; text: string }

    // Logical combinators
    | { type: 'and'; conditions: DeclarativeCheck[] }
    | { type: 'or'; conditions: DeclarativeCheck[] }
    | { type: 'not'; condition: DeclarativeCheck }

    // SEC-001: Custom code (sandboxed execution)
    // Use sparingly - only when declarative checks are insufficient
    | { type: 'custom'; code: string };

/**
 * A declarative rule definition that can be safely evaluated.
 *
 * Unlike IRule with its JavaScript check function, DeclarativeRule
 * uses a JSON-serializable check condition that can be evaluated
 * without running arbitrary code.
 */
export interface DeclarativeRule {
    /** Unique rule identifier */
    id: string;

    /** Optional selector for node filtering */
    selector?: string;

    /** Optional vendor(s) this rule applies to */
    vendor?: RuleVendor | RuleVendor[];

    /** Rule metadata */
    metadata: RuleMetadata;

    /** The declarative check condition */
    check: DeclarativeCheck;
}

/**
 * Type guard to check if an object is a valid DeclarativeCheck.
 */
export function isDeclarativeCheck(obj: unknown): obj is DeclarativeCheck {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }

    const check = obj as Record<string, unknown>;

    switch (check.type) {
        case 'match':
        case 'not_match':
            return typeof check.pattern === 'string' &&
                (check.flags === undefined || typeof check.flags === 'string');

        case 'contains':
        case 'not_contains':
            return typeof check.text === 'string';

        case 'child_exists':
        case 'child_not_exists':
            return typeof check.selector === 'string';

        case 'child_matches':
            return typeof check.selector === 'string' &&
                typeof check.pattern === 'string' &&
                (check.flags === undefined || typeof check.flags === 'string');

        case 'child_contains':
            return typeof check.selector === 'string' &&
                typeof check.text === 'string';

        case 'and':
        case 'or':
            return Array.isArray(check.conditions) &&
                check.conditions.every(isDeclarativeCheck);

        case 'not':
            return isDeclarativeCheck(check.condition);

        case 'custom':
            return typeof check.code === 'string';

        default:
            return false;
    }
}

/**
 * Type guard to check if an object is a valid DeclarativeRule.
 */
export function isDeclarativeRule(obj: unknown): obj is DeclarativeRule {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }

    const rule = obj as Record<string, unknown>;

    // Check required fields
    if (typeof rule.id !== 'string' || rule.id.length === 0) {
        return false;
    }

    // Check optional selector
    if (rule.selector !== undefined && typeof rule.selector !== 'string') {
        return false;
    }

    // Check metadata
    if (typeof rule.metadata !== 'object' || rule.metadata === null) {
        return false;
    }

    const metadata = rule.metadata as Record<string, unknown>;
    if (!['error', 'warning', 'info'].includes(metadata.level as string)) {
        return false;
    }
    if (typeof metadata.obu !== 'string') {
        return false;
    }
    if (typeof metadata.owner !== 'string') {
        return false;
    }

    // Check declarative check
    if (!isDeclarativeCheck(rule.check)) {
        return false;
    }

    return true;
}
