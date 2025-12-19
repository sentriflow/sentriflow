// packages/core/src/json-rules/types.ts

/**
 * JSON Rule Types
 *
 * Provides a JSON-serializable rule format that allows third-party customers
 * to write validation rules without TypeScript knowledge. Supports full access
 * to helper functions via the `helper` check type.
 */

import type { RuleVendor, RuleMetadata } from '../types/IRule';
import { MAX_METADATA_LENGTH } from '../constants';

/**
 * Argument value for helper function invocation.
 * Can be a literal value or a reference to node properties.
 */
export type JsonArgValue =
    | string
    | number
    | boolean
    | null
    | { $ref: 'node' | 'node.id' | 'node.type' | 'node.children' | 'node.params' | 'node.rawText' };

/**
 * JSON-serializable check conditions for rule evaluation.
 * Extends DeclarativeCheck with helper function invocation and expression support.
 */
export type JsonCheck =
    // Pattern matching on node.id
    | { type: 'match'; pattern: string; flags?: string }
    | { type: 'not_match'; pattern: string; flags?: string }

    // Text contains on node.id
    | { type: 'contains'; text: string }
    | { type: 'not_contains'; text: string }

    // Child node existence (case-insensitive prefix match)
    | { type: 'child_exists'; selector: string }
    | { type: 'child_not_exists'; selector: string }

    // Child text matching
    | { type: 'child_matches'; selector: string; pattern: string; flags?: string }
    | { type: 'child_contains'; selector: string; text: string }

    // Helper function invocation (NEW)
    | {
          type: 'helper';
          /** Helper name, optionally namespaced (e.g., "cisco.isTrunkPort", "hasChildCommand") */
          helper: string;
          /** Arguments to pass to the helper function */
          args?: JsonArgValue[];
          /** If true, negate the result */
          negate?: boolean;
      }

    // Simple expression evaluation (NEW)
    | {
          type: 'expr';
          /** JavaScript expression to evaluate (sandboxed) */
          expr: string;
      }

    // Logical combinators
    | { type: 'and'; conditions: JsonCheck[] }
    | { type: 'or'; conditions: JsonCheck[] }
    | { type: 'not'; condition: JsonCheck };

/**
 * A complete JSON rule definition.
 * Can be serialized to/from JSON for external rule distribution.
 */
export interface JsonRule {
    /** Unique rule identifier (e.g., "JSON-SEC-001") */
    id: string;

    /** Optional selector for node filtering (e.g., "interface", "router bgp") */
    selector?: string;

    /** Optional vendor(s) this rule applies to */
    vendor?: RuleVendor | RuleVendor[];

    /** Rule metadata including severity, description, remediation */
    metadata: RuleMetadata;

    /** The check condition to evaluate */
    check: JsonCheck;

    /**
     * Optional: Custom message template for failures.
     * Supports placeholders: {nodeId}, {ruleId}
     */
    failureMessage?: string;

    /**
     * Optional: Custom message template for passes.
     * Supports placeholders: {nodeId}, {ruleId}
     */
    successMessage?: string;
}

/**
 * A JSON rule file containing multiple rules with optional metadata.
 */
export interface JsonRuleFile {
    /** Schema version for forward compatibility */
    version: '1.0';

    /** Optional metadata about this rule file */
    meta?: {
        /** Name of this rule collection */
        name?: string;
        /** Description of the rule collection */
        description?: string;
        /** Author or organization */
        author?: string;
        /** License for the rules */
        license?: string;
    };

    /** Array of JSON rules */
    rules: JsonRule[];
}

/**
 * Type guard to check if an object is a valid JsonArgValue.
 */
export function isJsonArgValue(obj: unknown): obj is JsonArgValue {
    if (obj === null) return true;
    if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
        return true;
    }
    if (typeof obj === 'object' && '$ref' in obj) {
        const ref = (obj as { $ref: unknown }).$ref;
        return (
            ref === 'node' ||
            ref === 'node.id' ||
            ref === 'node.type' ||
            ref === 'node.children' ||
            ref === 'node.params' ||
            ref === 'node.rawText'
        );
    }
    return false;
}

/**
 * Type guard to check if an object is a valid JsonCheck.
 */
export function isJsonCheck(obj: unknown): obj is JsonCheck {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }

    const check = obj as Record<string, unknown>;

    switch (check.type) {
        case 'match':
        case 'not_match':
            return (
                typeof check.pattern === 'string' &&
                (check.flags === undefined || typeof check.flags === 'string')
            );

        case 'contains':
        case 'not_contains':
            return typeof check.text === 'string';

        case 'child_exists':
        case 'child_not_exists':
            return typeof check.selector === 'string';

        case 'child_matches':
            return (
                typeof check.selector === 'string' &&
                typeof check.pattern === 'string' &&
                (check.flags === undefined || typeof check.flags === 'string')
            );

        case 'child_contains':
            return typeof check.selector === 'string' && typeof check.text === 'string';

        case 'helper':
            if (typeof check.helper !== 'string') return false;
            if (check.args !== undefined) {
                if (!Array.isArray(check.args)) return false;
                if (!check.args.every(isJsonArgValue)) return false;
            }
            if (check.negate !== undefined && typeof check.negate !== 'boolean') return false;
            return true;

        case 'expr':
            return typeof check.expr === 'string';

        case 'and':
        case 'or':
            return Array.isArray(check.conditions) && check.conditions.every(isJsonCheck);

        case 'not':
            return isJsonCheck(check.condition);

        default:
            return false;
    }
}

/**
 * Type guard to check if an object is a valid JsonRule.
 */
export function isJsonRule(obj: unknown): obj is JsonRule {
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
    if (typeof metadata.obu !== 'string' || metadata.obu.length > MAX_METADATA_LENGTH) {
        return false;
    }
    if (typeof metadata.owner !== 'string' || metadata.owner.length > MAX_METADATA_LENGTH) {
        return false;
    }
    // Validate optional string fields length
    if (metadata.description !== undefined) {
        if (typeof metadata.description !== 'string' || metadata.description.length > MAX_METADATA_LENGTH) {
            return false;
        }
    }
    if (metadata.remediation !== undefined) {
        if (typeof metadata.remediation !== 'string' || metadata.remediation.length > MAX_METADATA_LENGTH) {
            return false;
        }
    }

    // Check the check condition
    if (!isJsonCheck(rule.check)) {
        return false;
    }

    // Check optional message templates
    if (rule.failureMessage !== undefined && typeof rule.failureMessage !== 'string') {
        return false;
    }
    if (rule.successMessage !== undefined && typeof rule.successMessage !== 'string') {
        return false;
    }

    return true;
}

/**
 * Type guard to check if an object is a valid JsonRuleFile.
 */
export function isJsonRuleFile(obj: unknown): obj is JsonRuleFile {
    if (typeof obj !== 'object' || obj === null) {
        return false;
    }

    const file = obj as Record<string, unknown>;

    // Check version
    if (file.version !== '1.0') {
        return false;
    }

    // Check optional meta
    if (file.meta !== undefined) {
        if (typeof file.meta !== 'object' || file.meta === null) {
            return false;
        }
        const meta = file.meta as Record<string, unknown>;
        if (meta.name !== undefined && typeof meta.name !== 'string') return false;
        if (meta.description !== undefined && typeof meta.description !== 'string') return false;
        if (meta.author !== undefined && typeof meta.author !== 'string') return false;
        if (meta.license !== undefined && typeof meta.license !== 'string') return false;
    }

    // Check rules array
    if (!Array.isArray(file.rules)) {
        return false;
    }

    return file.rules.every(isJsonRule);
}
