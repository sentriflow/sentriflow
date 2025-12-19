// packages/core/src/json-rules/JsonRuleValidator.ts

/**
 * JSON Rule Validator
 *
 * Validates JSON rule files for both structural correctness and semantic validity.
 * Provides detailed error messages for debugging rule authoring issues.
 */

import { isValidVendorId, VALID_VENDOR_IDS, type RuleVendor } from '../types/IRule';
import { RULE_ID_PATTERN, MAX_PATTERN_LENGTH, REDOS_PATTERN } from '../constants';
import { isJsonRule, isJsonRuleFile, isJsonCheck, type JsonRule, type JsonRuleFile, type JsonCheck } from './types';
import { getHelperRegistry, hasHelper, type HelperRegistry } from './HelperRegistry';
import { isValidExpression } from './ExpressionEvaluator';

/**
 * A validation error with path and message.
 */
export interface ValidationError {
    /** JSON path to the error location (e.g., "/rules/0/check/helper") */
    path: string;
    /** Human-readable error message */
    message: string;
    /** Error severity */
    severity: 'error' | 'warning';
}

/**
 * Result of validation.
 */
export interface ValidationResult {
    /** Whether the validation passed (no errors) */
    valid: boolean;
    /** Array of validation errors */
    errors: ValidationError[];
    /** Array of validation warnings */
    warnings: ValidationError[];
}

/**
 * Options for validation.
 */
export interface ValidationOptions {
    /** Custom helper registry for validating helper names */
    registry?: HelperRegistry;
    /** Whether to validate helper names exist (default: true) */
    validateHelpers?: boolean;
    /** Whether to validate expressions are safe (default: true) */
    validateExpressions?: boolean;
    /** Whether to allow unknown vendors (default: false) */
    allowUnknownVendors?: boolean;
}

/**
 * Validate a JSON rule file.
 *
 * @param data The data to validate
 * @param options Validation options
 * @returns Validation result with errors and warnings
 */
export function validateJsonRuleFile(
    data: unknown,
    options: ValidationOptions = {}
): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];
    const registry = options.registry ?? getHelperRegistry();
    const validateHelpers = options.validateHelpers ?? true;
    const validateExpressions = options.validateExpressions ?? true;
    const allowUnknownVendors = options.allowUnknownVendors ?? false;

    // Phase 1: Structural validation using type guards
    if (!isJsonRuleFile(data)) {
        errors.push({
            path: '',
            message: 'Invalid JSON rule file structure',
            severity: 'error',
        });

        // Try to provide more specific errors
        if (typeof data !== 'object' || data === null) {
            errors.push({
                path: '',
                message: 'Expected an object',
                severity: 'error',
            });
        } else {
            const obj = data as Record<string, unknown>;

            if (obj.version !== '1.0') {
                errors.push({
                    path: '/version',
                    message: `Invalid version: expected "1.0", got "${String(obj.version)}"`,
                    severity: 'error',
                });
            }

            if (!Array.isArray(obj.rules)) {
                errors.push({
                    path: '/rules',
                    message: 'Expected "rules" to be an array',
                    severity: 'error',
                });
            }
        }

        return { valid: false, errors, warnings };
    }

    const file = data as JsonRuleFile;

    // Phase 2: Validate each rule
    for (let i = 0; i < file.rules.length; i++) {
        const rule = file.rules[i];
        if (!rule) continue;
        const rulePath = `/rules/${i}`;

        validateRule(rule, rulePath, {
            errors,
            warnings,
            registry,
            validateHelpers,
            validateExpressions,
            allowUnknownVendors,
        });
    }

    // Phase 3: Check for duplicate rule IDs
    const ruleIds = new Set<string>();
    for (let i = 0; i < file.rules.length; i++) {
        const rule = file.rules[i];
        if (!rule) continue;

        if (ruleIds.has(rule.id)) {
            errors.push({
                path: `/rules/${i}/id`,
                message: `Duplicate rule ID: "${rule.id}"`,
                severity: 'error',
            });
        }
        ruleIds.add(rule.id);
    }

    return {
        valid: errors.length === 0,
        errors,
        warnings,
    };
}

/**
 * Validate a single JSON rule.
 */
export function validateJsonRule(
    data: unknown,
    options: ValidationOptions = {}
): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];
    const registry = options.registry ?? getHelperRegistry();
    const validateHelpers = options.validateHelpers ?? true;
    const validateExpressions = options.validateExpressions ?? true;
    const allowUnknownVendors = options.allowUnknownVendors ?? false;

    if (!isJsonRule(data)) {
        errors.push({
            path: '',
            message: 'Invalid JSON rule structure',
            severity: 'error',
        });
        return { valid: false, errors, warnings };
    }

    validateRule(data as JsonRule, '', {
        errors,
        warnings,
        registry,
        validateHelpers,
        validateExpressions,
        allowUnknownVendors,
    });

    return {
        valid: errors.length === 0,
        errors,
        warnings,
    };
}

interface ValidationContext {
    errors: ValidationError[];
    warnings: ValidationError[];
    registry: HelperRegistry;
    validateHelpers: boolean;
    validateExpressions: boolean;
    allowUnknownVendors: boolean;
}

/**
 * Validate a rule and add errors/warnings to context.
 */
function validateRule(rule: JsonRule, path: string, ctx: ValidationContext): void {
    // Validate rule ID format
    if (!RULE_ID_PATTERN.test(rule.id)) {
        ctx.errors.push({
            path: `${path}/id`,
            message: `Invalid rule ID format: "${rule.id}". Must match pattern: ^[A-Z][A-Z0-9_-]{2,49}$`,
            severity: 'error',
        });
    }

    // Validate vendor(s)
    if (rule.vendor !== undefined) {
        const vendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
        for (const vendor of vendors) {
            if (!ctx.allowUnknownVendors && !isValidVendorId(vendor)) {
                ctx.errors.push({
                    path: `${path}/vendor`,
                    message: `Unknown vendor: "${vendor}". Valid vendors: ${VALID_VENDOR_IDS.join(', ')}`,
                    severity: 'error',
                });
            }
        }
    }

    // Validate metadata
    if (!rule.metadata.description) {
        ctx.warnings.push({
            path: `${path}/metadata/description`,
            message: 'Rule should have a description',
            severity: 'warning',
        });
    }

    if (!rule.metadata.remediation) {
        ctx.warnings.push({
            path: `${path}/metadata/remediation`,
            message: 'Rule should have remediation guidance',
            severity: 'warning',
        });
    }

    // Validate check
    validateCheck(rule.check, `${path}/check`, ctx);
}

/**
 * Validate a check condition recursively.
 */
function validateCheck(check: JsonCheck, path: string, ctx: ValidationContext): void {
    switch (check.type) {
        case 'match':
        case 'not_match':
            validateRegex(check.pattern, check.flags, `${path}/pattern`, ctx);
            break;

        case 'child_matches':
            validateRegex(check.pattern, check.flags, `${path}/pattern`, ctx);
            break;

        case 'helper':
            if (ctx.validateHelpers && !hasHelper(ctx.registry, check.helper)) {
                ctx.errors.push({
                    path: `${path}/helper`,
                    message: `Unknown helper: "${check.helper}"`,
                    severity: 'error',
                });
            }
            break;

        case 'expr':
            if (ctx.validateExpressions && !isValidExpression(check.expr)) {
                ctx.errors.push({
                    path: `${path}/expr`,
                    message: `Invalid or unsafe expression: "${check.expr}"`,
                    severity: 'error',
                });
            }
            break;

        case 'and':
        case 'or':
            if (check.conditions.length === 0) {
                ctx.errors.push({
                    path: `${path}/conditions`,
                    message: `Empty conditions array in "${check.type}" check - this will always ${check.type === 'and' ? 'pass' : 'fail'}`,
                    severity: 'error',
                });
            }
            for (let i = 0; i < check.conditions.length; i++) {
                const cond = check.conditions[i];
                if (cond) {
                    validateCheck(cond, `${path}/conditions/${i}`, ctx);
                }
            }
            break;

        case 'not':
            validateCheck(check.condition, `${path}/condition`, ctx);
            break;
    }
}

/**
 * Validate a regex pattern.
 */
function validateRegex(
    pattern: string,
    flags: string | undefined,
    path: string,
    ctx: ValidationContext
): void {
    // Check pattern length (ReDoS protection)
    if (pattern.length > MAX_PATTERN_LENGTH) {
        ctx.errors.push({
            path,
            message: `Regex pattern too long: ${pattern.length} chars exceeds limit of ${MAX_PATTERN_LENGTH}`,
            severity: 'error',
        });
        return;
    }

    // Check for ReDoS patterns (nested quantifiers)
    if (REDOS_PATTERN.test(pattern)) {
        ctx.errors.push({
            path,
            message: `Regex pattern contains nested quantifiers which may cause ReDoS: "${pattern.slice(0, 50)}${pattern.length > 50 ? '...' : ''}"`,
            severity: 'error',
        });
        return;
    }

    try {
        new RegExp(pattern, flags);
    } catch (e) {
        ctx.errors.push({
            path,
            message: `Invalid regex: ${e instanceof Error ? e.message : 'unknown error'}`,
            severity: 'error',
        });
    }
}

/**
 * Format validation result as a human-readable string.
 */
export function formatValidationResult(result: ValidationResult): string {
    const lines: string[] = [];

    if (result.valid) {
        lines.push('✓ Validation passed');
    } else {
        lines.push('✗ Validation failed');
    }

    if (result.errors.length > 0) {
        lines.push(`\nErrors (${result.errors.length}):`);
        for (const error of result.errors) {
            lines.push(`  ${error.path || '/'}: ${error.message}`);
        }
    }

    if (result.warnings.length > 0) {
        lines.push(`\nWarnings (${result.warnings.length}):`);
        for (const warning of result.warnings) {
            lines.push(`  ${warning.path || '/'}: ${warning.message}`);
        }
    }

    return lines.join('\n');
}
