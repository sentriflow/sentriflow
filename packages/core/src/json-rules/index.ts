// packages/core/src/json-rules/index.ts

/**
 * JSON Rules Module
 *
 * Provides support for JSON-based rule definitions that can be
 * authored without TypeScript knowledge while maintaining full
 * access to helper functions.
 *
 * @example
 * ```typescript
 * import { compileJsonRules, validateJsonRuleFile } from '@sentriflow/core';
 *
 * // Validate a JSON rule file
 * const validation = validateJsonRuleFile(jsonData);
 * if (!validation.valid) {
 *   console.error(validation.errors);
 * }
 *
 * // Compile JSON rules to IRule objects
 * const rules = compileJsonRules(jsonData.rules);
 * ```
 */

// Types
export type {
    JsonArgValue,
    JsonCheck,
    JsonRule,
    JsonRuleFile,
} from './types';

export {
    isJsonArgValue,
    isJsonCheck,
    isJsonRule,
    isJsonRuleFile,
} from './types';

// Helper Registry
export type {
    HelperFunction,
    VendorHelpers,
    HelperRegistry,
} from './HelperRegistry';

export {
    createHelperRegistry,
    resolveHelper,
    getAvailableHelpers,
    hasHelper,
    getHelperRegistry,
    clearHelperRegistryCache,
    VENDOR_NAMESPACES,
} from './HelperRegistry';

export type { VendorNamespace } from './HelperRegistry';

// Expression Evaluator
export {
    ExpressionEvaluator,
    createExpressionEvaluator,
    getExpressionEvaluator,
    clearExpressionEvaluator,
    isValidExpression,
} from './ExpressionEvaluator';

// JSON Rule Compiler
export type {
    JsonRuleCompilerOptions,
} from './JsonRuleCompiler';

export {
    JsonRuleCompiler,
    createJsonRuleCompiler,
    getJsonRuleCompiler,
    compileJsonRule,
    compileJsonRules,
    clearJsonRuleCompiler,
} from './JsonRuleCompiler';

// JSON Rule Validator
export type {
    ValidationError,
    ValidationResult,
    ValidationOptions,
} from './JsonRuleValidator';

export {
    validateJsonRuleFile,
    validateJsonRule,
    formatValidationResult,
} from './JsonRuleValidator';

// JSON Schema (as a module for runtime access)
import schema from './schema.json';
export { schema as jsonRuleSchema };
