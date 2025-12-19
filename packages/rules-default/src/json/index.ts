// packages/rules-default/src/json/index.ts

/**
 * JSON Rules Module
 *
 * Exports pre-compiled JSON rules alongside TypeScript rules.
 * JSON rules are loaded, validated, and compiled at import time.
 */

import { compileJsonRules, validateJsonRuleFile, type JsonRuleFile } from '@sentriflow/core';
import type { IRule } from '@sentriflow/core';

// Import JSON rule files
import ciscoJsonRulesFile from './cisco-json-rules.json';
import commonJsonRulesFile from './common-json-rules.json';
import juniperJsonRulesFile from './juniper-json-rules.json';

/**
 * Validate and compile a JSON rule file, logging any validation errors.
 */
function loadJsonRuleFile(file: unknown, fileName: string): IRule[] {
    const validation = validateJsonRuleFile(file);

    if (!validation.valid) {
        console.warn(`[JSON Rules] Validation errors in ${fileName}:`);
        for (const error of validation.errors) {
            console.warn(`  ${error.path}: ${error.message}`);
        }
        return [];
    }

    if (validation.warnings.length > 0) {
        console.debug(`[JSON Rules] Validation warnings in ${fileName}:`);
        for (const warning of validation.warnings) {
            console.debug(`  ${warning.path}: ${warning.message}`);
        }
    }

    const ruleFile = file as JsonRuleFile;
    return compileJsonRules(ruleFile.rules);
}

/**
 * Compiled Cisco JSON rules.
 */
export const ciscoJsonRules: IRule[] = loadJsonRuleFile(
    ciscoJsonRulesFile,
    'cisco-json-rules.json'
);

/**
 * Compiled common (vendor-agnostic) JSON rules.
 */
export const commonJsonRules: IRule[] = loadJsonRuleFile(
    commonJsonRulesFile,
    'common-json-rules.json'
);

/**
 * Compiled Juniper JSON rules.
 */
export const juniperJsonRules: IRule[] = loadJsonRuleFile(
    juniperJsonRulesFile,
    'juniper-json-rules.json'
);

/**
 * All JSON rules combined.
 */
export const allJsonRules: IRule[] = [
    ...ciscoJsonRules,
    ...commonJsonRules,
    ...juniperJsonRules,
];

/**
 * Get JSON rules by vendor.
 */
export function getJsonRulesByVendor(vendorId: string): IRule[] {
    return allJsonRules.filter((rule) => {
        if (!rule.vendor) return true; // No vendor = applies to all
        if (rule.vendor === 'common') return true;
        if (Array.isArray(rule.vendor)) {
            return rule.vendor.includes(vendorId as never) || rule.vendor.includes('common');
        }
        return rule.vendor === vendorId;
    });
}

// Re-export types for convenience
export type { JsonRuleFile, JsonRule, JsonCheck } from '@sentriflow/core';
