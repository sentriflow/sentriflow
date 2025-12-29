/**
 * Rule and RulePack validation utilities
 * Shared between CLI and VS Code extension for DRY compliance.
 */

import { RULE_ID_PATTERN } from '../constants';
import { isValidVendorId } from '../types/IRule';
import type { IRule, RulePack, RuleVendor } from '../types/IRule';

/**
 * Validates that an object has the basic structure of an IRule.
 * Returns error message if invalid, null if valid.
 *
 * Security: Prevents malicious extensions from registering invalid rules.
 */
export function validateRule(rule: unknown): string | null {
  if (typeof rule !== 'object' || rule === null) {
    return 'Rule is not an object';
  }

  const obj = rule as Record<string, unknown>;

  // Required: id (string matching pattern)
  if (typeof obj.id !== 'string') {
    return 'Rule id is not a string';
  }
  if (!RULE_ID_PATTERN.test(obj.id)) {
    return `Rule id "${obj.id}" does not match pattern ${RULE_ID_PATTERN}`;
  }

  // Required: check (function)
  if (typeof obj.check !== 'function') {
    return `Rule ${obj.id}: check is not a function (got ${typeof obj.check})`;
  }

  // Optional but recommended: selector (string)
  if (obj.selector !== undefined && typeof obj.selector !== 'string') {
    return `Rule ${obj.id}: selector is not a string`;
  }

  // Optional: vendor (string or array of valid vendors)
  if (obj.vendor !== undefined) {
    if (Array.isArray(obj.vendor)) {
      for (const v of obj.vendor) {
        if (typeof v !== 'string') {
          return `Rule ${obj.id}: vendor array contains non-string`;
        }
        if (!isValidVendorId(v)) {
          return `Rule ${obj.id}: invalid vendor "${v}"`;
        }
      }
    } else if (typeof obj.vendor !== 'string') {
      return `Rule ${obj.id}: vendor is not a string`;
    } else if (!isValidVendorId(obj.vendor)) {
      return `Rule ${obj.id}: invalid vendor "${obj.vendor}"`;
    }
  }

  // Required: metadata (object with level)
  if (typeof obj.metadata !== 'object' || obj.metadata === null) {
    return `Rule ${obj.id}: metadata is not an object`;
  }

  const metadata = obj.metadata as Record<string, unknown>;
  if (!['error', 'warning', 'info'].includes(metadata.level as string)) {
    return `Rule ${obj.id}: invalid metadata.level "${metadata.level}"`;
  }

  return null;
}

/**
 * Type guard to check if an object is a valid IRule.
 */
export function isValidRule(rule: unknown): rule is IRule {
  return validateRule(rule) === null;
}

/**
 * Validates that an object has the basic structure of a RulePack.
 * Returns error message if invalid, null if valid.
 *
 * @param pack - The object to validate
 * @param reservedPackName - Optional pack name that is reserved (e.g., "Default Rules")
 */
export function validateRulePack(
  pack: unknown,
  reservedPackName?: string
): string | null {
  if (typeof pack !== 'object' || pack === null) {
    return 'Pack is not an object';
  }

  const obj = pack as Record<string, unknown>;

  // Required: name (non-empty string)
  if (typeof obj.name !== 'string' || obj.name.length === 0) {
    return 'Pack name is missing or empty';
  }

  // Check reserved name if provided
  if (reservedPackName && obj.name === reservedPackName) {
    return `Pack name "${obj.name}" is reserved`;
  }

  // Required: version (string)
  if (typeof obj.version !== 'string' || obj.version.length === 0) {
    return 'Pack version is missing or empty';
  }

  // Required: publisher (string)
  if (typeof obj.publisher !== 'string' || obj.publisher.length === 0) {
    return 'Pack publisher is missing or empty';
  }

  // Required: priority (number >= 0)
  if (typeof obj.priority !== 'number' || obj.priority < 0) {
    return `Pack priority is invalid (got ${obj.priority})`;
  }

  // Required: rules (array)
  if (!Array.isArray(obj.rules)) {
    return 'Pack rules is not an array';
  }

  // Validate each rule in the pack
  for (let i = 0; i < obj.rules.length; i++) {
    const ruleError = validateRule(obj.rules[i]);
    if (ruleError) {
      return `Rule[${i}]: ${ruleError}`;
    }
  }

  // Optional: disables (object with specific structure)
  if (obj.disables !== undefined) {
    if (typeof obj.disables !== 'object' || obj.disables === null) {
      return 'Pack disables is not an object';
    }

    const disables = obj.disables as Record<string, unknown>;

    // Optional: all (boolean)
    if (disables.all !== undefined && typeof disables.all !== 'boolean') {
      return 'Pack disables.all is not a boolean';
    }

    // Optional: vendors (array of valid vendor strings)
    if (disables.vendors !== undefined) {
      if (!Array.isArray(disables.vendors)) {
        return 'Pack disables.vendors is not an array';
      }
      for (const v of disables.vendors) {
        if (typeof v !== 'string' || !isValidVendorId(v)) {
          return `Pack disables.vendors contains invalid vendor "${v}"`;
        }
      }
    }

    // Optional: rules (array of strings)
    if (disables.rules !== undefined) {
      if (!Array.isArray(disables.rules)) {
        return 'Pack disables.rules is not an array';
      }
      for (const r of disables.rules) {
        if (typeof r !== 'string') {
          return 'Pack disables.rules contains non-string';
        }
      }
    }
  }

  return null;
}

/**
 * Type guard to check if an object is a valid RulePack.
 *
 * @param pack - The object to validate
 * @param reservedPackName - Optional pack name that is reserved
 */
export function isValidRulePack(
  pack: unknown,
  reservedPackName?: string
): pack is RulePack {
  return validateRulePack(pack, reservedPackName) === null;
}

/**
 * Check if a rule applies to the given vendor.
 * Rules without a vendor property are considered vendor-agnostic (apply to all).
 * Rules with vendor: 'common' also apply to all vendors.
 */
export function ruleAppliesToVendor(rule: IRule, vendorId: string): boolean {
  // No vendor specified = vendor-agnostic, applies to all
  if (!rule.vendor) {
    return true;
  }

  // Handle array of vendors
  if (Array.isArray(rule.vendor)) {
    return (
      rule.vendor.includes('common') ||
      rule.vendor.includes(vendorId as RuleVendor)
    );
  }

  // Single vendor
  return rule.vendor === 'common' || rule.vendor === vendorId;
}
