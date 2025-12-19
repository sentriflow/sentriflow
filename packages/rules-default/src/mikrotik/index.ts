// packages/rules-default/src/mikrotik/index.ts
// MikroTik RouterOS rules module exports

import type { IRule } from '@sentriflow/core';

// Re-export all rules
export * from './routeros-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/mikrotik';

// Import for local use
import { allMikroTikRules } from './routeros-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all rules applicable to MikroTik RouterOS configurations.
 * Includes common vendor-agnostic rules plus MikroTik-specific rules.
 *
 * @returns Array of IRule objects for MikroTik RouterOS
 */
export function getRulesByMikroTikVendor(): IRule[] {
  return [...allCommonRules, ...allMikroTikRules];
}

/**
 * Get only MikroTik-specific rules (no common rules).
 *
 * @returns Array of MikroTik-specific IRule objects
 */
export function getMikroTikOnlyRules(): IRule[] {
  return [...allMikroTikRules];
}
