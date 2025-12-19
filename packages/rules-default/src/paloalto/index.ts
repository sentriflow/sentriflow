// packages/rules-default/src/paloalto/index.ts
// Palo Alto PAN-OS rules module entry point

export * from './panos-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/paloalto';

import type { IRule } from '@sentriflow/core';
import { allPaloAltoRules } from './panos-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Palo Alto rules (common + PAN-OS specific)
 * @returns Array of all applicable rules for Palo Alto firewalls
 */
export function getRulesByPaloAltoVendor(): IRule[] {
  return [...allCommonRules, ...allPaloAltoRules];
}
