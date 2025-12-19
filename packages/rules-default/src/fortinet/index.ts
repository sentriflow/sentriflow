// packages/rules-default/src/fortinet/index.ts
// Fortinet FortiGate (FortiOS) rules module entry point

export * from './fortigate-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/fortinet';

import type { IRule } from '@sentriflow/core';
import { allFortinetRules } from './fortigate-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Fortinet FortiGate rules (common + FortiGate specific)
 * @returns Array of all applicable rules for FortiGate firewalls
 */
export function getRulesByFortinetVendor(): IRule[] {
  return [...allCommonRules, ...allFortinetRules];
}
