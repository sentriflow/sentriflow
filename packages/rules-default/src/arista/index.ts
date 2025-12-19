// packages/rules-default/src/arista/index.ts
// Arista EOS rules module entry point

export * from './eos-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/arista';

import type { IRule } from '@sentriflow/core';
import { allAristaRules } from './eos-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Arista rules (common + EOS specific)
 * @returns Array of all applicable rules for Arista switches
 */
export function getRulesByAristaVendor(): IRule[] {
  return [...allCommonRules, ...allAristaRules];
}
