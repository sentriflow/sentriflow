// packages/rules-default/src/cumulus/index.ts
// NVIDIA Cumulus Linux specific rules

export * from './cumulus-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/cumulus';

import type { IRule } from '@sentriflow/core';
import { allCumulusRules } from './cumulus-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Cumulus rules including common rules.
 * @returns Array of IRule for Cumulus Linux vendor
 */
export function getRulesByCumulusVendor(): IRule[] {
  return [...allCommonRules, ...allCumulusRules];
}
