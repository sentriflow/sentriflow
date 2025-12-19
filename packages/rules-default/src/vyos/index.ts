// packages/rules-default/src/vyos/index.ts
// VyOS/EdgeOS specific rules

export * from './vyos-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/vyos';

import type { IRule } from '@sentriflow/core';
import { allVyosRules } from './vyos-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all VyOS rules including common rules.
 * @returns Array of IRule for VyOS vendor
 */
export function getRulesByVyosVendor(): IRule[] {
  return [...allCommonRules, ...allVyosRules];
}
