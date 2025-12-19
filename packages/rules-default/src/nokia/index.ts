// packages/rules-default/src/nokia/index.ts
// Nokia SR OS rules module entry point

export * from './sros-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/nokia';

import type { IRule } from '@sentriflow/core';
import { allNokiaRules } from './sros-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Nokia SR OS rules (common + Nokia specific)
 * @returns Array of all applicable rules for Nokia SR OS devices
 */
export function getRulesByNokiaVendor(): IRule[] {
  return [...allCommonRules, ...allNokiaRules];
}
