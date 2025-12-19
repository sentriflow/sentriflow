// packages/rules-default/src/huawei/index.ts
// Huawei VRP rules module entry point

export * from './vrp-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/huawei';

import type { IRule } from '@sentriflow/core';
import { allHuaweiRules } from './vrp-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * Get all Huawei VRP rules (common + Huawei specific)
 * @returns Array of all applicable rules for Huawei VRP devices
 */
export function getRulesByHuaweiVendor(): IRule[] {
  return [...allCommonRules, ...allHuaweiRules];
}
