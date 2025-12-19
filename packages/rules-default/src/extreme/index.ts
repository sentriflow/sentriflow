// packages/rules-default/src/extreme/index.ts
// Extreme Networks (EXOS and VOSS) rules module entry point

export * from './exos-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/extreme';
export * from './voss-rules';

import type { IRule } from '@sentriflow/core';
import { allExosRules } from './exos-rules';
import { allVossRules } from './voss-rules';
import { allCommonRules } from '../common/network-rules';

/**
 * All Extreme Networks rules combined (EXOS + VOSS)
 */
export const allExtremeRules: IRule[] = [
  ...allExosRules,
  ...allVossRules,
];

/**
 * Get all EXOS rules (common + EXOS specific)
 * @returns Array of all applicable rules for EXOS switches
 */
export function getRulesByExosVendor(): IRule[] {
  return [...allCommonRules, ...allExosRules];
}

/**
 * Get all VOSS rules (common + VOSS specific)
 * @returns Array of all applicable rules for VOSS switches
 */
export function getRulesByVossVendor(): IRule[] {
  return [...allCommonRules, ...allVossRules];
}

/**
 * Get all Extreme Networks rules by specific vendor
 * @param vendorId The vendor identifier ('extreme-exos' or 'extreme-voss')
 * @returns Array of applicable rules for that vendor
 */
export function getRulesByExtremeVendor(vendorId: string): IRule[] {
  switch (vendorId) {
    case 'extreme-exos':
      return getRulesByExosVendor();
    case 'extreme-voss':
      return getRulesByVossVendor();
    default:
      // Return all Extreme rules for unknown/generic Extreme vendor
      return [...allCommonRules, ...allExtremeRules];
  }
}
