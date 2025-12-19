// packages/rules-default/src/aruba/index.ts
// Aruba HPE rules module - supports AOS-CX, AOS-Switch, and ArubaOS WLC

export * from './common-rules';

// Re-export helpers from @sentriflow/core for backward compatibility
export * from '@sentriflow/core/helpers/aruba';
export * from './aoscx-rules';
export * from './aosswitch-rules';
export * from './wlc-rules';

import type { IRule } from '@sentriflow/core';

// Import all rule arrays
import { allArubaCommonRules } from './common-rules';
import { allAosCxRules } from './aoscx-rules';
import { allAosSwitchRules } from './aosswitch-rules';
import { allWlcRules } from './wlc-rules';

/**
 * All Aruba rules combined (common + all platform-specific).
 * Use getRulesByArubaVendor() for platform-specific rule sets.
 */
export const allArubaRules: IRule[] = [
  ...allArubaCommonRules,
  ...allAosCxRules,
  ...allAosSwitchRules,
  ...allWlcRules,
];

/**
 * Get rules by Aruba vendor/platform.
 * @param vendorId The vendor identifier ('aruba-aoscx', 'aruba-aosswitch', 'aruba-wlc')
 * @returns Array of applicable rules for that platform
 */
export function getRulesByArubaVendor(vendorId: string): IRule[] {
  switch (vendorId) {
    case 'aruba-aoscx':
      return [...allArubaCommonRules, ...allAosCxRules];
    case 'aruba-aosswitch':
      return [...allArubaCommonRules, ...allAosSwitchRules];
    case 'aruba-wlc':
      return [...allArubaCommonRules, ...allWlcRules];
    default:
      // Return all Aruba rules for unknown variants
      return allArubaRules;
  }
}

/**
 * Get only common Aruba rules (applicable to all platforms).
 */
export function getArubaCommonRules(): IRule[] {
  return [...allArubaCommonRules];
}

/**
 * Get only AOS-CX specific rules.
 */
export function getAosCxRules(): IRule[] {
  return [...allAosCxRules];
}

/**
 * Get only AOS-Switch specific rules.
 */
export function getAosSwitchRules(): IRule[] {
  return [...allAosSwitchRules];
}

/**
 * Get only WLC specific rules.
 */
export function getWlcRules(): IRule[] {
  return [...allWlcRules];
}
