// packages/rules-default/src/index.ts
// Main entry point for the rules-default package

import type { IRule } from '@sentriflow/core';

// Import rule arrays from each module
import { allCommonRules } from './common/network-rules';
import { allCiscoRules } from './cisco/ios-rules';
import { allJuniperRules } from './juniper/junos-rules';
import { allArubaRules, getRulesByArubaVendor } from './aruba';
import { allPaloAltoRules, getRulesByPaloAltoVendor } from './paloalto';
import { allAristaRules, getRulesByAristaVendor } from './arista';
import { allVyosRules, getRulesByVyosVendor } from './vyos';
import { allFortinetRules, getRulesByFortinetVendor } from './fortinet';
import { allExtremeRules, getRulesByExtremeVendor } from './extreme';
import { allHuaweiRules, getRulesByHuaweiVendor } from './huawei';
import { allMikroTikRules, getRulesByMikroTikVendor } from './mikrotik';
import { allNokiaRules, getRulesByNokiaVendor } from './nokia';
import { allCumulusRules, getRulesByCumulusVendor } from './cumulus';

// JSON rules
import {
  allJsonRules,
  ciscoJsonRules,
  commonJsonRules,
  juniperJsonRules,
  getJsonRulesByVendor,
} from './json';

// Legacy exports for backward compatibility
// NOTE: SSHVersion2Required, VTYAccessClassRequired, OspfNetworkBestPractice moved to basic-netsec-pack
export {
  NoMulticastBroadcastIp,
  InterfaceDescriptionRequired,
  NoPlaintextPasswords,
} from './common/network-rules';

// Re-export the cisco rules array for backward compatibility
export { allCiscoRules, OspfNetworkBestPractice } from './cisco/ios-rules';

// Export JSON rules
export {
  allJsonRules,
  ciscoJsonRules,
  commonJsonRules,
  juniperJsonRules,
  getJsonRulesByVendor,
} from './json';

// Re-export JSON rule types for convenience
export type { JsonRuleFile, JsonRule, JsonCheck } from './json';

/**
 * All default rules bundled together.
 * Includes:
 * - Common/vendor-agnostic rules (NET-IP-001, NET-DOC-001, etc.)
 * - Cisco IOS/IOS-XE rules (NET-TRUNK-*, NET-ACCESS-*, etc.)
 * - Juniper JunOS rules (JUN-SYS-*, JUN-BGP-*, etc.)
 * - Aruba HPE rules (ARU-*, AOSCX-*, AOSSW-*, ARUWLC-*)
 * - Palo Alto PAN-OS rules (PAN-SYS-*, PAN-SEC-*, PAN-ZONE-*, etc.)
 * - Arista EOS rules (ARI-SYS-*, ARI-MLAG-*, ARI-VXLAN-*, etc.)
 * - VyOS/EdgeOS rules (VYOS-SYS-*, VYOS-FW-*, VYOS-NAT-*, etc.)
 * - Fortinet FortiGate rules (FGT-SYS-*, FGT-POL-*, FGT-ADMIN-*, etc.)
 * - Extreme Networks rules (EXOS-*, VOSS-*)
 * - Huawei VRP rules (HUAWEI-SYS-*, HUAWEI-IF-*, HUAWEI-VTY-*, etc.)
 * - MikroTik RouterOS rules (MIK-SYS-*, MIK-FW-*, MIK-SEC-*, etc.)
 * - Nokia SR OS rules (NOKIA-SYS-*, NOKIA-PORT-*, NOKIA-BGP-*, etc.)
 * - NVIDIA Cumulus Linux rules (CUM-IF-*, CUM-BR-*, CUM-BGP-*, etc.)
 * - JSON-defined rules (JSON-CISCO-*, JSON-JUNOS-*, JSON-COMMON-*)
 */
export const allRules: IRule[] = [
  // Common vendor-agnostic rules
  ...allCommonRules,
  // Cisco-specific rules
  ...allCiscoRules,
  // Juniper-specific rules
  ...allJuniperRules,
  // Aruba HPE rules (all platforms)
  ...allArubaRules,
  // Palo Alto PAN-OS rules
  ...allPaloAltoRules,
  // Arista EOS rules
  ...allAristaRules,
  // VyOS/EdgeOS rules
  ...allVyosRules,
  // Fortinet FortiGate rules
  ...allFortinetRules,
  // Extreme Networks rules (EXOS + VOSS)
  ...allExtremeRules,
  // Huawei VRP rules
  ...allHuaweiRules,
  // MikroTik RouterOS rules
  ...allMikroTikRules,
  // Nokia SR OS rules
  ...allNokiaRules,
  // NVIDIA Cumulus Linux rules
  ...allCumulusRules,
  // JSON-defined rules (compiled from JSON files)
  ...allJsonRules,
];

/**
 * Vendor-to-rules mapping registry.
 * Maps vendor IDs to functions that return applicable rules.
 * Dynamically constructed - add new vendors by adding entries here.
 */
const vendorRulesRegistry: Record<string, () => IRule[]> = {
  // Cisco platforms share the same rules
  'cisco-ios': () => [...allCommonRules, ...allCiscoRules],
  'cisco-nxos': () => [...allCommonRules, ...allCiscoRules],
  // Juniper
  'juniper-junos': () => [...allCommonRules, ...allJuniperRules],
  // Aruba platforms have variant-specific rules
  'aruba-aoscx': () => getRulesByArubaVendor('aruba-aoscx'),
  'aruba-aosswitch': () => getRulesByArubaVendor('aruba-aosswitch'),
  'aruba-wlc': () => getRulesByArubaVendor('aruba-wlc'),
  // Other vendors
  'paloalto-panos': () => getRulesByPaloAltoVendor(),
  'arista-eos': () => getRulesByAristaVendor(),
  'vyos': () => getRulesByVyosVendor(),
  'fortinet-fortigate': () => getRulesByFortinetVendor(),
  'extreme-exos': () => getRulesByExtremeVendor('extreme-exos'),
  'extreme-voss': () => getRulesByExtremeVendor('extreme-voss'),
  'huawei-vrp': () => getRulesByHuaweiVendor(),
  'mikrotik-routeros': () => getRulesByMikroTikVendor(),
  'nokia-sros': () => getRulesByNokiaVendor(),
  'cumulus-linux': () => getRulesByCumulusVendor(),
};

/**
 * Get rules by vendor.
 * Uses the vendorRulesRegistry lookup map for O(1) vendor resolution.
 * @param vendorId The vendor identifier (e.g., 'cisco-ios', 'juniper-junos')
 * @returns Array of applicable rules for that vendor
 */
export function getRulesByVendor(vendorId: string): IRule[] {
  const getRules = vendorRulesRegistry[vendorId];
  if (getRules) {
    return getRules();
  }
  // Return all rules for unknown vendors
  return allRules;
}

/**
 * Get only common (vendor-agnostic) rules.
 */
export function getCommonRules(): IRule[] {
  return [...allCommonRules];
}

/**
 * Get only Cisco-specific rules.
 */
export function getCiscoRules(): IRule[] {
  return [...allCiscoRules];
}

/**
 * Get only Juniper-specific rules.
 */
export function getJuniperRules(): IRule[] {
  return [...allJuniperRules];
}

/**
 * Get only Aruba-specific rules (all platforms combined).
 */
export function getArubaRules(): IRule[] {
  return [...allArubaRules];
}

/**
 * Get only Palo Alto-specific rules.
 */
export function getPaloAltoRules(): IRule[] {
  return [...allPaloAltoRules];
}

/**
 * Get only Arista-specific rules.
 */
export function getAristaRules(): IRule[] {
  return [...allAristaRules];
}

/**
 * Get only VyOS/EdgeOS-specific rules.
 */
export function getVyosRules(): IRule[] {
  return [...allVyosRules];
}

/**
 * Get only Fortinet FortiGate-specific rules.
 */
export function getFortinetRules(): IRule[] {
  return [...allFortinetRules];
}

/**
 * Get only Extreme Networks-specific rules (EXOS + VOSS).
 */
export function getExtremeRules(): IRule[] {
  return [...allExtremeRules];
}

/**
 * Get only Huawei VRP-specific rules.
 */
export function getHuaweiRules(): IRule[] {
  return [...allHuaweiRules];
}

/**
 * Get only MikroTik RouterOS-specific rules.
 */
export function getMikroTikRules(): IRule[] {
  return [...allMikroTikRules];
}

/**
 * Get only Nokia SR OS-specific rules.
 */
export function getNokiaRules(): IRule[] {
  return [...allNokiaRules];
}

/**
 * Get only NVIDIA Cumulus Linux-specific rules.
 */
export function getCumulusRules(): IRule[] {
  return [...allCumulusRules];
}
