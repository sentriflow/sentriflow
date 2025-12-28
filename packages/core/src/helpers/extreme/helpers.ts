// packages/rule-helpers/src/extreme/helpers.ts
// Extreme Networks (EXOS and VOSS) specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand } from '../common/helpers';

// =============================================================================
// EXOS-specific helpers
// =============================================================================

/**
 * Check if node is an EXOS VLAN creation command
 * @param node The ConfigNode to check
 * @returns true if it's a "create vlan" command
 */
export const isExosVlanCreate = (node: ConfigNode): boolean => {
  return /^create\s+vlan\s+/i.test(node.id);
};

/**
 * Extract VLAN name from EXOS VLAN command
 * @param node The ConfigNode
 * @returns The VLAN name or undefined
 */
export const getExosVlanName = (node: ConfigNode): string | undefined => {
  const match = node.id.match(/^(?:create|configure)\s+vlan\s+["']?(\w+)["']?/i);
  const vlanName = match?.[1];
  return vlanName?.trim();
};

/**
 * Extract VLAN tag from EXOS VLAN command
 * @param node The ConfigNode
 * @returns The VLAN tag number or undefined
 */
export const getExosVlanTag = (node: ConfigNode): number | undefined => {
  const match = node.id.match(/tag\s+(\d+)/i);
  const vlanTag = match?.[1];
  return vlanTag ? parseInt(vlanTag, 10) : undefined;
};

/**
 * Check if EXOS command is a configure command
 * @param node The ConfigNode
 * @returns true if it's a configure command
 */
export const isExosConfigureCommand = (node: ConfigNode): boolean => {
  return /^configure\s+/i.test(node.id);
};

/**
 * Check if EXOS has SNMP sysname configured
 * @param ast The full AST array
 * @returns true if snmp sysname is configured
 */
export const hasExosSysname = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^configure\s+snmp\s+sysname\s+/i.test(node.id)
  );
};

/**
 * Get EXOS sysname value
 * @param ast The full AST array
 * @returns The sysname or undefined
 */
export const getExosSysname = (ast: ConfigNode[]): string | undefined => {
  const node = ast.find((n) => /^configure\s+snmp\s+sysname\s+/i.test(n.id));
  if (!node) return undefined;
  const match = node.id.match(/sysname\s+["']?([^"'\s]+)["']?/i);
  const sysname = match?.[1];
  return sysname?.trim();
};

/**
 * Check if EXOS has SNTP configured
 * @param ast The full AST array
 * @returns true if SNTP is configured
 */
export const hasExosSntp = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^configure\s+sntp-client\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS SNTP is enabled
 * @param ast The full AST array
 * @returns true if SNTP is enabled
 */
export const isExosSntpEnabled = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^enable\s+sntp-client/i.test(node.id)
  );
};

/**
 * Check if EXOS has syslog configured
 * @param ast The full AST array
 * @returns true if syslog is configured
 */
export const hasExosSyslog = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^configure\s+syslog\s+/i.test(node.id) ||
    /^configure\s+log\s+target\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS has SSH2 enabled
 * @param ast The full AST array
 * @returns true if SSH2 is configured
 */
export const hasExosSsh2 = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^enable\s+ssh2/i.test(node.id) ||
    /^configure\s+ssh2\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS has RADIUS configured
 * @param ast The full AST array
 * @returns true if RADIUS is configured
 */
export const hasExosRadius = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^configure\s+radius\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS has TACACS configured
 * @param ast The full AST array
 * @returns true if TACACS is configured
 */
export const hasExosTacacs = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^configure\s+tacacs\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS LAG (sharing) is configured
 * @param node The ConfigNode
 * @returns true if it's an enable sharing command
 */
export const isExosLag = (node: ConfigNode): boolean => {
  return /^enable\s+sharing\s+/i.test(node.id);
};

/**
 * Extract LAG master port from EXOS sharing command
 * @param node The ConfigNode
 * @returns The master port (e.g., "1:1") or undefined
 */
export const getExosLagMasterPort = (node: ConfigNode): string | undefined => {
  const match = node.id.match(/^enable\s+sharing\s+(\d+:\d+)/i);
  const masterPort = match?.[1];
  return masterPort?.trim();
};

/**
 * Check if EXOS EAPS is configured
 * @param ast The full AST array
 * @returns true if EAPS is configured
 */
export const hasExosEaps = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^create\s+eaps\s+/i.test(node.id) ||
    /^configure\s+eaps\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS stacking is enabled
 * @param ast The full AST array
 * @returns true if stacking is enabled
 */
export const hasExosStacking = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^enable\s+stacking$/i.test(node.id) ||
    /^configure\s+stacking\s+/i.test(node.id)
  );
};

/**
 * Check if EXOS MLAG is configured
 * @param ast The full AST array
 * @returns true if MLAG is configured
 */
export const hasExosMlag = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^create\s+mlag\s+peer\s+/i.test(node.id) ||
    /^configure\s+mlag\s+peer\s+/i.test(node.id)
  );
};

// =============================================================================
// VOSS-specific helpers
// =============================================================================

/**
 * Check if node is a VOSS VLAN creation command
 * @param node The ConfigNode
 * @returns true if it's a "vlan create" command
 */
export const isVossVlanCreate = (node: ConfigNode): boolean => {
  return /^vlan\s+create\s+\d+/i.test(node.id);
};

/**
 * Extract VLAN ID from VOSS VLAN command
 * @param node The ConfigNode
 * @returns The VLAN ID or undefined
 */
export const getVossVlanId = (node: ConfigNode): number | undefined => {
  const match = node.id.match(/^vlan\s+(?:create|members|i-sid)\s+(\d+)/i);
  const vlanId = match?.[1];
  return vlanId ? parseInt(vlanId, 10) : undefined;
};

/**
 * Check if VOSS has SPBM configured
 * @param ast The full AST array
 * @returns true if SPBM is configured
 */
export const hasVossSpbm = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^spbm\s+\d+/i.test(node.id) ||
    /^router\s+isis[\s\S]*spbm/i.test(node.id)
  );
};

/**
 * Check if VOSS has ISIS configured
 * @param ast The full AST array
 * @returns true if ISIS is configured
 */
export const hasVossIsis = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^router\s+isis/i.test(node.id)
  );
};

/**
 * Check if VOSS has I-SID configured for VLAN
 * @param ast The full AST array
 * @param vlanId The VLAN ID to check
 * @returns true if I-SID is configured for the VLAN
 */
export const hasVossVlanIsid = (ast: ConfigNode[], vlanId: number): boolean => {
  return ast.some((node) =>
    new RegExp(`^vlan\\s+i-sid\\s+${vlanId}\\s+\\d+`, 'i').test(node.id)
  );
};

/**
 * Get I-SID for a VOSS VLAN
 * @param ast The full AST array
 * @param vlanId The VLAN ID
 * @returns The I-SID or undefined
 */
export const getVossVlanIsid = (ast: ConfigNode[], vlanId: number): number | undefined => {
  const node = ast.find((n) =>
    new RegExp(`^vlan\\s+i-sid\\s+${vlanId}\\s+\\d+`, 'i').test(n.id)
  );
  if (!node) return undefined;
  const match = node.id.match(/i-sid\s+\d+\s+(\d+)/i);
  const isid = match?.[1];
  return isid ? parseInt(isid, 10) : undefined;
};

/**
 * Check if VOSS interface is a GigabitEthernet
 * @param node The ConfigNode
 * @returns true if it's a GigabitEthernet interface
 */
export const isVossGigabitEthernet = (node: ConfigNode): boolean => {
  return /^interface\s+GigabitEthernet\s+\d+\/\d+/i.test(node.id);
};

/**
 * Check if VOSS interface is an MLT (Multi-Link Trunk)
 * @param node The ConfigNode
 * @returns true if it's an MLT interface
 */
export const isVossMlt = (node: ConfigNode): boolean => {
  return /^interface\s+mlt\s+\d+/i.test(node.id) ||
         /^mlt\s+\d+/i.test(node.id);
};

/**
 * Get VOSS MLT ID
 * @param node The ConfigNode
 * @returns The MLT ID or undefined
 */
export const getVossMltId = (node: ConfigNode): number | undefined => {
  const match = node.id.match(/(?:interface\s+)?mlt\s+(\d+)/i);
  const mltId = match?.[1];
  return mltId ? parseInt(mltId, 10) : undefined;
};

/**
 * Check if VOSS interface is shutdown
 * @param node The interface ConfigNode
 * @returns true if interface is shutdown
 */
export const isVossShutdown = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  const hasShutdown = node.children.some((child) =>
    child?.id?.toLowerCase() === 'shutdown'
  );
  const hasNoShutdown = node.children.some((child) =>
    child?.id?.toLowerCase() === 'no shutdown'
  );
  return hasShutdown && !hasNoShutdown;
};

/**
 * Check if VOSS has snmp-server name configured
 * @param ast The full AST array
 * @returns true if snmp-server name is configured
 */
export const hasVossSnmpName = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^snmp-server\s+name\s+/i.test(node.id)
  );
};

/**
 * Get VOSS snmp-server name
 * @param ast The full AST array
 * @returns The name or undefined
 */
export const getVossSnmpName = (ast: ConfigNode[]): string | undefined => {
  const node = ast.find((n) => /^snmp-server\s+name\s+/i.test(n.id));
  if (!node) return undefined;
  const match = node.id.match(/name\s+["']?([^"'\s]+)["']?/i);
  const name = match?.[1];
  return name?.trim();
};

/**
 * Check if VOSS has NTP configured
 * @param ast The full AST array
 * @returns true if NTP is configured
 */
export const hasVossNtp = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ntp\s+server\s+/i.test(node.id)
  );
};

/**
 * Check if VOSS has logging configured
 * @param ast The full AST array
 * @returns true if logging is configured
 */
export const hasVossLogging = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^logging\s+(host|server)\s+/i.test(node.id)
  );
};

/**
 * Check if VOSS has SSH enabled
 * @param ast The full AST array
 * @returns true if SSH is configured
 */
export const hasVossSsh = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ssh\s+/i.test(node.id)
  );
};

/**
 * Check if VOSS has LACP configured on interface
 * @param node The interface ConfigNode
 * @returns true if LACP is configured
 */
export const hasVossLacp = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) =>
    child?.id && /^lacp\s+(enable|key)/i.test(child.id)
  );
};

/**
 * Check if VOSS has DVR (Distributed Virtual Routing) configured
 * @param ast The full AST array
 * @returns true if DVR is configured
 */
export const hasVossDvr = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^dvr\s+(leaf|controller)/i.test(node.id)
  );
};

/**
 * Check if VOSS has CFM (Connectivity Fault Management) configured
 * @param ast The full AST array
 * @returns true if CFM is configured
 */
export const hasVossCfm = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^cfm\s+/i.test(node.id)
  );
};

/**
 * Get VOSS interface default VLAN
 * @param node The interface ConfigNode
 * @returns The default VLAN ID or undefined
 */
export const getVossDefaultVlan = (node: ConfigNode): number | undefined => {
  if (!node?.children) return undefined;
  const defaultVlan = node.children.find((child) =>
    child?.id && /^default-vlan-id\s+\d+/i.test(child.id)
  );
  if (!defaultVlan?.id) return undefined;
  const match = defaultVlan.id.match(/default-vlan-id\s+(\d+)/i);
  const vlanId = match?.[1];
  return vlanId ? parseInt(vlanId, 10) : undefined;
};
