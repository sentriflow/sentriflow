// packages/rule-helpers/src/common/helpers.ts
// Common helper functions used across vendor-specific rules

import type { ConfigNode } from '../../types/ConfigNode';

// Re-export validation helpers for convenience
export {
  equalsIgnoreCase,
  includesIgnoreCase,
  startsWithIgnoreCase,
  parseInteger,
  isInRange,
  parsePort,
  isValidPort,
  parsePortRange,
  parseVlanId,
  isValidVlanId,
  isDefaultVlan,
  isReservedVlan,
  isFeatureEnabled,
  isFeatureDisabled,
  isValidMacAddress,
  normalizeMacAddress,
  parseCidr,
  isIpInNetwork,
  isIpInCidr,
  type CidrInfo,
} from './validation';

/**
 * Parse an IP address string to a 32-bit unsigned integer.
 * @param addr The IP address string (e.g., "10.0.0.1")
 * @returns The IP as a 32-bit unsigned number, or null if invalid
 */
export const parseIp = (addr: string): number | null => {
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  // Safe: we verified parts.length === 4 above
  const [p0, p1, p2, p3] = parts as [number, number, number, number];
  return ((p0 << 24) | (p1 << 16) | (p2 << 8) | p3) >>> 0;
};

/**
 * Convert a 32-bit unsigned integer to an IP address string.
 * @param num The IP as a 32-bit unsigned number
 * @returns The IP address string
 */
export const numToIp = (num: number): string => {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255,
  ].join('.');
};

/**
 * Parse a CIDR prefix length to a subnet mask number.
 * @param prefix The prefix length (e.g., 24)
 * @returns The subnet mask as a 32-bit unsigned number
 */
export const prefixToMask = (prefix: number): number => {
  if (prefix < 0 || prefix > 32) return 0;
  return prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
};

/**
 * Convert a subnet mask to CIDR prefix length.
 * @param mask The subnet mask as a 32-bit unsigned number
 * @returns The prefix length
 */
export const maskToPrefix = (mask: number): number => {
  let count = 0;
  let m = mask;
  while (m & 0x80000000) {
    count++;
    m <<= 1;
  }
  return count;
};

/**
 * Check if a node has a specific child command (case-insensitive prefix match).
 * @param node The parent ConfigNode
 * @param prefix The command prefix to search for
 * @returns true if a matching child exists, false if node/children is nullish
 */
export const hasChildCommand = (node: ConfigNode, prefix: string): boolean => {
  if (!node?.children || !prefix) return false;
  return node.children.some((child) =>
    child?.id?.toLowerCase().startsWith(prefix.toLowerCase()) ?? false
  );
};

/**
 * Get a child command's node if it exists.
 * @param node The parent ConfigNode
 * @param prefix The command prefix to search for
 * @returns The matching child node, or undefined if not found or node is nullish
 */
export const getChildCommand = (
  node: ConfigNode,
  prefix: string
): ConfigNode | undefined => {
  if (!node?.children || !prefix) return undefined;
  return node.children.find((child) =>
    child?.id?.toLowerCase().startsWith(prefix.toLowerCase()) ?? false
  );
};

/**
 * Get all child commands matching a prefix.
 * @param node The parent ConfigNode
 * @param prefix The command prefix to search for
 * @returns Array of matching child nodes, empty array if node is nullish
 */
export const getChildCommands = (
  node: ConfigNode,
  prefix: string
): ConfigNode[] => {
  if (!node?.children || !prefix) return [];
  return node.children.filter((child) =>
    child?.id?.toLowerCase().startsWith(prefix.toLowerCase()) ?? false
  );
};

/**
 * Check if a value is a valid IP address string.
 * @param value The string to check
 * @returns true if it's a valid IP address
 */
export const isValidIpAddress = (value: string): boolean => {
  return parseIp(value) !== null;
};

/**
 * Check if an IP is in the multicast range (224.0.0.0 - 239.255.255.255).
 * @param ipNum The IP as a 32-bit unsigned number
 * @returns true if it's a multicast address
 */
export const isMulticastAddress = (ipNum: number): boolean => {
  const firstOctet = ipNum >>> 24;
  return firstOctet >= 224 && firstOctet <= 239;
};

/**
 * Check if an IP is the global broadcast address (255.255.255.255).
 * @param ipNum The IP as a 32-bit unsigned number
 * @returns true if it's the broadcast address
 */
export const isBroadcastAddress = (ipNum: number): boolean => {
  return ipNum === 0xffffffff;
};

/**
 * Check if an IP is a private address (RFC 1918).
 * @param ipNum The IP as a 32-bit unsigned number
 * @returns true if it's a private address
 */
export const isPrivateAddress = (ipNum: number): boolean => {
  // 10.0.0.0/8
  if ((ipNum & 0xff000000) >>> 0 === 0x0a000000) return true;
  // 172.16.0.0/12
  if ((ipNum & 0xfff00000) >>> 0 === 0xac100000) return true;
  // 192.168.0.0/16
  if ((ipNum & 0xffff0000) >>> 0 === 0xc0a80000) return true;
  return false;
};

/**
 * Extract a parameter value from a node's params array.
 * @param node The ConfigNode
 * @param keyword The keyword to find
 * @returns The value after the keyword, or undefined
 */
export const getParamValue = (
  node: ConfigNode,
  keyword: string
): string | undefined => {
  const idx = node.params.findIndex(
    (p) => p.toLowerCase() === keyword.toLowerCase()
  );
  if (idx >= 0 && idx < node.params.length - 1) {
    return node.params[idx + 1];
  }
  return undefined;
};

/**
 * Check if an interface is administratively shutdown.
 * Works for both Cisco ("shutdown") and Juniper ("disable") syntax.
 * @param node The interface ConfigNode
 * @returns true if the interface is shutdown/disabled, false if node is nullish
 */
export const isShutdown = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const id = child?.id?.toLowerCase().trim();
    return id === 'shutdown' || id === 'disable';
  });
};

/**
 * Check if a node is an actual interface definition (not a reference or sub-command).
 * Interface definitions are top-level sections that define physical/logical interfaces.
 *
 * This helper distinguishes real interface definitions from:
 * - Interface references inside protocol blocks (OSPF, LLDP, etc.)
 * - Sub-commands like "interface-type", "interface-mode"
 * - Generic references like "interface all"
 *
 * @param node The ConfigNode to check
 * @returns true if this is an actual interface definition, false if node is nullish
 */
export const isInterfaceDefinition = (node: ConfigNode): boolean => {
  if (!node?.id) return false;
  const id = node.id.toLowerCase();

  // Must be a section type (has children or is a block)
  if (node.type !== 'section') {
    return false;
  }

  // Must start with exactly "interface " followed by interface name
  if (!id.startsWith('interface ')) {
    return false;
  }

  // Skip "interface-type", "interface-mode", etc. (compound words)
  if (id.startsWith('interface-')) {
    return false;
  }

  // Get the interface name part
  const ifName = id.slice('interface '.length).trim();

  // Skip generic references like "interface all" (LLDP/CDP config)
  if (ifName === 'all' || ifName === 'default') {
    return false;
  }

  // For Juniper: interface references inside protocols/routing don't have meaningful children
  // Real interface definitions in "interfaces { }" block have unit, family, etc.
  // References inside ospf/lldp/etc. typically have no children or just simple options
  // Check if this looks like a Juniper interface reference (inside protocols block)
  // These typically have 0-1 children with simple options like "passive" or "interface-type"
  const childrenLength = node.children?.length ?? 0;
  if (childrenLength <= 1) {
    const hasOnlySimpleChild = (node.children ?? []).every((child) => {
      const childId = child?.id?.toLowerCase() ?? '';
      return (
        childId === 'passive' ||
        childId.startsWith('interface-type') ||
        childId.startsWith('metric') ||
        childId.startsWith('hello-interval') ||
        childId.startsWith('dead-interval') ||
        childId.startsWith('priority') ||
        childId.startsWith('authentication') ||
        childId.startsWith('bfd-liveness')
      );
    });
    // If only simple OSPF/routing options, this is likely a reference, not a definition
    if (hasOnlySimpleChild && childrenLength > 0) {
      return false;
    }
  }

  return true;
};
