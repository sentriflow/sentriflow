// packages/core/src/ip/classifier.ts

import type { IPSummary, IPCounts } from './types';

// ============================================================================
// IP Classification Types
// ============================================================================

/**
 * Classification categories for IP addresses.
 */
export type IPClassification =
  | 'public'      // Globally routable
  | 'private'     // RFC 1918 private ranges
  | 'loopback'    // 127.0.0.0/8, ::1
  | 'link-local'  // 169.254.0.0/16, fe80::/10
  | 'multicast'   // 224.0.0.0/4, ff00::/8
  | 'reserved'    // 240.0.0.0/4, other reserved
  | 'unspecified' // 0.0.0.0, ::
  | 'broadcast'   // 255.255.255.255
  | 'documentation' // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32
  | 'cgnat';      // 100.64.0.0/10 (Carrier-grade NAT)

/**
 * Options for filtering IP addresses.
 */
export interface IPFilterOptions {
  /**
   * Keep public (globally routable) addresses.
   * @default true
   */
  keepPublic?: boolean;

  /**
   * Keep private (RFC 1918) addresses.
   * @default true
   */
  keepPrivate?: boolean;

  /**
   * Keep loopback addresses (127.x.x.x, ::1).
   * @default false
   */
  keepLoopback?: boolean;

  /**
   * Keep link-local addresses (169.254.x.x, fe80::).
   * @default false
   */
  keepLinkLocal?: boolean;

  /**
   * Keep multicast addresses (224.x.x.x - 239.x.x.x, ff00::).
   * @default false
   */
  keepMulticast?: boolean;

  /**
   * Keep reserved/future use addresses (240.x.x.x - 255.x.x.x).
   * @default false
   */
  keepReserved?: boolean;

  /**
   * Keep unspecified addresses (0.0.0.0, ::).
   * @default false
   */
  keepUnspecified?: boolean;

  /**
   * Keep broadcast address (255.255.255.255).
   * @default false
   */
  keepBroadcast?: boolean;

  /**
   * Keep documentation addresses (TEST-NET ranges, 2001:db8::).
   * @default false
   */
  keepDocumentation?: boolean;

  /**
   * Keep CGNAT addresses (100.64.0.0/10).
   * @default true
   */
  keepCgnat?: boolean;
}

/**
 * Default filter options - keep only public and private addresses.
 */
export const DEFAULT_FILTER_OPTIONS: Required<IPFilterOptions> = {
  keepPublic: true,
  keepPrivate: true,
  keepLoopback: false,
  keepLinkLocal: false,
  keepMulticast: false,
  keepReserved: false,
  keepUnspecified: false,
  keepBroadcast: false,
  keepDocumentation: false,
  keepCgnat: true,
};

// ============================================================================
// IPv4 Classification
// ============================================================================

/**
 * Convert IPv4 address string to 32-bit number.
 */
function ipv4ToNumber(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;

  let result = 0;
  for (let i = 0; i < 4; i++) {
    const octet = parseInt(parts[i] ?? '0', 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return 0;
    result = (result << 8) + octet;
  }
  return result >>> 0; // Ensure unsigned
}

/**
 * Check if IPv4 address is in a given CIDR range.
 */
function isInIPv4Range(ip: string, network: string, prefix: number): boolean {
  const ipNum = ipv4ToNumber(ip);
  const netNum = ipv4ToNumber(network);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

/**
 * Classify an IPv4 address.
 */
export function classifyIPv4(ip: string): IPClassification {
  // Unspecified
  if (ip === '0.0.0.0') return 'unspecified';

  // Broadcast
  if (ip === '255.255.255.255') return 'broadcast';

  // Current network (0.0.0.0/8) - treat as unspecified
  if (isInIPv4Range(ip, '0.0.0.0', 8)) return 'unspecified';

  // Loopback (127.0.0.0/8)
  if (isInIPv4Range(ip, '127.0.0.0', 8)) return 'loopback';

  // Link-local (169.254.0.0/16)
  if (isInIPv4Range(ip, '169.254.0.0', 16)) return 'link-local';

  // Private ranges (RFC 1918)
  if (isInIPv4Range(ip, '10.0.0.0', 8)) return 'private';
  if (isInIPv4Range(ip, '172.16.0.0', 12)) return 'private';
  if (isInIPv4Range(ip, '192.168.0.0', 16)) return 'private';

  // CGNAT (100.64.0.0/10)
  if (isInIPv4Range(ip, '100.64.0.0', 10)) return 'cgnat';

  // Documentation ranges (TEST-NET)
  if (isInIPv4Range(ip, '192.0.2.0', 24)) return 'documentation';
  if (isInIPv4Range(ip, '198.51.100.0', 24)) return 'documentation';
  if (isInIPv4Range(ip, '203.0.113.0', 24)) return 'documentation';

  // Multicast (224.0.0.0/4)
  if (isInIPv4Range(ip, '224.0.0.0', 4)) return 'multicast';

  // Reserved for future use (240.0.0.0/4)
  if (isInIPv4Range(ip, '240.0.0.0', 4)) return 'reserved';

  // Everything else is public
  return 'public';
}

/**
 * Classify an IPv4 subnet (uses network address for classification).
 */
export function classifyIPv4Subnet(subnet: string): IPClassification {
  const slashIndex = subnet.lastIndexOf('/');
  if (slashIndex === -1) return classifyIPv4(subnet);

  const network = subnet.substring(0, slashIndex);
  return classifyIPv4(network);
}

// ============================================================================
// IPv6 Classification
// ============================================================================

/**
 * Expand IPv6 address to full form and return as array of 16-bit values.
 */
function expandIPv6(ip: string): number[] {
  // Strip zone ID if present
  const zoneIndex = ip.indexOf('%');
  const addr = zoneIndex !== -1 ? ip.substring(0, zoneIndex) : ip;

  const parts = addr.split(':');
  const result: number[] = [];

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] ?? '';
    if (part === '' && i > 0 && i < parts.length - 1) {
      // Middle :: - expand
      const nonEmpty = parts.filter((p) => p !== '').length;
      const zeros = 8 - nonEmpty;
      for (let j = 0; j < zeros; j++) {
        result.push(0);
      }
    } else if (part !== '') {
      result.push(parseInt(part, 16) || 0);
    } else if (i === 0 && (parts[1] ?? '') === '') {
      // Leading ::
      const nonEmpty = parts.filter((p) => p !== '').length;
      const zeros = 8 - nonEmpty;
      for (let j = 0; j < zeros; j++) {
        result.push(0);
      }
    }
  }

  // Pad to 8 if needed
  while (result.length < 8) {
    result.push(0);
  }

  return result.slice(0, 8);
}

/**
 * Check if IPv6 starts with a specific prefix.
 */
function ipv6StartsWith(ip: string, prefixHex: number, prefixBits: number): boolean {
  const parts = expandIPv6(ip);

  // Calculate how many 16-bit groups we need to check
  const fullGroups = Math.floor(prefixBits / 16);
  const remainingBits = prefixBits % 16;

  // Build the prefix value from parts
  let value = 0;
  for (let i = 0; i < fullGroups && i < parts.length; i++) {
    value = (value << 16) | (parts[i] ?? 0);
  }

  if (remainingBits > 0 && fullGroups < parts.length) {
    const mask = (~0 << (16 - remainingBits)) & 0xffff;
    value = (value << remainingBits) | (((parts[fullGroups] ?? 0) & mask) >> (16 - remainingBits));
  }

  return value === prefixHex;
}

/**
 * Classify an IPv6 address.
 */
export function classifyIPv6(ip: string): IPClassification {
  const parts = expandIPv6(ip);

  // Unspecified (::)
  if (parts.every((p) => p === 0)) return 'unspecified';

  // Loopback (::1)
  if (parts.slice(0, 7).every((p) => p === 0) && parts[7] === 1) return 'loopback';

  // Link-local (fe80::/10)
  if ((parts[0] ?? 0) >= 0xfe80 && (parts[0] ?? 0) <= 0xfebf) return 'link-local';

  // Multicast (ff00::/8)
  if (((parts[0] ?? 0) & 0xff00) === 0xff00) return 'multicast';

  // Documentation (2001:db8::/32)
  if (parts[0] === 0x2001 && parts[1] === 0x0db8) return 'documentation';

  // Unique local (fc00::/7) - similar to private
  if (((parts[0] ?? 0) & 0xfe00) === 0xfc00) return 'private';

  // Everything else is public
  return 'public';
}

/**
 * Classify an IPv6 subnet (uses network address for classification).
 */
export function classifyIPv6Subnet(subnet: string): IPClassification {
  const slashIndex = subnet.lastIndexOf('/');
  if (slashIndex === -1) return classifyIPv6(subnet);

  const network = subnet.substring(0, slashIndex);
  return classifyIPv6(network);
}

// ============================================================================
// Filtering Functions
// ============================================================================

/**
 * Check if a classification should be kept based on filter options.
 */
function shouldKeepClassification(
  classification: IPClassification,
  options: Required<IPFilterOptions>
): boolean {
  switch (classification) {
    case 'public':
      return options.keepPublic;
    case 'private':
      return options.keepPrivate;
    case 'loopback':
      return options.keepLoopback;
    case 'link-local':
      return options.keepLinkLocal;
    case 'multicast':
      return options.keepMulticast;
    case 'reserved':
      return options.keepReserved;
    case 'unspecified':
      return options.keepUnspecified;
    case 'broadcast':
      return options.keepBroadcast;
    case 'documentation':
      return options.keepDocumentation;
    case 'cgnat':
      return options.keepCgnat;
    default:
      return true;
  }
}

/**
 * Filter an array of IPv4 addresses based on classification.
 */
export function filterIPv4Addresses(
  addresses: string[],
  options: IPFilterOptions = {}
): string[] {
  const opts: Required<IPFilterOptions> = { ...DEFAULT_FILTER_OPTIONS, ...options };
  return addresses.filter((ip) => {
    const classification = classifyIPv4(ip);
    return shouldKeepClassification(classification, opts);
  });
}

/**
 * Filter an array of IPv6 addresses based on classification.
 */
export function filterIPv6Addresses(
  addresses: string[],
  options: IPFilterOptions = {}
): string[] {
  const opts: Required<IPFilterOptions> = { ...DEFAULT_FILTER_OPTIONS, ...options };
  return addresses.filter((ip) => {
    const classification = classifyIPv6(ip);
    return shouldKeepClassification(classification, opts);
  });
}

/**
 * Filter an array of IPv4 subnets based on classification.
 */
export function filterIPv4Subnets(
  subnets: string[],
  options: IPFilterOptions = {}
): string[] {
  const opts: Required<IPFilterOptions> = { ...DEFAULT_FILTER_OPTIONS, ...options };
  return subnets.filter((subnet) => {
    const classification = classifyIPv4Subnet(subnet);
    return shouldKeepClassification(classification, opts);
  });
}

/**
 * Filter an array of IPv6 subnets based on classification.
 */
export function filterIPv6Subnets(
  subnets: string[],
  options: IPFilterOptions = {}
): string[] {
  const opts: Required<IPFilterOptions> = { ...DEFAULT_FILTER_OPTIONS, ...options };
  return subnets.filter((subnet) => {
    const classification = classifyIPv6Subnet(subnet);
    return shouldKeepClassification(classification, opts);
  });
}

/**
 * Filter an entire IPSummary based on classification options.
 * Returns a new IPSummary with filtered results and updated counts.
 */
export function filterIPSummary(
  summary: IPSummary,
  options: IPFilterOptions = {}
): IPSummary {
  const ipv4Addresses = filterIPv4Addresses(summary.ipv4Addresses, options);
  const ipv6Addresses = filterIPv6Addresses(summary.ipv6Addresses, options);
  const ipv4Subnets = filterIPv4Subnets(summary.ipv4Subnets, options);
  const ipv6Subnets = filterIPv6Subnets(summary.ipv6Subnets, options);

  const counts: IPCounts = {
    ipv4: ipv4Addresses.length,
    ipv6: ipv6Addresses.length,
    ipv4Subnets: ipv4Subnets.length,
    ipv6Subnets: ipv6Subnets.length,
    total: ipv4Addresses.length + ipv6Addresses.length + ipv4Subnets.length + ipv6Subnets.length,
  };

  return {
    ipv4Addresses,
    ipv6Addresses,
    ipv4Subnets,
    ipv6Subnets,
    counts,
  };
}
