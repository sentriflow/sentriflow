// packages/core/src/ip/extractor.ts

import type { IPAddressType, IPSummary, IPCounts, ExtractOptions } from './types';
import { InputValidationError, DEFAULT_MAX_CONTENT_SIZE } from './types';

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Strip zone ID from IPv6 address.
 * e.g., "fe80::1%eth0" -> "fe80::1"
 *
 * @param ip - IPv6 address string (with or without zone ID)
 * @returns IPv6 address without zone ID
 */
function stripZoneId(ip: string): string {
  const zoneIndex = ip.indexOf('%');
  return zoneIndex !== -1 ? ip.substring(0, zoneIndex) : ip;
}

// ============================================================================
// Regex Factory Functions
// ============================================================================

/**
 * Create IPv4 pattern regex.
 * Using factory function prevents lastIndex state issues with global flag.
 */
function createIPv4Pattern(): RegExp {
  return /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g;
}

/**
 * Create IPv4 CIDR pattern regex.
 */
function createIPv4CidrPattern(): RegExp {
  return /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(?:3[0-2]|[12]?[0-9])\b/g;
}

/**
 * Create IPv4 + subnet mask pattern regex.
 */
function createIPv4WithMaskPattern(): RegExp {
  return /\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\s+(255\.(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\b/g;
}

/**
 * Create IPv4 + "mask" keyword + subnet mask pattern regex.
 */
function createIPv4WithMaskKeywordPattern(): RegExp {
  return /\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\s+mask\s+(255\.(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\b/gi;
}

/**
 * Create IPv4 + wildcard mask pattern regex.
 */
function createIPv4WithWildcardPattern(): RegExp {
  return /\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\s+(0\.(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\b/g;
}

/**
 * Create IPv6 pattern regex.
 */
function createIPv6Pattern(): RegExp {
  return /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::/g;
}

/**
 * Create IPv6 CIDR pattern regex.
 * Uses negative lookahead (?!\d) to prevent matching partial prefixes like /12 from /129
 */
function createIPv6CidrPattern(): RegExp {
  return /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::)\/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])(?!\d)/g;
}

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate an IPv4 address string.
 * Rejects leading zeros (e.g., 192.168.01.1 is invalid).
 *
 * @param ip - String to validate
 * @returns true if valid IPv4 address
 */
export function isValidIPv4(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;

  const octets = ip.split('.');
  if (octets.length !== 4) return false;

  for (const octet of octets) {
    // Must be a number without leading zeros (except "0" itself)
    if (!/^\d+$/.test(octet)) return false;
    if (octet.length > 1 && octet.startsWith('0')) return false;

    const num = parseInt(octet, 10);
    if (isNaN(num) || num < 0 || num > 255) return false;
  }

  return true;
}

/**
 * Validate an IPv6 address string.
 * Handles compressed notation (::) and strips zone IDs (%eth0).
 *
 * @param ip - String to validate (with or without zone ID)
 * @returns true if valid IPv6 address
 */
export function isValidIPv6(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;

  // Strip zone ID if present (e.g., fe80::1%eth0)
  const addr = stripZoneId(ip);

  // Must have at least one colon
  if (!addr.includes(':')) return false;

  // Triple colons are invalid
  if (addr.includes(':::')) return false;

  // Count double colons - only one allowed
  const doubleColonCount = (addr.match(/::/g) || []).length;
  if (doubleColonCount > 1) return false;

  // Split by colon
  const parts = addr.split(':');

  // Handle :: compression
  if (doubleColonCount === 1) {
    // With ::, we need to have fewer than 8 parts total
    // The empty strings from :: are counted
    const nonEmptyParts = parts.filter((p) => p !== '');

    // Each non-empty part must be valid hex (1-4 digits)
    for (const part of nonEmptyParts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
    }

    // With ::, we can have at most 7 non-empty parts (8 - 1 for the zero run)
    if (nonEmptyParts.length > 7) return false;
  } else {
    // No ::, must have exactly 8 parts
    if (parts.length !== 8) return false;

    for (const part of parts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
    }
  }

  return true;
}

/**
 * Validate a CIDR subnet notation.
 *
 * @param subnet - String in format "IP/prefix"
 * @returns true if valid CIDR notation
 */
export function isValidSubnet(subnet: string): boolean {
  if (!subnet || typeof subnet !== 'string') return false;

  const slashIndex = subnet.lastIndexOf('/');
  if (slashIndex === -1) return false;

  const ip = subnet.substring(0, slashIndex);
  const prefixStr = subnet.substring(slashIndex + 1);

  // Prefix must be a number
  if (!/^\d+$/.test(prefixStr)) return false;
  const prefix = parseInt(prefixStr, 10);

  // Check if IPv4 or IPv6
  if (isValidIPv4(ip)) {
    return prefix >= 0 && prefix <= 32;
  } else if (isValidIPv6(ip)) {
    return prefix >= 0 && prefix <= 128;
  }

  return false;
}

// ============================================================================
// Normalization Functions
// ============================================================================

/**
 * Normalize IPv4 address to canonical form.
 * Removes leading zeros from octets.
 *
 * @param ip - Valid IPv4 address
 * @returns Normalized IPv4 string
 */
export function normalizeIPv4(ip: string): string {
  return ip
    .split('.')
    .map((octet) => parseInt(octet, 10).toString())
    .join('.');
}

/**
 * Normalize IPv6 address to canonical form.
 * - Lowercase hex digits
 * - Removes leading zeros from groups
 * - Zone ID removed
 * - Fully expanded to 8 groups
 *
 * @param ip - Valid IPv6 address
 * @returns Normalized IPv6 string (lowercase, no zone ID, fully expanded)
 */
export function normalizeIPv6(ip: string): string {
  // Strip zone ID and convert to lowercase
  const addr = stripZoneId(ip).toLowerCase();

  // Handle :: expansion
  if (addr.includes('::')) {
    const sides = addr.split('::');
    const left = sides[0] ? sides[0].split(':').filter((p) => p !== '') : [];
    const right = sides[1] ? sides[1].split(':').filter((p) => p !== '') : [];

    // Calculate how many zeros we need
    const zerosNeeded = 8 - left.length - right.length;

    const expanded: string[] = [];

    // Add left parts
    for (const part of left) {
      expanded.push(parseInt(part, 16).toString(16));
    }

    // Add zeros
    for (let i = 0; i < zerosNeeded; i++) {
      expanded.push('0');
    }

    // Add right parts
    for (const part of right) {
      expanded.push(parseInt(part, 16).toString(16));
    }

    return expanded.join(':');
  }

  // No ::, just normalize each part
  const parts = addr.split(':');
  const result: string[] = [];

  for (const part of parts) {
    if (part !== '') {
      result.push(parseInt(part, 16).toString(16));
    }
  }

  return result.join(':');
}

// ============================================================================
// Comparison Functions
// ============================================================================

/**
 * Validate and clamp octet value to valid range.
 * T019/T020/T021: Defensive bounds checking for IPv4 octets.
 *
 * @param n - Raw number value
 * @returns Valid octet value (0-255), clamped if out of range
 */
function clampOctet(n: number): number {
  // T021: Check if value is an integer
  if (!Number.isInteger(n)) {
    return 0;
  }
  // T019/T020: Clamp to valid octet range
  if (n < 0 || n > 255) {
    return 0;
  }
  return n;
}

/**
 * Convert IPv4 to 32-bit number for comparison.
 * Uses defensive octet validation to handle malformed input.
 */
function ipv4ToNumber(ip: string): number {
  const octets = ip.split('.').map((n) => clampOctet(Number(n)));
  const o0 = octets[0] ?? 0;
  const o1 = octets[1] ?? 0;
  const o2 = octets[2] ?? 0;
  const o3 = octets[3] ?? 0;
  return ((o0 << 24) >>> 0) + (o1 << 16) + (o2 << 8) + o3;
}

/**
 * Compare two IPv4 addresses numerically.
 *
 * @returns -1 if a < b, 0 if equal, 1 if a > b
 */
export function compareIPv4(a: string, b: string): number {
  const numA = ipv4ToNumber(a);
  const numB = ipv4ToNumber(b);
  return numA < numB ? -1 : numA > numB ? 1 : 0;
}

/**
 * Expand IPv6 to full form (8 groups) for comparison.
 */
function expandIPv6(ip: string): string[] {
  // Strip zone ID
  const addr = stripZoneId(ip);
  const parts = addr.split(':');
  const result: string[] = [];

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === '' && i > 0 && i < parts.length - 1) {
      // Middle ::, expand
      const nonEmpty = parts.filter((p) => p !== '').length;
      const zeros = 8 - nonEmpty;
      for (let j = 0; j < zeros; j++) {
        result.push('0');
      }
    } else if (parts[i] !== '') {
      result.push(parts[i] ?? '0');
    } else if (i === 0 && parts[1] === '') {
      // Leading ::
      const nonEmpty = parts.filter((p) => p !== '').length;
      const zeros = 8 - nonEmpty;
      for (let j = 0; j < zeros; j++) {
        result.push('0');
      }
    } else if (i === parts.length - 1 && parts[i - 1] === '') {
      // Trailing :: already handled
    }
  }

  // Pad to 8 if needed
  while (result.length < 8) {
    result.push('0');
  }

  return result.slice(0, 8);
}

/**
 * Convert IPv6 to BigInt for comparison.
 */
function ipv6ToBigInt(ip: string): bigint {
  const parts = expandIPv6(ip);
  let result = 0n;
  for (const part of parts) {
    result = (result << 16n) + BigInt(parseInt(part, 16) || 0);
  }
  return result;
}

/**
 * Compare two IPv6 addresses numerically.
 *
 * @returns -1 if a < b, 0 if equal, 1 if a > b
 */
export function compareIPv6(a: string, b: string): number {
  const bigA = ipv6ToBigInt(a);
  const bigB = ipv6ToBigInt(b);
  return bigA < bigB ? -1 : bigA > bigB ? 1 : 0;
}

// ============================================================================
// Sorting Functions
// ============================================================================

/**
 * Sort IPv4 addresses numerically.
 *
 * @param ips - Array of valid IPv4 addresses
 * @returns New sorted array (original unchanged)
 */
export function sortIPv4Addresses(ips: string[]): string[] {
  return [...ips].sort(compareIPv4);
}

/**
 * Sort IPv6 addresses numerically.
 *
 * @param ips - Array of valid IPv6 addresses
 * @returns New sorted array (original unchanged)
 */
export function sortIPv6Addresses(ips: string[]): string[] {
  return [...ips].sort(compareIPv6);
}

/**
 * Parse subnet into network and prefix.
 * T016/T017/T018: Validates format before parsing.
 *
 * @param subnet - CIDR notation string (e.g., "10.0.0.0/24")
 * @returns Parsed network address and prefix length
 * @throws InputValidationError if format is invalid
 */
function parseSubnet(subnet: string): { network: string; prefix: number } {
  const slashIndex = subnet.lastIndexOf('/');

  // T016: Validate slash presence
  if (slashIndex === -1) {
    throw new InputValidationError(
      `Invalid subnet format (missing /): ${subnet}`,
      'INVALID_FORMAT'
    );
  }

  const prefixStr = subnet.substring(slashIndex + 1);
  const prefix = parseInt(prefixStr, 10);

  // T017: Validate prefix is a valid number
  if (isNaN(prefix)) {
    throw new InputValidationError(
      `Invalid subnet prefix: ${prefixStr}`,
      'INVALID_FORMAT'
    );
  }

  return {
    network: subnet.substring(0, slashIndex),
    prefix,
  };
}

/**
 * Sort subnets by network address, then prefix length.
 *
 * @param subnets - Array of CIDR strings
 * @param type - 'ipv4' or 'ipv6'
 * @returns New sorted array (original unchanged)
 */
export function sortSubnets(subnets: string[], type: IPAddressType): string[] {
  const compare = type === 'ipv4' ? compareIPv4 : compareIPv6;

  return [...subnets].sort((a, b) => {
    const subA = parseSubnet(a);
    const subB = parseSubnet(b);

    // First compare by network address
    const netCompare = compare(subA.network, subB.network);
    if (netCompare !== 0) return netCompare;

    // Then by prefix length (ascending)
    return subA.prefix - subB.prefix;
  });
}

// ============================================================================
// Main Extraction Function
// ============================================================================

/**
 * Check if an IPv4 address looks like a subnet mask.
 * Common masks: 255.0.0.0, 255.255.0.0, 255.255.255.0, 255.255.255.252, etc.
 * Valid masks have contiguous 1-bits followed by contiguous 0-bits.
 */
function isSubnetMask(ip: string): boolean {
  // Quick check for masks starting with 255
  if (!ip.startsWith('255.')) return false;

  const octets = ip.split('.').map(Number);

  // Convert to 32-bit number
  const num =
    ((octets[0] ?? 0) << 24) +
    ((octets[1] ?? 0) << 16) +
    ((octets[2] ?? 0) << 8) +
    (octets[3] ?? 0);

  // Valid subnet mask: when we invert and add 1, result should be power of 2
  // e.g., 255.255.255.0 -> inverted = 255 -> 255 + 1 = 256 = 2^8
  const inverted = ~num >>> 0;
  return inverted === 0 || (inverted & (inverted + 1)) === 0;
}

/**
 * Check if an IPv4 address looks like a wildcard mask (inverse subnet mask).
 * Common wildcards: 0.0.0.255, 0.0.255.255, 0.255.255.255, etc.
 * Valid wildcards have contiguous 0-bits followed by contiguous 1-bits.
 */
function isWildcardMask(ip: string): boolean {
  // Quick check - wildcards typically start with 0
  if (!ip.startsWith('0.')) return false;

  const octets = ip.split('.').map(Number);

  // Convert to 32-bit number
  const num =
    ((octets[0] ?? 0) << 24) +
    ((octets[1] ?? 0) << 16) +
    ((octets[2] ?? 0) << 8) +
    (octets[3] ?? 0);

  // Valid wildcard mask: num + 1 should be power of 2
  // e.g., 0.0.0.255 -> 255 + 1 = 256 = 2^8
  return num === 0 || ((num + 1) & num) === 0;
}

/**
 * Convert a subnet mask to CIDR prefix length.
 * e.g., 255.255.255.0 -> 24, 255.255.0.0 -> 16
 * Returns -1 if not a valid subnet mask.
 */
function maskToCidr(mask: string): number {
  if (!isSubnetMask(mask)) return -1;

  const octets = mask.split('.').map(Number);
  const num =
    ((octets[0] ?? 0) << 24) +
    ((octets[1] ?? 0) << 16) +
    ((octets[2] ?? 0) << 8) +
    (octets[3] ?? 0);

  // Count leading 1-bits
  let prefix = 0;
  let n = num >>> 0; // Ensure unsigned
  while (n & 0x80000000) {
    prefix++;
    n = (n << 1) >>> 0;
  }
  return prefix;
}

/**
 * Convert a wildcard mask to CIDR prefix length.
 * e.g., 0.0.0.255 -> 24 (matches /24 network), 0.0.255.255 -> 16
 * Returns -1 if not a valid wildcard mask.
 */
function wildcardToCidr(wildcard: string): number {
  if (!isWildcardMask(wildcard)) return -1;

  const octets = wildcard.split('.').map(Number);
  const num =
    ((octets[0] ?? 0) << 24) +
    ((octets[1] ?? 0) << 16) +
    ((octets[2] ?? 0) << 8) +
    (octets[3] ?? 0);

  // Wildcard is inverse of mask, so count leading 0-bits
  // 0.0.0.255 (00000000.00000000.00000000.11111111) = 24 leading zeros = /24
  let prefix = 0;
  let n = num >>> 0;
  while (prefix < 32 && !(n & 0x80000000)) {
    prefix++;
    n = (n << 1) >>> 0;
  }
  return prefix;
}

/**
 * Create an empty IP summary.
 */
function createEmptyIPSummary(): IPSummary {
  return {
    ipv4Addresses: [],
    ipv6Addresses: [],
    ipv4Subnets: [],
    ipv6Subnets: [],
    counts: {
      ipv4: 0,
      ipv6: 0,
      ipv4Subnets: 0,
      ipv6Subnets: 0,
      total: 0,
    },
  };
}

/**
 * Extract all IP addresses and subnets from configuration text.
 *
 * @param content - Raw configuration file content
 * @param options - Optional extraction settings
 * @returns IPSummary with deduplicated, sorted addresses and subnets
 */
export function extractIPSummary(content: string, options: ExtractOptions = {}): IPSummary {
  if (!content || typeof content !== 'string') {
    return createEmptyIPSummary();
  }

  // T011/T012: Validate content size to prevent DoS via memory exhaustion
  const maxSize = options.maxContentSize ?? DEFAULT_MAX_CONTENT_SIZE;
  if (content.length > maxSize) {
    throw new InputValidationError(
      `Content exceeds maximum size of ${maxSize} bytes`,
      'SIZE_LIMIT_EXCEEDED'
    );
  }

  const ipv4Set = new Set<string>();
  const ipv6Set = new Set<string>();
  const ipv4SubnetSet = new Set<string>();
  const ipv6SubnetSet = new Set<string>();

  // Track subnet network addresses to avoid double-counting
  const subnetNetworks = new Set<string>();

  // Track IP addresses paired with masks (so we don't double-count them)
  const ipsWithMasks = new Set<string>();

  // Extract IPv4 subnets first (so we can exclude their network addresses from standalone IPs)
  if (!options.skipSubnets) {
    // Extract CIDR notation subnets (e.g., 10.0.0.0/24)
    const ipv4CidrMatches = content.matchAll(createIPv4CidrPattern());
    for (const match of ipv4CidrMatches) {
      const subnet = match[0];
      if (isValidSubnet(subnet)) {
        const { network } = parseSubnet(subnet);
        const normalizedNetwork = normalizeIPv4(network);
        ipv4SubnetSet.add(`${normalizedNetwork}/${parseSubnet(subnet).prefix}`);
        subnetNetworks.add(normalizedNetwork);
      }
    }

    // Extract IP + mask pairs (e.g., "192.168.1.1 255.255.255.0")
    // These are interface addresses with their subnet info
    const ipMaskMatches = content.matchAll(createIPv4WithMaskPattern());
    for (const match of ipMaskMatches) {
      const ip = match[1];
      const mask = match[2];
      if (ip && mask && isValidIPv4(ip) && isSubnetMask(mask)) {
        const normalizedIP = normalizeIPv4(ip);
        const prefix = maskToCidr(mask);
        if (prefix >= 0) {
          // Add as subnet with the host IP (interface address)
          ipv4SubnetSet.add(`${normalizedIP}/${prefix}`);
          ipsWithMasks.add(normalizedIP);
        }
      }
    }

    // Extract IP + "mask" + mask pairs (e.g., "network 10.0.0.0 mask 255.0.0.0" in BGP)
    const ipMaskKeywordMatches = content.matchAll(createIPv4WithMaskKeywordPattern());
    for (const match of ipMaskKeywordMatches) {
      const ip = match[1];
      const mask = match[2];
      if (ip && mask && isValidIPv4(ip) && isSubnetMask(mask)) {
        const normalizedIP = normalizeIPv4(ip);
        const prefix = maskToCidr(mask);
        if (prefix >= 0) {
          // Add as subnet
          ipv4SubnetSet.add(`${normalizedIP}/${prefix}`);
          ipsWithMasks.add(normalizedIP);
        }
      }
    }

    // Extract IP + wildcard pairs (e.g., "192.168.1.0 0.0.0.255" in ACLs)
    // These define network ranges in access lists
    const ipWildcardMatches = content.matchAll(createIPv4WithWildcardPattern());
    for (const match of ipWildcardMatches) {
      const ip = match[1];
      const wildcard = match[2];
      if (ip && wildcard && isValidIPv4(ip) && isWildcardMask(wildcard)) {
        const normalizedIP = normalizeIPv4(ip);
        const prefix = wildcardToCidr(wildcard);
        if (prefix >= 0) {
          // Add as subnet (network address from ACL)
          ipv4SubnetSet.add(`${normalizedIP}/${prefix}`);
          ipsWithMasks.add(normalizedIP);
        }
      }
    }
  }

  // Extract IPv4 addresses (excluding those that are subnet network addresses)
  const ipv4Matches = content.matchAll(createIPv4Pattern());
  for (const match of ipv4Matches) {
    const ip = match[0];
    if (isValidIPv4(ip)) {
      const normalized = normalizeIPv4(ip);
      // Only add if:
      // - Not a subnet network address already captured from CIDR notation
      // - Not already captured as part of IP+mask or IP+wildcard pair
      // - Not a subnet mask (255.x.x.x)
      // - Not a wildcard mask (0.x.x.x patterns)
      if (
        !subnetNetworks.has(normalized) &&
        !ipsWithMasks.has(normalized) &&
        !isSubnetMask(normalized) &&
        !isWildcardMask(normalized)
      ) {
        ipv4Set.add(normalized);
      }
    }
  }

  // Extract IPv6 if not skipped
  if (!options.skipIPv6) {
    // Extract IPv6 subnets first
    if (!options.skipSubnets) {
      const ipv6CidrMatches = content.matchAll(createIPv6CidrPattern());
      for (const match of ipv6CidrMatches) {
        const subnet = match[0];
        if (isValidSubnet(subnet)) {
          const { network, prefix } = parseSubnet(subnet);
          const normalizedNetwork = normalizeIPv6(network);
          ipv6SubnetSet.add(`${normalizedNetwork}/${prefix}`);
          subnetNetworks.add(normalizedNetwork);
        }
      }
    }

    // Extract IPv6 addresses
    const ipv6Matches = content.matchAll(createIPv6Pattern());
    for (const match of ipv6Matches) {
      const ip = match[0];
      if (isValidIPv6(ip)) {
        const normalized = normalizeIPv6(ip);
        if (!subnetNetworks.has(normalized)) {
          ipv6Set.add(normalized);
        }
      }
    }
  }

  // If includeSubnetNetworks is true, add subnet network addresses to the address sets
  if (options.includeSubnetNetworks) {
    for (const subnet of ipv4SubnetSet) {
      const { network } = parseSubnet(subnet);
      ipv4Set.add(network);
    }
    for (const subnet of ipv6SubnetSet) {
      const { network } = parseSubnet(subnet);
      ipv6Set.add(network);
    }
  }

  // Convert sets to sorted arrays
  const ipv4Addresses = sortIPv4Addresses([...ipv4Set]);
  const ipv6Addresses = sortIPv6Addresses([...ipv6Set]);
  const ipv4Subnets = sortSubnets([...ipv4SubnetSet], 'ipv4');
  const ipv6Subnets = sortSubnets([...ipv6SubnetSet], 'ipv6');

  // Calculate counts
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
