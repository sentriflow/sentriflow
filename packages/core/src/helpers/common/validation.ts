// packages/rule-helpers/src/common/validation.ts
// Centralized validation helpers for network configuration rules

import { parseIp, prefixToMask } from './helpers';

// ============================================================================
// String Comparison Helpers
// ============================================================================

/**
 * Case-insensitive string equality check.
 * @param a First string
 * @param b Second string
 * @returns true if strings are equal (case-insensitive)
 */
export const equalsIgnoreCase = (a: string, b: string): boolean =>
  a.toLowerCase() === b.toLowerCase();

/**
 * Case-insensitive substring check.
 * @param haystack String to search in
 * @param needle String to search for
 * @returns true if needle is found (case-insensitive)
 */
export const includesIgnoreCase = (haystack: string, needle: string): boolean =>
  haystack.toLowerCase().includes(needle.toLowerCase());

/**
 * Case-insensitive prefix check.
 * @param str String to check
 * @param prefix Prefix to match
 * @returns true if str starts with prefix (case-insensitive)
 */
export const startsWithIgnoreCase = (str: string, prefix: string): boolean =>
  str.toLowerCase().startsWith(prefix.toLowerCase());

// ============================================================================
// Numeric Validation Helpers
// ============================================================================

/**
 * Parse a string to integer, returning null if invalid.
 * @param value String to parse
 * @returns Parsed integer or null if invalid
 */
export const parseInteger = (value: string): number | null => {
  const num = parseInt(value, 10);
  return isNaN(num) ? null : num;
};

/**
 * Check if a number is within a range (inclusive).
 * @param value Number to check
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @returns true if value is in range
 */
export const isInRange = (value: number, min: number, max: number): boolean =>
  value >= min && value <= max;

/**
 * Parse and validate a port number (1-65535).
 * @param value Port string to parse
 * @returns Port number or null if invalid
 */
export const parsePort = (value: string): number | null => {
  const port = parseInteger(value);
  if (port === null || port < 1 || port > 65535) return null;
  return port;
};

/**
 * Check if a port number is valid (1-65535).
 * @param port Port number to validate
 * @returns true if valid port
 */
export const isValidPort = (port: number): boolean =>
  Number.isInteger(port) && port >= 1 && port <= 65535;

/**
 * Parse a port range string (e.g., "1-24", "80,443", "1-10,20,30-32").
 * @param portStr Port range string
 * @returns Array of individual port numbers (empty array if no valid ports found)
 */
export const parsePortRange = (portStr: string): number[] => {
  const ports: number[] = [];
  const parts = portStr.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes('-')) {
      const rangeParts = trimmed.split('-').map((p) => parseInt(p.trim(), 10));
      const start = rangeParts[0];
      const end = rangeParts[1];
      if (start !== undefined && end !== undefined && !isNaN(start) && !isNaN(end)) {
        for (let i = start; i <= end; i++) {
          ports.push(i);
        }
      }
    } else {
      const num = parseInt(trimmed, 10);
      if (!isNaN(num)) {
        ports.push(num);
      }
    }
  }

  return ports;
};

// ============================================================================
// VLAN Validation Helpers
// ============================================================================

/**
 * Parse a VLAN ID string to number.
 * @param vlanStr VLAN ID string
 * @returns VLAN number or null if invalid
 */
export const parseVlanId = (vlanStr: string): number | null => {
  const vlan = parseInteger(vlanStr);
  if (vlan === null || vlan < 1 || vlan > 4094) return null;
  return vlan;
};

/**
 * Check if a VLAN ID is valid (1-4094).
 * @param vlanId VLAN ID to validate
 * @returns true if valid VLAN ID
 */
export const isValidVlanId = (vlanId: number): boolean =>
  Number.isInteger(vlanId) && vlanId >= 1 && vlanId <= 4094;

/**
 * Check if VLAN is the default VLAN (VLAN 1).
 * @param vlanId VLAN ID string or number
 * @returns true if VLAN 1
 */
export const isDefaultVlan = (vlanId: string | number): boolean => {
  const id = typeof vlanId === 'string' ? parseInteger(vlanId) : vlanId;
  return id === 1;
};

/**
 * Check if VLAN is in the reserved range (1002-1005 for Cisco).
 * @param vlanId VLAN ID
 * @returns true if in reserved range
 */
export const isReservedVlan = (vlanId: number): boolean =>
  vlanId >= 1002 && vlanId <= 1005;

// ============================================================================
// Feature State Helpers
// ============================================================================

/**
 * Check if a feature value represents "enabled" state.
 * Handles common variations: "enable", "enabled", "yes", "true", "on", "1"
 * @param value Feature state string
 * @returns true if enabled
 */
export const isFeatureEnabled = (value: string | undefined): boolean => {
  if (!value) return false;
  const normalized = value.toLowerCase().trim();
  return ['enable', 'enabled', 'yes', 'true', 'on', '1'].includes(normalized);
};

/**
 * Check if a feature value represents "disabled" state.
 * Handles common variations: "disable", "disabled", "no", "false", "off", "0"
 * @param value Feature state string
 * @returns true if disabled
 */
export const isFeatureDisabled = (value: string | undefined): boolean => {
  if (!value) return false;
  const normalized = value.toLowerCase().trim();
  return ['disable', 'disabled', 'no', 'false', 'off', '0'].includes(normalized);
};

// ============================================================================
// MAC Address Validation Helpers
// ============================================================================

/**
 * Validate MAC address format.
 * Supports: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX.XXXX.XXXX
 * @param mac MAC address string
 * @returns true if valid MAC format
 */
export const isValidMacAddress = (mac: string): boolean => {
  // Colon-separated (Linux/Unix style)
  if (/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(mac)) return true;
  // Hyphen-separated (Windows style)
  if (/^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$/.test(mac)) return true;
  // Dot-separated (Cisco style)
  if (/^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$/.test(mac)) return true;
  return false;
};

/**
 * Normalize MAC address to lowercase colon-separated format.
 * @param mac MAC address in any supported format
 * @returns Normalized MAC or null if invalid
 */
export const normalizeMacAddress = (mac: string): string | null => {
  if (!isValidMacAddress(mac)) return null;

  // Remove all separators and convert to lowercase
  const hex = mac.replace(/[:\-.]/g, '').toLowerCase();

  // Insert colons every 2 characters
  const matched = hex.match(/.{2}/g);
  return matched ? matched.join(':') : null;
};

// ============================================================================
// CIDR/Subnet Validation Helpers
// ============================================================================

/**
 * Result of parsing CIDR notation.
 */
export interface CidrInfo {
  /** Network address as 32-bit unsigned number */
  network: number;
  /** CIDR prefix length (0-32) */
  prefix: number;
  /** Subnet mask as 32-bit unsigned number */
  mask: number;
}

/**
 * Parse CIDR notation (e.g., "10.0.0.0/24").
 * @param cidr CIDR string
 * @returns Object with network, prefix, mask or null if invalid
 */
export const parseCidr = (cidr: string): CidrInfo | null => {
  const parts = cidr.split('/');
  if (parts.length !== 2) return null;

  const ipPart = parts[0];
  const prefixPart = parts[1];

  if (!ipPart || !prefixPart) return null;

  const network = parseIp(ipPart);
  const prefix = parseInteger(prefixPart);

  if (network === null || prefix === null) return null;
  if (prefix < 0 || prefix > 32) return null;

  const mask = prefixToMask(prefix);

  return { network, prefix, mask };
};

/**
 * Check if an IP is within a CIDR block.
 * @param ip IP address (as 32-bit number)
 * @param network Network address (as 32-bit number)
 * @param mask Subnet mask (as 32-bit number)
 * @returns true if IP is in the network
 */
export const isIpInNetwork = (ip: number, network: number, mask: number): boolean =>
  (ip & mask) === (network & mask);

/**
 * Check if an IP string is within a CIDR block string.
 * @param ipStr IP address string
 * @param cidrStr CIDR notation string
 * @returns true if IP is in the CIDR block, false if invalid or not in range
 */
export const isIpInCidr = (ipStr: string, cidrStr: string): boolean => {
  const ip = parseIp(ipStr);
  const cidr = parseCidr(cidrStr);

  if (ip === null || cidr === null) return false;

  return isIpInNetwork(ip, cidr.network, cidr.mask);
};
