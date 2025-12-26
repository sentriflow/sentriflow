// packages/core/src/ip/types.ts

// ============================================================================
// Constants
// ============================================================================

/**
 * Default maximum content size for IP extraction (50MB).
 * Prevents DoS attacks via memory exhaustion from processing very large files.
 */
export const DEFAULT_MAX_CONTENT_SIZE = 50 * 1024 * 1024; // 50MB

// ============================================================================
// Error Types
// ============================================================================

/**
 * Error codes for input validation failures.
 */
export type InputValidationErrorCode = 'SIZE_LIMIT_EXCEEDED' | 'INVALID_FORMAT';

/**
 * Error thrown when input validation fails.
 * Used for size limits and malformed input detection.
 */
export class InputValidationError extends Error {
  constructor(
    message: string,
    public readonly code: InputValidationErrorCode
  ) {
    super(message);
    this.name = 'InputValidationError';
  }
}

// ============================================================================
// Core Types
// ============================================================================

/**
 * Discriminator for IPv4 vs IPv6 addresses.
 */
export type IPAddressType = 'ipv4' | 'ipv6';

/**
 * Represents a validated IP address (standalone, not a subnet).
 */
export interface IPAddress {
  /** The IP address string (normalized form) */
  value: string;

  /** Address type discriminator */
  type: IPAddressType;

  /** Optional: Line number where this IP was found (1-based) */
  line?: number;
}

/**
 * Represents a network address with CIDR prefix length.
 */
export interface Subnet {
  /** The network address (normalized form) */
  network: string;

  /** CIDR prefix length (0-32 for IPv4, 0-128 for IPv6) */
  prefix: number;

  /** Address type discriminator */
  type: IPAddressType;

  /** Optional: Line number where this subnet was found (1-based) */
  line?: number;
}

/**
 * Summary statistics for the extraction.
 */
export interface IPCounts {
  /** Total unique IPv4 addresses */
  ipv4: number;

  /** Total unique IPv6 addresses */
  ipv6: number;

  /** Total unique IPv4 subnets */
  ipv4Subnets: number;

  /** Total unique IPv6 subnets */
  ipv6Subnets: number;

  /** Grand total of all unique IPs and subnets */
  total: number;
}

/**
 * Aggregated extraction results for a configuration file.
 */
export interface IPSummary {
  /** Standalone IPv4 addresses (sorted numerically) */
  ipv4Addresses: string[];

  /** Standalone IPv6 addresses (sorted numerically) */
  ipv6Addresses: string[];

  /** IPv4 subnets in CIDR notation (sorted by network, then prefix) */
  ipv4Subnets: string[];

  /** IPv6 subnets in CIDR notation (sorted by network, then prefix) */
  ipv6Subnets: string[];

  /** Summary counts */
  counts: IPCounts;
}

/**
 * Options for IP extraction.
 */
export interface ExtractOptions {
  /**
   * Include line numbers in results.
   * @default false
   */
  includeLineNumbers?: boolean;

  /**
   * Skip extraction of IPv6 addresses (performance optimization).
   * @default false
   */
  skipIPv6?: boolean;

  /**
   * Skip extraction of subnets.
   * @default false
   */
  skipSubnets?: boolean;

  /**
   * Include subnet network addresses in the addresses lists.
   * When true, a subnet like 10.0.0.0/24 will add 10.0.0.0 to ipv4Addresses.
   * @default false
   */
  includeSubnetNetworks?: boolean;

  /**
   * Maximum content size in bytes.
   * Content exceeding this limit will throw InputValidationError.
   * @default DEFAULT_MAX_CONTENT_SIZE (50MB)
   */
  maxContentSize?: number;
}
