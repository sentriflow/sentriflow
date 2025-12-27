/**
 * GRX2 Extended Loader Types
 *
 * Types for encrypted GRX2 rule pack loading.
 * Used by both CLI and VS Code extension.
 *
 * @module @sentriflow/core/grx2-loader/types
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

// =============================================================================
// License Types
// =============================================================================

/**
 * JWT License payload structure
 *
 * The license key is a JWT containing this payload.
 * It can be decoded offline to get entitlements.
 */
export interface LicensePayload {
  /** Customer ID (JWT subject) */
  sub: string;

  /** Customer tier */
  tier: 'community' | 'professional' | 'enterprise';

  /** Entitled feed IDs */
  feeds: string[];

  /** API URL for cloud updates */
  api: string;

  /** Expiration timestamp (Unix seconds) */
  exp: number;

  /** Issued at timestamp (Unix seconds) */
  iat: number;

  /** Optional machine ID binding */
  mid?: string;

  /** Optional customer name */
  name?: string;
}

// =============================================================================
// GRX2 Extended Format Types
// =============================================================================

/**
 * Extended GRX2 header structure (96 bytes)
 *
 * The extended format uses version=3 and includes a wrapped TMK block
 * after the standard header.
 */
export interface GRX2ExtendedHeader {
  /** Magic bytes ("GRX2") */
  magic: Buffer;

  /** Format version (3 for extended) */
  version: number;

  /** Encryption algorithm (1 = AES-256-GCM) */
  algorithm: number;

  /** Key derivation function (1 = PBKDF2) */
  kdf: number;

  /** Key type (1 = TMK, 2 = CTMK) */
  keyType: number;

  /** Tier ID */
  tierId: number;

  /** TMK version */
  tmkVersion: number;

  /** Initialization vector (12 bytes) */
  iv: Buffer;

  /** Authentication tag (16 bytes) */
  authTag: Buffer;

  /** PBKDF2 salt (32 bytes, zeros for TMK mode) */
  salt: Buffer;

  /** Encrypted payload length */
  payloadLength: number;

  /** Pack hash (16 bytes, truncated SHA-256) */
  packHash: Buffer;

  /** Reserved bytes */
  reserved: Buffer;

  /** Indicates extended format */
  isExtended: true;

  /** Indicates portable pack (no machine binding required) */
  isPortable: boolean;

  /** Wrapped TMK embedded in pack */
  wrappedTMK: WrappedTMK;

  /** Total header size (96 + 4 + wrapped TMK length) */
  totalHeaderSize: number;
}

/**
 * Wrapped TMK structure
 *
 * TMK encrypted with LDK (derived from license key + salt).
 * Embedded in extended GRX2 packs.
 *
 * SECURITY: Uses random salt for PBKDF2 key derivation.
 * The salt is stored with the wrapped TMK, not derived from predictable values.
 */
export interface WrappedTMK {
  /** Encrypted TMK (32 bytes encrypted) */
  encryptedKey: Buffer;

  /** IV used for TMK encryption (12 bytes) */
  iv: Buffer;

  /** Auth tag for TMK (16 bytes) */
  authTag: Buffer;

  /** TMK version that was wrapped */
  tmkVersion: number;

  /**
   * Random salt for LDK derivation (32 bytes)
   * SECURITY: This is a cryptographically random value, NOT derived from machineId.
   * The machineId is used as additional input to the KDF, not as the sole salt.
   */
  ldkSalt: Buffer;
}

/**
 * Serialized wrapped TMK (for JSON storage)
 */
export interface SerializedWrappedTMK {
  /** Base64-encoded encrypted key */
  k: string;
  /** Base64-encoded IV */
  i: string;
  /** Base64-encoded auth tag */
  t: string;
  /** TMK version */
  v: number;
  /** Base64-encoded LDK salt (32 bytes random) */
  s: string;
}

// =============================================================================
// Pack Types
// =============================================================================

/**
 * Information about a loaded encrypted pack
 */
export interface EncryptedPackInfo {
  /** Feed ID */
  feedId: string;

  /** Pack name */
  name: string;

  /** Pack version */
  version: string;

  /** Publisher */
  publisher: string;

  /** Number of rules in pack */
  ruleCount: number;

  /** File path of the pack */
  filePath: string;

  /** Whether pack was loaded successfully */
  loaded: boolean;

  /** Error message if loading failed */
  error?: string;

  /** Source: local directory or cloud cache */
  source: 'local' | 'cache';
}

/**
 * GRX2 Pack loading result
 * Named GRX2PackLoadResult to avoid collision with pack-provider's PackLoadResult
 */
export interface GRX2PackLoadResult {
  /** Whether loading was successful */
  success: boolean;

  /** Loaded packs */
  packs: EncryptedPackInfo[];

  /** Total rules loaded */
  totalRules: number;

  /** Errors encountered */
  errors: string[];
}

// =============================================================================
// Error Types
// =============================================================================

/**
 * Encrypted pack error codes
 */
export type EncryptedPackErrorCode =
  | 'LICENSE_MISSING'
  | 'LICENSE_EXPIRED'
  | 'LICENSE_INVALID'
  | 'NOT_ENTITLED'
  | 'PACK_NOT_FOUND'
  | 'PACK_CORRUPTED'
  | 'DECRYPTION_FAILED'
  | 'MACHINE_MISMATCH'
  | 'NETWORK_ERROR'
  | 'API_ERROR';

/**
 * Encrypted pack error
 */
export class EncryptedPackError extends Error {
  constructor(
    message: string,
    public readonly code: EncryptedPackErrorCode,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = 'EncryptedPackError';
  }
}

// =============================================================================
// Constants
// =============================================================================

/** Standard GRX2 header size */
export const GRX2_HEADER_SIZE = 96;

/** Extended format version */
export const GRX2_EXTENDED_VERSION = 3;

/** Extended format flag in reserved byte (bit 0) */
export const GRX2_EXTENDED_FLAG = 0x01;

/** Portable pack flag in reserved byte (bit 1) - no machine binding */
export const GRX2_PORTABLE_FLAG = 0x02;

/** AES-256-GCM algorithm ID */
export const GRX2_ALGORITHM_AES_256_GCM = 1;

/** PBKDF2 KDF ID */
export const GRX2_KDF_PBKDF2 = 1;

/** TMK key type */
export const GRX2_KEY_TYPE_TMK = 1;

/** CTMK key type */
export const GRX2_KEY_TYPE_CTMK = 2;

/** Default packs directory (platform-aware) */
export const DEFAULT_PACKS_DIRECTORY = join(homedir(), '.sentriflow', 'packs');

/** Cache directory (for downloaded packs, platform-aware) */
export const CACHE_DIRECTORY = join(homedir(), '.sentriflow', 'cache');
