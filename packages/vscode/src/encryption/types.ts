/**
 * Encryption Types for SentriFlow VS Code Extension
 *
 * Re-exports types from @sentriflow/core/grx2-loader for VS Code extension use.
 * Additional VS Code-specific types are defined below.
 *
 * @module encryption/types
 */

// Re-export all types from core grx2-loader
export {
  // Types
  type LicensePayload,
  type GRX2ExtendedHeader,
  type WrappedTMK,
  type SerializedWrappedTMK,
  type EncryptedPackInfo,
  type GRX2PackLoadResult,
  type EncryptedPackErrorCode,
  // Error class
  EncryptedPackError,
  // Constants
  GRX2_HEADER_SIZE,
  GRX2_EXTENDED_VERSION,
  GRX2_EXTENDED_FLAG,
  GRX2_PORTABLE_FLAG,
  GRX2_ALGORITHM_AES_256_GCM,
  GRX2_KDF_PBKDF2,
  GRX2_KEY_TYPE_TMK,
  GRX2_KEY_TYPE_CTMK,
  DEFAULT_PACKS_DIRECTORY,
  CACHE_DIRECTORY,
} from '@sentriflow/core/grx2-loader';

// =============================================================================
// VS Code Extension-Specific Types
// =============================================================================

/**
 * Parsed license information (VS Code extension specific)
 */
export interface LicenseInfo {
  /** Raw JWT string */
  jwt: string;

  /** Decoded payload */
  payload: import('@sentriflow/core/grx2-loader').LicensePayload;

  /** Whether the license is expired */
  isExpired: boolean;

  /** Days until expiry (negative if expired) */
  daysUntilExpiry: number;

  /** Human-readable expiry date */
  expiryDate: string;
}

// =============================================================================
// Cloud Types (VS Code extension specific)
// =============================================================================

/**
 * Feed information from cloud API
 */
export interface FeedInfo {
  /** Feed ID */
  id: string;

  /** Display name */
  name: string;

  /** Current version */
  version: string;

  /** File size in bytes */
  sizeBytes: number;

  /** Last updated timestamp */
  updatedAt: string;
}

/**
 * Entitlements response from cloud API
 */
export interface EntitlementsResponse {
  /** Customer ID */
  customerId: string;

  /** Customer tier */
  tier: 'community' | 'professional' | 'enterprise';

  /** Entitled feeds */
  feeds: FeedInfo[];

  /** License expiry */
  expiresAt: string;
}

/**
 * Pack download info from cloud API
 */
export interface PackDownloadInfo {
  /** Feed ID */
  feedId: string;

  /** Signed download URL */
  url: string;

  /** URL expiry */
  expiresAt: string;

  /** Expected file size */
  sizeBytes: number;

  /** Expected SHA-256 hash */
  sha256: string;
}

/**
 * Update check result
 */
export interface UpdateCheckResult {
  /** Whether updates are available */
  hasUpdates: boolean;

  /** Feeds with available updates */
  updatesAvailable: {
    feedId: string;
    currentVersion: string;
    newVersion: string;
  }[];

  /** Last check timestamp */
  checkedAt: string;
}

// =============================================================================
// Configuration Types (VS Code extension specific)
// =============================================================================

/**
 * Encrypted packs configuration
 */
export interface EncryptedPacksConfig {
  /** Whether encrypted pack loading is enabled */
  enabled: boolean;

  /** Directory to scan for .grx2 files */
  packsDirectory: string;

  /** Auto-update behavior */
  autoUpdate: 'disabled' | 'on-activation' | 'daily' | 'manual';

  /** Whether to show encrypted packs in tree view */
  showInTree: boolean;
}

// =============================================================================
// Offline Mode Types
// =============================================================================

/**
 * Cached entitlements for offline mode
 *
 * Stores entitlements with a timestamp for 72-hour offline grace period.
 */
export interface CachedEntitlements {
  /** Cached entitlements response */
  entitlements: EntitlementsResponse;

  /** When the cache was created (ISO timestamp) */
  cachedAt: string;

  /** When the cache expires (ISO timestamp) */
  expiresAt: string;
}

/**
 * Connection status for cloud API
 */
export type CloudConnectionStatus = 'online' | 'offline' | 'unknown';
