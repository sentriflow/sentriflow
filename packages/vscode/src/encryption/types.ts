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

  /** SHA-256 hash for change detection */
  hash?: string;
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
    /** Server hash for cache comparison */
    serverHash?: string;
  }[];

  /** Number of packs skipped because cache has matching hash */
  skippedByCacheHash?: number;

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

/**
 * Cache manifest entry for a downloaded pack
 */
export interface CacheManifestEntry {
  /** Feed ID */
  feedId: string;

  /** Version string */
  version: string;

  /** SHA-256 hash of pack content */
  hash: string;

  /** Path to cached file (relative to cache dir) */
  fileName: string;

  /** When the pack was downloaded (ISO timestamp) */
  downloadedAt: string;
}

/**
 * Cache manifest - tracks downloaded packs to avoid re-downloading
 */
export interface CacheManifest {
  /** Manifest version */
  version: number;

  /** Map of feedId -> entry */
  entries: Record<string, CacheManifestEntry>;

  /** Last updated timestamp */
  updatedAt: string;
}

// =============================================================================
// Cloud License Activation Types
// =============================================================================

/**
 * License key type
 */
export type LicenseKeyType = 'jwt' | 'cloud';

/**
 * Cloud activation request
 */
export interface CloudActivationRequest {
  /** License key (XXXX-XXXX-XXXX-XXXX format) */
  licenseKey: string;

  /** Machine ID for binding */
  machineId: string;

  /** Hostname */
  hostname: string;

  /** Operating system */
  os: string;

  /** Client version */
  cliVersion: string;

  /** Unique nonce for replay protection */
  nonce: string;

  /** Request timestamp */
  timestamp: string;
}

/**
 * Wrapped TMK structure from cloud activation
 * Matches the cloud-api WrappedTMK type
 */
export interface CloudWrappedTMK {
  /** AES-256-GCM encrypted TMK (base64) */
  encryptedKey: string;

  /** 96-bit initialization vector (base64) */
  iv: string;

  /** 128-bit GCM auth tag (base64) */
  authTag: string;

  /** TMK version for rotation tracking */
  tmkVersion: number;

  /** Salt for LDK derivation (base64) */
  ldkSalt: string;
}

/**
 * Cloud activation response
 */
export interface CloudActivationResponse {
  /** Whether activation was successful */
  valid: boolean;

  /** JWT for API authentication */
  jwt: string;

  /** Wrapped TMK for pack decryption */
  wrappedTMK: CloudWrappedTMK;

  /** Wrapped customer TMK (if customer has custom feeds) */
  wrappedCustomerTMK?: CloudWrappedTMK | null;

  /** Customer tier */
  tier: 'community' | 'professional' | 'enterprise';

  /** License expiry */
  expiresAt: string;

  /** Activation ID */
  activationId: string;

  /** Entitled feeds */
  allowedFeeds: string[];

  /** Current feed versions */
  feedVersions: {
    feedId: string;
    version: string;
    hash: string;
    keyType: 'tier-master-key' | 'customer-tmk';
  }[];

  /** How long client can cache activation (seconds) */
  cacheValiditySeconds: number;

  /** Server time for clock synchronization */
  serverTime: string;
}

/**
 * License status
 */
export type LicenseStatus = 'active' | 'revoked' | 'expired';

/**
 * Stored cloud license (persisted in global state)
 */
export interface StoredCloudLicense {
  /** Original cloud license key (XXXX-XXXX-XXXX-XXXX) */
  licenseKey: string;

  /** JWT from activation */
  jwt: string;

  /** Wrapped TMK from activation */
  wrappedTMK: CloudWrappedTMK | null;

  /** Wrapped customer TMK (if applicable) */
  wrappedCustomerTMK?: CloudWrappedTMK | null;

  /** Activation ID */
  activationId: string;

  /** When the license was activated */
  activatedAt: string;

  /** API URL used for activation */
  apiUrl: string;

  /** Cache validity from server */
  cacheValiditySeconds: number;

  /** License/subscription expiry (ISO 8601) - when subscription ends */
  licenseExpiresAt?: string;

  /** Customer tier */
  tier?: 'community' | 'professional' | 'enterprise';

  /** License status - set when server returns LICENSE_REVOKED or LICENSE_EXPIRED */
  status?: LicenseStatus;

  /** ISO timestamp when license was marked as revoked/expired */
  invalidatedAt?: string;
}
