/**
 * Pack Provider Interface
 *
 * Provides an abstraction layer for loading rule packs from different sources:
 * - Local file-based packs (OSS default)
 * - Cloud licensing (via @sentriflow/licensing)
 * - Offline bundles
 *
 * This enables the commercial licensing package to provide cloud-based
 * pack loading without modifying the core engine.
 *
 * @module pack-provider
 */

import type { IRule, RulePack, RulePackMetadata } from '../types/IRule';

/**
 * Information about available pack updates
 */
export interface PackUpdateInfo {
  /** Feed/pack identifier */
  feedId: string;

  /** Currently cached version */
  currentVersion: string;

  /** Available version on server */
  availableVersion: string;

  /** Download size in bytes (if known) */
  downloadSize?: number;
}

/**
 * License status information
 */
export interface PackProviderLicenseStatus {
  /** Whether the license is currently valid */
  isValid: boolean;

  /** License tier */
  tier: 'community' | 'professional' | 'enterprise' | string;

  /** List of entitled feed/pack IDs */
  entitledFeeds: string[];

  /** Whether currently operating in offline mode */
  isOffline?: boolean;

  /** ISO timestamp when cached license expires */
  cacheExpiresAt?: string;

  /** Number of packs available in cache */
  cachedPackCount?: number;

  /** Total number of rules available */
  totalRuleCount?: number;

  /** Whether updates are available */
  hasUpdates?: boolean;
}

/**
 * Pack Provider Interface
 *
 * Abstracts rule pack loading to support different sources:
 * - Default: Local file loading with license key
 * - Cloud: Network-based activation and downloads
 * - Offline: Air-gapped bundle loading
 *
 * Usage:
 * ```typescript
 * import { setPackProvider, getPackProvider } from '@sentriflow/core';
 *
 * // Use cloud provider (requires @sentriflow/licensing)
 * const cloudProvider = new CloudPackProvider({ apiUrl, licenseKey });
 * setPackProvider(cloudProvider);
 *
 * // Load packs using the registered provider
 * const packs = await getPackProvider().loadPacks();
 * ```
 */
export interface IPackProvider {
  /**
   * Load all available rule packs
   *
   * @returns Promise resolving to array of rule packs
   * @throws Error if loading fails
   */
  loadPacks(): Promise<RulePack[]>;

  /**
   * Check for available updates
   *
   * Optional - only implemented by cloud/network providers.
   * Local providers can return empty array.
   *
   * @returns Promise resolving to array of update info
   */
  checkForUpdates?(): Promise<PackUpdateInfo[]>;

  /**
   * Download and apply available updates
   *
   * Optional - only implemented by cloud/network providers.
   *
   * @param feedIds - Specific feeds to update (all if undefined)
   * @returns Promise resolving to number of packs updated
   */
  applyUpdates?(feedIds?: string[]): Promise<number>;

  /**
   * Get current license status
   *
   * Optional - only implemented by licensed providers.
   * OSS providers can return a default community status.
   *
   * @returns Promise resolving to license status
   */
  getLicenseStatus?(): Promise<PackProviderLicenseStatus>;

  /**
   * Clean up resources
   *
   * Optional - called when provider is being replaced or application exits.
   * Should clear sensitive data from memory.
   */
  destroy?(): void;
}

/**
 * Result of loading a single pack
 */
export interface PackLoadResult {
  /** The loaded rule pack */
  pack: RulePack;

  /** Source of the pack (file path, feed ID, etc.) */
  source: string;

  /** ISO timestamp when the pack expires (if applicable) */
  validUntil?: string;
}

/**
 * Options for the default local pack provider
 */
export interface LocalPackProviderOptions {
  /** License key for decryption */
  licenseKey: string;

  /** Paths to .grpx pack files */
  packPaths: string[];

  /** Optional machine ID for node-locked licenses */
  machineId?: string;

  /** Fail on first error (default: false, continue loading other packs) */
  strict?: boolean;
}
