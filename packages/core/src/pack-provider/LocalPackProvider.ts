/**
 * Local Pack Provider
 *
 * Default IPackProvider implementation for local file-based pack loading.
 * Uses the existing loadEncryptedPack function for .grpx files.
 *
 * @module pack-provider/LocalPackProvider
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { resolve, basename } from 'path';
import type {
  IPackProvider,
  PackUpdateInfo,
  PackProviderLicenseStatus,
  LocalPackProviderOptions,
} from './PackProvider';
import type { RulePack } from '../types/IRule';
import { loadEncryptedPack, validatePackFormat, PackLoadError } from '../pack-loader';

/**
 * Local file-based pack provider
 *
 * Loads encrypted rule packs (.grpx) from the local filesystem
 * using a license key for decryption.
 *
 * @example
 * ```typescript
 * const provider = new LocalPackProvider({
 *   licenseKey: 'XXXX-XXXX-XXXX-XXXX',
 *   packPaths: ['./rules/security.grpx', './rules/compliance.grpx'],
 * });
 *
 * const packs = await provider.loadPacks();
 * ```
 */
export class LocalPackProvider implements IPackProvider {
  private readonly licenseKey: string;
  private readonly packPaths: string[];
  private readonly machineId?: string;
  private readonly strict: boolean;

  private loadedPacks: RulePack[] = [];
  private lastLoadError: string | null = null;

  constructor(options: LocalPackProviderOptions) {
    this.licenseKey = options.licenseKey;
    this.packPaths = options.packPaths.map((p) => resolve(p));
    this.machineId = options.machineId;
    this.strict = options.strict ?? false;
  }

  /**
   * Load all configured pack files
   *
   * @returns Promise resolving to array of loaded RulePacks
   * @throws Error if strict mode and any pack fails to load
   */
  async loadPacks(): Promise<RulePack[]> {
    const packs: RulePack[] = [];
    const errors: string[] = [];

    for (const packPath of this.packPaths) {
      try {
        const pack = await this.loadSinglePack(packPath);
        packs.push(pack);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const fileName = basename(packPath);

        if (this.strict) {
          throw new Error(`Failed to load pack ${fileName}: ${message}`);
        }

        errors.push(`${fileName}: ${message}`);
        console.warn(`Warning: Failed to load pack ${fileName}: ${message}`);
      }
    }

    this.loadedPacks = packs;
    this.lastLoadError = errors.length > 0 ? errors.join('; ') : null;

    return packs;
  }

  /**
   * Check for updates (not supported for local files)
   *
   * @returns Empty array - local files don't support updates
   */
  async checkForUpdates(): Promise<PackUpdateInfo[]> {
    // Local file provider doesn't support update checking
    return [];
  }

  /**
   * Apply updates (not supported for local files)
   *
   * @returns 0 - local files don't support updates
   */
  async applyUpdates(_feedIds?: string[]): Promise<number> {
    // Local file provider doesn't support updates
    return 0;
  }

  /**
   * Get license status
   *
   * Returns basic status based on loaded packs.
   */
  async getLicenseStatus(): Promise<PackProviderLicenseStatus> {
    return {
      isValid: this.loadedPacks.length > 0,
      tier: 'community', // Local packs don't have tier info
      entitledFeeds: this.loadedPacks.map((p) => p.name),
      isOffline: true, // Local is always "offline"
      cachedPackCount: this.loadedPacks.length,
      totalRuleCount: this.loadedPacks.reduce((sum, p) => sum + p.rules.length, 0),
      hasUpdates: false,
    };
  }

  /**
   * Clean up resources
   */
  destroy(): void {
    // Clear loaded packs
    this.loadedPacks = [];
  }

  /**
   * Load a single pack file
   *
   * @param packPath - Path to the .grpx file
   * @returns Loaded RulePack
   */
  private async loadSinglePack(packPath: string): Promise<RulePack> {
    // Check file exists
    if (!existsSync(packPath)) {
      throw new Error(`Pack file not found: ${packPath}`);
    }

    // Read binary data
    const packData = await readFile(packPath);

    // Validate format
    if (!validatePackFormat(packData)) {
      throw new Error('Invalid pack format');
    }

    // Load and decrypt
    const loadedPack = await loadEncryptedPack(packData, {
      licenseKey: this.licenseKey,
      machineId: this.machineId,
      timeout: 10000,
    });

    // Convert LoadedPack to RulePack
    return {
      ...loadedPack.metadata,
      priority: 200, // High priority for licensed packs
      rules: loadedPack.rules,
    };
  }

  /**
   * Get the last load error message (if any)
   */
  getLastError(): string | null {
    return this.lastLoadError;
  }

  /**
   * Get list of configured pack paths
   */
  getPackPaths(): readonly string[] {
    return this.packPaths;
  }
}

/**
 * Create a local pack provider
 *
 * Factory function for creating LocalPackProvider instances.
 *
 * @param options - Provider configuration
 * @returns Configured LocalPackProvider
 */
export function createLocalPackProvider(
  options: LocalPackProviderOptions
): LocalPackProvider {
  return new LocalPackProvider(options);
}
