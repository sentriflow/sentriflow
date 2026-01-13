/**
 * Unified Pack Loader
 *
 * Provides multi-format pack loading support for VS Code extension.
 * Scans for both GRX2 and GRPX formats, auto-detects format from magic bytes,
 * and routes to the appropriate loader.
 *
 * Supported formats:
 * - GRX2: Extended encrypted format with embedded wrapped TMK
 * - GRPX: Encrypted format with PBKDF2 key derivation
 * - Unencrypted: Detected but not loaded (info message shown)
 *
 * @module encryption/UnifiedPackLoader
 */

import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, basename, extname } from 'node:path';
import { homedir } from 'node:os';
import type { RulePack } from '@sentriflow/core';
import {
  detectPackFormat,
  type PackFormat,
  loadEncryptedPack as loadGrpxPack,
} from '@sentriflow/core';
import { loadExtendedPack as loadGrx2Pack, isExtendedGRX2 } from './GRX2ExtendedLoader';
import { loadCloudPack, isStandardGRX2, getPackTierId, getPackKeyType } from './CloudPackLoader';
import type { EncryptedPackInfo, GRX2PackLoadResult, CloudWrappedTMK, TierId } from './types';

/**
 * Pack info with format detection
 */
export interface PackFileInfo {
  /** Absolute path to pack file */
  filePath: string;
  /** Detected format */
  format: PackFormat;
  /** Feed ID (derived from filename) */
  feedId: string;
  /** File extension */
  extension: string;
}

/**
 * Result of loading a single pack
 */
export interface PackLoadResult {
  /** Pack info */
  info: PackFileInfo;
  /** Loaded pack (if successful) */
  pack?: RulePack;
  /** Whether loading succeeded */
  loaded: boolean;
  /** Error message (if failed) */
  error?: string;
}

/**
 * Loaded pack with full data
 */
export interface LoadedPackData {
  /** Pack info */
  info: EncryptedPackInfo;
  /** Loaded pack (contains rules) */
  pack: RulePack;
}

/**
 * Result of loading all packs
 */
export interface UnifiedPackLoadResult {
  /** Whether overall operation succeeded */
  success: boolean;
  /** Loaded packs info */
  packs: EncryptedPackInfo[];
  /** Loaded packs with full data (rules) */
  loadedPacks: LoadedPackData[];
  /** Total rules loaded */
  totalRules: number;
  /** Errors encountered */
  errors: string[];
  /** Skipped packs (unencrypted format) */
  skipped: PackFileInfo[];
}

/**
 * Resolve path with tilde expansion
 */
function resolvePath(path: string): string {
  if (path.startsWith('~')) {
    return join(homedir(), path.slice(1));
  }
  return path;
}

/**
 * Scan directory for pack files (.grx2 and .grpx)
 *
 * @param directory - Directory to scan
 * @param debug - Optional debug logger
 * @returns Array of pack file info with detected formats
 */
export async function scanForPackFiles(
  directory: string,
  debug?: (msg: string) => void
): Promise<PackFileInfo[]> {
  const resolvedDir = resolvePath(directory);
  debug?.(`[UnifiedLoader] Scanning directory: ${directory} -> resolved: ${resolvedDir}`);

  if (!existsSync(resolvedDir)) {
    debug?.(`[UnifiedLoader] Directory does not exist: ${resolvedDir}`);
    return [];
  }

  const entries = await readdir(resolvedDir);
  debug?.(`[UnifiedLoader] Found ${entries.length} entries in directory`);

  // Filter for pack files (.grx2 and .grpx)
  const packExtensions = ['.grx2', '.grpx'];
  const packEntries = entries.filter((entry) => {
    const ext = extname(entry).toLowerCase();
    return packExtensions.includes(ext);
  });

  debug?.(`[UnifiedLoader] Found ${packEntries.length} pack files`);

  // Detect format for each file
  const packFiles: PackFileInfo[] = [];
  for (const entry of packEntries) {
    const filePath = join(resolvedDir, entry);
    const ext = extname(entry).toLowerCase();
    const feedId = basename(entry, ext);

    try {
      const format = await detectPackFormat(filePath);
      debug?.(`[UnifiedLoader]   ${entry}: format=${format}`);

      packFiles.push({
        filePath,
        format,
        feedId,
        extension: ext,
      });
    } catch (error) {
      debug?.(`[UnifiedLoader]   ${entry}: format detection failed - ${error}`);
      packFiles.push({
        filePath,
        format: 'unknown',
        feedId,
        extension: ext,
      });
    }
  }

  return packFiles;
}

/**
 * Context for loading cloud packs (standard GRX2)
 */
export interface CloudPackContext {
  /** Cloud license key (XXXX-XXXX-XXXX-XXXX format) */
  licenseKey: string;
  /** Wrapped tier TMK from cloud activation (primary, for backward compat) */
  wrappedTMK: CloudWrappedTMK;
  /**
   * Wrapped TMKs for all accessible tiers (tier hierarchy)
   * Maps tier ID to wrapped TMK for that tier.
   * Used to select correct TMK based on pack's tier header.
   */
  wrappedTierTMKs?: Record<TierId, CloudWrappedTMK>;
  /** Wrapped customer TMK (for custom feeds) */
  wrappedCustomerTMK?: CloudWrappedTMK | null;
}

/**
 * Load a single pack file based on detected format
 *
 * Supports multi-license mode: tries each provided license key until
 * one successfully decrypts the pack. This enables both cloud and
 * offline licenses to work independently.
 *
 * For GRX2 format, automatically detects standard vs extended:
 * - Extended GRX2: Has embedded TMK, uses license key (JWT) for decryption
 * - Standard GRX2: Requires external TMK from cloud activation
 *
 * @param fileInfo - Pack file info with format
 * @param licenseKeys - License key(s) for decryption (single or array)
 * @param machineId - Machine ID for key derivation
 * @param cloudContext - Optional cloud pack context (for standard GRX2)
 * @param debug - Optional debug logger
 * @returns Pack load result
 */
export async function loadPackFile(
  fileInfo: PackFileInfo,
  licenseKeys: string | string[],
  machineId: string,
  cloudContext?: CloudPackContext,
  debug?: (msg: string) => void
): Promise<PackLoadResult> {
  const { filePath, format, feedId } = fileInfo;

  // Normalize to array for multi-license support
  const keys = Array.isArray(licenseKeys) ? licenseKeys : [licenseKeys];

  if (keys.length === 0 && !cloudContext) {
    return {
      info: fileInfo,
      loaded: false,
      error: 'No license keys provided',
    };
  }

  // Handle based on format
  switch (format) {
    case 'grx2': {
      // Read file to detect standard vs extended format
      const packData = await readFile(filePath);

      // Check if this is a standard GRX2 (cloud pack) or extended GRX2 (offline pack)
      if (isStandardGRX2(packData)) {
        // Standard GRX2 requires cloud context (wrapped TMK)
        if (!cloudContext) {
          debug?.(`[UnifiedLoader] ${feedId} is standard GRX2 but no cloud context available`);
          return {
            info: fileInfo,
            loaded: false,
            error: 'Standard GRX2 pack requires cloud license activation',
          };
        }

        // Read pack tier and key type from header to select correct TMK
        const packTierId = getPackTierId(packData) as TierId | null;
        const packKeyType = getPackKeyType(packData);
        debug?.(`[UnifiedLoader] Pack ${feedId}: tier=${packTierId}, keyType=${packKeyType}`);

        // Select TMK based on key type and tier
        let selectedTMK: CloudWrappedTMK | undefined;

        if (packKeyType === 2 && cloudContext.wrappedCustomerTMK) {
          // Key type 2 = customer TMK
          selectedTMK = cloudContext.wrappedCustomerTMK;
          debug?.(`[UnifiedLoader] Using customer TMK for ${feedId}`);
        } else if (packTierId && cloudContext.wrappedTierTMKs?.[packTierId]) {
          // Use tier-specific TMK from the map
          selectedTMK = cloudContext.wrappedTierTMKs[packTierId];
          debug?.(`[UnifiedLoader] Using ${packTierId} tier TMK for ${feedId}`);
        } else {
          // Fallback to primary TMK (backward compatibility)
          selectedTMK = cloudContext.wrappedTMK;
          debug?.(`[UnifiedLoader] Using primary TMK for ${feedId} (fallback)`);
        }

        debug?.(`[UnifiedLoader] Loading standard GRX2 (cloud pack): ${feedId}`);
        try {
          const pack = await loadCloudPack(
            filePath,
            selectedTMK,
            cloudContext.licenseKey,
            machineId,
            debug
          );
          return {
            info: fileInfo,
            pack,
            loaded: true,
          };
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          debug?.(`[UnifiedLoader] Cloud pack load failed: ${errorMsg}`);

          // If tier TMK failed and we have customer TMK as fallback, try that
          if (packKeyType !== 2 && cloudContext.wrappedCustomerTMK) {
            debug?.(`[UnifiedLoader] Trying customer TMK as fallback for ${feedId}`);
            try {
              const pack = await loadCloudPack(
                filePath,
                cloudContext.wrappedCustomerTMK,
                cloudContext.licenseKey,
                machineId,
                debug
              );
              return {
                info: fileInfo,
                pack,
                loaded: true,
              };
            } catch (customerError) {
              const customerErrorMsg = customerError instanceof Error ? customerError.message : String(customerError);
              debug?.(`[UnifiedLoader] Customer TMK also failed: ${customerErrorMsg}`);
            }
          }

          return {
            info: fileInfo,
            loaded: false,
            error: errorMsg,
          };
        }
      }

      // Extended GRX2 - try each license key (JWT) until one works
      debug?.(`[UnifiedLoader] Loading extended GRX2 (offline pack): ${feedId}`);
      let lastError: string = 'Unknown error';
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i]!;
        try {
          debug?.(`[UnifiedLoader] Trying license key ${i + 1}/${keys.length} for ${feedId}`);
          const pack = await loadGrx2Pack(filePath, key, machineId, debug);
          return {
            info: fileInfo,
            pack,
            loaded: true,
          };
        } catch (error) {
          lastError = error instanceof Error ? error.message : String(error);
          debug?.(`[UnifiedLoader] License key ${i + 1} failed: ${lastError}`);
          // Continue to try next key
        }
      }
      // All keys failed
      return {
        info: fileInfo,
        loaded: false,
        error: keys.length > 1
          ? `Failed with all ${keys.length} license keys. Last error: ${lastError}`
          : lastError,
      };
    }

    case 'grpx': {
      // Try each license key until one works
      let lastError: string = 'Unknown error';
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i]!;
        try {
          debug?.(`[UnifiedLoader] Trying license key ${i + 1}/${keys.length} for ${feedId}`);
          const packData = await readFile(filePath);
          const loadedPack = await loadGrpxPack(packData, {
            licenseKey: key,
            machineId,
          });

          // Convert to RulePack format
          // GRPX packs use FORMAT_PRIORITIES.grpx (200) as default priority
          const pack: RulePack = {
            name: feedId,
            version: loadedPack.metadata.version,
            publisher: loadedPack.metadata.publisher,
            description: loadedPack.metadata.description,
            license: loadedPack.metadata.license,
            priority: 200, // GRPX format tier priority
            rules: loadedPack.rules,
          };

          return {
            info: fileInfo,
            pack,
            loaded: true,
          };
        } catch (error) {
          lastError = error instanceof Error ? error.message : String(error);
          debug?.(`[UnifiedLoader] License key ${i + 1} failed: ${lastError}`);
          // Continue to try next key
        }
      }
      // All keys failed
      return {
        info: fileInfo,
        loaded: false,
        error: keys.length > 1
          ? `Failed with all ${keys.length} license keys. Last error: ${lastError}`
          : lastError,
      };
    }

    case 'unencrypted':
      // Skip unencrypted packs in VS Code extension
      return {
        info: fileInfo,
        loaded: false,
        error: 'Unencrypted packs not supported in VS Code extension',
      };

    default:
      return {
        info: fileInfo,
        loaded: false,
        error: `Unknown pack format: ${format}`,
      };
  }
}

/**
 * Load all packs from a directory with unified format detection
 *
 * Scans for .grx2 and .grpx files, auto-detects format, and loads
 * using the appropriate loader. Unencrypted packs are skipped.
 *
 * For GRX2 packs, automatically detects standard vs extended format:
 * - Standard GRX2 (cloud packs): Requires cloudContext with wrapped TMK
 * - Extended GRX2 (offline packs): Uses license keys (JWT) for embedded TMK
 *
 * Supports multi-license mode: when multiple license keys are provided,
 * each pack is tried with all keys until one succeeds. This enables
 * both cloud and offline licenses to work independently.
 *
 * @param directory - Directory containing pack files
 * @param licenseKeys - License key(s) for decryption (single or array)
 * @param machineId - Machine ID for key derivation
 * @param entitledFeeds - Optional list of entitled feed IDs (filter)
 * @param cloudContext - Optional cloud pack context (for standard GRX2)
 * @param debug - Optional debug logger
 * @returns Unified pack load result
 */
export async function loadAllPacksUnified(
  directory: string,
  licenseKeys: string | string[],
  machineId: string,
  entitledFeeds?: string[],
  cloudContext?: CloudPackContext,
  debug?: (msg: string) => void
): Promise<UnifiedPackLoadResult> {
  const packs: EncryptedPackInfo[] = [];
  const loadedPacks: LoadedPackData[] = [];
  const errors: string[] = [];
  const skipped: PackFileInfo[] = [];
  let totalRules = 0;

  // Scan for pack files
  const packFiles = await scanForPackFiles(directory, debug);

  if (packFiles.length === 0) {
    return {
      success: true,
      packs: [],
      loadedPacks: [],
      totalRules: 0,
      errors: [],
      skipped: [],
    };
  }

  debug?.(`[UnifiedLoader] Found ${packFiles.length} pack files to process`);

  // Load each pack
  for (const fileInfo of packFiles) {
    const { feedId: filenameFeedId, format, filePath } = fileInfo;

    // Skip unencrypted packs
    if (format === 'unencrypted') {
      debug?.(`[UnifiedLoader] Skipping ${filenameFeedId}: unencrypted format not supported`);
      skipped.push(fileInfo);
      continue;
    }

    // Pre-check entitlement if filename looks like a valid feedId (not random hex)
    // Random hex filenames (32+ chars) are from cloud cache - check entitlement post-load
    const isRandomFilename = /^[a-f0-9]{32,}$/i.test(filenameFeedId);
    if (!isRandomFilename && entitledFeeds && !entitledFeeds.includes(filenameFeedId)) {
      debug?.(`[UnifiedLoader] Skipping ${filenameFeedId}: not in entitled feeds`);
      continue;
    }

    // Load the pack (tries cloud context first for standard GRX2, then license keys)
    const result = await loadPackFile(fileInfo, licenseKeys, machineId, cloudContext, debug);

    if (result.loaded && result.pack) {
      // Use the pack's internal name as the actual feedId
      // This is critical for random-named cache files
      const actualFeedId = result.pack.name;

      // For cached packs (random filenames), skip entitlement check:
      // - Cloud API only serves packs user is entitled to
      // - TMK decryption ensures only authorized users can decrypt
      // - Pack's internal name may differ from feedId used in publishing
      // (e.g., pack name "sf-essentials" but published as feedId "enterprise")
      //
      // For regular packs, entitlement was already checked pre-load based on filename

      const packInfo: EncryptedPackInfo = {
        feedId: actualFeedId, // Use pack's name, not filename
        name: result.pack.name,
        version: result.pack.version,
        publisher: result.pack.publisher,
        ruleCount: result.pack.rules.length,
        filePath,
        loaded: true,
        source: 'local',
        format, // Include format in pack info
      };

      packs.push(packInfo);
      loadedPacks.push({ info: packInfo, pack: result.pack });

      totalRules += result.pack.rules.length;
      debug?.(`[UnifiedLoader] Loaded ${actualFeedId} (${format}): ${result.pack.rules.length} rules`);
    } else {
      // For failed loads with random filenames, don't add to errors list
      // (likely just wrong license key for this pack)
      if (!isRandomFilename) {
        errors.push(`${filenameFeedId}: ${result.error}`);
        packs.push({
          feedId: filenameFeedId,
          name: filenameFeedId,
          version: 'unknown',
          publisher: 'unknown',
          ruleCount: 0,
          filePath,
          loaded: false,
          error: result.error,
          source: 'local',
          format,
        });
      } else {
        debug?.(`[UnifiedLoader] Cache file ${filenameFeedId} failed to load: ${result.error}`);
      }
    }
  }

  return {
    success: errors.length === 0,
    packs,
    loadedPacks,
    totalRules,
    errors,
    skipped,
  };
}
