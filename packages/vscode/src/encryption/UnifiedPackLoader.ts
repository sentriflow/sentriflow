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
import { loadExtendedPack as loadGrx2Pack } from './GRX2ExtendedLoader';
import type { EncryptedPackInfo, GRX2PackLoadResult } from './types';

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
 * Load a single pack file based on detected format
 *
 * @param fileInfo - Pack file info with format
 * @param licenseKey - License key for decryption
 * @param machineId - Machine ID for key derivation
 * @param debug - Optional debug logger
 * @returns Pack load result
 */
export async function loadPackFile(
  fileInfo: PackFileInfo,
  licenseKey: string,
  machineId: string,
  debug?: (msg: string) => void
): Promise<PackLoadResult> {
  const { filePath, format, feedId } = fileInfo;

  // Handle based on format
  switch (format) {
    case 'grx2':
      try {
        const pack = await loadGrx2Pack(filePath, licenseKey, machineId, debug);
        return {
          info: fileInfo,
          pack,
          loaded: true,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          info: fileInfo,
          loaded: false,
          error: message,
        };
      }

    case 'grpx':
      try {
        const packData = await readFile(filePath);
        const loadedPack = await loadGrpxPack(packData, {
          licenseKey,
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
        const message = error instanceof Error ? error.message : String(error);
        return {
          info: fileInfo,
          loaded: false,
          error: message,
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
 * @param directory - Directory containing pack files
 * @param licenseKey - License key for decryption
 * @param machineId - Machine ID for key derivation
 * @param entitledFeeds - Optional list of entitled feed IDs (filter)
 * @param debug - Optional debug logger
 * @returns Unified pack load result
 */
export async function loadAllPacksUnified(
  directory: string,
  licenseKey: string,
  machineId: string,
  entitledFeeds?: string[],
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
    const { feedId, format, filePath } = fileInfo;

    // Check entitlement if filter provided
    if (entitledFeeds && !entitledFeeds.includes(feedId)) {
      debug?.(`[UnifiedLoader] Skipping ${feedId}: not in entitled feeds`);
      continue;
    }

    // Skip unencrypted packs
    if (format === 'unencrypted') {
      debug?.(`[UnifiedLoader] Skipping ${feedId}: unencrypted format not supported`);
      skipped.push(fileInfo);
      continue;
    }

    // Load the pack
    const result = await loadPackFile(fileInfo, licenseKey, machineId, debug);

    if (result.loaded && result.pack) {
      const packInfo: EncryptedPackInfo = {
        feedId,
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
      debug?.(`[UnifiedLoader] Loaded ${feedId} (${format}): ${result.pack.rules.length} rules`);
    } else {
      errors.push(`${feedId}: ${result.error}`);
      packs.push({
        feedId,
        name: feedId,
        version: 'unknown',
        publisher: 'unknown',
        ruleCount: 0,
        filePath,
        loaded: false,
        error: result.error,
        source: 'local',
        format,
      });
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
