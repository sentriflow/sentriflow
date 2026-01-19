/**
 * Unified GRX2 Pack Loader
 *
 * - With @sentriflow/licensing: Uses GRX2Loader (v2 + v3 support)
 * - Without licensing: Falls back to loadExtendedPack (v3 only)
 *
 * @module loaders/pack-loader
 */

import type { RulePack } from '@sentriflow/core';
import { loadExtendedPack } from '@sentriflow/core';

interface LoadGRX2PackOptions {
  filePath: string;
  licenseKey: string;
  machineId: string;
  cacheDir?: string;
}

interface LoadGRX2PackResult {
  rulePack: RulePack;
  usedLicensingLoader: boolean;
}

/**
 * Load a GRX2 pack using the best available loader.
 *
 * Strategy:
 * 1. Try core's loadExtendedPack first (v3/extended format, always available)
 * 2. If that fails with NOT_EXTENDED_FORMAT, try licensing's GRX2Loader (v2 support)
 * 3. If licensing module isn't available, report that v2 packs require activation
 */
export async function loadGRX2Pack(options: LoadGRX2PackOptions): Promise<LoadGRX2PackResult> {
  const { filePath, licenseKey, machineId, cacheDir } = options;

  // Try core loader first (v3/extended format)
  // This handles offline/extended packs without needing the licensing module
  try {
    const rulePack = await loadExtendedPack(filePath, licenseKey, machineId);
    return {
      rulePack,
      usedLicensingLoader: false,
    };
  } catch (coreError) {
    // If the error is NOT_EXTENDED_FORMAT, the pack might be v2 (standard) format
    // Try the licensing module's GRX2Loader which supports both v2 and v3
    const errorCode = (coreError as { code?: string })?.code;
    if (errorCode !== 'NOT_EXTENDED_FORMAT') {
      // Core loader failed for reasons other than format - re-throw
      throw coreError;
    }

    // Pack is v2 format - need licensing module
    try {
      // Use variable to prevent TypeScript from trying to resolve optional package at compile time
      const licensingModulePath = '@sentriflow/licensing';
      const licensing = await import(/* @vite-ignore */ licensingModulePath) as {
        getDefaultCacheDir: () => string;
        createCacheManager: (licenseKey: string, machineId: string, cacheDir: string) => {
          getTierTMK: () => Promise<{ tmk: string } | null>;
          tmkCache: { getAllTierTMKs: () => Promise<Map<number, { tmk: string }>> };
        };
        GRX2Loader: new (options: {
          formatPolicy: 'auto' | 'standard-only' | 'extended-only';
          licenseKey: string;
          machineId: string;
          tierTMK?: Buffer;
          tierTMKs?: Map<number, Buffer>;
        }) => {
          loadFromFile: (filePath: string) => Promise<{ rulePack: RulePack }>;
        };
      };

      // Get cached TMK for v2 packs (from previous activation)
      const effectiveCacheDir = cacheDir ?? licensing.getDefaultCacheDir();
      const cacheManager = licensing.createCacheManager(licenseKey, machineId, effectiveCacheDir);

      // Retrieve tier TMKs from cache
      let tierTMK: Buffer | undefined;
      let tierTMKs: Map<number, Buffer> | undefined;

      try {
        const cachedTMK = await cacheManager.getTierTMK();
        if (cachedTMK) {
          tierTMK = Buffer.from(cachedTMK.tmk, 'base64');
        }

        // Get all tier TMKs for multi-tier support
        const allTMKs = await cacheManager.tmkCache.getAllTierTMKs();
        if (allTMKs.size > 0) {
          tierTMKs = new Map();
          for (const [tierId, tmkData] of allTMKs) {
            tierTMKs.set(tierId, Buffer.from(tmkData.tmk, 'base64'));
          }
        }
      } catch (cacheError) {
        // TMK cache may not exist yet - log for debugging but continue
        // v3 packs don't need cached TMKs, only v2 packs do
        if (process.env.DEBUG) {
          console.debug(
            '[pack-loader] TMK cache retrieval skipped:',
            cacheError instanceof Error ? cacheError.message : 'Unknown error'
          );
        }
      }

      // Create loader with full v2 + v3 support
      const loader = new licensing.GRX2Loader({
        formatPolicy: 'auto',
        licenseKey,
        machineId,
        tierTMK,
        tierTMKs,
      });

      const result = await loader.loadFromFile(filePath);

      return {
        rulePack: result.rulePack,
        usedLicensingLoader: true,
      };
    } catch (licensingError) {
      // Licensing module not available or failed
      if (isModuleNotFoundError(licensingError)) {
        // Licensing module not installed - can't load v2 packs
        throw new Error('Pack requires v2 format support - run "sentriflow activate" first');
      }
      // Re-throw licensing loader errors
      throw licensingError;
    }
  }
}

function isModuleNotFoundError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes('Cannot find module') ||
     error.message.includes('Cannot find package') ||
     (error as NodeJS.ErrnoException).code === 'ERR_MODULE_NOT_FOUND')
  );
}

/**
 * Sanitize error messages to remove sensitive information like absolute paths.
 */
function sanitizeErrorMessage(msg: string): string {
  // Remove absolute paths (keep only filename)
  const sanitized = msg.replace(/(?:\/[\w.-]+)+\/([\w.-]+)/g, '$1');
  // Remove stack trace references
  return sanitized.replace(/\s+at\s+.+/g, '').trim();
}

/**
 * Map GRX2LoaderError codes to user-friendly messages.
 *
 * Handles both GRX2LoaderError from licensing and EncryptedPackError from core,
 * as both have a `code` property.
 */
export function mapGRX2LoadError(error: unknown): string {
  // Handle errors with code property (GRX2LoaderError, EncryptedPackError)
  if (error instanceof Error && 'code' in error) {
    const code = (error as { code: string }).code;
    const messages: Record<string, string> = {
      // GRX2LoaderError codes (from licensing)
      HEADER_INVALID: 'Pack file is corrupted or invalid',
      DECRYPTION_FAILED: 'Failed to decrypt pack (invalid key or corrupted data)',
      PARSE_ERROR: 'Pack content is malformed',
      FILE_READ_ERROR: 'Cannot read pack file',
      HASH_MISMATCH: 'Pack integrity check failed',
      TMK_NOT_AVAILABLE: 'License not activated - run "sentriflow activate" first',
      // EncryptedPackError codes (from core)
      LICENSE_MISSING: 'Invalid or missing license key',
      LICENSE_EXPIRED: 'License has expired',
      LICENSE_INVALID: 'License key is invalid for this pack',
      MACHINE_MISMATCH: 'License is not valid for this machine',
      PACK_CORRUPTED: 'Pack file is corrupted or invalid',
      NOT_EXTENDED_FORMAT: 'Pack requires extended format (v3) - activate license for v2 pack support',
    };
    return messages[code] ?? 'Pack load failed';
  }

  return error instanceof Error ? sanitizeErrorMessage(error.message) : 'Pack load failed';
}
