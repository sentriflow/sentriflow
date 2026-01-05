/**
 * Encryption Module for SentriFlow VS Code Extension
 *
 * Provides encrypted rule pack support:
 * - GRX2 extended format loading
 * - GRPX format loading (via unified loader)
 * - License key management
 * - Cloud update checking and downloading
 *
 * @module encryption
 */

// Types
export * from './types';

// GRX2 Loader (legacy, for backward compatibility)
export {
  isExtendedGRX2,
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
} from './GRX2ExtendedLoader';

// Unified Pack Loader (supports GRX2 and GRPX)
export {
  scanForPackFiles,
  loadPackFile,
  loadAllPacksUnified,
  type PackFileInfo,
  type PackLoadResult,
  type LoadedPackData,
  type UnifiedPackLoadResult,
  type CloudPackContext,
} from './UnifiedPackLoader';

// License Manager
export { LicenseManager, DEFAULT_CLOUD_API_URL } from './LicenseManager';

// Cloud Client
export {
  CloudClient,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
} from './CloudClient';

// Cloud Pack Loader (for standard GRX2 packs with cloud TMK)
export {
  isStandardGRX2,
  isExtendedGRX2 as isExtendedGRX2Cloud,
  unwrapCloudTMK,
  loadStandardPackWithTMK,
  loadCloudPack,
} from './CloudPackLoader';
