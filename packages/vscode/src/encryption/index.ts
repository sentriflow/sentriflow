/**
 * Encryption Module for SentriFlow VS Code Extension
 *
 * Provides encrypted rule pack support:
 * - GRX2 extended format loading
 * - License key management
 * - Cloud update checking and downloading
 *
 * @module encryption
 */

// Types
export * from './types';

// GRX2 Loader
export {
  isExtendedGRX2,
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
} from './GRX2ExtendedLoader';

// License Manager
export { LicenseManager } from './LicenseManager';

// Cloud Client
export {
  CloudClient,
  checkForUpdatesWithProgress,
  downloadUpdatesWithProgress,
} from './CloudClient';
