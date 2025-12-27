/**
 * GRX2 Extended Loader Module
 *
 * Provides functionality for loading and decrypting extended GRX2 encrypted rule packs.
 * This module is used by both the CLI and VS Code extension.
 *
 * @module @sentriflow/core/grx2-loader
 */

// Types
export type {
  LicensePayload,
  GRX2ExtendedHeader,
  WrappedTMK,
  SerializedWrappedTMK,
  EncryptedPackInfo,
  GRX2PackLoadResult,
  EncryptedPackErrorCode,
} from './types';

// Error class
export { EncryptedPackError } from './types';

// Constants
export {
  GRX2_HEADER_SIZE,
  GRX2_EXTENDED_VERSION,
  GRX2_EXTENDED_FLAG,
  GRX2_ALGORITHM_AES_256_GCM,
  GRX2_KDF_PBKDF2,
  GRX2_KEY_TYPE_TMK,
  GRX2_KEY_TYPE_CTMK,
  DEFAULT_PACKS_DIRECTORY,
  CACHE_DIRECTORY,
} from './types';

// Machine ID functions
export { getMachineId, getMachineIdSync } from './MachineId';

// Loader functions
export {
  isExtendedGRX2,
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
} from './GRX2ExtendedLoader';
