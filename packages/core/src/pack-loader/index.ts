// packages/core/src/pack-loader/index.ts

/**
 * SEC-012: Encrypted Rule Pack System (Consumer API)
 *
 * Provides loading and validation of encrypted rule packs:
 * - AES-256-GCM decryption
 * - PBKDF2 key derivation
 * - VM sandboxed validation
 * - Native runtime execution
 *
 * For pack CREATION (buildEncryptedPack, generateLicenseKey, etc.),
 * use the separate @sentriflow/pack-builder package.
 */

export * from './types';
export { loadEncryptedPack, validatePackFormat } from './PackLoader';
