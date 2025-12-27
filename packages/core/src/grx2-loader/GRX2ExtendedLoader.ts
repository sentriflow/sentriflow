/**
 * GRX2 Extended Pack Loader
 *
 * Loads and decrypts extended GRX2 packs (self-contained with embedded wrapped TMK).
 * Uses Node.js built-in crypto module for all operations.
 *
 * Security:
 * - AES-256-GCM encryption with authenticated encryption
 * - PBKDF2 key derivation (100,000 iterations)
 * - Constant-time comparisons for auth tags
 * - Memory zeroing for sensitive data
 *
 * @module @sentriflow/core/grx2-loader/GRX2ExtendedLoader
 */

import {
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  timingSafeEqual,
} from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { homedir } from 'node:os';
import type { RulePack } from '../types/IRule';
import {
  type GRX2ExtendedHeader,
  type WrappedTMK,
  type SerializedWrappedTMK,
  type EncryptedPackInfo,
  type GRX2PackLoadResult,
  EncryptedPackError,
  GRX2_HEADER_SIZE,
  GRX2_EXTENDED_VERSION,
  GRX2_EXTENDED_FLAG,
  GRX2_PORTABLE_FLAG,
  GRX2_ALGORITHM_AES_256_GCM,
  GRX2_KDF_PBKDF2,
} from './types';

// =============================================================================
// Constants
// =============================================================================

/** AES-256-GCM algorithm */
const AES_ALGORITHM = 'aes-256-gcm';

/** PBKDF2 iterations (NIST recommended) */
const PBKDF2_ITERATIONS = 100000;

/** AES key size (32 bytes = 256 bits) */
const AES_KEY_SIZE = 32;

/** GCM IV size (12 bytes) */
const GCM_IV_SIZE = 12;

/** GCM auth tag size (16 bytes) */
const GCM_AUTH_TAG_SIZE = 16;

/** Pack hash size (truncated SHA-256) */
const PACK_HASH_SIZE = 16;

/** GRX2 magic bytes */
const GRX2_MAGIC = Buffer.from('GRX2', 'ascii');

/** Minimum wrapped TMK block size */
const MIN_WRAPPED_TMK_SIZE = 64;

/** Maximum wrapped TMK block size */
const MAX_WRAPPED_TMK_SIZE = 1024;

// =============================================================================
// Crypto Utilities
// =============================================================================

/**
 * Derive LDK (License-Derived Key) from license key, random salt, and machine ID
 *
 * SECURITY: Uses proper random salt for PBKDF2, with machineId as additional binding.
 * The salt MUST be cryptographically random (stored in wrapped TMK).
 * MachineId provides device binding but is NOT the primary entropy source.
 *
 * Key derivation: PBKDF2-SHA256(licenseKey, salt || machineId, 100000 iterations)
 *
 * @param licenseKey - The license key (primary secret)
 * @param ldkSalt - Random 32-byte salt (from wrapped TMK)
 * @param machineId - Machine identifier (optional binding, can be empty for portable packs)
 * @returns 32-byte derived key
 */
function deriveLDK(licenseKey: string, ldkSalt: Buffer, machineId: string): Buffer {
  // Combine random salt with machineId for device binding
  // The random salt provides entropy; machineId provides device-specific binding
  const combinedSalt = Buffer.concat([
    ldkSalt,
    Buffer.from(machineId, 'utf-8'),
  ]);
  return pbkdf2Sync(licenseKey, combinedSalt, PBKDF2_ITERATIONS, AES_KEY_SIZE, 'sha256');
}

/**
 * Decrypt data with AES-256-GCM
 *
 * @param ciphertext - Encrypted data
 * @param key - 32-byte decryption key
 * @param iv - 12-byte initialization vector
 * @param authTag - 16-byte authentication tag
 * @returns Decrypted plaintext
 * @throws EncryptedPackError if decryption fails
 */
function decrypt(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer
): Buffer {
  try {
    const decipher = createDecipheriv(AES_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return plaintext;
  } catch (error) {
    throw new EncryptedPackError(
      'Decryption failed (invalid key or corrupted data)',
      'DECRYPTION_FAILED',
      error
    );
  }
}

/**
 * Compute truncated SHA-256 hash
 *
 * @param data - Data to hash
 * @returns 16-byte truncated hash
 */
function packHash(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest().subarray(0, PACK_HASH_SIZE);
}

/**
 * Zero out sensitive buffer
 *
 * @param buffer - Buffer to zero
 */
function zeroize(buffer: Buffer): void {
  buffer.fill(0);
}

// =============================================================================
// GRX2 Parser
// =============================================================================

/**
 * Check if buffer contains extended GRX2 format
 *
 * @param data - Buffer to check
 * @returns true if extended format
 */
export function isExtendedGRX2(data: Buffer): boolean {
  if (data.length < GRX2_HEADER_SIZE) {
    return false;
  }

  const magic = data.subarray(0, 4);
  const version = data.readUInt8(4);
  const reservedByte = data.readUInt8(94);

  return (
    magic.equals(GRX2_MAGIC) &&
    version === GRX2_EXTENDED_VERSION &&
    (reservedByte & GRX2_EXTENDED_FLAG) !== 0
  );
}

/**
 * Parse extended GRX2 header from buffer
 *
 * @param data - Pack data buffer
 * @returns Parsed header with wrapped TMK
 * @throws EncryptedPackError if format is invalid
 */
function parseExtendedHeader(data: Buffer): {
  header: GRX2ExtendedHeader;
  payloadOffset: number;
} {
  // Check minimum size
  if (data.length < GRX2_HEADER_SIZE + 4) {
    throw new EncryptedPackError(
      'Pack too small for extended GRX2 format',
      'PACK_CORRUPTED'
    );
  }

  // Check format
  if (!isExtendedGRX2(data)) {
    throw new EncryptedPackError(
      'Not an extended GRX2 pack (wrong magic, version, or flag)',
      'PACK_CORRUPTED'
    );
  }

  // Parse base header fields
  const magic = data.subarray(0, 4);
  const version = data.readUInt8(4);
  const algorithm = data.readUInt8(5);
  const kdf = data.readUInt8(6);
  const keyType = data.readUInt8(7);
  const tierId = data.readUInt16BE(8);
  const tmkVersion = data.readUInt32BE(10);
  const iv = Buffer.from(data.subarray(14, 26));
  const authTag = Buffer.from(data.subarray(26, 42));
  const salt = Buffer.from(data.subarray(42, 74));
  const payloadLength = data.readUInt32BE(74);
  const packHashBytes = Buffer.from(data.subarray(78, 94));
  const reserved = Buffer.from(data.subarray(94, 96));

  // Validate algorithm
  if (algorithm !== GRX2_ALGORITHM_AES_256_GCM) {
    throw new EncryptedPackError(
      `Unsupported encryption algorithm: ${algorithm}`,
      'PACK_CORRUPTED'
    );
  }

  // Validate KDF
  if (kdf !== GRX2_KDF_PBKDF2) {
    throw new EncryptedPackError(
      `Unsupported KDF: ${kdf}`,
      'PACK_CORRUPTED'
    );
  }

  // Read wrapped TMK block length
  const wrappedTMKLength = data.readUInt32BE(GRX2_HEADER_SIZE);

  if (wrappedTMKLength < MIN_WRAPPED_TMK_SIZE || wrappedTMKLength > MAX_WRAPPED_TMK_SIZE) {
    throw new EncryptedPackError(
      `Invalid wrapped TMK length: ${wrappedTMKLength}`,
      'PACK_CORRUPTED'
    );
  }

  const totalHeaderSize = GRX2_HEADER_SIZE + 4 + wrappedTMKLength;

  if (data.length < totalHeaderSize) {
    throw new EncryptedPackError(
      `Pack too small for wrapped TMK block`,
      'PACK_CORRUPTED'
    );
  }

  // Parse wrapped TMK JSON
  const wrappedTMKBuffer = data.subarray(GRX2_HEADER_SIZE + 4, totalHeaderSize);
  let serialized: SerializedWrappedTMK;
  try {
    serialized = JSON.parse(wrappedTMKBuffer.toString('utf8'));
  } catch {
    throw new EncryptedPackError(
      'Failed to parse wrapped TMK block',
      'PACK_CORRUPTED'
    );
  }

  // Validate and deserialize
  if (!serialized.k || !serialized.i || !serialized.t || typeof serialized.v !== 'number' || !serialized.s) {
    throw new EncryptedPackError(
      'Invalid wrapped TMK structure (missing required fields)',
      'PACK_CORRUPTED'
    );
  }

  const wrappedTMK: WrappedTMK = {
    encryptedKey: Buffer.from(serialized.k, 'base64'),
    iv: Buffer.from(serialized.i, 'base64'),
    authTag: Buffer.from(serialized.t, 'base64'),
    tmkVersion: serialized.v,
    ldkSalt: Buffer.from(serialized.s, 'base64'),
  };

  // Check portable flag (bit 1 of reserved byte 94)
  const reservedByte = data.readUInt8(94);
  const isPortable = (reservedByte & GRX2_PORTABLE_FLAG) !== 0;

  const header: GRX2ExtendedHeader = {
    magic: Buffer.from(magic),
    version,
    algorithm,
    kdf,
    keyType,
    tierId,
    tmkVersion,
    iv,
    authTag,
    salt,
    payloadLength,
    packHash: packHashBytes,
    reserved,
    isExtended: true,
    isPortable,
    wrappedTMK,
    totalHeaderSize,
  };

  return { header, payloadOffset: totalHeaderSize };
}

// =============================================================================
// Pack Loader
// =============================================================================

/**
 * Load and decrypt a single extended GRX2 pack
 *
 * @param filePath - Path to the .grx2 file
 * @param licenseKey - License key for decryption
 * @param machineId - Machine ID for LDK derivation (empty string for portable packs)
 * @param debug - Optional debug callback for logging
 * @returns Loaded rule pack
 * @throws EncryptedPackError if loading fails
 */
export async function loadExtendedPack(
  filePath: string,
  licenseKey: string,
  machineId: string,
  debug?: (msg: string) => void
): Promise<RulePack> {
  debug?.(`[GRX2Loader] Loading pack: ${filePath}`);
  debug?.(`[GRX2Loader] License key length: ${licenseKey.length}, first 20 chars: ${licenseKey.substring(0, 20)}...`);
  debug?.(`[GRX2Loader] Machine ID: "${machineId}" (length: ${machineId.length})`);

  // Read pack file
  const data = await readFile(filePath);
  debug?.(`[GRX2Loader] Pack file size: ${data.length} bytes`);

  // Parse extended header
  const { header, payloadOffset } = parseExtendedHeader(data);
  debug?.(`[GRX2Loader] Header parsed - version: ${header.version}, keyType: ${header.keyType}, tmkVersion: ${header.tmkVersion}, isPortable: ${header.isPortable}`);

  // For portable packs, use empty machineId regardless of what was passed
  // This allows portable packs to work on any machine
  const effectiveMachineId = header.isPortable ? '' : machineId;
  if (header.isPortable) {
    debug?.(`[GRX2Loader] Portable pack detected - ignoring machineId for decryption`);
  }

  // Derive LDK from license key, random salt, and machine ID
  // SECURITY: Salt is cryptographically random (stored in wrapped TMK)
  // MachineId provides device binding but is NOT the primary entropy source
  const ldk = deriveLDK(licenseKey, header.wrappedTMK.ldkSalt, effectiveMachineId);
  debug?.(`[GRX2Loader] LDK derived successfully`);

  // Unwrap TMK using LDK
  let tmk: Buffer;
  try {
    tmk = decrypt(
      header.wrappedTMK.encryptedKey,
      ldk,
      header.wrappedTMK.iv,
      header.wrappedTMK.authTag
    );
    debug?.(`[GRX2Loader] TMK unwrapped successfully`);
  } catch (error) {
    debug?.(`[GRX2Loader] TMK unwrap FAILED: ${(error as Error).message}`);
    zeroize(ldk);
    throw new EncryptedPackError(
      'Failed to unwrap TMK - invalid license key or machine ID mismatch',
      'DECRYPTION_FAILED',
      error
    );
  }

  // Zero out LDK (no longer needed)
  zeroize(ldk);

  // Extract encrypted payload
  const encryptedPayload = data.subarray(payloadOffset);

  if (encryptedPayload.length !== header.payloadLength) {
    zeroize(tmk);
    throw new EncryptedPackError(
      `Payload length mismatch: expected ${header.payloadLength}, got ${encryptedPayload.length}`,
      'PACK_CORRUPTED'
    );
  }

  // Decrypt payload using TMK
  let plaintext: Buffer;
  try {
    plaintext = decrypt(encryptedPayload, tmk, header.iv, header.authTag);
  } catch (error) {
    zeroize(tmk);
    throw new EncryptedPackError(
      'Failed to decrypt pack payload',
      'DECRYPTION_FAILED',
      error
    );
  }

  // Zero out TMK (no longer needed)
  zeroize(tmk);

  // Verify pack hash
  const computedHash = packHash(plaintext);
  if (!timingSafeEqual(computedHash, header.packHash)) {
    throw new EncryptedPackError(
      'Pack integrity check failed (hash mismatch)',
      'PACK_CORRUPTED'
    );
  }

  // Parse JSON content
  let pack: RulePack;
  try {
    pack = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new EncryptedPackError(
      'Failed to parse pack JSON content',
      'PACK_CORRUPTED'
    );
  }

  return pack;
}

/**
 * Resolve path with ~ expansion
 *
 * @param path - Path that may contain ~
 * @returns Resolved path
 */
function resolvePath(path: string): string {
  if (path.startsWith('~/')) {
    return join(homedir(), path.slice(2));
  }
  return path;
}

/**
 * Scan directory for .grx2 files
 *
 * @param directory - Directory to scan
 * @param debug - Optional debug callback for logging
 * @returns Array of .grx2 file paths
 */
async function scanForPacks(
  directory: string,
  debug?: (msg: string) => void
): Promise<string[]> {
  const resolvedDir = resolvePath(directory);
  debug?.(`[GRX2Loader] Scanning directory: ${directory} -> resolved: ${resolvedDir}`);

  if (!existsSync(resolvedDir)) {
    debug?.(`[GRX2Loader] Directory does not exist: ${resolvedDir}`);
    return [];
  }

  const entries = await readdir(resolvedDir);
  debug?.(`[GRX2Loader] Found ${entries.length} entries in directory`);

  const grx2Files = entries
    .filter((entry) => entry.endsWith('.grx2'))
    .map((entry) => join(resolvedDir, entry));

  debug?.(`[GRX2Loader] Found ${grx2Files.length} .grx2 files: ${grx2Files.join(', ')}`);

  return grx2Files;
}

/**
 * Load all extended packs from a directory
 *
 * @param directory - Directory containing .grx2 files
 * @param licenseKey - License key for decryption
 * @param machineId - Machine ID for LDK derivation
 * @param entitledFeeds - Optional list of entitled feed IDs (filter)
 * @param debug - Optional debug callback for logging
 * @returns Load result with packs and errors
 */
export async function loadAllPacks(
  directory: string,
  licenseKey: string,
  machineId: string,
  entitledFeeds?: string[],
  debug?: (msg: string) => void
): Promise<GRX2PackLoadResult> {
  const packs: EncryptedPackInfo[] = [];
  const errors: string[] = [];
  let totalRules = 0;

  // Scan for pack files
  const packFiles = await scanForPacks(directory, debug);

  if (packFiles.length === 0) {
    return {
      success: true,
      packs: [],
      totalRules: 0,
      errors: [],
    };
  }

  // Load each pack
  for (const filePath of packFiles) {
    const fileName = basename(filePath, '.grx2');

    // Check entitlement if filter provided
    if (entitledFeeds && !entitledFeeds.includes(fileName)) {
      continue;
    }

    try {
      const pack = await loadExtendedPack(filePath, licenseKey, machineId, debug);

      packs.push({
        feedId: fileName,
        name: pack.name,
        version: pack.version,
        publisher: pack.publisher,
        ruleCount: pack.rules.length,
        filePath,
        loaded: true,
        source: 'local',
      });

      totalRules += pack.rules.length;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`${fileName}: ${message}`);

      packs.push({
        feedId: fileName,
        name: fileName,
        version: 'unknown',
        publisher: 'unknown',
        ruleCount: 0,
        filePath,
        loaded: false,
        error: message,
        source: 'local',
      });
    }
  }

  return {
    success: errors.length === 0,
    packs,
    totalRules,
    errors,
  };
}

/**
 * Get pack info without fully decrypting
 *
 * Useful for displaying pack metadata in UI before license is entered.
 * Only parses header, does not require license key.
 *
 * @param filePath - Path to .grx2 file
 * @returns Basic pack info from header
 */
export async function getPackInfo(filePath: string): Promise<{
  feedId: string;
  tierId: number;
  tmkVersion: number;
  isExtended: boolean;
}> {
  const data = await readFile(filePath);

  if (!isExtendedGRX2(data)) {
    throw new EncryptedPackError(
      'Not an extended GRX2 pack',
      'PACK_CORRUPTED'
    );
  }

  const tierId = data.readUInt16BE(8);
  const tmkVersion = data.readUInt32BE(10);

  return {
    feedId: basename(filePath, '.grx2'),
    tierId,
    tmkVersion,
    isExtended: true,
  };
}
