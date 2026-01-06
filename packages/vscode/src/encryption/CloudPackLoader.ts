/**
 * Cloud Pack Loader
 *
 * Loads standard GRX2 packs using the wrapped TMK from cloud activation.
 * Unlike extended packs (which have embedded TMK), standard cloud packs
 * require the TMK from the activation response.
 *
 * Security:
 * - AES-256-GCM encryption with authenticated encryption
 * - PBKDF2 key derivation (100,000 iterations)
 * - TMK from cloud activation (wrapped with LDK)
 *
 * @module encryption/CloudPackLoader
 */

import {
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  timingSafeEqual,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { RulePack, IRule, RuleMetadata, RuleVendor } from '@sentriflow/core';
import { compileNativeCheckFunction } from '@sentriflow/core';
import {
  type GRX2ExtendedHeader,
  EncryptedPackError,
  GRX2_HEADER_SIZE,
  GRX2_ALGORITHM_AES_256_GCM,
  GRX2_KDF_PBKDF2,
} from './types';
import type { CloudWrappedTMK } from './types';

// =============================================================================
// Constants
// =============================================================================

/** AES-256-GCM algorithm */
const AES_ALGORITHM = 'aes-256-gcm';

/** PBKDF2 iterations (NIST recommended) */
const PBKDF2_ITERATIONS = 100000;

/** AES key size (32 bytes = 256 bits) */
const AES_KEY_SIZE = 32;

/** Pack hash size (truncated SHA-256) */
const PACK_HASH_SIZE = 16;

/** GRX2 magic bytes */
const GRX2_MAGIC = Buffer.from('GRX2', 'ascii');

/** Extended format flag in reserved byte */
const GRX2_EXTENDED_FLAG = 0x01;

/**
 * Serialized rule structure in GRX2 packs.
 */
interface SerializedRule {
  id: string;
  selector?: string;
  vendor?: RuleVendor | RuleVendor[];
  category?: string | string[];
  metadata: RuleMetadata;
  checkSource: string;
}

/**
 * Serialized rule pack structure.
 */
interface SerializedRulePack {
  name: string;
  version: string;
  publisher: string;
  description?: string;
  license?: string;
  homepage?: string;
  priority: number;
  rules: SerializedRule[];
}

// =============================================================================
// Crypto Utilities
// =============================================================================

/**
 * Derive LDK (License-Derived Key) from license key, salt, and machine ID
 *
 * @param licenseKey - The cloud license key (XXXX-XXXX-XXXX-XXXX format)
 * @param ldkSalt - Random salt from wrapped TMK (base64)
 * @param machineId - Machine identifier
 * @returns 32-byte derived key
 */
function deriveLDK(licenseKey: string, ldkSalt: string, machineId: string): Buffer {
  const saltBuffer = Buffer.from(ldkSalt, 'base64');
  const combinedSalt = Buffer.concat([
    saltBuffer,
    Buffer.from(machineId, 'utf-8'),
  ]);
  return pbkdf2Sync(licenseKey.toUpperCase(), combinedSalt, PBKDF2_ITERATIONS, AES_KEY_SIZE, 'sha256');
}

/**
 * Decrypt data with AES-256-GCM
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
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
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
 */
function packHash(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest().subarray(0, PACK_HASH_SIZE);
}

/**
 * Zero out sensitive buffer
 */
function zeroize(buffer: Buffer): void {
  buffer.fill(0);
}

// =============================================================================
// Pack Detection
// =============================================================================

/**
 * Check if buffer contains standard (non-extended) GRX2 format
 *
 * Standard packs have the GRX2 magic but NOT the extended flag.
 * They require external TMK from cloud activation.
 *
 * @param data - Buffer to check
 * @returns true if standard GRX2 format
 */
export function isStandardGRX2(data: Buffer): boolean {
  if (data.length < GRX2_HEADER_SIZE) {
    return false;
  }

  const magic = data.subarray(0, 4);
  const reservedByte = data.readUInt8(94);

  // Has GRX2 magic but NOT the extended flag
  return magic.equals(GRX2_MAGIC) && (reservedByte & GRX2_EXTENDED_FLAG) === 0;
}

/**
 * Check if buffer contains extended GRX2 format (has embedded TMK)
 *
 * @param data - Buffer to check
 * @returns true if extended GRX2 format
 */
export function isExtendedGRX2(data: Buffer): boolean {
  if (data.length < GRX2_HEADER_SIZE) {
    return false;
  }

  const magic = data.subarray(0, 4);
  const reservedByte = data.readUInt8(94);

  return magic.equals(GRX2_MAGIC) && (reservedByte & GRX2_EXTENDED_FLAG) !== 0;
}

// =============================================================================
// Header Parser
// =============================================================================

/**
 * Parse standard GRX2 header
 *
 * Standard packs don't have the wrapped TMK block.
 */
function parseStandardHeader(data: Buffer): {
  iv: Buffer;
  authTag: Buffer;
  payloadLength: number;
  packHashBytes: Buffer;
} {
  if (data.length < GRX2_HEADER_SIZE) {
    throw new EncryptedPackError('Pack too small for GRX2 format', 'PACK_CORRUPTED');
  }

  if (!isStandardGRX2(data)) {
    throw new EncryptedPackError(
      'Not a standard GRX2 pack (expected standard format, got extended or invalid)',
      'PACK_CORRUPTED'
    );
  }

  // Validate algorithm
  const algorithm = data.readUInt8(5);
  if (algorithm !== GRX2_ALGORITHM_AES_256_GCM) {
    throw new EncryptedPackError(`Unsupported algorithm: ${algorithm}`, 'PACK_CORRUPTED');
  }

  // Validate KDF
  const kdf = data.readUInt8(6);
  if (kdf !== GRX2_KDF_PBKDF2) {
    throw new EncryptedPackError(`Unsupported KDF: ${kdf}`, 'PACK_CORRUPTED');
  }

  return {
    iv: Buffer.from(data.subarray(14, 26)),
    authTag: Buffer.from(data.subarray(26, 42)),
    payloadLength: data.readUInt32BE(74),
    packHashBytes: Buffer.from(data.subarray(78, 94)),
  };
}

// =============================================================================
// Cloud Pack Loader
// =============================================================================

/**
 * Unwrap TMK using cloud license key
 *
 * @param wrappedTMK - Wrapped TMK from cloud activation
 * @param licenseKey - Cloud license key (XXXX-XXXX-XXXX-XXXX)
 * @param machineId - Machine identifier
 * @returns Unwrapped TMK (32 bytes)
 */
export function unwrapCloudTMK(
  wrappedTMK: CloudWrappedTMK,
  licenseKey: string,
  machineId: string
): Buffer {
  // SECURITY: Validate TMK fields are present before attempting decryption
  if (!wrappedTMK.encryptedKey || !wrappedTMK.iv || !wrappedTMK.authTag) {
    throw new EncryptedPackError(
      'Invalid TMK: missing required encryption fields',
      'LICENSE_INVALID'
    );
  }

  // Derive LDK from license key, salt, and machine ID
  const ldk = deriveLDK(licenseKey, wrappedTMK.ldkSalt, machineId);

  try {
    // Unwrap TMK using LDK
    const tmk = decrypt(
      Buffer.from(wrappedTMK.encryptedKey, 'base64'),
      ldk,
      Buffer.from(wrappedTMK.iv, 'base64'),
      Buffer.from(wrappedTMK.authTag, 'base64')
    );

    return tmk;
  } finally {
    zeroize(ldk);
  }
}

/**
 * Load a standard GRX2 pack using cloud TMK
 *
 * @param filePath - Path to the .grx2 file
 * @param tmk - Pre-unwrapped TMK (32 bytes)
 * @param debug - Optional debug callback
 * @returns Loaded rule pack
 */
export async function loadStandardPackWithTMK(
  filePath: string,
  tmk: Buffer,
  debug?: (msg: string) => void
): Promise<RulePack> {
  debug?.(`[CloudPackLoader] Loading standard pack: ${filePath}`);

  // Read pack file
  const data = await readFile(filePath);
  debug?.(`[CloudPackLoader] Pack size: ${data.length} bytes`);

  // Parse header
  const header = parseStandardHeader(data);
  debug?.(`[CloudPackLoader] Header parsed, payload length: ${header.payloadLength}`);

  // Extract encrypted payload (starts after fixed header)
  const encryptedPayload = data.subarray(GRX2_HEADER_SIZE);

  if (encryptedPayload.length !== header.payloadLength) {
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
    throw new EncryptedPackError('Failed to decrypt pack payload', 'DECRYPTION_FAILED', error);
  }

  // Verify hash
  const computedHash = packHash(plaintext);
  if (!timingSafeEqual(computedHash, header.packHashBytes)) {
    throw new EncryptedPackError('Pack integrity check failed (hash mismatch)', 'PACK_CORRUPTED');
  }

  // Parse JSON content
  let serializedPack: SerializedRulePack;
  try {
    serializedPack = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new EncryptedPackError('Failed to parse pack JSON content', 'PACK_CORRUPTED');
  }

  // Compile rules
  const compiledRules: IRule[] = serializedPack.rules.map((ruleDef) => {
    const checkFn = compileNativeCheckFunction(ruleDef.checkSource);
    return {
      id: ruleDef.id,
      selector: ruleDef.selector,
      vendor: ruleDef.vendor,
      category: ruleDef.category,
      metadata: ruleDef.metadata,
      check: checkFn,
    };
  });

  return {
    name: serializedPack.name,
    version: serializedPack.version,
    publisher: serializedPack.publisher,
    description: serializedPack.description,
    license: serializedPack.license,
    homepage: serializedPack.homepage,
    priority: serializedPack.priority,
    rules: compiledRules,
  };
}

/**
 * Load a standard GRX2 pack using cloud activation credentials
 *
 * @param filePath - Path to the .grx2 file
 * @param wrappedTMK - Wrapped TMK from cloud activation
 * @param licenseKey - Cloud license key (XXXX-XXXX-XXXX-XXXX)
 * @param machineId - Machine identifier
 * @param debug - Optional debug callback
 * @returns Loaded rule pack
 */
export async function loadCloudPack(
  filePath: string,
  wrappedTMK: CloudWrappedTMK,
  licenseKey: string,
  machineId: string,
  debug?: (msg: string) => void
): Promise<RulePack> {
  debug?.(`[CloudPackLoader] Unwrapping TMK for cloud pack`);

  // Unwrap TMK
  const tmk = unwrapCloudTMK(wrappedTMK, licenseKey, machineId);

  try {
    return await loadStandardPackWithTMK(filePath, tmk, debug);
  } finally {
    zeroize(tmk);
  }
}
