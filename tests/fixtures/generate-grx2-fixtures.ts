#!/usr/bin/env bun
/**
 * GRX2 Test Fixture Generator
 *
 * Generates various test .grx2 packs for unit testing:
 * - Valid pack with rules
 * - Expired license pack (simulated via tampered header)
 * - Corrupted pack (invalid header)
 * - Machine-bound pack
 * - Portable pack (no machine binding)
 *
 * Usage:
 *   bun run tests/fixtures/generate-grx2-fixtures.ts
 *
 * Output: tests/fixtures/*.grx2
 *
 * @module tests/fixtures/generate-grx2-fixtures
 */

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createCipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
} from 'node:crypto';

// =============================================================================
// Constants
// =============================================================================

const AES_ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 100000;
const AES_KEY_SIZE = 32;
const GCM_IV_SIZE = 12;
const GCM_AUTH_TAG_SIZE = 16;
const PACK_HASH_SIZE = 16;

const GRX2_MAGIC = Buffer.from('GRX2', 'ascii');
const GRX2_EXTENDED_VERSION = 3;
const GRX2_EXTENDED_FLAG = 0x01;
const GRX2_PORTABLE_FLAG = 0x02;
const GRX2_ALGORITHM_AES_256_GCM = 1;
const GRX2_KDF_PBKDF2 = 1;
const GRX2_KEY_TYPE_TMK = 1;
const GRX2_HEADER_SIZE = 96;

// Test constants - exported for use in tests
export const TEST_LICENSE_KEY = 'test-license-key-12345678901234567890';
export const TEST_MACHINE_ID = 'test-machine-id-abcdef123456';
export const TEST_MACHINE_ID_2 = 'different-machine-id-xyz789';

// =============================================================================
// Crypto Utilities
// =============================================================================

function generateTMK(): Buffer {
  return randomBytes(AES_KEY_SIZE);
}

function generateIV(): Buffer {
  return randomBytes(GCM_IV_SIZE);
}

function generateSalt(): Buffer {
  return randomBytes(32);
}

function deriveLDK(licenseKey: string, ldkSalt: Buffer, machineId: string): Buffer {
  const combinedSalt = Buffer.concat([
    ldkSalt,
    Buffer.from(machineId, 'utf-8'),
  ]);
  return pbkdf2Sync(licenseKey, combinedSalt, PBKDF2_ITERATIONS, AES_KEY_SIZE, 'sha256');
}

function encrypt(plaintext: Buffer, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
  const iv = generateIV();
  const cipher = createCipheriv(AES_ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return { ciphertext, iv, authTag };
}

function packHash(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest().subarray(0, PACK_HASH_SIZE);
}

function wrapTMK(tmk: Buffer, licenseKey: string, machineId: string, tmkVersion: number): {
  encryptedKey: Buffer;
  iv: Buffer;
  authTag: Buffer;
  ldkSalt: Buffer;
} {
  const ldkSalt = generateSalt();
  const ldk = deriveLDK(licenseKey, ldkSalt, machineId);

  const encrypted = encrypt(tmk, ldk);

  return {
    encryptedKey: encrypted.ciphertext,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    ldkSalt,
  };
}

export function buildExtendedGRX2Pack(
  content: Buffer,
  licenseKey: string,
  machineId: string,
  tierId: number,
  tmkVersion: number,
  portable: boolean = false
): Buffer {
  // Generate TMK
  const tmk = generateTMK();

  // Wrap TMK
  const wrappedTMK = wrapTMK(tmk, licenseKey, machineId, tmkVersion);

  // Encrypt content with TMK
  const encrypted = encrypt(content, tmk);

  // Compute pack hash
  const hash = packHash(content);

  // Build wrapped TMK JSON
  const wrappedTMKJson = JSON.stringify({
    k: wrappedTMK.encryptedKey.toString('base64'),
    i: wrappedTMK.iv.toString('base64'),
    t: wrappedTMK.authTag.toString('base64'),
    v: tmkVersion,
    s: wrappedTMK.ldkSalt.toString('base64'),
  });

  const wrappedTMKBuffer = Buffer.from(wrappedTMKJson, 'utf8');
  const wrappedTMKLength = wrappedTMKBuffer.length;

  // Build header (96 bytes)
  const header = Buffer.alloc(GRX2_HEADER_SIZE);

  // Magic (0-3)
  GRX2_MAGIC.copy(header, 0);

  // Version (4)
  header.writeUInt8(GRX2_EXTENDED_VERSION, 4);

  // Algorithm (5)
  header.writeUInt8(GRX2_ALGORITHM_AES_256_GCM, 5);

  // KDF (6)
  header.writeUInt8(GRX2_KDF_PBKDF2, 6);

  // Key Type (7)
  header.writeUInt8(GRX2_KEY_TYPE_TMK, 7);

  // Tier ID (8-9)
  header.writeUInt16BE(tierId, 8);

  // TMK Version (10-13)
  header.writeUInt32BE(tmkVersion, 10);

  // IV (14-25)
  encrypted.iv.copy(header, 14);

  // Auth Tag (26-41)
  encrypted.authTag.copy(header, 26);

  // Salt (42-73) - zeros for TMK mode
  Buffer.alloc(32, 0).copy(header, 42);

  // Payload Length (74-77)
  header.writeUInt32BE(encrypted.ciphertext.length, 74);

  // Pack Hash (78-93)
  hash.copy(header, 78);

  // Reserved (94-95) - set extended flag, and portable flag if applicable
  const reservedFlags = GRX2_EXTENDED_FLAG | (portable ? GRX2_PORTABLE_FLAG : 0);
  header.writeUInt8(reservedFlags, 94);

  // Build wrapped TMK length prefix (4 bytes)
  const lengthPrefix = Buffer.alloc(4);
  lengthPrefix.writeUInt32BE(wrappedTMKLength, 0);

  // Combine: header + length + wrapped TMK + ciphertext
  return Buffer.concat([
    header,
    lengthPrefix,
    wrappedTMKBuffer,
    encrypted.ciphertext,
  ]);
}

// =============================================================================
// Test Pack Generators
// =============================================================================

// Simple check function that always passes
const PASS_CHECK_SOURCE = 'function(node, ctx) { return null; }';

export function generateValidPack(): Buffer {
  const rulePack = {
    name: 'test-pack',
    version: '1.0.0',
    publisher: 'netsectech',
    description: 'Test rule pack',
    priority: 100,
    rules: [
      {
        id: 'TEST-001',
        selector: 'interface',
        metadata: { level: 'error', obu: 'network', owner: 'test', description: 'Test rule 1' },
        checkSource: PASS_CHECK_SOURCE,
      },
      {
        id: 'TEST-002',
        selector: 'router bgp',
        metadata: { level: 'warning', obu: 'network', owner: 'test', description: 'Test rule 2' },
        checkSource: PASS_CHECK_SOURCE,
      },
    ],
  };

  const content = Buffer.from(JSON.stringify(rulePack), 'utf8');
  return buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, TEST_MACHINE_ID, 1, 1);
}

export function generateCorruptedPack(): Buffer {
  // Generate a valid pack first
  const validPack = generateValidPack();

  // Corrupt the magic bytes
  const corrupted = Buffer.from(validPack);
  corrupted.write('XXXX', 0, 'ascii');

  return corrupted;
}

export function generateMachineBoundPack(): Buffer {
  const rulePack = {
    name: 'machine-bound-pack',
    version: '1.0.0',
    publisher: 'netsectech',
    description: 'Machine-bound test pack',
    priority: 100,
    rules: [
      {
        id: 'MB-001',
        selector: 'interface',
        metadata: { level: 'error', obu: 'network', owner: 'test', description: 'Machine-bound rule' },
        checkSource: PASS_CHECK_SOURCE,
      },
    ],
  };

  const content = Buffer.from(JSON.stringify(rulePack), 'utf8');
  return buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, TEST_MACHINE_ID, 1, 1);
}

export function generatePortablePack(): Buffer {
  const rulePack = {
    name: 'portable-pack',
    version: '1.0.0',
    publisher: 'netsectech',
    description: 'Portable test pack (no machine binding)',
    priority: 100,
    rules: [
      {
        id: 'PORT-001',
        selector: 'interface',
        metadata: { level: 'error', obu: 'network', owner: 'test', description: 'Portable rule' },
        checkSource: PASS_CHECK_SOURCE,
      },
    ],
  };

  const content = Buffer.from(JSON.stringify(rulePack), 'utf8');
  // Portable packs use empty machineId and set the portable flag
  return buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, '', 1, 1, true);
}

export function generateInvalidJsonPack(): Buffer {
  // Not valid JSON
  const invalidContent = Buffer.from('{ invalid json content', 'utf8');
  return buildExtendedGRX2Pack(invalidContent, TEST_LICENSE_KEY, TEST_MACHINE_ID, 1, 1);
}

// =============================================================================
// Main
// =============================================================================

function main() {
  console.log('Generating GRX2 test fixtures...\n');

  // Determine output directory
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const outputDir = __dirname;

  // Ensure directory exists
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  // Generate fixtures
  const fixtures = [
    { name: 'valid-pack.grx2', generator: generateValidPack },
    { name: 'corrupted-pack.grx2', generator: generateCorruptedPack },
    { name: 'machine-bound.grx2', generator: generateMachineBoundPack },
    { name: 'portable.grx2', generator: generatePortablePack },
    { name: 'invalid-json.grx2', generator: generateInvalidJsonPack },
  ];

  for (const fixture of fixtures) {
    const packBuffer = fixture.generator();
    const outputPath = join(outputDir, fixture.name);

    writeFileSync(outputPath, packBuffer);
    console.log(`✓ Generated ${fixture.name} (${packBuffer.length} bytes)`);
  }

  console.log('\n=== Fixture Generation Complete ===');
  console.log(`\nTest constants:`);
  console.log(`  License Key: ${TEST_LICENSE_KEY}`);
  console.log(`  Machine ID 1: ${TEST_MACHINE_ID}`);
  console.log(`  Machine ID 2: ${TEST_MACHINE_ID_2}`);
  console.log(`\nFixtures saved to: ${outputDir}`);
}

// Run if executed directly
if (import.meta.main) {
  main();
}
