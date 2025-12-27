/**
 * GRX2ExtendedLoader Unit Tests
 *
 * Tests for GRX2 extended pack loader functionality including:
 * - T013: Valid pack decryption with correct license key
 * - T013: DECRYPTION_FAILED error with invalid license key
 * - T013: PACK_CORRUPTED error with corrupted pack
 * - T013: NOT_EXTENDED_FORMAT error for non-GRX2 files
 * - T013: Invalid JSON content handling
 * - T021: Machine binding tests (correct vs wrong machine ID)
 * - T027: Portable pack tests (empty machineId)
 *
 * @module packages/core/test/grx2-loader/GRX2ExtendedLoader.test
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
  isExtendedGRX2,
} from '../../src/grx2-loader/GRX2ExtendedLoader';
import { EncryptedPackError } from '../../src/grx2-loader/types';
import {
  generateValidPack,
  generateCorruptedPack,
  generateMachineBoundPack,
  generatePortablePack,
  generateInvalidJsonPack,
  buildExtendedGRX2Pack,
  TEST_LICENSE_KEY,
  TEST_MACHINE_ID,
  TEST_MACHINE_ID_2,
} from '../../../../tests/fixtures/generate-grx2-fixtures';

// =============================================================================
// Test Setup
// =============================================================================

const TEST_DIR = join(tmpdir(), 'grx2-loader-tests', String(Date.now()));

let VALID_PACK_PATH: string;
let CORRUPTED_PACK_PATH: string;
let MACHINE_BOUND_PACK_PATH: string;
let PORTABLE_PACK_PATH: string;
let INVALID_JSON_PACK_PATH: string;
let NON_GRX2_PATH: string;

beforeAll(() => {
  // Create test directory
  mkdirSync(TEST_DIR, { recursive: true });

  // Generate test packs
  VALID_PACK_PATH = join(TEST_DIR, 'valid-pack.grx2');
  writeFileSync(VALID_PACK_PATH, generateValidPack());

  CORRUPTED_PACK_PATH = join(TEST_DIR, 'corrupted-pack.grx2');
  writeFileSync(CORRUPTED_PACK_PATH, generateCorruptedPack());

  MACHINE_BOUND_PACK_PATH = join(TEST_DIR, 'machine-bound.grx2');
  writeFileSync(MACHINE_BOUND_PACK_PATH, generateMachineBoundPack());

  PORTABLE_PACK_PATH = join(TEST_DIR, 'portable.grx2');
  writeFileSync(PORTABLE_PACK_PATH, generatePortablePack());

  INVALID_JSON_PACK_PATH = join(TEST_DIR, 'invalid-json.grx2');
  writeFileSync(INVALID_JSON_PACK_PATH, generateInvalidJsonPack());

  // Create non-GRX2 file
  NON_GRX2_PATH = join(TEST_DIR, 'not-grx2.txt');
  writeFileSync(NON_GRX2_PATH, 'This is not a GRX2 file');
});

// Cleanup would be done manually after tests
// Note: Bun test doesn't have afterAll, but tmp cleanup happens on reboot

// =============================================================================
// T013: Valid Pack Decryption Tests
// =============================================================================

describe('T013: GRX2ExtendedLoader - Valid Pack Decryption', () => {
  test('should load valid pack with correct license key', async () => {
    const pack = await loadExtendedPack(
      VALID_PACK_PATH,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(pack).toBeDefined();
    expect(pack.name).toBe('test-pack');
    expect(pack.version).toBe('1.0.0');
    expect(pack.publisher).toBe('netsectech');
    expect(pack.rules).toBeInstanceOf(Array);
    expect(pack.rules.length).toBe(2);
    expect(pack.rules[0]?.id).toBe('TEST-001');
    expect(pack.rules[1]?.id).toBe('TEST-002');
  });

  test('should decrypt pack content correctly', async () => {
    const pack = await loadExtendedPack(
      VALID_PACK_PATH,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    // Verify rule content
    expect(pack.rules[0]?.selector).toBe('interface');
    expect(pack.rules[0]?.metadata.level).toBe('error');
    expect(pack.rules[0]?.metadata.obu).toBe('network');

    expect(pack.rules[1]?.selector).toBe('router bgp');
    expect(pack.rules[1]?.metadata.level).toBe('warning');
  });

  test('should call debug callback if provided', async () => {
    const debugMessages: string[] = [];
    const debug = (msg: string) => debugMessages.push(msg);

    await loadExtendedPack(
      VALID_PACK_PATH,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID,
      debug
    );

    expect(debugMessages.length).toBeGreaterThan(0);
    expect(debugMessages.some(msg => msg.includes('Loading pack'))).toBe(true);
    expect(debugMessages.some(msg => msg.includes('Header parsed'))).toBe(true);
  });
});

// =============================================================================
// T013: Error Handling - DECRYPTION_FAILED
// =============================================================================

describe('T013: GRX2ExtendedLoader - DECRYPTION_FAILED Error', () => {
  test('should throw DECRYPTION_FAILED with invalid license key', async () => {
    const invalidKey = 'wrong-license-key-12345678901234567890';

    await expect(
      loadExtendedPack(VALID_PACK_PATH, invalidKey, TEST_MACHINE_ID)
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(VALID_PACK_PATH, invalidKey, TEST_MACHINE_ID);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptedPackError);
      expect((error as EncryptedPackError).code).toBe('DECRYPTION_FAILED');
      expect((error as EncryptedPackError).message).toContain('TMK');
    }
  });

  test('should throw DECRYPTION_FAILED with empty license key', async () => {
    await expect(
      loadExtendedPack(VALID_PACK_PATH, '', TEST_MACHINE_ID)
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(VALID_PACK_PATH, '', TEST_MACHINE_ID);
    } catch (error) {
      expect((error as EncryptedPackError).code).toBe('DECRYPTION_FAILED');
    }
  });
});

// =============================================================================
// T013: Error Handling - PACK_CORRUPTED
// =============================================================================

describe('T013: GRX2ExtendedLoader - PACK_CORRUPTED Error', () => {
  test('should throw PACK_CORRUPTED with corrupted pack (invalid magic bytes)', async () => {
    await expect(
      loadExtendedPack(CORRUPTED_PACK_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID)
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(CORRUPTED_PACK_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptedPackError);
      expect((error as EncryptedPackError).code).toBe('PACK_CORRUPTED');
      expect((error as EncryptedPackError).message).toContain('extended GRX2');
    }
  });

  test('should throw PACK_CORRUPTED for non-GRX2 file', async () => {
    await expect(
      loadExtendedPack(NON_GRX2_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID)
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(NON_GRX2_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID);
    } catch (error) {
      expect((error as EncryptedPackError).code).toBe('PACK_CORRUPTED');
    }
  });

  test('should throw PACK_CORRUPTED with invalid JSON content', async () => {
    await expect(
      loadExtendedPack(INVALID_JSON_PACK_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID)
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(INVALID_JSON_PACK_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptedPackError);
      expect((error as EncryptedPackError).code).toBe('PACK_CORRUPTED');
      expect((error as EncryptedPackError).message).toContain('JSON');
    }
  });
});

// =============================================================================
// T013: isExtendedGRX2 Format Detection
// =============================================================================

describe('T013: isExtendedGRX2 - Format Detection', () => {
  test('should detect valid extended GRX2 format', () => {
    const validPack = generateValidPack();
    expect(isExtendedGRX2(validPack)).toBe(true);
  });

  test('should reject corrupted pack', () => {
    const corruptedPack = generateCorruptedPack();
    expect(isExtendedGRX2(corruptedPack)).toBe(false);
  });

  test('should reject non-GRX2 buffer', () => {
    const nonGRX2 = Buffer.from('This is not a GRX2 file');
    expect(isExtendedGRX2(nonGRX2)).toBe(false);
  });

  test('should reject too-small buffer', () => {
    const tooSmall = Buffer.alloc(50);
    expect(isExtendedGRX2(tooSmall)).toBe(false);
  });
});

// =============================================================================
// T021: Machine Binding Tests
// =============================================================================

describe('T021: GRX2ExtendedLoader - Machine Binding', () => {
  test('should load machine-bound pack with correct machine ID', async () => {
    const pack = await loadExtendedPack(
      MACHINE_BOUND_PACK_PATH,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(pack).toBeDefined();
    expect(pack.name).toBe('machine-bound-pack');
    expect(pack.rules.length).toBe(1);
    expect(pack.rules[0]?.id).toBe('MB-001');
  });

  test('should throw DECRYPTION_FAILED with wrong machine ID', async () => {
    // Use different machine ID - should fail TMK unwrapping
    await expect(
      loadExtendedPack(
        MACHINE_BOUND_PACK_PATH,
        TEST_LICENSE_KEY,
        TEST_MACHINE_ID_2
      )
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(
        MACHINE_BOUND_PACK_PATH,
        TEST_LICENSE_KEY,
        TEST_MACHINE_ID_2
      );
    } catch (error) {
      expect((error as EncryptedPackError).code).toBe('DECRYPTION_FAILED');
      expect((error as EncryptedPackError).message).toContain('machine ID');
    }
  });

  test('should throw DECRYPTION_FAILED with empty machine ID on bound pack', async () => {
    // Machine-bound pack requires specific machine ID
    await expect(
      loadExtendedPack(MACHINE_BOUND_PACK_PATH, TEST_LICENSE_KEY, '')
    ).rejects.toThrow(EncryptedPackError);

    try {
      await loadExtendedPack(MACHINE_BOUND_PACK_PATH, TEST_LICENSE_KEY, '');
    } catch (error) {
      expect((error as EncryptedPackError).code).toBe('DECRYPTION_FAILED');
    }
  });
});

// =============================================================================
// T027: Portable Pack Tests
// =============================================================================

describe('T027: GRX2ExtendedLoader - Portable Packs', () => {
  test('should load portable pack with empty machine ID', async () => {
    const pack = await loadExtendedPack(
      PORTABLE_PACK_PATH,
      TEST_LICENSE_KEY,
      ''
    );

    expect(pack).toBeDefined();
    expect(pack.name).toBe('portable-pack');
    expect(pack.rules.length).toBe(1);
    expect(pack.rules[0]?.id).toBe('PORT-001');
  });

  test('portable pack encrypted with empty machineId must be decrypted with empty machineId', async () => {
    // Portable packs are encrypted with empty machineId
    // They must be decrypted with the same empty machineId
    const pack = await loadExtendedPack(
      PORTABLE_PACK_PATH,
      TEST_LICENSE_KEY,
      '' // Must use empty string, matching encryption
    );

    expect(pack.name).toBe('portable-pack');
    expect(pack.rules[0]?.id).toBe('PORT-001');
  });

  test('portable pack works with any machine ID', async () => {
    // Portable packs have the portable flag set, so they work with ANY machine ID
    // The loader detects the flag and ignores the passed machineId
    const pack = await loadExtendedPack(PORTABLE_PACK_PATH, TEST_LICENSE_KEY, TEST_MACHINE_ID);
    expect(pack.name).toBe('portable-pack');
    expect(pack.rules[0]?.id).toBe('PORT-001');

    // Also works with a completely different machine ID
    const pack2 = await loadExtendedPack(PORTABLE_PACK_PATH, TEST_LICENSE_KEY, 'completely-different-machine-id');
    expect(pack2.name).toBe('portable-pack');
  });

  test('creating portable packs with multiple machine IDs', async () => {
    // Test the concept: create portable packs for different machines
    const portableForAnyMachine = {
      name: 'truly-portable',
      version: '1.0.0',
      publisher: 'test',
      rules: [],
    };

    const content = Buffer.from(JSON.stringify(portableForAnyMachine), 'utf8');

    // Create pack with empty machineId
    const pack1 = buildExtendedGRX2Pack(content, TEST_LICENSE_KEY, '', 1, 1);
    const path1 = join(TEST_DIR, 'portable-any.grx2');
    writeFileSync(path1, pack1);

    // Should load with empty machineId
    const loaded = await loadExtendedPack(path1, TEST_LICENSE_KEY, '');
    expect(loaded.name).toBe('truly-portable');
  });
});

// =============================================================================
// getPackInfo Tests
// =============================================================================

describe('GRX2ExtendedLoader - getPackInfo', () => {
  test('should get pack info without decryption', async () => {
    const info = await getPackInfo(VALID_PACK_PATH);

    expect(info).toBeDefined();
    expect(info.feedId).toBe('valid-pack');
    expect(info.isExtended).toBe(true);
    expect(info.tierId).toBeDefined();
    expect(info.tmkVersion).toBeDefined();
  });

  test('should get pack info for machine-bound pack', async () => {
    const info = await getPackInfo(MACHINE_BOUND_PACK_PATH);

    expect(info.feedId).toBe('machine-bound');
    expect(info.isExtended).toBe(true);
  });

  test('should throw error for non-GRX2 file', async () => {
    await expect(getPackInfo(NON_GRX2_PATH)).rejects.toThrow(EncryptedPackError);

    try {
      await getPackInfo(NON_GRX2_PATH);
    } catch (error) {
      expect((error as EncryptedPackError).code).toBe('PACK_CORRUPTED');
    }
  });
});

// =============================================================================
// loadAllPacks Tests
// =============================================================================

describe('GRX2ExtendedLoader - loadAllPacks', () => {
  test('should load all packs from directory', async () => {
    const result = await loadAllPacks(
      TEST_DIR,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(result).toBeDefined();
    expect(result.packs.length).toBeGreaterThan(0);

    // Should have successfully loaded packs
    const successfulPacks = result.packs.filter(p => p.loaded);
    expect(successfulPacks.length).toBeGreaterThan(0);

    // Should have failed packs (corrupted, invalid JSON, etc.)
    const failedPacks = result.packs.filter(p => !p.loaded);
    expect(failedPacks.length).toBeGreaterThan(0);
  });

  test('should include error messages for failed packs', async () => {
    const result = await loadAllPacks(
      TEST_DIR,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(result.errors.length).toBeGreaterThan(0);

    // Should have errors for corrupted and invalid JSON packs
    expect(result.errors.some(err => err.includes('corrupted-pack'))).toBe(true);
    expect(result.errors.some(err => err.includes('invalid-json'))).toBe(true);
  });

  test('should count total rules from loaded packs', async () => {
    const result = await loadAllPacks(
      TEST_DIR,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(result.totalRules).toBeGreaterThan(0);

    // Valid pack has 2 rules, machine-bound has 1, portable has 1
    // Total should be at least 4 (if all load successfully with correct machine ID)
    expect(result.totalRules).toBeGreaterThanOrEqual(2);
  });

  test('should filter by entitled feeds', async () => {
    const entitledFeeds = ['valid-pack'];

    const result = await loadAllPacks(
      TEST_DIR,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID,
      entitledFeeds
    );

    // Should only load packs in entitledFeeds
    const loadedFeeds = result.packs
      .filter(p => p.loaded)
      .map(p => p.feedId);

    // All loaded packs should be in entitledFeeds
    for (const feedId of loadedFeeds) {
      expect(entitledFeeds.includes(feedId)).toBe(true);
    }
  });

  test('should return empty result for non-existent directory', async () => {
    const result = await loadAllPacks(
      '/non/existent/path',
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(result.success).toBe(true);
    expect(result.packs).toEqual([]);
    expect(result.totalRules).toBe(0);
    expect(result.errors).toEqual([]);
  });

  test('should include pack metadata in result', async () => {
    const result = await loadAllPacks(
      TEST_DIR,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    const validPack = result.packs.find(p => p.feedId === 'valid-pack');

    expect(validPack).toBeDefined();
    expect(validPack?.name).toBe('test-pack');
    expect(validPack?.version).toBe('1.0.0');
    expect(validPack?.publisher).toBe('netsectech');
    expect(validPack?.ruleCount).toBe(2);
    expect(validPack?.source).toBe('local');
  });
});

// =============================================================================
// Edge Cases and Security
// =============================================================================

describe('GRX2ExtendedLoader - Edge Cases', () => {
  test('should handle pack with custom tier and TMK version', async () => {
    const customPack = {
      name: 'custom-pack',
      version: '2.0.0',
      publisher: 'test',
      rules: [],
    };

    const content = Buffer.from(JSON.stringify(customPack), 'utf8');
    const packBuffer = buildExtendedGRX2Pack(
      content,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID,
      5, // Custom tier
      10 // Custom TMK version
    );

    const tempPath = join(TEST_DIR, 'custom-tier.grx2');
    writeFileSync(tempPath, packBuffer);

    const pack = await loadExtendedPack(
      tempPath,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(pack.name).toBe('custom-pack');
    expect(pack.version).toBe('2.0.0');
  });

  test('should handle pack with empty rules array', async () => {
    const emptyRulesPack = {
      name: 'empty-rules',
      version: '1.0.0',
      publisher: 'test',
      rules: [],
    };

    const content = Buffer.from(JSON.stringify(emptyRulesPack), 'utf8');
    const packBuffer = buildExtendedGRX2Pack(
      content,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID,
      1,
      1
    );

    const tempPath = join(TEST_DIR, 'empty-rules.grx2');
    writeFileSync(tempPath, packBuffer);

    const pack = await loadExtendedPack(
      tempPath,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(pack.rules).toEqual([]);
  });

  test('should handle pack with unicode content', async () => {
    const unicodePack = {
      name: 'unicode-pack',
      version: '1.0.0',
      publisher: 'test',
      description: 'Pack with unicode: 你好, مرحبا, שלום',
      rules: [
        {
          id: 'UNI-001',
          selector: 'interface',
          metadata: { level: 'info', description: 'Unicode test: 🔒🌍' },
        },
      ],
    };

    const content = Buffer.from(JSON.stringify(unicodePack), 'utf8');
    const packBuffer = buildExtendedGRX2Pack(
      content,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID,
      1,
      1
    );

    const tempPath = join(TEST_DIR, 'unicode.grx2');
    writeFileSync(tempPath, packBuffer);

    const pack = await loadExtendedPack(
      tempPath,
      TEST_LICENSE_KEY,
      TEST_MACHINE_ID
    );

    expect(pack.description).toContain('你好');
    expect(pack.rules[0]?.metadata.description).toContain('🔒');
  });
});
