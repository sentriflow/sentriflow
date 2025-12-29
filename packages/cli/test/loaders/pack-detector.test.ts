// packages/cli/test/loaders/pack-detector.test.ts

import { describe, expect, test, beforeAll, afterAll } from 'bun:test';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  detectPackFormat,
  createPackDescriptor,
  createPackDescriptors,
  FORMAT_PRIORITIES,
} from '../../src/loaders/pack-detector';

describe('Pack Format Detection', () => {
  let testDir: string;

  beforeAll(async () => {
    // Create temp directory for test files
    testDir = join(tmpdir(), `pack-detector-test-${Date.now()}`);
    await mkdir(testDir, { recursive: true });
  });

  afterAll(async () => {
    // Cleanup temp directory
    await rm(testDir, { recursive: true, force: true });
  });

  describe('FORMAT_PRIORITIES', () => {
    test('defines correct priority tiers', () => {
      expect(FORMAT_PRIORITIES.unknown).toBe(0);
      expect(FORMAT_PRIORITIES.unencrypted).toBe(100);
      expect(FORMAT_PRIORITIES.grpx).toBe(200);
      expect(FORMAT_PRIORITIES.grx2).toBe(300);
    });

    test('GRX2 has highest priority', () => {
      expect(FORMAT_PRIORITIES.grx2).toBeGreaterThan(FORMAT_PRIORITIES.grpx);
      expect(FORMAT_PRIORITIES.grpx).toBeGreaterThan(FORMAT_PRIORITIES.unencrypted);
      expect(FORMAT_PRIORITIES.unencrypted).toBeGreaterThan(FORMAT_PRIORITIES.unknown);
    });
  });

  describe('detectPackFormat', () => {
    test('detects GRX2 format from magic bytes', async () => {
      const testFile = join(testDir, 'test.grx2');
      const content = Buffer.concat([
        Buffer.from('GRX2', 'ascii'),
        Buffer.alloc(100), // Some additional content
      ]);
      await writeFile(testFile, content);

      const format = await detectPackFormat(testFile);
      expect(format).toBe('grx2');
    });

    test('detects GRPX format from magic bytes', async () => {
      const testFile = join(testDir, 'test.grpx');
      const content = Buffer.concat([
        Buffer.from('GRPX', 'ascii'),
        Buffer.alloc(100),
      ]);
      await writeFile(testFile, content);

      const format = await detectPackFormat(testFile);
      expect(format).toBe('grpx');
    });

    test('returns unencrypted for JS files', async () => {
      const testFile = join(testDir, 'test.js');
      await writeFile(testFile, 'module.exports = { rules: [] };');

      const format = await detectPackFormat(testFile);
      expect(format).toBe('unencrypted');
    });

    test('returns unencrypted for files with no magic bytes', async () => {
      const testFile = join(testDir, 'random.bin');
      await writeFile(testFile, 'random content without magic bytes');

      const format = await detectPackFormat(testFile);
      expect(format).toBe('unencrypted');
    });

    test('handles files smaller than 4 bytes', async () => {
      const testFile = join(testDir, 'tiny.bin');
      await writeFile(testFile, 'abc'); // Only 3 bytes

      const format = await detectPackFormat(testFile);
      expect(format).toBe('unencrypted');
    });

    test('handles empty files', async () => {
      const testFile = join(testDir, 'empty.bin');
      await writeFile(testFile, '');

      const format = await detectPackFormat(testFile);
      expect(format).toBe('unencrypted');
    });

    test('detects format regardless of file extension', async () => {
      // GRX2 content with .bin extension
      const testFile = join(testDir, 'grx2-with-wrong-ext.bin');
      const content = Buffer.concat([
        Buffer.from('GRX2', 'ascii'),
        Buffer.alloc(100),
      ]);
      await writeFile(testFile, content);

      const format = await detectPackFormat(testFile);
      expect(format).toBe('grx2');
    });

    test('throws for non-existent files', async () => {
      const testFile = join(testDir, 'does-not-exist.grx2');

      await expect(detectPackFormat(testFile)).rejects.toThrow('Pack file not found');
    });
  });

  describe('createPackDescriptor', () => {
    test('assigns correct priority for GRX2 pack', async () => {
      const testFile = join(testDir, 'priority-test.grx2');
      const content = Buffer.concat([
        Buffer.from('GRX2', 'ascii'),
        Buffer.alloc(100),
      ]);
      await writeFile(testFile, content);

      const desc = await createPackDescriptor(testFile, 2);

      expect(desc.format).toBe('grx2');
      expect(desc.basePriority).toBe(300);
      expect(desc.priority).toBe(302); // 300 + 2
    });

    test('assigns correct priority for GRPX pack', async () => {
      const testFile = join(testDir, 'priority-grpx.grpx');
      const content = Buffer.concat([
        Buffer.from('GRPX', 'ascii'),
        Buffer.alloc(100),
      ]);
      await writeFile(testFile, content);

      const desc = await createPackDescriptor(testFile, 5);

      expect(desc.format).toBe('grpx');
      expect(desc.basePriority).toBe(200);
      expect(desc.priority).toBe(205); // 200 + 5
    });

    test('assigns correct priority for unencrypted pack', async () => {
      const testFile = join(testDir, 'priority-unenc.js');
      await writeFile(testFile, 'module.exports = {};');

      const desc = await createPackDescriptor(testFile, 0);

      expect(desc.format).toBe('unencrypted');
      expect(desc.basePriority).toBe(100);
      expect(desc.priority).toBe(100); // 100 + 0
    });

    test('returns absolute path in descriptor', async () => {
      const testFile = join(testDir, 'abs-path.js');
      await writeFile(testFile, '');

      const desc = await createPackDescriptor(testFile, 0);

      // Should be absolute path
      expect(desc.path.startsWith('/') || desc.path.match(/^[A-Z]:\\/)).toBeTruthy();
    });
  });

  describe('createPackDescriptors', () => {
    test('creates descriptors for multiple packs', async () => {
      const grx2File = join(testDir, 'multi-1.grx2');
      const grpxFile = join(testDir, 'multi-2.grpx');
      const jsFile = join(testDir, 'multi-3.js');

      await writeFile(grx2File, Buffer.concat([Buffer.from('GRX2', 'ascii'), Buffer.alloc(10)]));
      await writeFile(grpxFile, Buffer.concat([Buffer.from('GRPX', 'ascii'), Buffer.alloc(10)]));
      await writeFile(jsFile, 'module.exports = {};');

      const descriptors = await createPackDescriptors([grx2File, grpxFile, jsFile]);

      expect(descriptors).toHaveLength(3);

      // First pack (index 0)
      expect(descriptors[0]?.format).toBe('grx2');
      expect(descriptors[0]?.priority).toBe(300); // 300 + 0

      // Second pack (index 1)
      expect(descriptors[1]?.format).toBe('grpx');
      expect(descriptors[1]?.priority).toBe(201); // 200 + 1

      // Third pack (index 2)
      expect(descriptors[2]?.format).toBe('unencrypted');
      expect(descriptors[2]?.priority).toBe(102); // 100 + 2
    });

    test('handles empty array', async () => {
      const descriptors = await createPackDescriptors([]);
      expect(descriptors).toHaveLength(0);
    });

    test('maintains order of input paths', async () => {
      const file1 = join(testDir, 'order-1.js');
      const file2 = join(testDir, 'order-2.js');

      await writeFile(file1, '// first');
      await writeFile(file2, '// second');

      const descriptors = await createPackDescriptors([file1, file2]);

      expect(descriptors[0]?.path).toContain('order-1');
      expect(descriptors[1]?.path).toContain('order-2');
    });
  });
});
