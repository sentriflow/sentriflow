/**
 * Tests for the pack format detector module
 *
 * Tests format detection from magic bytes for GRX2, GRPX, and unencrypted packs.
 */

import { describe, expect, it, beforeEach, afterEach } from 'bun:test';
import { writeFile, unlink, mkdir, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { detectPackFormat, FORMAT_PRIORITIES } from '../src/pack-loader/format-detector';

describe('FORMAT_PRIORITIES', () => {
  it('should have correct priority tiers', () => {
    expect(FORMAT_PRIORITIES.unknown).toBe(0);
    expect(FORMAT_PRIORITIES.unencrypted).toBe(100);
    expect(FORMAT_PRIORITIES.grpx).toBe(200);
    expect(FORMAT_PRIORITIES.grx2).toBe(300);
  });

  it('should have grx2 as highest priority', () => {
    const priorities = Object.values(FORMAT_PRIORITIES);
    expect(Math.max(...priorities)).toBe(FORMAT_PRIORITIES.grx2);
  });
});

describe('detectPackFormat', () => {
  let testDir: string;
  let testFiles: string[] = [];

  beforeEach(async () => {
    testDir = join(tmpdir(), `sentriflow-test-${Date.now()}`);
    await mkdir(testDir, { recursive: true });
    testFiles = [];
  });

  afterEach(async () => {
    // Clean up test files
    for (const file of testFiles) {
      try {
        await unlink(file);
      } catch {
        // Ignore errors
      }
    }
    try {
      await rmdir(testDir);
    } catch {
      // Ignore errors
    }
  });

  async function createTestFile(name: string, content: Buffer | string): Promise<string> {
    const path = join(testDir, name);
    await writeFile(path, content);
    testFiles.push(path);
    return path;
  }

  it('should detect GRX2 format from magic bytes', async () => {
    // GRX2 magic bytes: 'GRX2'
    const grx2Buffer = Buffer.alloc(96);
    grx2Buffer.write('GRX2', 0, 'ascii');

    const path = await createTestFile('test.grx2', grx2Buffer);
    const format = await detectPackFormat(path);

    expect(format).toBe('grx2');
  });

  it('should detect GRPX format from magic bytes', async () => {
    // GRPX magic bytes: 'GRPX'
    const grpxBuffer = Buffer.alloc(76);
    grpxBuffer.write('GRPX', 0, 'ascii');

    const path = await createTestFile('test.grpx', grpxBuffer);
    const format = await detectPackFormat(path);

    expect(format).toBe('grpx');
  });

  it('should detect unencrypted JavaScript format', async () => {
    const jsContent = `
// Rule pack
module.exports = {
  name: 'test-pack',
  version: '1.0.0',
  rules: []
};
`;
    const path = await createTestFile('test.js', jsContent);
    const format = await detectPackFormat(path);

    expect(format).toBe('unencrypted');
  });

  it('should detect unencrypted TypeScript format', async () => {
    const tsContent = `
export const pack = {
  name: 'test-pack',
  version: '1.0.0',
  rules: []
};
`;
    const path = await createTestFile('test.ts', tsContent);
    const format = await detectPackFormat(path);

    expect(format).toBe('unencrypted');
  });

  it('should return unencrypted for unrecognized binary format', async () => {
    // Random binary data with no recognizable magic bytes - treated as unencrypted
    const randomBuffer = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

    const path = await createTestFile('test.bin', randomBuffer);
    const format = await detectPackFormat(path);

    expect(format).toBe('unencrypted');
  });

  it('should return unencrypted for empty file', async () => {
    // Empty files without magic bytes are treated as unencrypted
    const path = await createTestFile('empty.bin', Buffer.alloc(0));
    const format = await detectPackFormat(path);

    expect(format).toBe('unencrypted');
  });

  it('should throw for non-existent file', async () => {
    await expect(detectPackFormat('/non/existent/path/file.grx2'))
      .rejects.toThrow('Pack file not found');
  });

  it('should handle files with .grx2 extension but wrong magic', async () => {
    // File has .grx2 extension but GRPX magic bytes
    const grpxBuffer = Buffer.alloc(76);
    grpxBuffer.write('GRPX', 0, 'ascii');

    const path = await createTestFile('misnamed.grx2', grpxBuffer);
    const format = await detectPackFormat(path);

    // Should detect based on magic bytes, not extension
    expect(format).toBe('grpx');
  });

  it('should handle files with .grpx extension but wrong magic', async () => {
    // File has .grpx extension but GRX2 magic bytes
    const grx2Buffer = Buffer.alloc(96);
    grx2Buffer.write('GRX2', 0, 'ascii');

    const path = await createTestFile('misnamed.grpx', grx2Buffer);
    const format = await detectPackFormat(path);

    // Should detect based on magic bytes, not extension
    expect(format).toBe('grx2');
  });
});
