/**
 * Pack Format Detection
 *
 * Detects pack format from magic bytes.
 * Shared between CLI and VS Code extension.
 *
 * @module format-detector
 */

import { open } from 'node:fs/promises';
import { resolve } from 'node:path';

/**
 * Detected pack format
 */
export type PackFormat = 'grx2' | 'grpx' | 'unencrypted' | 'unknown';

/**
 * Priority tiers by format.
 * Higher priority packs override lower priority packs for the same rule.
 *
 * - unknown: 0 (fallback, should not occur in normal operation)
 * - unencrypted: 100 (plain JS/TS modules)
 * - grpx: 200 (legacy encrypted format)
 * - grx2: 300 (extended encrypted format)
 */
export const FORMAT_PRIORITIES: Record<PackFormat, number> = {
  unknown: 0,
  unencrypted: 100,
  grpx: 200,
  grx2: 300,
};

/**
 * Magic bytes for format detection
 */
const MAGIC_BYTES = {
  GRX2: Buffer.from('GRX2', 'ascii'),
  GRPX: Buffer.from('GRPX', 'ascii'),
} as const;

const MAGIC_BYTES_LENGTH = 4;

/**
 * Detect the format of a pack file by reading magic bytes.
 *
 * @param filePath - Path to the pack file
 * @returns Promise resolving to the detected format
 *
 * @example
 * ```typescript
 * import { detectPackFormat } from '@sentriflow/core';
 *
 * const format = await detectPackFormat('/path/to/pack.grx2');
 * // Returns: 'grx2'
 *
 * const format2 = await detectPackFormat('/path/to/rules.js');
 * // Returns: 'unencrypted'
 * ```
 */
export async function detectPackFormat(filePath: string): Promise<PackFormat> {
  const absolutePath = resolve(filePath);
  let fileHandle;

  try {
    fileHandle = await open(absolutePath, 'r');
    const stats = await fileHandle.stat();

    // Files smaller than magic bytes length are treated as unencrypted
    if (stats.size < MAGIC_BYTES_LENGTH) {
      return 'unencrypted';
    }

    const buffer = Buffer.alloc(MAGIC_BYTES_LENGTH);
    const { bytesRead } = await fileHandle.read(
      buffer,
      0,
      MAGIC_BYTES_LENGTH,
      0
    );

    if (bytesRead < MAGIC_BYTES_LENGTH) {
      return 'unencrypted';
    }

    // Check for GRX2 magic bytes
    if (buffer.equals(MAGIC_BYTES.GRX2)) {
      return 'grx2';
    }

    // Check for GRPX magic bytes
    if (buffer.equals(MAGIC_BYTES.GRPX)) {
      return 'grpx';
    }

    // No magic bytes match - treat as unencrypted module
    return 'unencrypted';
  } catch (error) {
    // Re-throw file access errors with context
    if (error instanceof Error) {
      const nodeError = error as NodeJS.ErrnoException;
      if (nodeError.code === 'ENOENT') {
        throw new Error(`Pack file not found: ${absolutePath}`);
      }
      if (nodeError.code === 'EACCES') {
        throw new Error(`Permission denied reading pack file: ${absolutePath}`);
      }
    }
    throw error;
  } finally {
    await fileHandle?.close();
  }
}
