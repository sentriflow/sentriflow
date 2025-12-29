/**
 * Pack Format Detection Module
 *
 * Re-exports format detection from core and provides CLI-specific
 * pack descriptor utilities.
 *
 * @module pack-detector
 */

import { resolve } from 'node:path';
import {
  detectPackFormat,
  FORMAT_PRIORITIES,
  type PackFormat,
} from '@sentriflow/core';

// Re-export core format detection utilities
export { detectPackFormat, FORMAT_PRIORITIES, type PackFormat };

/**
 * Pack descriptor with detected format and priority
 */
export interface PackDescriptor {
  /** Absolute path to the pack file */
  path: string;

  /** Detected format */
  format: PackFormat;

  /** Base priority from format tier */
  basePriority: number;

  /** Final priority (basePriority + order index) */
  priority: number;
}

/**
 * Create a pack descriptor with format detection and priority.
 *
 * @param filePath - Path to the pack file
 * @param orderIndex - Position in the pack list (0-based)
 * @returns Promise resolving to the pack descriptor
 *
 * @example
 * const desc = await createPackDescriptor('/path/to/pack.grx2', 0);
 * // Returns: {
 * //   path: '/path/to/pack.grx2',
 * //   format: 'grx2',
 * //   basePriority: 300,
 * //   priority: 300  // 300 + 0
 * // }
 */
export async function createPackDescriptor(
  filePath: string,
  orderIndex: number
): Promise<PackDescriptor> {
  const absolutePath = resolve(filePath);
  const format = await detectPackFormat(absolutePath);
  const basePriority = FORMAT_PRIORITIES[format];

  return {
    path: absolutePath,
    format,
    basePriority,
    priority: basePriority + orderIndex,
  };
}

/**
 * Create pack descriptors for multiple pack paths.
 *
 * @param packPaths - Array of pack file paths
 * @returns Promise resolving to array of pack descriptors
 *
 * @example
 * const descriptors = await createPackDescriptors(['a.grx2', 'b.grpx', 'c.js']);
 */
export async function createPackDescriptors(
  packPaths: string[]
): Promise<PackDescriptor[]> {
  const descriptors: PackDescriptor[] = [];

  for (let i = 0; i < packPaths.length; i++) {
    const packPath = packPaths[i];
    if (packPath !== undefined) {
      const descriptor = await createPackDescriptor(packPath, i);
      descriptors.push(descriptor);
    }
  }

  return descriptors;
}
