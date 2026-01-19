/**
 * Generic file loader with validation.
 * Consolidates common patterns from 5 file loading functions.
 *
 * Common pattern:
 * 1. Validate path with security checks
 * 2. Load file content (import or read)
 * 3. Validate structure with type guard
 * 4. Handle errors with SentriflowConfigError
 */
import { SentriflowConfigError } from '@sentriflow/core';
import type { LoadOptions } from './types';
import type { PathValidationResult } from '../security/pathValidator';

export type { LoadOptions } from './types';

/**
 * Validate a path and return the canonical path.
 * Throws SentriflowConfigError if validation fails.
 */
export function validatePathOrThrow(
  path: string,
  pathValidator: (p: string, b?: string[]) => PathValidationResult,
  errorContext: string,
  baseDirs?: string[]
): string {
  const validation = pathValidator(path, baseDirs);
  if (!validation.valid) {
    throw new SentriflowConfigError(
      `Invalid ${errorContext} path: ${validation.error}`
    );
  }
  return validation.canonicalPath!;
}

/**
 * Wrap an async operation with SentriflowConfigError handling.
 * Re-throws SentriflowConfigError, wraps other errors.
 */
export async function wrapLoadError<T>(
  operation: () => Promise<T>,
  errorContext: string
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof SentriflowConfigError) {
      throw error;
    }
    throw new SentriflowConfigError(`Failed to load ${errorContext} file`);
  }
}

/**
 * Generic file loader with path validation and type checking.
 *
 * @template T - The expected return type after validation
 * @param options - Load options including path, validators, and loader
 * @returns Promise resolving to the validated data of type T
 * @throws SentriflowConfigError on path validation failure, load failure, or validation failure
 */
export async function loadAndValidate<T>(options: LoadOptions<T>): Promise<T> {
  const { path, baseDirs, pathValidator, loader, validator, errorContext } =
    options;

  const canonicalPath = validatePathOrThrow(
    path,
    pathValidator,
    errorContext,
    baseDirs
  );

  return wrapLoadError(async () => {
    const data = await loader(canonicalPath);
    if (!validator(data)) {
      throw new SentriflowConfigError(`Invalid ${errorContext} structure`);
    }
    return data;
  }, errorContext);
}

// Pack format detection exports
export {
  detectPackFormat,
  createPackDescriptor,
  createPackDescriptors,
  FORMAT_PRIORITIES,
} from './pack-detector';
export type { PackFormat, PackDescriptor } from './pack-detector';

// Unified pack loader exports
export { loadGRX2Pack, mapGRX2LoadError } from './pack-loader';
