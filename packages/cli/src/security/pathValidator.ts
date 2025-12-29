// packages/cli/src/security/pathValidator.ts

import { existsSync, statSync, realpathSync } from 'fs';
import { extname, resolve, isAbsolute, sep } from 'path';
import {
  ALLOWED_CONFIG_EXTENSIONS,
  ALLOWED_ENCRYPTED_PACK_EXTENSIONS,
  ALLOWED_GRX2_PACK_EXTENSIONS,
  ALLOWED_JSON_RULES_EXTENSIONS,
  MAX_CONFIG_FILE_SIZE,
  MAX_ENCRYPTED_PACK_SIZE,
} from '@sentriflow/core';
import { SentriflowPathError } from '@sentriflow/core';

/**
 * Normalizes path separators for cross-platform comparison.
 * Converts Windows backslashes to forward slashes for consistent comparison.
 */
function normalizeSeparators(p: string): string {
  return p.replace(/\\/g, '/');
}

/**
 * Result of path validation.
 */
export interface PathValidationResult {
  valid: boolean;
  canonicalPath?: string;
  error?: string;
}

/**
 * Options for path validation.
 */
export interface PathValidationOptions {
  /** Allowed base directories (paths must be within one of these) */
  allowedBaseDirs?: string[];
  /** Maximum file size in bytes */
  maxFileSize?: number;
  /** Allowed file extensions */
  allowedExtensions?: string[];
  /** Whether the path must exist */
  mustExist?: boolean;
}

/**
 * Validates a file path for security concerns.
 *
 * Checks:
 * 1. File extension is allowed
 * 2. File exists (if required)
 * 3. Resolves symlinks to canonical path
 * 4. File is a regular file (not directory, device, etc.)
 * 5. File size is within limits
 * 6. Path is within allowed directories (if specified)
 *
 * @param inputPath - The path to validate
 * @param options - Validation options
 * @returns Validation result with canonical path if valid
 */
export function validatePath(
  inputPath: string,
  options: PathValidationOptions = {}
): PathValidationResult {
  const {
    allowedBaseDirs,
    maxFileSize = MAX_CONFIG_FILE_SIZE,
    allowedExtensions = ALLOWED_CONFIG_EXTENSIONS,
    mustExist = true,
  } = options;

  try {
    // SEC-011: Block UNC paths on Windows (\\server\share)
    if (inputPath.startsWith('\\\\') || inputPath.startsWith('//')) {
      return {
        valid: false,
        error: 'Network (UNC) paths are not allowed',
      };
    }

    // Resolve to absolute path
    const absolutePath = resolve(inputPath);

    // Validate extension
    const ext = extname(absolutePath).toLowerCase();
    if (allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
      return {
        valid: false,
        error: `Invalid file extension: ${ext}. Allowed: ${allowedExtensions.join(
          ', '
        )}`,
      };
    }

    // Check if file exists
    if (!existsSync(absolutePath)) {
      if (mustExist) {
        return { valid: false, error: 'File not found' };
      }
      // If file doesn't need to exist, return the absolute path
      return { valid: true, canonicalPath: absolutePath };
    }

    // Resolve symlinks to get canonical path
    let canonicalPath: string;
    try {
      canonicalPath = realpathSync(absolutePath);
    } catch (error) {
      // Log error for debugging, but don't expose sensitive path details
      const errorType = error instanceof Error ? error.name : 'Unknown';
      if (process.env.DEBUG) {
        console.error(`[pathValidator] Failed to resolve path: ${errorType}`, error);
      }
      return {
        valid: false,
        error: 'Failed to resolve path (possible broken symlink)',
      };
    }

    // Verify it's a regular file
    const stats = statSync(canonicalPath);
    if (!stats.isFile()) {
      return { valid: false, error: 'Path is not a regular file' };
    }

    // Check file size
    if (stats.size > maxFileSize) {
      return {
        valid: false,
        error: `File too large: ${stats.size} bytes (max: ${maxFileSize})`,
      };
    }

    // Boundary check - ensure path is within allowed directories
    // SEC-011: Use normalized separators for cross-platform compatibility
    if (allowedBaseDirs && allowedBaseDirs.length > 0) {
      const normalizedCanonical = normalizeSeparators(canonicalPath);

      const isWithinBounds = allowedBaseDirs.some((baseDir) => {
        try {
          const canonicalBase = realpathSync(resolve(baseDir));
          const normalizedBase = normalizeSeparators(canonicalBase);
          // Ensure the canonical path starts with the base dir
          // and is followed by a path separator (to prevent /home/userX matching /home/user)
          return (
            normalizedCanonical === normalizedBase ||
            normalizedCanonical.startsWith(normalizedBase + '/')
          );
        } catch {
          return false;
        }
      });

      if (!isWithinBounds) {
        return {
          valid: false,
          error: 'Path is outside allowed directories',
        };
      }
    }

    return { valid: true, canonicalPath };
  } catch (error) {
    return {
      valid: false,
      error: 'Path validation failed',
    };
  }
}

/**
 * Validates a configuration file path.
 * Wrapper around validatePath with config-specific defaults.
 *
 * @param configPath - Path to the configuration file
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validateConfigPath(
  configPath: string,
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(configPath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: ALLOWED_CONFIG_EXTENSIONS,
    maxFileSize: MAX_CONFIG_FILE_SIZE,
    mustExist: true,
  });
}

/**
 * SEC-012: Validates an encrypted rule pack (.grpx) file path.
 * Wrapper around validatePath with encrypted pack-specific defaults.
 *
 * @param packPath - Path to the encrypted pack file
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validateEncryptedPackPath(
  packPath: string,
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(packPath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: ALLOWED_ENCRYPTED_PACK_EXTENSIONS,
    maxFileSize: MAX_ENCRYPTED_PACK_SIZE,
    mustExist: true,
  });
}

/**
 * Validates a GRX2 extended encrypted rule pack (.grx2) file path.
 * Wrapper around validatePath with GRX2 pack-specific defaults.
 *
 * @param packPath - Path to the GRX2 pack file
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validateGrx2PackPath(
  packPath: string,
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(packPath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: ALLOWED_GRX2_PACK_EXTENSIONS,
    maxFileSize: MAX_ENCRYPTED_PACK_SIZE,
    mustExist: true,
  });
}

/**
 * Validates a JSON rules file path.
 * Wrapper around validatePath with JSON-specific defaults.
 *
 * @param jsonPath - Path to the JSON rules file
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validateJsonRulesPath(
  jsonPath: string,
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(jsonPath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: ALLOWED_JSON_RULES_EXTENSIONS,
    maxFileSize: MAX_CONFIG_FILE_SIZE,
    mustExist: true,
  });
}

/**
 * Validates a file path for reading (any text file).
 * Less restrictive than config validation.
 *
 * @param filePath - Path to the file
 * @param maxSize - Maximum file size in bytes
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validateInputFilePath(
  filePath: string,
  maxSize: number = 10 * 1024 * 1024, // 10MB default
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(filePath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: [], // Allow any extension for input files
    maxFileSize: maxSize,
    mustExist: true,
  });
}

/**
 * Validates a unified pack file path (any format: .grx2, .grpx, .js, etc.).
 * Used by the unified --pack argument. Format detection is done via magic bytes,
 * so any extension is allowed.
 *
 * @param packPath - Path to the pack file
 * @param baseDirs - Optional allowed base directories
 * @returns Validation result
 */
export function validatePackPath(
  packPath: string,
  baseDirs?: string[]
): PathValidationResult {
  return validatePath(packPath, {
    allowedBaseDirs: baseDirs,
    allowedExtensions: [], // Allow any extension - format detected via magic bytes
    maxFileSize: MAX_ENCRYPTED_PACK_SIZE,
    mustExist: true,
  });
}

/**
 * Throws sentriflowPathError if validation fails.
 * Convenience wrapper for validatePath.
 *
 * @param inputPath - Path to validate
 * @param options - Validation options
 * @returns Canonical path if valid
 * @throws sentriflowPathError if validation fails
 */
export function assertValidPath(
  inputPath: string,
  options: PathValidationOptions = {}
): string {
  const result = validatePath(inputPath, options);
  if (!result.valid) {
    throw new SentriflowPathError(result.error || 'Invalid path');
  }
  return result.canonicalPath!;
}
