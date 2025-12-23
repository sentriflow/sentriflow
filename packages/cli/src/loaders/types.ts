/**
 * Types for the generic file loader module.
 * Part of the DRY refactor to consolidate 5 similar file loading functions.
 */
import type { PathValidationResult } from '../security/pathValidator';

/**
 * Options for the generic loadAndValidate function.
 * @template T - The expected return type after validation
 */
export interface LoadOptions<T> {
  /** Path to the file to load */
  path: string;

  /** SEC-011: Optional allowed base directories for path validation */
  baseDirs?: string[];

  /** Function to validate the path (returns PathValidationResult) */
  pathValidator: (path: string, baseDirs?: string[]) => PathValidationResult;

  /** Function to load/import the file content */
  loader: (canonicalPath: string) => Promise<unknown>;

  /** Type guard function to validate the loaded data */
  validator: (data: unknown) => data is T;

  /** Context string for error messages (e.g., "config", "rules", "JSON rules") */
  errorContext: string;
}
