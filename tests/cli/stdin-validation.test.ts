/**
 * TR-007: Unit tests for stdin argument validation
 * Tests: `-` alone valid, `-` with files invalid, `-` with `-D` invalid
 */
import { describe, it, expect } from 'bun:test';

/**
 * Validation result for stdin argument
 */
interface StdinValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validates stdin argument usage (FR-020)
 * - `-` must be the only file argument
 * - `-` cannot be combined with `-D` directory mode
 */
function validateStdinArgument(
  files: string[],
  hasDirectory: boolean
): StdinValidationResult {
  const hasStdin = files.includes('-');

  if (!hasStdin) {
    return { valid: true };
  }

  // FR-020: `-` cannot be combined with other files
  if (files.length > 1) {
    return {
      valid: false,
      error: 'Cannot combine stdin (-) with other file arguments',
    };
  }

  // FR-020: `-` cannot be combined with -D directory mode
  if (hasDirectory) {
    return {
      valid: false,
      error: 'Cannot combine stdin (-) with directory mode (-D)',
    };
  }

  return { valid: true };
}

/**
 * Checks if stdin is requested
 */
function isStdinRequested(files: string[]): boolean {
  return files.length === 1 && files[0] === '-';
}

describe('stdin argument validation', () => {
  describe('valid: `-` alone', () => {
    it('should accept `-` as only argument', () => {
      const result = validateStdinArgument(['-'], false);
      expect(result.valid).toBe(true);
    });

    it('should detect stdin is requested', () => {
      expect(isStdinRequested(['-'])).toBe(true);
    });

    it('should not detect stdin for normal file', () => {
      expect(isStdinRequested(['file.cfg'])).toBe(false);
    });

    it('should not detect stdin for file named with dash', () => {
      expect(isStdinRequested(['-config.cfg'])).toBe(false);
    });

    it('should not detect stdin for empty files array', () => {
      expect(isStdinRequested([])).toBe(false);
    });
  });

  describe('invalid: `-` with files', () => {
    it('should reject `-` with another file', () => {
      const result = validateStdinArgument(['-', 'file.cfg'], false);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Cannot combine stdin');
    });

    it('should reject `-` with multiple files', () => {
      const result = validateStdinArgument(['-', 'a.cfg', 'b.cfg'], false);
      expect(result.valid).toBe(false);
    });

    it('should reject `-` appearing second', () => {
      const result = validateStdinArgument(['file.cfg', '-'], false);
      expect(result.valid).toBe(false);
    });

    it('should reject `-` in middle of files', () => {
      const result = validateStdinArgument(['a.cfg', '-', 'b.cfg'], false);
      expect(result.valid).toBe(false);
    });
  });

  describe('invalid: `-` with `-D`', () => {
    it('should reject `-` with directory mode', () => {
      const result = validateStdinArgument(['-'], true);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('directory mode');
    });
  });

  describe('valid: no stdin', () => {
    it('should accept single file', () => {
      const result = validateStdinArgument(['file.cfg'], false);
      expect(result.valid).toBe(true);
    });

    it('should accept multiple files', () => {
      const result = validateStdinArgument(['a.cfg', 'b.cfg'], false);
      expect(result.valid).toBe(true);
    });

    it('should accept empty files (will use help)', () => {
      const result = validateStdinArgument([], false);
      expect(result.valid).toBe(true);
    });

    it('should accept file starting with dash', () => {
      const result = validateStdinArgument(['-config.cfg'], false);
      expect(result.valid).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should handle file named literally "-"', () => {
      // In practice, users should use `./-` for literal dash file
      // Our validation treats `-` as stdin
      const result = validateStdinArgument(['-'], false);
      expect(result.valid).toBe(true);
    });

    it('should not confuse `--` with stdin', () => {
      const result = validateStdinArgument(['--'], false);
      expect(result.valid).toBe(true);
      expect(isStdinRequested(['--'])).toBe(false);
    });

    it('should handle multiple dashes in filename', () => {
      const result = validateStdinArgument(['--config--file.cfg'], false);
      expect(result.valid).toBe(true);
    });
  });
});
