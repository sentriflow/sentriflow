/**
 * TR-005: Unit tests for mergeDirectoryOptions()
 * Tests: CLI-only, config-only, merged, precedence rules
 */
import { describe, it, expect } from 'bun:test';
import { mergeDirectoryOptions, type DirectoryConfig } from '../../packages/cli/src/config';
import type { DirectoryScanOptions } from '../../packages/cli/src/scanner/DirectoryScanner';

describe('mergeDirectoryOptions', () => {
  describe('CLI-only options', () => {
    it('should use CLI options when no config provided', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        recursive: true,
        extensions: ['cfg'],
        maxDepth: 5,
      };

      const result = mergeDirectoryOptions(cliOptions, undefined);

      expect(result.recursive).toBe(true);
      expect(result.extensions).toEqual(['cfg']);
      expect(result.maxDepth).toBe(5);
    });

    it('should use CLI excludePatterns when no config', () => {
      const pattern = /\.bak$/;
      const cliOptions: Partial<DirectoryScanOptions> = {
        excludePatterns: [pattern],
      };

      const result = mergeDirectoryOptions(cliOptions, undefined);

      expect(result.excludePatterns).toEqual([pattern]);
    });

    it('should use CLI exclude when no config', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        exclude: ['**/backup/**'],
      };

      const result = mergeDirectoryOptions(cliOptions, undefined);

      expect(result.exclude).toEqual(['**/backup/**']);
    });
  });

  describe('config-only options', () => {
    it('should use config options when no CLI options provided', () => {
      const config: DirectoryConfig = {
        recursive: true,
        extensions: ['conf'],
        maxDepth: 10,
      };

      const result = mergeDirectoryOptions({}, config);

      expect(result.recursive).toBe(true);
      expect(result.extensions).toEqual(['conf']);
      expect(result.maxDepth).toBe(10);
    });

    it('should compile config excludePatterns to RegExp', () => {
      const config: DirectoryConfig = {
        excludePatterns: ['.*\\.bak$', '^test_'],
      };

      const result = mergeDirectoryOptions({}, config);

      expect(result.excludePatterns).toBeDefined();
      expect(result.excludePatterns!.length).toBe(2);
      expect(result.excludePatterns![0]).toBeInstanceOf(RegExp);
      expect(result.excludePatterns![0]!.test('file.bak')).toBe(true);
    });

    it('should use config exclude patterns', () => {
      const config: DirectoryConfig = {
        exclude: ['**/node_modules/**'],
      };

      const result = mergeDirectoryOptions({}, config);

      expect(result.exclude).toEqual(['**/node_modules/**']);
    });
  });

  describe('merged options', () => {
    it('should merge excludePatterns from both CLI and config (union)', () => {
      const cliPattern = /\.tmp$/;
      const cliOptions: Partial<DirectoryScanOptions> = {
        excludePatterns: [cliPattern],
      };
      const config: DirectoryConfig = {
        excludePatterns: ['.*\\.bak$'],
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.excludePatterns!.length).toBe(2);
      expect(result.excludePatterns).toContain(cliPattern);
    });

    it('should merge exclude patterns from both CLI and config (union)', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        exclude: ['**/temp/**'],
      };
      const config: DirectoryConfig = {
        exclude: ['**/backup/**'],
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.exclude).toContain('**/temp/**');
      expect(result.exclude).toContain('**/backup/**');
    });
  });

  describe('precedence rules (CLI wins for scalars)', () => {
    it('should prefer CLI recursive over config', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        recursive: false,
      };
      const config: DirectoryConfig = {
        recursive: true,
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.recursive).toBe(false);
    });

    it('should prefer CLI maxDepth over config', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        maxDepth: 3,
      };
      const config: DirectoryConfig = {
        maxDepth: 10,
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.maxDepth).toBe(3);
    });

    it('should prefer CLI extensions over config', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        extensions: ['cfg'],
      };
      const config: DirectoryConfig = {
        extensions: ['conf', 'ios'],
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.extensions).toEqual(['cfg']);
    });

    it('should use config value when CLI option is undefined', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        recursive: true,
        // maxDepth not specified
      };
      const config: DirectoryConfig = {
        maxDepth: 5,
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      expect(result.recursive).toBe(true);
      expect(result.maxDepth).toBe(5);
    });
  });

  describe('edge cases', () => {
    it('should handle both undefined', () => {
      const result = mergeDirectoryOptions({}, undefined);

      expect(result.excludePatterns).toEqual([]);
      expect(result.exclude).toEqual([]);
    });

    it('should handle empty config', () => {
      const result = mergeDirectoryOptions({}, {});

      expect(result.excludePatterns).toEqual([]);
    });

    it('should handle empty arrays in config', () => {
      const config: DirectoryConfig = {
        excludePatterns: [],
        exclude: [],
        extensions: [],
      };

      const result = mergeDirectoryOptions({}, config);

      expect(result.excludePatterns).toEqual([]);
      expect(result.exclude).toEqual([]);
    });

    it('should deduplicate exclude patterns', () => {
      const cliOptions: Partial<DirectoryScanOptions> = {
        exclude: ['**/backup/**'],
      };
      const config: DirectoryConfig = {
        exclude: ['**/backup/**', '**/temp/**'],
      };

      const result = mergeDirectoryOptions(cliOptions, config);

      // Should contain unique patterns only
      const uniquePatterns = [...new Set(result.exclude)];
      expect(result.exclude!.length).toBe(uniquePatterns.length);
    });
  });
});
