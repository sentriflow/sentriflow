/**
 * TR-004: Unit tests for DirectoryConfig validation
 * Tests: valid config, invalid regex patterns, type errors
 */
import { describe, it, expect } from 'bun:test';
import { isValidDirectoryConfig, type DirectoryConfig } from '../../packages/cli/src/config';

describe('DirectoryConfig validation', () => {
  describe('valid configurations', () => {
    it('should accept empty config', () => {
      const config: DirectoryConfig = {};
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept config with excludePatterns', () => {
      const config: DirectoryConfig = {
        excludePatterns: ['.*\\.bak$', '^test_'],
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept config with extensions', () => {
      const config: DirectoryConfig = {
        extensions: ['cfg', 'conf', 'ios'],
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept config with recursive flag', () => {
      const config: DirectoryConfig = {
        recursive: true,
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept config with maxDepth', () => {
      const config: DirectoryConfig = {
        maxDepth: 5,
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept config with exclude (glob patterns)', () => {
      const config: DirectoryConfig = {
        exclude: ['**/node_modules/**', '**/.git/**'],
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept fully populated config', () => {
      const config: DirectoryConfig = {
        excludePatterns: ['.*\\.bak$'],
        extensions: ['cfg', 'conf'],
        recursive: true,
        maxDepth: 10,
        exclude: ['**/backup/**'],
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });
  });

  describe('invalid regex patterns', () => {
    it('should reject config with invalid regex in excludePatterns', () => {
      const config = {
        excludePatterns: ['[invalid'],
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject config with multiple invalid regexes', () => {
      const config = {
        excludePatterns: ['valid', '[bad', '(unclosed'],
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-string in excludePatterns', () => {
      const config = {
        excludePatterns: ['valid', 123],
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });
  });

  describe('type errors', () => {
    it('should reject non-array excludePatterns', () => {
      const config = {
        excludePatterns: '.*\\.bak$',
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-array extensions', () => {
      const config = {
        extensions: 'cfg',
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-boolean recursive', () => {
      const config = {
        recursive: 'true',
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-number maxDepth', () => {
      const config = {
        maxDepth: '5',
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject negative maxDepth', () => {
      const config = {
        maxDepth: -1,
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject maxDepth exceeding limit', () => {
      const config = {
        maxDepth: 2000,
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-array exclude', () => {
      const config = {
        exclude: '**/backup/**',
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });

    it('should reject non-string in extensions', () => {
      const config = {
        extensions: ['cfg', 123],
      };
      expect(isValidDirectoryConfig(config)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should accept empty arrays', () => {
      const config: DirectoryConfig = {
        excludePatterns: [],
        extensions: [],
        exclude: [],
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should reject null config', () => {
      expect(isValidDirectoryConfig(null)).toBe(false);
    });

    it('should reject undefined config', () => {
      expect(isValidDirectoryConfig(undefined)).toBe(false);
    });

    it('should ignore unknown properties', () => {
      const config = {
        recursive: true,
        unknownProperty: 'ignored',
      };
      expect(isValidDirectoryConfig(config)).toBe(true);
    });

    it('should accept maxDepth of 0', () => {
      const config: DirectoryConfig = {
        maxDepth: 0,
      };
      // maxDepth of 0 means no recursion at all - should be valid
      expect(isValidDirectoryConfig(config)).toBe(true);
    });
  });
});
