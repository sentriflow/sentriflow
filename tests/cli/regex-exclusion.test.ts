/**
 * TR-002: Unit tests for isExcludedByRegex()
 * Tests: matching, non-matching, multiple patterns
 */
import { describe, it, expect } from 'bun:test';
import { isExcludedByRegex } from '../../packages/cli/src/scanner/DirectoryScanner';

describe('isExcludedByRegex', () => {
  describe('matching patterns', () => {
    it('should exclude file matching suffix pattern', () => {
      const patterns = [/\.bak$/];
      expect(isExcludedByRegex('config.bak', patterns)).toBe(true);
      expect(isExcludedByRegex('router.cfg.bak', patterns)).toBe(true);
    });

    it('should exclude file matching prefix pattern', () => {
      const patterns = [/^test_/];
      expect(isExcludedByRegex('test_config.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('test_', patterns)).toBe(true);
    });

    it('should exclude file matching directory pattern', () => {
      const patterns = [/backup\//];
      expect(isExcludedByRegex('backup/router.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('configs/backup/file.cfg', patterns)).toBe(true);
    });

    it('should match full path patterns', () => {
      const patterns = [/^subdir\/file\.cfg$/];
      expect(isExcludedByRegex('subdir/file.cfg', patterns)).toBe(true);
    });

    it('should match case-sensitive by default', () => {
      const patterns = [/\.BAK$/];
      expect(isExcludedByRegex('file.BAK', patterns)).toBe(true);
      expect(isExcludedByRegex('file.bak', patterns)).toBe(false);
    });

    it('should support case-insensitive flag', () => {
      const patterns = [/\.bak$/i];
      expect(isExcludedByRegex('file.BAK', patterns)).toBe(true);
      expect(isExcludedByRegex('file.bak', patterns)).toBe(true);
      expect(isExcludedByRegex('file.Bak', patterns)).toBe(true);
    });
  });

  describe('non-matching patterns', () => {
    it('should not exclude files that do not match', () => {
      const patterns = [/\.bak$/];
      expect(isExcludedByRegex('config.cfg', patterns)).toBe(false);
      expect(isExcludedByRegex('router.conf', patterns)).toBe(false);
    });

    it('should not exclude with prefix pattern when no prefix', () => {
      const patterns = [/^test_/];
      expect(isExcludedByRegex('config.cfg', patterns)).toBe(false);
      expect(isExcludedByRegex('mytest_file.cfg', patterns)).toBe(false);
    });

    it('should not match partial directory names', () => {
      const patterns = [/^backup$/];
      // Pattern requires exact match, not just contains
      expect(isExcludedByRegex('backup/file.cfg', patterns)).toBe(false);
      expect(isExcludedByRegex('mybackup/file.cfg', patterns)).toBe(false);
    });

    it('should return false for empty file path', () => {
      const patterns = [/\.bak$/];
      expect(isExcludedByRegex('', patterns)).toBe(false);
    });
  });

  describe('multiple patterns (OR logic)', () => {
    it('should exclude if any pattern matches', () => {
      const patterns = [/\.bak$/, /^test_/, /\.tmp$/];
      expect(isExcludedByRegex('file.bak', patterns)).toBe(true);
      expect(isExcludedByRegex('test_file.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('config.tmp', patterns)).toBe(true);
    });

    it('should not exclude if no pattern matches', () => {
      const patterns = [/\.bak$/, /^test_/, /\.tmp$/];
      expect(isExcludedByRegex('router.cfg', patterns)).toBe(false);
      expect(isExcludedByRegex('production_config.conf', patterns)).toBe(false);
    });

    it('should handle empty patterns array', () => {
      expect(isExcludedByRegex('any-file.cfg', [])).toBe(false);
    });

    it('should handle many patterns efficiently', () => {
      const patterns = Array.from({ length: 20 }, (_, i) =>
        new RegExp(`pattern${i}`)
      );
      expect(isExcludedByRegex('pattern15', patterns)).toBe(true);
      expect(isExcludedByRegex('nomatch', patterns)).toBe(false);
    });
  });

  describe('path normalization', () => {
    it('should match forward slashes in paths', () => {
      const patterns = [/subdir\/file/];
      expect(isExcludedByRegex('subdir/file.cfg', patterns)).toBe(true);
    });

    it('should work with nested directories', () => {
      const patterns = [/configs\/backup\/.*/];
      expect(isExcludedByRegex('configs/backup/router.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('configs/active/router.cfg', patterns)).toBe(false);
    });

    it('should handle relative paths', () => {
      const patterns = [/^\.\//];
      expect(isExcludedByRegex('./hidden.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('visible.cfg', patterns)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle patterns with special regex characters', () => {
      const patterns = [/file\[1\]\.cfg/];
      expect(isExcludedByRegex('file[1].cfg', patterns)).toBe(true);
    });

    it('should handle wildcard-like patterns', () => {
      const patterns = [/.*\.cfg$/];
      expect(isExcludedByRegex('anything.cfg', patterns)).toBe(true);
      expect(isExcludedByRegex('sub/dir/file.cfg', patterns)).toBe(true);
    });

    it('should handle patterns matching anywhere in path', () => {
      const patterns = [/node_modules/];
      expect(isExcludedByRegex('node_modules/file.js', patterns)).toBe(true);
      expect(isExcludedByRegex('src/node_modules/lib.js', patterns)).toBe(true);
    });

    it('should handle unicode in paths', () => {
      const patterns = [/файл/];
      expect(isExcludedByRegex('config_файл.cfg', patterns)).toBe(true);
    });
  });
});
