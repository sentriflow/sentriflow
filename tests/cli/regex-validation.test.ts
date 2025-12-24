/**
 * TR-001: Unit tests for validateRegexPattern()
 * Tests: valid patterns, invalid patterns, edge cases
 */
import { describe, it, expect } from 'bun:test';
import { validateRegexPattern } from '../../packages/cli/src/scanner/DirectoryScanner';

describe('validateRegexPattern', () => {
  describe('valid patterns', () => {
    it('should accept simple literal patterns', () => {
      const result = validateRegexPattern('test');
      expect(result.valid).toBe(true);
      expect(result.regex).toBeInstanceOf(RegExp);
    });

    it('should accept patterns with anchors', () => {
      expect(validateRegexPattern('^test$').valid).toBe(true);
      expect(validateRegexPattern('^prefix').valid).toBe(true);
      expect(validateRegexPattern('suffix$').valid).toBe(true);
    });

    it('should accept patterns with character classes', () => {
      expect(validateRegexPattern('[a-z]+').valid).toBe(true);
      expect(validateRegexPattern('[^a-z]').valid).toBe(true);
      expect(validateRegexPattern('[0-9]{2,4}').valid).toBe(true);
    });

    it('should accept patterns with quantifiers', () => {
      expect(validateRegexPattern('a+').valid).toBe(true);
      expect(validateRegexPattern('a*').valid).toBe(true);
      expect(validateRegexPattern('a?').valid).toBe(true);
      expect(validateRegexPattern('a{2,5}').valid).toBe(true);
    });

    it('should accept patterns with alternation', () => {
      expect(validateRegexPattern('foo|bar').valid).toBe(true);
      expect(validateRegexPattern('(foo|bar|baz)').valid).toBe(true);
    });

    it('should accept escaped special characters', () => {
      expect(validateRegexPattern('\\.bak$').valid).toBe(true);
      expect(validateRegexPattern('\\[test\\]').valid).toBe(true);
      expect(validateRegexPattern('a\\*b').valid).toBe(true);
    });

    it('should accept common file exclusion patterns', () => {
      expect(validateRegexPattern('.*\\.bak$').valid).toBe(true);
      expect(validateRegexPattern('^test_').valid).toBe(true);
      expect(validateRegexPattern('backup/.*').valid).toBe(true);
      expect(validateRegexPattern('.*\\.tmp$').valid).toBe(true);
    });

    it('should accept dot (any character) patterns', () => {
      expect(validateRegexPattern('.+').valid).toBe(true);
      expect(validateRegexPattern('.*').valid).toBe(true);
      expect(validateRegexPattern('a.b').valid).toBe(true);
    });

    it('should accept lookahead/lookbehind patterns', () => {
      expect(validateRegexPattern('foo(?=bar)').valid).toBe(true);
      expect(validateRegexPattern('(?<=foo)bar').valid).toBe(true);
      expect(validateRegexPattern('foo(?!bar)').valid).toBe(true);
    });
  });

  describe('invalid patterns', () => {
    it('should reject unclosed character class', () => {
      const result = validateRegexPattern('[abc');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject unclosed group', () => {
      const result = validateRegexPattern('(abc');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject invalid quantifier', () => {
      const result = validateRegexPattern('a{5,2}');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject invalid escape sequence in some cases', () => {
      // Note: JavaScript regex is lenient with escapes, but we test edge cases
      const result = validateRegexPattern('\\');
      expect(result.valid).toBe(false);
    });

    it('should reject unbalanced parentheses', () => {
      expect(validateRegexPattern('(a(b)').valid).toBe(false);
      expect(validateRegexPattern('a)b').valid).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should accept empty string pattern', () => {
      const result = validateRegexPattern('');
      expect(result.valid).toBe(true);
      expect(result.regex?.test('')).toBe(true);
    });

    it('should handle patterns with unicode', () => {
      const result = validateRegexPattern('файл');
      expect(result.valid).toBe(true);
    });

    it('should handle very long patterns', () => {
      const longPattern = 'a'.repeat(1000);
      const result = validateRegexPattern(longPattern);
      expect(result.valid).toBe(true);
    });

    it('should handle patterns with newlines', () => {
      const result = validateRegexPattern('line1\\nline2');
      expect(result.valid).toBe(true);
    });

    it('should handle patterns with only special chars', () => {
      expect(validateRegexPattern('^$').valid).toBe(true);
      expect(validateRegexPattern('|').valid).toBe(true);
    });

    it('should return compiled RegExp when valid', () => {
      const result = validateRegexPattern('^test$');
      expect(result.valid).toBe(true);
      expect(result.regex).toBeDefined();
      expect(result.regex?.test('test')).toBe(true);
      expect(result.regex?.test('notest')).toBe(false);
    });
  });
});
