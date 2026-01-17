// packages/vscode/test/suppression-manager.test.ts
//
// Unit tests for Suppression Manager utility functions.

import { describe, expect, test } from 'bun:test';
import {
  contentHash,
  truncateForPreview,
  MAX_PREVIEW_LENGTH,
} from '../src/services/suppressionHelpers';

// =============================================================================
// contentHash Tests
// =============================================================================

describe('contentHash', () => {
  test('returns consistent hash for same content', () => {
    const hash1 = contentHash('no ip domain-lookup');
    const hash2 = contentHash('no ip domain-lookup');
    expect(hash1).toBe(hash2);
  });

  test('ignores leading whitespace', () => {
    const hash1 = contentHash('  no ip domain-lookup');
    const hash2 = contentHash('no ip domain-lookup');
    expect(hash1).toBe(hash2);
  });

  test('ignores trailing whitespace', () => {
    const hash1 = contentHash('no ip domain-lookup  ');
    const hash2 = contentHash('no ip domain-lookup');
    expect(hash1).toBe(hash2);
  });

  test('ignores mixed leading/trailing whitespace', () => {
    const hash1 = contentHash('  no ip domain-lookup  ');
    const hash2 = contentHash('no ip domain-lookup');
    expect(hash1).toBe(hash2);
  });

  test('ignores tabs in leading/trailing whitespace', () => {
    const hash1 = contentHash('\t\tno ip domain-lookup\t');
    const hash2 = contentHash('no ip domain-lookup');
    expect(hash1).toBe(hash2);
  });

  test('different content produces different hash', () => {
    const hash1 = contentHash('line A');
    const hash2 = contentHash('line B');
    expect(hash1).not.toBe(hash2);
  });

  test('preserves internal whitespace differences', () => {
    const hash1 = contentHash('no  ip domain-lookup'); // two spaces
    const hash2 = contentHash('no ip domain-lookup'); // one space
    expect(hash1).not.toBe(hash2);
  });

  test('returns string in base36 format', () => {
    const hash = contentHash('test line');
    // base36 contains only 0-9 and a-z
    expect(hash).toMatch(/^[0-9a-z]+$/);
  });

  test('handles empty string', () => {
    const hash = contentHash('');
    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });

  test('handles whitespace-only string', () => {
    const hash1 = contentHash('   ');
    const hash2 = contentHash('');
    expect(hash1).toBe(hash2); // trimmed to empty
  });

  test('handles unicode characters', () => {
    const hash1 = contentHash('interface 日本語');
    const hash2 = contentHash('interface 日本語');
    expect(hash1).toBe(hash2);
  });

  test('handles long lines', () => {
    const longLine = 'a'.repeat(10000);
    const hash = contentHash(longLine);
    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });

  test('case sensitive', () => {
    const hash1 = contentHash('Interface GigabitEthernet0/0');
    const hash2 = contentHash('interface GigabitEthernet0/0');
    expect(hash1).not.toBe(hash2);
  });

  test('handles special characters', () => {
    const hash1 = contentHash('ip access-list extended BLOCK_RFC1918');
    const hash2 = contentHash('ip access-list extended BLOCK_RFC1918');
    expect(hash1).toBe(hash2);
  });

  test('stability across multiple calls', () => {
    // Test that the hash function is deterministic
    const input = 'service password-encryption';
    const hashes = new Set<string>();

    for (let i = 0; i < 100; i++) {
      hashes.add(contentHash(input));
    }

    expect(hashes.size).toBe(1); // All hashes should be identical
  });
});

// =============================================================================
// truncateForPreview Tests
// =============================================================================

describe('truncateForPreview', () => {
  test('returns unchanged text when under max length', () => {
    const short = 'no ip domain-lookup';
    expect(truncateForPreview(short)).toBe(short);
  });

  test('trims leading whitespace', () => {
    const text = '  no ip domain-lookup';
    expect(truncateForPreview(text)).toBe('no ip domain-lookup');
  });

  test('trims trailing whitespace', () => {
    const text = 'no ip domain-lookup  ';
    expect(truncateForPreview(text)).toBe('no ip domain-lookup');
  });

  test('truncates long text with ellipsis', () => {
    const longText = 'a'.repeat(100);
    const result = truncateForPreview(longText);
    expect(result.length).toBe(MAX_PREVIEW_LENGTH);
    expect(result.endsWith('...')).toBe(true);
  });

  test('respects custom max length', () => {
    const text = 'This is a test string for truncation';
    const result = truncateForPreview(text, 20);
    expect(result.length).toBe(20);
    expect(result.endsWith('...')).toBe(true);
  });

  test('handles exact max length', () => {
    const text = 'a'.repeat(MAX_PREVIEW_LENGTH);
    const result = truncateForPreview(text);
    expect(result.length).toBe(MAX_PREVIEW_LENGTH);
    expect(result.endsWith('...')).toBe(false); // No truncation needed
  });

  test('handles empty string', () => {
    expect(truncateForPreview('')).toBe('');
  });

  test('handles whitespace-only string', () => {
    expect(truncateForPreview('   ')).toBe('');
  });
});
