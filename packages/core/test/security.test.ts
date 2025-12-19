// packages/core/test/security.test.ts

import { describe, test, expect } from 'bun:test';
import { sanitizeText, parseParameters } from '../src/parser/Sanitizer';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import {
    SentriflowError,
    SentriflowConfigError,
    SentriflowPathError,
    SentriflowParseError,
    SentriflowSizeLimitError,
    MAX_LINE_LENGTH,
    MAX_CONFIG_SIZE,
    MAX_NESTING_DEPTH,
    RULE_ID_PATTERN,
} from '../src';

describe('Security: Input Sanitization (M-3)', () => {
    test('removes null bytes', () => {
        expect(sanitizeText('hello\x00world')).toBe('helloworld');
    });

    test('removes control characters', () => {
        expect(sanitizeText('hello\x01\x02\x03world')).toBe('helloworld');
        expect(sanitizeText('test\x1Bstring')).toBe('teststring'); // ESC
        expect(sanitizeText('delete\x7Fchar')).toBe('deletechar'); // DEL
    });

    test('preserves tabs in middle of string', () => {
        // Tabs are valid whitespace in configs and should be preserved
        expect(sanitizeText('hello\tworld').includes('\t')).toBe(true);
        expect(sanitizeText('\thello\tworld\t')).toBe('hello\tworld'); // Leading/trailing tabs trimmed
    });

    test('normalizes unicode spaces', () => {
        expect(sanitizeText('hello\u00A0world')).toBe('hello world'); // No-Break Space
        expect(sanitizeText('hello\u2003world')).toBe('hello world'); // Em Space
        expect(sanitizeText('hello\u3000world')).toBe('hello world'); // Ideographic Space
    });

    test('handles mixed control chars and unicode spaces', () => {
        expect(sanitizeText('he\x00llo\u00A0wo\x1Brld')).toBe('hello world');
    });

    test('trims leading and trailing whitespace', () => {
        expect(sanitizeText('  hello world  ')).toBe('hello world');
        expect(sanitizeText('\n\thello\t\n')).toBe('hello');
    });
});

describe('Security: Parameter Parsing (M-3)', () => {
    test('parses simple parameters', () => {
        expect(parseParameters('interface GigabitEthernet1')).toEqual(['interface', 'GigabitEthernet1']);
    });

    test('handles quoted strings with spaces', () => {
        expect(parseParameters('banner motd "Hello World"')).toEqual(['banner', 'motd', 'Hello World']);
        expect(parseParameters("username bob password 'my secret'")).toEqual(['username', 'bob', 'password', 'my secret']);
    });

    test('handles mixed quotes', () => {
        expect(parseParameters('test "double quoted" and \'single quoted\'')).toEqual([
            'test', 'double quoted', 'and', 'single quoted'
        ]);
    });

    test('handles empty input', () => {
        expect(parseParameters('')).toEqual([]);
        expect(parseParameters('   ')).toEqual([]);
    });

    test('handles multiple spaces between parameters', () => {
        expect(parseParameters('ip    address   1.1.1.1')).toEqual(['ip', 'address', '1.1.1.1']);
    });
});

describe('Security: ReDoS Protection (M-2)', () => {
    test('parser handles content within size limits', () => {
        const parser = new SchemaAwareParser();
        const normalConfig = 'interface GigabitEthernet1\n ip address 10.0.0.1 255.255.255.0';

        const nodes = parser.parse(normalConfig);
        expect(nodes.length).toBeGreaterThan(0);
    });

    test('parser throws on oversized input', () => {
        const parser = new SchemaAwareParser();
        // Create input larger than MAX_CONFIG_SIZE
        const oversizedConfig = 'x'.repeat(MAX_CONFIG_SIZE + 1);

        expect(() => parser.parse(oversizedConfig)).toThrow(SentriflowSizeLimitError);
    });

    test('parser skips excessively long lines', () => {
        const parser = new SchemaAwareParser();
        const longLine = 'interface ' + 'x'.repeat(MAX_LINE_LENGTH + 100);
        const normalLine = 'interface GigabitEthernet1';
        const config = `${longLine}\n${normalLine}`;

        const nodes = parser.parse(config);
        // Should only parse the normal line, skipping the long one
        expect(nodes.length).toBe(1);
        expect(nodes[0]?.id).toBe('interface GigabitEthernet1');
    });

    test('parser handles many lines efficiently', () => {
        const parser = new SchemaAwareParser();
        // Use block starters so they don't get wrapped in virtual_root
        const lines = Array(1000).fill(0).map((_, i) => `interface GigabitEthernet${i}`);
        const config = lines.join('\n');

        const start = Date.now();
        const nodes = parser.parse(config);
        const elapsed = Date.now() - start;

        // Should complete quickly (under 1 second)
        expect(elapsed).toBeLessThan(1000);
        // Each interface block becomes a separate top-level node
        expect(nodes.length).toBe(1000);
    });
});

describe('Security: Custom Error Classes (L-1)', () => {
    test('SentriflowError has correct structure', () => {
        const error = new SentriflowError('TEST_CODE', 'Test message', { key: 'value' });

        expect(error.code).toBe('TEST_CODE');
        expect(error.message).toBe('Test message');
        expect(error.details).toEqual({ key: 'value' });
        expect(error.name).toBe('SentriflowError');
    });

    test('SentriflowError toUserMessage hides details', () => {
        const error = new SentriflowError('ERR_001', 'Something went wrong', { internal: 'secret' });

        expect(error.toUserMessage()).toBe('[ERR_001] Something went wrong');
        expect(error.toUserMessage()).not.toContain('secret');
    });

    test('SentriflowConfigError has CONFIG_ERROR code', () => {
        const error = new SentriflowConfigError('Invalid configuration');

        expect(error.code).toBe('CONFIG_ERROR');
        expect(error.name).toBe('SentriflowConfigError');
    });

    test('SentriflowPathError has PATH_ERROR code', () => {
        const error = new SentriflowPathError('Invalid path');

        expect(error.code).toBe('PATH_ERROR');
        expect(error.name).toBe('SentriflowPathError');
    });

    test('SentriflowSizeLimitError has SIZE_LIMIT_ERROR code', () => {
        const error = new SentriflowSizeLimitError('Too large');

        expect(error.code).toBe('SIZE_LIMIT_ERROR');
        expect(error.name).toBe('SentriflowSizeLimitError');
    });
});

describe('Security: Rule ID Validation', () => {
    test('RULE_ID_PATTERN accepts valid IDs', () => {
        expect(RULE_ID_PATTERN.test('NET-IP-001')).toBe(true);
        expect(RULE_ID_PATTERN.test('SEC-AUTH-123')).toBe(true);
        expect(RULE_ID_PATTERN.test('CUSTOM_RULE_42')).toBe(true);
        expect(RULE_ID_PATTERN.test('ABC')).toBe(true);
    });

    test('RULE_ID_PATTERN rejects invalid IDs', () => {
        expect(RULE_ID_PATTERN.test('ab')).toBe(false); // Too short
        expect(RULE_ID_PATTERN.test('lowercase')).toBe(false); // Starts lowercase
        expect(RULE_ID_PATTERN.test('123-NUM')).toBe(false); // Starts with number
        expect(RULE_ID_PATTERN.test('RULE WITH SPACE')).toBe(false); // Contains space
        expect(RULE_ID_PATTERN.test('')).toBe(false); // Empty
    });
});

describe('Security: Constants', () => {
    test('MAX_LINE_LENGTH is reasonable', () => {
        expect(MAX_LINE_LENGTH).toBeGreaterThan(100);
        expect(MAX_LINE_LENGTH).toBeLessThan(100000);
    });

    test('MAX_CONFIG_SIZE is reasonable', () => {
        expect(MAX_CONFIG_SIZE).toBeGreaterThan(1024 * 1024); // > 1MB
        expect(MAX_CONFIG_SIZE).toBeLessThan(100 * 1024 * 1024); // < 100MB
    });

    test('MAX_NESTING_DEPTH is reasonable', () => {
        expect(MAX_NESTING_DEPTH).toBeGreaterThan(10);
        expect(MAX_NESTING_DEPTH).toBeLessThan(1000);
    });
});

describe('Security: Nesting Depth Protection', () => {
    test('parser handles reasonable nesting', () => {
        const parser = new SchemaAwareParser();
        const config = `
interface GigabitEthernet1
 ip address 10.0.0.1 255.255.255.0
 description Test
router bgp 65000
 address-family ipv4 unicast
  network 10.0.0.0/24
`;

        const nodes = parser.parse(config);
        expect(nodes.length).toBeGreaterThan(0);
    });
});
