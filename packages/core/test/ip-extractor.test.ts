// packages/core/test/ip-extractor.test.ts
// T027-T039: Comprehensive test coverage for IP extraction security hardening

import { describe, expect, test } from 'bun:test';
import {
  extractIPSummary,
  isValidIPv4,
  isValidIPv6,
  isValidSubnet,
  InputValidationError,
  DEFAULT_MAX_CONTENT_SIZE,
} from '../src/ip';

describe('extractIPSummary', () => {
  describe('security', () => {
    // T028: Test size limit rejection
    test('should reject content exceeding size limit', () => {
      // Create content that exceeds the 50MB limit
      const hugeContent = 'a'.repeat(DEFAULT_MAX_CONTENT_SIZE + 1);
      expect(() => extractIPSummary(hugeContent)).toThrow(InputValidationError);
    });

    // T029: Test ReDoS protection
    test('should not hang on ReDoS-triggering IPv6 input', () => {
      // Create potentially malicious input that could trigger ReDoS
      const malicious = 'aaaa:'.repeat(100) + 'aaaa';
      const start = Date.now();
      extractIPSummary(malicious);
      const elapsed = Date.now() - start;
      // Should complete in less than 1 second
      expect(elapsed).toBeLessThan(1000);
    });

    // T038: Test content at exactly 50MB limit (should succeed)
    test('should accept content at exactly 50MB limit', () => {
      // This test uses a smaller mock to avoid memory issues
      // The actual limit check is validated by the rejection test
      const atLimit = '192.168.1.1\n'.repeat(100);
      const result = extractIPSummary(atLimit, { maxContentSize: atLimit.length });
      expect(result.counts.ipv4).toBeGreaterThan(0);
    });

    // T039: Test content at 50MB + 1 byte (should fail)
    test('should reject content at 50MB + 1 byte', () => {
      const content = '192.168.1.1\n'.repeat(100);
      const limit = content.length - 1;
      expect(() => extractIPSummary(content, { maxContentSize: limit })).toThrow(InputValidationError);
    });
  });

  describe('edge cases', () => {
    // T030: Test empty string input
    test('should handle empty string', () => {
      const result = extractIPSummary('');
      expect(result.counts.total).toBe(0);
      expect(result.ipv4Addresses).toHaveLength(0);
      expect(result.ipv6Addresses).toHaveLength(0);
      expect(result.ipv4Subnets).toHaveLength(0);
      expect(result.ipv6Subnets).toHaveLength(0);
    });

    // T031: Test IPv6 zone ID stripping
    test('should handle IPv6 zone IDs', () => {
      const result = extractIPSummary('fe80::1%eth0');
      expect(result.ipv6Addresses).toContain('fe80:0:0:0:0:0:0:1');
    });

    test('should handle multiple IPv6 with different zone IDs', () => {
      const content = 'fe80::1%eth0 fe80::2%wlan0 fe80::3%lo';
      const result = extractIPSummary(content);
      expect(result.counts.ipv6).toBe(3);
    });

    // T032: Test CIDR prefix boundaries for IPv4
    test('should handle CIDR prefix boundaries for IPv4', () => {
      // /0 is valid
      const result0 = extractIPSummary('10.0.0.0/0');
      expect(result0.ipv4Subnets).toHaveLength(1);

      // /32 is valid
      const result32 = extractIPSummary('10.0.0.0/32');
      expect(result32.ipv4Subnets).toHaveLength(1);

      // /33 is invalid for IPv4
      const result33 = extractIPSummary('10.0.0.0/33');
      expect(result33.ipv4Subnets).toHaveLength(0);
    });

    // T033: Test CIDR prefix boundaries for IPv6
    test('should handle CIDR prefix boundaries for IPv6', () => {
      // /0 is valid
      const result0 = extractIPSummary('2001:db8::/0');
      expect(result0.ipv6Subnets).toHaveLength(1);

      // /128 is valid
      const result128 = extractIPSummary('2001:db8::/128');
      expect(result128.ipv6Subnets).toHaveLength(1);

      // /129 is invalid for IPv6
      const result129 = extractIPSummary('2001:db8::/129');
      expect(result129.ipv6Subnets).toHaveLength(0);
    });
  });
});

describe('isValidIPv4', () => {
  // T034: Test IPv4 validation with valid and invalid inputs
  test('should accept valid IPv4 addresses', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true);
    expect(isValidIPv4('0.0.0.0')).toBe(true);
    expect(isValidIPv4('255.255.255.255')).toBe(true);
    expect(isValidIPv4('10.0.0.1')).toBe(true);
    expect(isValidIPv4('172.16.0.1')).toBe(true);
  });

  test('should reject invalid IPv4 addresses', () => {
    expect(isValidIPv4('')).toBe(false);
    expect(isValidIPv4('256.1.1.1')).toBe(false);
    expect(isValidIPv4('1.1.1')).toBe(false);
    expect(isValidIPv4('1.1.1.1.1')).toBe(false);
    expect(isValidIPv4('192.168.01.1')).toBe(false); // leading zero
    expect(isValidIPv4('abc.def.ghi.jkl')).toBe(false);
    expect(isValidIPv4('192.168.1.-1')).toBe(false);
  });
});

describe('isValidIPv6', () => {
  // T035: Test IPv6 validation with valid and invalid inputs
  test('should accept valid IPv6 addresses', () => {
    expect(isValidIPv6('2001:db8::1')).toBe(true);
    expect(isValidIPv6('::1')).toBe(true);
    expect(isValidIPv6('::')).toBe(true);
    expect(isValidIPv6('fe80::1')).toBe(true);
    expect(isValidIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true);
    expect(isValidIPv6('fe80::1%eth0')).toBe(true); // with zone ID
  });

  test('should reject invalid IPv6 addresses', () => {
    expect(isValidIPv6('')).toBe(false);
    expect(isValidIPv6('2001:db8::1::2')).toBe(false); // multiple ::
    expect(isValidIPv6('2001:db8:::1')).toBe(false); // triple colon
    expect(isValidIPv6('gggg::1')).toBe(false); // invalid hex
    expect(isValidIPv6('12345::1')).toBe(false); // segment too long
  });
});

describe('isValidSubnet', () => {
  // T036: Test subnet validation with valid and invalid inputs
  test('should accept valid subnets', () => {
    expect(isValidSubnet('192.168.1.0/24')).toBe(true);
    expect(isValidSubnet('10.0.0.0/8')).toBe(true);
    expect(isValidSubnet('0.0.0.0/0')).toBe(true);
    expect(isValidSubnet('255.255.255.255/32')).toBe(true);
    expect(isValidSubnet('2001:db8::/32')).toBe(true);
    expect(isValidSubnet('::1/128')).toBe(true);
  });

  test('should reject invalid subnets', () => {
    expect(isValidSubnet('')).toBe(false);
    expect(isValidSubnet('192.168.1.0')).toBe(false); // no prefix
    expect(isValidSubnet('192.168.1.0/')).toBe(false); // empty prefix
    expect(isValidSubnet('192.168.1.0/33')).toBe(false); // IPv4 prefix > 32
    expect(isValidSubnet('2001:db8::/129')).toBe(false); // IPv6 prefix > 128
    expect(isValidSubnet('192.168.1.0/abc')).toBe(false); // non-numeric prefix
  });

  // T037: Test parseSubnet with invalid format (no slash)
  test('should handle invalid subnet format gracefully in extractIPSummary', () => {
    // The extractIPSummary should not crash when encountering invalid patterns
    // Invalid subnets are simply not extracted
    const result = extractIPSummary('192.168.1.0 without slash');
    // Should extract the IP but not as a subnet
    expect(result.ipv4Addresses).toContain('192.168.1.0');
    expect(result.ipv4Subnets).toHaveLength(0);
  });
});

describe('includeSubnetNetworks option', () => {
  test('should include subnet network addresses when option is true', () => {
    const result = extractIPSummary('10.0.0.0/24', { includeSubnetNetworks: true });
    expect(result.ipv4Subnets).toContain('10.0.0.0/24');
    expect(result.ipv4Addresses).toContain('10.0.0.0');
  });

  test('should not include subnet network addresses when option is false', () => {
    const result = extractIPSummary('10.0.0.0/24', { includeSubnetNetworks: false });
    expect(result.ipv4Subnets).toContain('10.0.0.0/24');
    expect(result.ipv4Addresses).not.toContain('10.0.0.0');
  });
});

describe('InputValidationError', () => {
  test('should have correct name and code', () => {
    const error = new InputValidationError('Test error', 'SIZE_LIMIT_EXCEEDED');
    expect(error.name).toBe('InputValidationError');
    expect(error.code).toBe('SIZE_LIMIT_EXCEEDED');
    expect(error.message).toBe('Test error');
  });

  test('should support INVALID_FORMAT code', () => {
    const error = new InputValidationError('Invalid format', 'INVALID_FORMAT');
    expect(error.code).toBe('INVALID_FORMAT');
  });
});
