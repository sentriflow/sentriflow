/**
 * Tests for the validation module
 *
 * Tests rule validation, pack validation, and vendor matching utilities.
 */

import { describe, expect, it } from 'bun:test';
import {
  validateRule,
  isValidRule,
  validateRulePack,
  isValidRulePack,
  ruleAppliesToVendor,
} from '../src/validation';
import type { IRule, RulePack } from '../src/types/IRule';

// Helper to create a minimal valid rule for testing
// Uses unknown cast since validation tests need minimal objects, not full IRule
function createTestRule(overrides = {}): IRule {
  return {
    id: 'NET-001',
    metadata: { level: 'info', obu: 'Test', owner: 'Tester' },
    check: () => ({ passed: true, message: '', ruleId: 'NET-001', nodeId: '', level: 'info' }),
    ...overrides,
  } as unknown as IRule;
}

describe('validateRule', () => {
  it('should return null for valid rule', () => {
    const rule = createTestRule();
    expect(validateRule(rule)).toBeNull();
  });

  it('should return error for null', () => {
    expect(validateRule(null)).toBe('Rule is not an object');
  });

  it('should return error for undefined', () => {
    expect(validateRule(undefined)).toBe('Rule is not an object');
  });

  it('should return error for missing id', () => {
    const rule = {
      metadata: { level: 'info' },
      check: () => ({ passed: true }),
    };
    expect(validateRule(rule)).toBe('Rule id is not a string');
  });

  it('should return error for invalid id format', () => {
    const rule = {
      id: 'invalid_id',
      metadata: { level: 'info' },
      check: () => ({ passed: true }),
    };
    expect(validateRule(rule)).toMatch(/Rule id "invalid_id" does not match pattern/);
  });

  it('should return error for missing metadata', () => {
    const rule = {
      id: 'NET-001',
      check: () => ({ passed: true }),
    };
    expect(validateRule(rule)).toBe('Rule NET-001: metadata is not an object');
  });

  it('should return error for missing check function', () => {
    const rule = {
      id: 'NET-001',
      metadata: { level: 'info' },
    };
    expect(validateRule(rule)).toBe('Rule NET-001: check is not a function (got undefined)');
  });

  it('should accept valid vendor string', () => {
    const rule = createTestRule({ vendor: 'cisco-ios' });
    expect(validateRule(rule)).toBeNull();
  });

  it('should accept valid vendor array', () => {
    const rule = createTestRule({ vendor: ['cisco-ios', 'juniper-junos'] });
    expect(validateRule(rule)).toBeNull();
  });
});

describe('isValidRule', () => {
  it('should return true for valid rule', () => {
    const rule = createTestRule();
    expect(isValidRule(rule)).toBe(true);
  });

  it('should return false for invalid rule', () => {
    expect(isValidRule(null)).toBe(false);
    expect(isValidRule({ id: 'bad' })).toBe(false);
  });
});

describe('validateRulePack', () => {
  it('should return null for valid pack', () => {
    const pack: RulePack = {
      name: 'test-pack',
      version: '1.0.0',
      publisher: 'Test Publisher',
      priority: 100,
      rules: [],
    };
    expect(validateRulePack(pack)).toBeNull();
  });

  it('should return error for null', () => {
    expect(validateRulePack(null)).toBe('Pack is not an object');
  });

  it('should return error for missing name', () => {
    const pack = {
      version: '1.0.0',
      publisher: 'Test',
      priority: 100,
      rules: [],
    };
    expect(validateRulePack(pack)).toBe('Pack name is missing or empty');
  });

  it('should return error for reserved name', () => {
    const pack = {
      name: 'sf-default',
      version: '1.0.0',
      publisher: 'Test',
      priority: 100,
      rules: [],
    };
    expect(validateRulePack(pack, 'sf-default')).toBe('Pack name "sf-default" is reserved');
  });

  it('should return error for missing version', () => {
    const pack = {
      name: 'test-pack',
      publisher: 'Test',
      priority: 100,
      rules: [],
    };
    expect(validateRulePack(pack)).toBe('Pack version is missing or empty');
  });

  it('should return error for missing priority', () => {
    const pack = {
      name: 'test-pack',
      version: '1.0.0',
      publisher: 'Test',
      rules: [],
    };
    expect(validateRulePack(pack)).toBe('Pack priority is invalid (got undefined)');
  });

  it('should return error for invalid rules', () => {
    const pack = {
      name: 'test-pack',
      version: '1.0.0',
      publisher: 'Test',
      priority: 100,
      rules: 'not-an-array',
    };
    expect(validateRulePack(pack)).toBe('Pack rules is not an array');
  });
});

describe('isValidRulePack', () => {
  it('should return true for valid pack', () => {
    const pack: RulePack = {
      name: 'test-pack',
      version: '1.0.0',
      publisher: 'Test',
      priority: 100,
      rules: [],
    };
    expect(isValidRulePack(pack)).toBe(true);
  });

  it('should return false for invalid pack', () => {
    expect(isValidRulePack(null)).toBe(false);
    expect(isValidRulePack({ name: 'test' })).toBe(false);
  });
});

describe('ruleAppliesToVendor', () => {
  it('should return true when rule has no vendor restriction', () => {
    const rule = createTestRule();
    expect(ruleAppliesToVendor(rule, 'cisco-ios')).toBe(true);
    expect(ruleAppliesToVendor(rule, 'juniper-junos')).toBe(true);
  });

  it('should return true when vendor matches string vendor', () => {
    const rule = createTestRule({ vendor: 'cisco-ios' });
    expect(ruleAppliesToVendor(rule, 'cisco-ios')).toBe(true);
  });

  it('should return false when vendor does not match string vendor', () => {
    const rule = createTestRule({ vendor: 'cisco-ios' });
    expect(ruleAppliesToVendor(rule, 'juniper-junos')).toBe(false);
  });

  it('should return true when vendor is in vendor array', () => {
    const rule = createTestRule({ vendor: ['cisco-ios', 'juniper-junos'] });
    expect(ruleAppliesToVendor(rule, 'cisco-ios')).toBe(true);
    expect(ruleAppliesToVendor(rule, 'juniper-junos')).toBe(true);
  });

  it('should return false when vendor is not in vendor array', () => {
    const rule = createTestRule({ vendor: ['cisco-ios', 'juniper-junos'] });
    expect(ruleAppliesToVendor(rule, 'arista-eos')).toBe(false);
  });
});
