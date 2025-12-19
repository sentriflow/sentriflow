// packages/rules-default/test/mikrotik-rules.test.ts
// Tests for MikroTik RouterOS demo rules (3 basic rules for demonstration)
// Full test suite available in @sentriflow/netsec-pack

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, MikroTikRouterOSSchema, RuleEngine } from '@sentriflow/core';
import {
  allMikroTikRules,
  MikrotikSystemIdentity,
  MikrotikDisableUnusedServices,
  MikrotikInputChainDrop,
} from '../src/mikrotik/routeros-rules';

const parseMikrotik = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: MikroTikRouterOSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof MikrotikSystemIdentity, config: string) => {
  const ast = parseMikrotik(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('MikroTik System Rules', () => {
  describe('MIK-SYS-001: System Identity', () => {
    test('should fail when identity is default MikroTik', () => {
      const config = `/system identity
set name=MikroTik`;
      const results = runRule(MikrotikSystemIdentity, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('default');
    });

    test('should pass when identity is customized', () => {
      const config = `/system identity
set name=CORE-RTR-01`;
      const results = runRule(MikrotikSystemIdentity, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Security Rules Tests
// ============================================================================

describe('MikroTik Security Rules', () => {
  describe('MIK-SEC-001: Disable Unused Services', () => {
    test('should warn when dangerous services are enabled', () => {
      const config = `/ip service
set telnet disabled=no
set ftp disabled=no`;
      const results = runRule(MikrotikDisableUnusedServices, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBeGreaterThan(0);
    });

    test('should pass when dangerous services are disabled', () => {
      const config = `/ip service
set telnet disabled=yes
set ftp disabled=yes
set api disabled=yes`;
      const results = runRule(MikrotikDisableUnusedServices, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Firewall Rules Tests
// ============================================================================

describe('MikroTik Firewall Rules', () => {
  describe('MIK-FW-001: Input Chain Drop', () => {
    test('should fail when input chain has no drop rule', () => {
      const config = `/ip firewall filter
add chain=input action=accept`;
      const results = runRule(MikrotikInputChainDrop, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no default drop');
    });

    test('should pass when input chain has drop rule', () => {
      const config = `/ip firewall filter
add chain=input action=accept connection-state=established,related
add chain=input action=drop`;
      const results = runRule(MikrotikInputChainDrop, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Rules Export Tests
// ============================================================================

describe('MikroTik Rules Export', () => {
  test('should export all MikroTik demo rules', () => {
    expect(allMikroTikRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allMikroTikRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allMikroTikRules) {
      expect(rule.id).toMatch(/^MIK-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('mikrotik-routeros');
    }
  });

  test('demo rules should cover system, security, and firewall', () => {
    const ruleIds = allMikroTikRules.map((r) => r.id);
    expect(ruleIds).toContain('MIK-SYS-001');
    expect(ruleIds).toContain('MIK-SEC-001');
    expect(ruleIds).toContain('MIK-FW-001');
  });
});
