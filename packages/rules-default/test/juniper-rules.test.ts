// packages/rules-default/test/juniper-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import { SchemaAwareParser, JuniperJunOSSchema, RuleEngine } from '@sentriflow/core';
import {
  allJuniperRules,
  RootAuthRequired,
  JunosBgpRouterId,
  JunosFirewallDefaultDeny,
} from '../src/juniper/junos-rules';

const parseJunos = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof RootAuthRequired, config: string) => {
  const ast = parseJunos(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Security Rules Tests
// ============================================================================

describe('Juniper System Rules', () => {
  describe('JUN-SYS-001: Root Authentication Required', () => {
    test('should fail when root-authentication is missing', () => {
      const config = `system {
    host-name router1;
}`;
      const results = runRule(RootAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('root-authentication');
    });

    test('should pass when root-authentication has encrypted-password', () => {
      const config = `system {
    host-name router1;
    root-authentication {
        encrypted-password "$6$abc123";
    }
}`;
      const results = runRule(RootAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when root-authentication has ssh-rsa key', () => {
      const config = `system {
    host-name router1;
    root-authentication {
        ssh-rsa "ssh-rsa AAAA...";
    }
}`;
      const results = runRule(RootAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Routing Protocol Rules Tests
// ============================================================================

describe('Juniper Routing Rules', () => {
  describe('JUN-BGP-001: Router-ID Required', () => {
    test('should fail when router-id is missing', () => {
      const config = `routing-options {
    autonomous-system 65000;
}`;
      const results = runRule(JunosBgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when router-id is configured', () => {
      const config = `routing-options {
    router-id 192.168.255.1;
    autonomous-system 65000;
}`;
      const results = runRule(JunosBgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Firewall Rules Tests
// ============================================================================

describe('Juniper Firewall Rules', () => {
  describe('JUN-FW-001: Default Deny Required', () => {
    test('should fail when filter has no default deny', () => {
      const config = `firewall {
    family inet {
        filter PROTECT-RE {
            term ALLOW-SSH {
                from {
                    protocol tcp;
                    destination-port ssh;
                }
                then accept;
            }
        }
    }
}`;
      const results = runRule(JunosFirewallDefaultDeny, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when filter ends with discard', () => {
      const config = `firewall {
    family inet {
        filter PROTECT-RE {
            term ALLOW-SSH {
                from {
                    protocol tcp;
                    destination-port ssh;
                }
                then accept;
            }
            term DEFAULT-DENY {
                then discard;
            }
        }
    }
}`;
      const results = runRule(JunosFirewallDefaultDeny, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('Juniper Rules Integration', () => {
  test('allJuniperRules array should contain expected rules', () => {
    // Reduced to 3 proof-of-concept rules; full set available in sf-essentials
    expect(allJuniperRules.length).toBe(3);

    const ruleIds = allJuniperRules.map((r) => r.id);
    expect(ruleIds).toContain('JUN-SYS-001');
    expect(ruleIds).toContain('JUN-BGP-001');
    expect(ruleIds).toContain('JUN-FW-001');
  });

  test('should parse and validate Juniper fixture file', () => {
    const fixturePath = join(__dirname, '../../core/test/fixtures/juniper-junos/bgp-config.txt');
    const config = readFileSync(fixturePath, 'utf-8');

    const ast = parseJunos(config);
    expect(ast.length).toBeGreaterThan(0);

    const engine = new RuleEngine();
    const results = engine.run(ast, allJuniperRules);

    // Should have some results (pass or fail)
    expect(results.length).toBeGreaterThan(0);
  });
});
