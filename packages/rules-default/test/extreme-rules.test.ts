// packages/rules-default/test/extreme-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, ExtremeEXOSSchema, ExtremeVOSSSchema, RuleEngine } from '@sentriflow/core';
import {
  allExosRules,
  ExosSysnameRequired,
  ExosSntpRequired,
  ExosSntpEnabled,
  ExosSyslogRequired,
  ExosSsh2Enabled,
  ExosTelnetDisabled,
  ExosAaaRequired,
  ExosVlanNaming,
  ExosVlanTagRequired,
  ExosLagLacp,
  ExosEapsControlVlan,
  ExosStackingPriority,
  ExosMlagIsc,
} from '../src/extreme/exos-rules';
import {
  allVossRules,
  VossSysNameRequired,
  VossNtpRequired,
  VossLoggingRequired,
  VossSshEnabled,
  VossVlanIsidRequired,
  VossVlanIsidRange,
  VossInterfaceDefaultVlan,
  VossInterfaceNoShutdown,
  VossMltLacp,
  VossSpbmBvid,
  VossSpbmNickname,
  VossIsisEnabled,
  VossIsisSpbm,
  VossDvrDomainId,
} from '../src/extreme/voss-rules';

// ============================================================================
// EXOS Parser and Test Helpers
// ============================================================================

const parseExos = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: ExtremeEXOSSchema });
  return parser.parse(config);
};

const runExosRule = (rule: typeof ExosSysnameRequired, config: string) => {
  const ast = parseExos(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// VOSS Parser and Test Helpers
// ============================================================================

const parseVoss = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: ExtremeVOSSSchema });
  return parser.parse(config);
};

const runVossRule = (rule: typeof VossSysNameRequired, config: string) => {
  const ast = parseVoss(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// EXOS System Rules Tests
// ============================================================================

describe('Extreme EXOS System Rules', () => {
  describe('EXOS-SYS-001: SNMP Sysname Required', () => {
    test('should pass when sysname is configured', () => {
      const config = `configure snmp sysname "CORE-SW01"`;
      const results = runExosRule(ExosSysnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('EXOS-SYS-002: SNTP Required', () => {
    test('should pass when SNTP server is configured', () => {
      const config = `configure sntp-client primary server 10.0.1.10 vr VR-Default`;
      const results = runExosRule(ExosSntpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('EXOS-SYS-003: SNTP Client Enabled', () => {
    test('should pass when SNTP client is enabled', () => {
      const config = `enable sntp-client`;
      const results = runExosRule(ExosSntpEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('EXOS-SYS-004: Syslog Required', () => {
    test('should pass when syslog is configured', () => {
      const config = `configure syslog add 10.0.1.100:514 vr VR-Default local0 warning`;
      const results = runExosRule(ExosSyslogRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS Security Rules Tests
// ============================================================================

describe('Extreme EXOS Security Rules', () => {
  describe('EXOS-SEC-001: SSH2 Enabled', () => {
    test('should pass when SSH2 is enabled', () => {
      const config = `enable ssh2`;
      const results = runExosRule(ExosSsh2Enabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('EXOS-SEC-002: Telnet Disabled', () => {
    test('should pass when telnet is disabled', () => {
      const config = `disable telnet`;
      const results = runExosRule(ExosTelnetDisabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    // Note: ExosTelnetDisabled uses selector 'disable telnet', so it only
    // matches when 'disable telnet' command is found. The rule passes by default
    // when telnet is not mentioned (assumes default behavior), and warns when
    // 'enable telnet' is found. The selector approach means the rule is only
    // evaluated against 'disable telnet' nodes.
  });

  describe('EXOS-SEC-003: AAA Required', () => {
    test('should pass when RADIUS is configured', () => {
      const config = `configure radius primary server 10.0.1.50`;
      const results = runExosRule(ExosAaaRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when TACACS is configured', () => {
      const config = `configure tacacs primary server 10.0.1.51`;
      const results = runExosRule(ExosAaaRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS VLAN Rules Tests
// ============================================================================

describe('Extreme EXOS VLAN Rules', () => {
  describe('EXOS-VLAN-001: VLAN Naming', () => {
    test('should pass with descriptive VLAN name', () => {
      const config = `create vlan "DATA_FLOOR1" tag 100`;
      const results = runExosRule(ExosVlanNaming, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should report generic VLAN name', () => {
      const config = `create vlan "vlan100" tag 100`;
      const results = runExosRule(ExosVlanNaming, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('generic');
    });
  });

  describe('EXOS-VLAN-002: VLAN Tag Required', () => {
    test('should pass when VLAN has tag', () => {
      const config = `create vlan "DATA" tag 100`;
      const results = runExosRule(ExosVlanTagRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when VLAN has no tag', () => {
      const config = `create vlan "DATA"`;
      const results = runExosRule(ExosVlanTagRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('without a tag');
    });

    test('should pass for default VLAN without tag', () => {
      const config = `create vlan "Default"`;
      const results = runExosRule(ExosVlanTagRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS LAG Rules Tests
// ============================================================================

describe('Extreme EXOS LAG Rules', () => {
  describe('EXOS-LAG-001: LAG Should Use LACP', () => {
    test('should pass when LAG uses LACP', () => {
      const config = `enable sharing 1:1 grouping 1:1-1:2 lacp`;
      const results = runExosRule(ExosLagLacp, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should report when LAG does not use LACP', () => {
      const config = `enable sharing 1:1 grouping 1:1-1:2`;
      const results = runExosRule(ExosLagLacp, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('not using LACP');
    });
  });
});

// ============================================================================
// EXOS EAPS Rules Tests
// ============================================================================

describe('Extreme EXOS EAPS Rules', () => {
  describe('EXOS-EAPS-001: EAPS Control VLAN', () => {
    test('should pass when EAPS control VLAN is configured', () => {
      const config = `configure eaps RING1 add control vlan EAPS_CTRL`;
      const results = runExosRule(ExosEapsControlVlan, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS Stacking Rules Tests
// ============================================================================

describe('Extreme EXOS Stacking Rules', () => {
  describe('EXOS-STACK-001: Stacking Priority', () => {
    test('should pass when stacking priority is configured', () => {
      const config = `configure stacking node-address 00:04:96:aa:bb:cc priority 100`;
      const results = runExosRule(ExosStackingPriority, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS MLAG Rules Tests
// ============================================================================

describe('Extreme EXOS MLAG Rules', () => {
  describe('EXOS-MLAG-001: MLAG Peer ISC', () => {
    test('should pass when MLAG peer IP is configured', () => {
      const config = `configure mlag peer PEER1 ipaddress 10.255.255.2 vr VR-Default`;
      const results = runExosRule(ExosMlagIsc, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// EXOS Rules Export Tests
// ============================================================================

describe('Extreme EXOS Rules Export', () => {
  test('should export all EXOS rules', () => {
    expect(allExosRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in sf-essentials
    expect(allExosRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allExosRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allExosRules) {
      expect(rule.id).toMatch(/^EXOS-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('extreme-exos');
    }
  });
});

// ============================================================================
// VOSS System Rules Tests
// ============================================================================

describe('Extreme VOSS System Rules', () => {
  describe('VOSS-SYS-001: System Name Required', () => {
    test('should pass when system name is configured', () => {
      const config = `snmp-server name "VSP-CORE-01"`;
      const results = runVossRule(VossSysNameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VOSS-SYS-002: NTP Required', () => {
    test('should pass when NTP server is configured', () => {
      const config = `ntp server 10.0.1.10`;
      const results = runVossRule(VossNtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VOSS-SYS-003: Logging Required', () => {
    test('should pass when logging host is configured', () => {
      const config = `logging host 10.0.1.100`;
      const results = runVossRule(VossLoggingRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VOSS Security Rules Tests
// ============================================================================

describe('Extreme VOSS Security Rules', () => {
  describe('VOSS-SEC-001: SSH Enabled', () => {
    test('should pass when SSH is configured without shutdown', () => {
      const config = `ssh
    no shutdown`;
      const results = runVossRule(VossSshEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when SSH is shutdown', () => {
      const config = `ssh
    shutdown`;
      const results = runVossRule(VossSshEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('shutdown');
    });
  });
});

// ============================================================================
// VOSS VLAN Rules Tests
// ============================================================================

describe('Extreme VOSS VLAN Rules', () => {
  describe('VOSS-VLAN-001: VLAN I-SID for Fabric Connect', () => {
    test('should pass for SPBM B-VID VLAN', () => {
      const config = `vlan create 4051 type spbm-bvlan`;
      const results = runVossRule(VossVlanIsidRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass for regular VLAN (info level)', () => {
      const config = `vlan create 100 type port-mstprstp`;
      const results = runVossRule(VossVlanIsidRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VOSS-VLAN-002: VLAN I-SID Range', () => {
    test('should pass for valid I-SID', () => {
      const config = `vlan i-sid 100 10100`;
      const results = runVossRule(VossVlanIsidRange, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail for I-SID below minimum', () => {
      const config = `vlan i-sid 100 100`;
      const results = runVossRule(VossVlanIsidRange, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('outside valid range');
    });

    test('should fail for I-SID above maximum', () => {
      const config = `vlan i-sid 100 16777215`;
      const results = runVossRule(VossVlanIsidRange, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('outside valid range');
    });
  });
});

// ============================================================================
// VOSS Interface Rules Tests
// ============================================================================

describe('Extreme VOSS Interface Rules', () => {
  describe('VOSS-INT-001: Interface Default VLAN', () => {
    test('should pass when interface has default-vlan-id', () => {
      const config = `interface GigabitEthernet 1/1
    default-vlan-id 100
    no shutdown`;
      const results = runVossRule(VossInterfaceDefaultVlan, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip shutdown interfaces', () => {
      const config = `interface GigabitEthernet 1/1
    shutdown`;
      const results = runVossRule(VossInterfaceDefaultVlan, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VOSS-INT-002: Interface No Shutdown', () => {
    test('should report when interface is shutdown', () => {
      const config = `interface GigabitEthernet 1/1
    shutdown`;
      const results = runVossRule(VossInterfaceNoShutdown, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('shutdown');
    });

    test('should pass when interface is not shutdown', () => {
      const config = `interface GigabitEthernet 1/1
    no shutdown`;
      const results = runVossRule(VossInterfaceNoShutdown, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VOSS MLT Rules Tests
// ============================================================================

describe('Extreme VOSS MLT Rules', () => {
  describe('VOSS-MLT-001: MLT Should Use LACP', () => {
    test('should check MLT with LACP', () => {
      const config = `interface mlt 1
    lacp enable`;
      const results = runVossRule(VossMltLacp, config);
      // Rule runs on mlt interfaces - verify it executes
      expect(results.length).toBeGreaterThan(0);
    });

    test('should report when MLT does not have LACP', () => {
      const config = `interface mlt 1
    name "Server Link"`;
      const results = runVossRule(VossMltLacp, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('LACP');
    });
  });
});

// ============================================================================
// VOSS SPBM Rules Tests
// ============================================================================

describe('Extreme VOSS SPBM Rules', () => {
  describe('VOSS-SPBM-001: SPBM B-VIDs', () => {
    test('should pass when B-VIDs are configured', () => {
      const config = `spbm 1 b-vid 4051-4052 primary 4051`;
      const results = runVossRule(VossSpbmBvid, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VOSS-SPBM-002: SPBM Nick-name', () => {
    test('should pass when nick-name is configured correctly', () => {
      const config = `spbm 1 nick-name 1.00.01`;
      const results = runVossRule(VossSpbmNickname, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VOSS ISIS Rules Tests
// ============================================================================

describe('Extreme VOSS ISIS Rules', () => {
  describe('VOSS-ISIS-001: ISIS Enabled', () => {
    test('should pass when ISIS is not shutdown', () => {
      const config = `router isis
    no shutdown`;
      const results = runVossRule(VossIsisEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when ISIS is shutdown', () => {
      const config = `router isis
    shutdown`;
      const results = runVossRule(VossIsisEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('shutdown');
    });
  });

  describe('VOSS-ISIS-002: ISIS SPBM Configuration', () => {
    test('should check ISIS with SPBM configuration', () => {
      const config = `router isis
    spbm 1
    no shutdown`;
      const results = runVossRule(VossIsisSpbm, config);
      // Rule runs on isis router blocks - verify it executes
      expect(results.length).toBeGreaterThan(0);
    });

    test('should fail when ISIS has no SPBM configuration', () => {
      const config = `router isis
    no shutdown`;
      const results = runVossRule(VossIsisSpbm, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('SPBM');
    });
  });
});

// ============================================================================
// VOSS DVR Rules Tests
// ============================================================================

describe('Extreme VOSS DVR Rules', () => {
  describe('VOSS-DVR-001: DVR Domain-ID', () => {
    test('should pass when DVR leaf is configured', () => {
      const config = `dvr leaf`;
      const results = runVossRule(VossDvrDomainId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VOSS Rules Export Tests
// ============================================================================

describe('Extreme VOSS Rules Export', () => {
  test('should export all VOSS rules', () => {
    expect(allVossRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in sf-essentials
    expect(allVossRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allVossRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allVossRules) {
      expect(rule.id).toMatch(/^VOSS-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('extreme-voss');
    }
  });
});
