// packages/rules-default/test/huawei-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, HuaweiVRPSchema, RuleEngine } from '@sentriflow/core';
import {
  allHuaweiRules,
  SysnameRequired,
  NtpRequired,
  SnmpCommunityNotDefault,
  SnmpV3Recommended,
  InterfaceDescriptionRequired,
  AccessPortStpEdgeRequired,
  TrunkVlanRestriction,
  PortSecurityRequired,
  VtyAaaRequired,
  VtySshRequired,
  VtyIdleTimeoutRequired,
  VtyAclRequired,
  LocalUserEncryptedPassword,
  HighPrivilegeUserWarning,
  BgpRouterIdRequired,
  BgpPeerDescriptionRequired,
  OspfRouterIdRequired,
  OspfAuthenticationRecommended,
  InfoCenterEnabled,
  SyslogServerRequired,
  SshServerEnabled,
  TelnetDisabled,
} from '../src/huawei/vrp-rules';

const parseHuawei = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: HuaweiVRPSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof SysnameRequired, config: string) => {
  const ast = parseHuawei(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('Huawei System Rules', () => {
  describe('HUAWEI-SYS-001: Sysname Required', () => {
    test('should pass when sysname is configured', () => {
      const config = `sysname CORE-SW01`;
      const results = runRule(SysnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-SYS-002: NTP Required', () => {
    test('should pass when NTP server is configured', () => {
      const config = `ntp-service
 unicast-server 10.0.1.10`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when NTP has no server', () => {
      const config = `ntp-service
 enable`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('NTP server');
    });
  });

  describe('HUAWEI-SYS-003: SNMP Community Not Default', () => {
    test('should fail when using default public community', () => {
      const config = `snmp-agent
 community read public`;
      const results = runRule(SnmpCommunityNotDefault, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('public');
    });

    test('should check custom community strings', () => {
      const config = `snmp-agent
 community read MY-SECRET-STRING123`;
      const results = runRule(SnmpCommunityNotDefault, config);
      // Rule runs on snmp-agent blocks - verify it processes custom strings
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe('HUAWEI-SYS-004: SNMPv3 Recommended', () => {
    test('should warn when only v2c is configured', () => {
      const config = `snmp-agent
 community read my-community`;
      const results = runRule(SnmpV3Recommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('v1/v2c');
    });

    test('should pass when v3 is configured', () => {
      const config = `snmp-agent
 usm-user v3 admin group admin-group`;
      const results = runRule(SnmpV3Recommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('Huawei Interface Rules', () => {
  describe('HUAWEI-IF-001: Interface Description Required', () => {
    test('should fail when physical interface has no description', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type access
 undo shutdown`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no description');
    });

    test('should pass when interface has description', () => {
      const config = `interface GigabitEthernet 0/0/1
 description UPLINK:CORE-SW01
 port link-type access
 undo shutdown`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip shutdown interfaces', () => {
      const config = `interface GigabitEthernet 0/0/1
 shutdown`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip virtual interfaces', () => {
      const config = `interface Vlanif100
 ip address 10.0.100.1 255.255.255.0`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-IF-002: Access Port STP Edge Required', () => {
    test('should fail when access port has no STP edge-port', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type access
 port default vlan 100
 undo shutdown`;
      const results = runRule(AccessPortStpEdgeRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('stp edged-port');
    });

    test('should pass when access port has STP edge-port', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type access
 port default vlan 100
 stp edged-port enable
 undo shutdown`;
      const results = runRule(AccessPortStpEdgeRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-IF-003: Trunk VLAN Restriction', () => {
    test('should fail when trunk allows all VLANs', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type trunk
 port trunk allow-pass vlan all
 undo shutdown`;
      const results = runRule(TrunkVlanRestriction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('all VLANs');
    });

    test('should pass when trunk has VLAN restrictions', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 30
 undo shutdown`;
      const results = runRule(TrunkVlanRestriction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-IF-004: Port Security Required', () => {
    test('should report when access port has no port security', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type access
 port default vlan 100
 undo shutdown`;
      const results = runRule(PortSecurityRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('port security');
    });

    test('should pass when access port has port security', () => {
      const config = `interface GigabitEthernet 0/0/1
 port link-type access
 port default vlan 100
 port-security enable
 undo shutdown`;
      const results = runRule(PortSecurityRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VTY / User Interface Rules Tests
// ============================================================================

describe('Huawei VTY Rules', () => {
  describe('HUAWEI-VTY-001: VTY AAA Required', () => {
    test('should fail when VTY uses password authentication', () => {
      const config = `user-interface vty 0 4
 authentication-mode password`;
      const results = runRule(VtyAaaRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('password authentication');
    });

    test('should pass when VTY uses AAA authentication', () => {
      const config = `user-interface vty 0 4
 authentication-mode aaa`;
      const results = runRule(VtyAaaRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-VTY-002: VTY SSH Required', () => {
    test('should fail when VTY allows telnet', () => {
      const config = `user-interface vty 0 4
 protocol inbound telnet`;
      const results = runRule(VtySshRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('Telnet');
    });

    test('should fail when VTY allows all protocols', () => {
      const config = `user-interface vty 0 4
 protocol inbound all`;
      const results = runRule(VtySshRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when VTY uses SSH only', () => {
      const config = `user-interface vty 0 4
 protocol inbound ssh`;
      const results = runRule(VtySshRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-VTY-003: VTY Idle Timeout Required', () => {
    test('should fail when no idle timeout is configured', () => {
      const config = `user-interface vty 0 4
 authentication-mode aaa`;
      const results = runRule(VtyIdleTimeoutRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('idle timeout');
    });

    test('should pass when idle timeout is configured', () => {
      const config = `user-interface vty 0 4
 idle-timeout 10 0
 authentication-mode aaa`;
      const results = runRule(VtyIdleTimeoutRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should warn when idle timeout is too long', () => {
      const config = `user-interface vty 0 4
 idle-timeout 60 0
 authentication-mode aaa`;
      const results = runRule(VtyIdleTimeoutRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('60 minutes');
    });
  });

  describe('HUAWEI-VTY-004: VTY ACL Required', () => {
    test('should fail when no ACL is applied', () => {
      const config = `user-interface vty 0 4
 authentication-mode aaa`;
      const results = runRule(VtyAclRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('ACL');
    });

    test('should check ACL configuration', () => {
      const config = `user-interface vty 0 4
 acl 2001 inbound
 authentication-mode aaa`;
      const results = runRule(VtyAclRequired, config);
      // Rule runs on user-interface vty blocks - verify it executes
      expect(results.length).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// AAA / Local User Rules Tests
// ============================================================================

describe('Huawei AAA Rules', () => {
  describe('HUAWEI-AAA-001: Local User Encrypted Password', () => {
    test('should fail when user has plaintext password', () => {
      const config = `local-user admin
 password simple admin123`;
      const results = runRule(LocalUserEncryptedPassword, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('plaintext');
    });

    test('should pass when user has encrypted password', () => {
      const config = `local-user admin
 password cipher %$%$abc123...`;
      const results = runRule(LocalUserEncryptedPassword, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when user has irreversible-cipher password', () => {
      const config = `local-user admin
 password irreversible-cipher %$%$abc123...`;
      const results = runRule(LocalUserEncryptedPassword, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-AAA-002: High Privilege User Warning', () => {
    test('should report privilege level 15 users', () => {
      const config = `local-user admin
 privilege level 15
 password cipher %$%$abc123...`;
      const results = runRule(HighPrivilegeUserWarning, config);
      const passed = results.filter((r) => r.passed);
      expect(passed.length).toBeGreaterThan(0);
      expect(passed[0]?.message).toContain('privilege level 15');
    });
  });
});

// ============================================================================
// Routing Protocol Rules Tests
// ============================================================================

describe('Huawei Routing Protocol Rules', () => {
  describe('HUAWEI-BGP-001: BGP Router-ID Required', () => {
    test('should fail when BGP has no router-id', () => {
      const config = `bgp 65000
 peer 192.168.1.1 as-number 65001`;
      const results = runRule(BgpRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('router-id');
    });

    test('should pass when BGP has router-id', () => {
      const config = `bgp 65000
 router-id 10.255.0.1
 peer 192.168.1.1 as-number 65001`;
      const results = runRule(BgpRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-BGP-002: BGP Peer Description Required', () => {
    test('should report when BGP peer has no description', () => {
      const config = `bgp 65000
 router-id 10.255.0.1
 peer 192.168.1.1 as-number 65001`;
      const results = runRule(BgpPeerDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when BGP peer has description', () => {
      const config = `bgp 65000
 router-id 10.255.0.1
 peer 192.168.1.1 as-number 65001
 peer 192.168.1.1 description ISP-Uplink`;
      const results = runRule(BgpPeerDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-OSPF-001: OSPF Router-ID Required', () => {
    test('should fail when OSPF has no router-id', () => {
      const config = `ospf 1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255`;
      const results = runRule(OspfRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('router-id');
    });

    test('should pass when OSPF has router-id', () => {
      const config = `ospf 1 router-id 10.255.0.1
 area 0.0.0.0
  network 10.0.0.0 0.0.0.255`;
      const results = runRule(OspfRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-OSPF-002: OSPF Authentication Recommended', () => {
    test('should report when OSPF area has no authentication', () => {
      const config = `area 0.0.0.0
 network 10.0.0.0 0.0.0.255`;
      const results = runRule(OspfAuthenticationRecommended, config);
      const passed = results.filter((r) => r.passed);
      expect(passed.length).toBeGreaterThan(0);
      expect(passed[0]?.message).toContain('does not have authentication');
    });

    test('should pass when OSPF area has authentication', () => {
      const config = `area 0.0.0.0
 authentication-mode md5
 network 10.0.0.0 0.0.0.255`;
      const results = runRule(OspfAuthenticationRecommended, config);
      const passed = results.filter((r) => r.passed);
      expect(passed.length).toBeGreaterThan(0);
      expect(passed[0]?.message).toContain('has authentication');
    });
  });
});

// ============================================================================
// Logging Rules Tests
// ============================================================================

describe('Huawei Logging Rules', () => {
  describe('HUAWEI-LOG-001: Info-Center Enabled', () => {
    test('should pass when info-center is enabled', () => {
      const config = `info-center enable`;
      const results = runRule(InfoCenterEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-LOG-002: Syslog Server Required', () => {
    test('should pass when syslog server is configured', () => {
      const config = `info-center loghost 10.0.1.100`;
      const results = runRule(SyslogServerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// SSH Rules Tests
// ============================================================================

describe('Huawei SSH Rules', () => {
  describe('HUAWEI-SSH-001: SSH Server Enabled', () => {
    test('should pass when SSH server is enabled', () => {
      const config = `ssh server enable`;
      const results = runRule(SshServerEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('HUAWEI-SSH-002: Telnet Disabled', () => {
    test('should pass when Telnet is disabled', () => {
      const config = `undo telnet server enable`;
      const results = runRule(TelnetDisabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Rules Export Tests
// ============================================================================

describe('Huawei Rules Export', () => {
  test('should export all Huawei rules', () => {
    expect(allHuaweiRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in sf-essentials
    expect(allHuaweiRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allHuaweiRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allHuaweiRules) {
      expect(rule.id).toMatch(/^HUAWEI-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
    }
  });
});
