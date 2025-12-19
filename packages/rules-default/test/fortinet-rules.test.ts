// packages/rules-default/test/fortinet-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, FortinetFortiGateSchema, RuleEngine } from '@sentriflow/core';
import {
  allFortinetRules,
  HostnameRequired,
  NtpRequired,
  DnsRequired,
  AdminTimeoutRequired,
  PasswordPolicyRequired,
  PreLoginBannerRequired,
  AdminTrustedHostRequired,
  LimitSuperAdmins,
  NoTelnetAccess,
  NoHttpManagement,
  InterfaceDescriptionRequired,
  PolicyLoggingRequired,
  PolicySecurityProfileRequired,
  NoOverlyPermissivePolicies,
  PolicyCommentRequired,
  NoAnyServicePolicy,
  HARecommended,
  HAEncryptionRequired,
  VpnStrongEncryption,
  VpnDpdEnabled,
  SyslogRequired,
  AntivirusProfileRequired,
  IpsSensorRequired,
  WebFilterProfileRequired,
  ApplicationListRequired,
} from '../src/fortinet/fortigate-rules';

const parseFortigate = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: FortinetFortiGateSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof HostnameRequired, config: string) => {
  const ast = parseFortigate(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('FortiGate System Rules', () => {
  describe('FGT-SYS-001: Hostname Required', () => {
    test('should fail when hostname is missing', () => {
      const config = `config system global
    set timezone "America/New_York"
end`;
      const results = runRule(HostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('hostname');
    });

    test('should pass when hostname is configured', () => {
      const config = `config system global
    set hostname "FW-01"
    set timezone "America/New_York"
end`;
      const results = runRule(HostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-SYS-002: NTP Required', () => {
    test('should fail when NTP is not enabled', () => {
      const config = `config system ntp
    set ntpsync disable
end`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('NTP');
    });

    test('should pass when NTP is enabled with servers', () => {
      const config = `config system ntp
    set ntpsync enable
    set type fortiguard
    edit 1
        set server "0.pool.ntp.org"
    next
end`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-SYS-003: DNS Required', () => {
    test('should fail when primary DNS is not configured', () => {
      const config = `config system dns
    set protocol cleartext
end`;
      const results = runRule(DnsRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when DNS servers are configured', () => {
      const config = `config system dns
    set primary 8.8.8.8
    set secondary 8.8.4.4
end`;
      const results = runRule(DnsRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-SYS-004: Admin Timeout Required', () => {
    test('should warn when admin timeout is too long', () => {
      const config = `config system global
    set hostname "FW-01"
    set admintimeout 60
end`;
      const results = runRule(AdminTimeoutRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('30 minutes');
    });

    test('should pass when admin timeout is appropriate', () => {
      const config = `config system global
    set hostname "FW-01"
    set admintimeout 15
end`;
      const results = runRule(AdminTimeoutRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-SYS-005: Password Policy Required', () => {
    test('should fail when strong-crypto is not enabled', () => {
      const config = `config system global
    set hostname "FW-01"
    set admin-lockout-threshold 3
end`;
      const results = runRule(PasswordPolicyRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('Strong crypto');
    });

    test('should pass when password policy is configured', () => {
      const config = `config system global
    set hostname "FW-01"
    set admin-lockout-threshold 3
    set strong-crypto enable
end`;
      const results = runRule(PasswordPolicyRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-SYS-006: Pre-Login Banner Required', () => {
    test('should report when pre-login banner is not enabled', () => {
      const config = `config system global
    set hostname "FW-01"
end`;
      const results = runRule(PreLoginBannerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when pre-login banner is enabled', () => {
      const config = `config system global
    set hostname "FW-01"
    set pre-login-banner enable
end`;
      const results = runRule(PreLoginBannerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Admin Rules Tests
// ============================================================================

describe('FortiGate Admin Rules', () => {
  describe('FGT-ADMIN-001: Admin Trusted Hosts Required', () => {
    test('should fail when admin has no trusted hosts', () => {
      const config = `config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
    next
end`;
      const results = runRule(AdminTrustedHostRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('trusted host');
    });

    test('should pass when admin has trusted hosts', () => {
      const config = `config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set trusthost1 192.168.1.0 255.255.255.0
    next
end`;
      const results = runRule(AdminTrustedHostRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-ADMIN-002: Limit Super Admins', () => {
    test('should warn when too many super_admin accounts exist', () => {
      const config = `config system admin
    edit "admin1"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
    next
    edit "admin2"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
    next
    edit "admin3"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
    next
    edit "admin4"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
    next
end`;
      const results = runRule(LimitSuperAdmins, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('super_admin');
    });

    test('should pass when super_admin count is reasonable', () => {
      const config = `config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost1 192.168.1.0 255.255.255.0
    next
    edit "readonly"
        set accprofile "prof_admin"
    next
end`;
      const results = runRule(LimitSuperAdmins, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('FortiGate Interface Rules', () => {
  describe('FGT-IF-001: No Telnet Access', () => {
    test('should fail when interface allows telnet', () => {
      const config = `config system interface
    edit "internal"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh telnet
    next
end`;
      const results = runRule(NoTelnetAccess, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('Telnet');
    });

    test('should pass when no interface has telnet access', () => {
      const config = `config system interface
    edit "lan"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh
    next
end`;
      const results = runRule(NoTelnetAccess, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-IF-002: No HTTP Management', () => {
    test('should warn when interface allows HTTP', () => {
      const config = `config system interface
    edit "mgmt"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess http https ssh
    next
end`;
      const results = runRule(NoHttpManagement, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('HTTP');
    });

    test('should pass when only HTTPS is allowed', () => {
      const config = `config system interface
    edit "mgmt"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess https ssh
    next
end`;
      const results = runRule(NoHttpManagement, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-IF-003: Interface Description Required', () => {
    test('should report when interface has no description', () => {
      const config = `config system interface
    edit "port1"
        set ip 192.168.1.1 255.255.255.0
        set type physical
    next
end`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when interface has description or alias', () => {
      const config = `config system interface
    edit "port1"
        set ip 192.168.1.1 255.255.255.0
        set description "WAN interface"
    next
    edit "port2"
        set ip 10.0.0.1 255.255.255.0
        set alias "LAN"
    next
end`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Firewall Policy Rules Tests
// ============================================================================

describe('FortiGate Firewall Policy Rules', () => {
  describe('FGT-POL-001: Policy Logging Required', () => {
    test('should fail when policy has no logging', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end`;
      const results = runRule(PolicyLoggingRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('logging');
    });

    test('should pass when logging is enabled', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end`;
      const results = runRule(PolicyLoggingRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-POL-002: Policy Security Profile Required', () => {
    test('should fail when accept policy has no UTM profile', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
    next
end`;
      const results = runRule(PolicySecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('UTM');
    });

    test('should pass when security profile is attached', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP"
        set logtraffic all
        set av-profile "default"
        set webfilter-profile "default"
    next
end`;
      const results = runRule(PolicySecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should not apply to deny policies', () => {
      const config = `config firewall policy
    edit 99
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end`;
      const results = runRule(PolicySecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-POL-003: No Overly Permissive Policies', () => {
    test('should fail on all-all-all policy', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end`;
      const results = runRule(NoOverlyPermissivePolicies, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('overly permissive');
    });

    test('should pass when policy is specific', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN_SUBNET"
        set dstaddr "WEB_SERVERS"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS"
        set logtraffic all
    next
end`;
      const results = runRule(NoOverlyPermissivePolicies, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-POL-004: Policy Comment Required', () => {
    test('should report when policy has no name or comment', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end`;
      const results = runRule(PolicyCommentRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when policy has name or comments', () => {
      const config = `config firewall policy
    edit 1
        set name "Allow-Internet"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
    edit 2
        set srcintf "dmz"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set comments "DMZ outbound access"
    next
end`;
      const results = runRule(PolicyCommentRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-POL-005: No Any Service Policy', () => {
    test('should warn when policy uses ALL service', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end`;
      const results = runRule(NoAnyServicePolicy, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('ALL');
    });

    test('should pass when specific services are used', () => {
      const config = `config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "LAN"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTP" "HTTPS" "DNS"
    next
end`;
      const results = runRule(NoAnyServicePolicy, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// HA Rules Tests
// ============================================================================

describe('FortiGate HA Rules', () => {
  describe('FGT-HA-001: HA Recommended', () => {
    test('should inform when HA is not configured', () => {
      const config = `config system ha
    set mode standalone
end`;
      const results = runRule(HARecommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('High Availability');
    });

    test('should pass when HA is configured', () => {
      const config = `config system ha
    set mode a-p
    set group-id 10
    set group-name "FW-Cluster"
end`;
      const results = runRule(HARecommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-HA-002: HA Encryption Required', () => {
    test('should warn when HA encryption is not enabled', () => {
      const config = `config system ha
    set mode a-p
    set group-id 10
end`;
      const results = runRule(HAEncryptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('encryption');
    });

    test('should pass when HA encryption is enabled', () => {
      const config = `config system ha
    set mode a-p
    set group-id 10
    set encryption enable
end`;
      const results = runRule(HAEncryptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VPN Rules Tests
// ============================================================================

describe('FortiGate VPN Rules', () => {
  describe('FGT-VPN-001: VPN Strong Encryption', () => {
    test('should fail when weak encryption is used', () => {
      const config = `config vpn ipsec phase1-interface
    edit "Legacy-VPN"
        set interface "wan1"
        set proposal des-md5
        set remote-gw 10.0.0.1
    next
end`;
      const results = runRule(VpnStrongEncryption, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('weak encryption');
    });

    test('should pass with strong encryption', () => {
      const config = `config vpn ipsec phase1-interface
    edit "Secure-VPN"
        set interface "wan1"
        set proposal aes256-sha256
        set remote-gw 10.0.0.1
    next
end`;
      const results = runRule(VpnStrongEncryption, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-VPN-002: VPN DPD Enabled', () => {
    test('should warn when DPD is disabled', () => {
      const config = `config vpn ipsec phase1-interface
    edit "VPN-Tunnel"
        set interface "wan1"
        set proposal aes256-sha256
        set remote-gw 10.0.0.1
        set dpd disable
    next
end`;
      const results = runRule(VpnDpdEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('DPD');
    });

    test('should pass when DPD is enabled', () => {
      const config = `config vpn ipsec phase1-interface
    edit "VPN-Tunnel"
        set interface "wan1"
        set proposal aes256-sha256
        set remote-gw 10.0.0.1
        set dpd on-demand
    next
end`;
      const results = runRule(VpnDpdEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Logging Rules Tests
// ============================================================================

describe('FortiGate Logging Rules', () => {
  describe('FGT-LOG-001: Syslog Required', () => {
    test('should warn when syslog is not enabled', () => {
      const config = `config log syslogd setting
    set status disable
end`;
      const results = runRule(SyslogRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when syslog is configured', () => {
      const config = `config log syslogd setting
    set status enable
    set server "192.168.1.100"
    set port 514
end`;
      const results = runRule(SyslogRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Security Profile Rules Tests
// ============================================================================

describe('FortiGate Security Profile Rules', () => {
  describe('FGT-PROF-001: Antivirus Profile Required', () => {
    test('should warn when no AV profile is configured', () => {
      const config = `config antivirus profile
end`;
      const results = runRule(AntivirusProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when AV profile is configured', () => {
      const config = `config antivirus profile
    edit "default"
        set scan-mode default
    next
end`;
      const results = runRule(AntivirusProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-PROF-002: IPS Sensor Required', () => {
    test('should warn when no IPS sensor is configured', () => {
      const config = `config ips sensor
end`;
      const results = runRule(IpsSensorRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when IPS sensor is configured', () => {
      const config = `config ips sensor
    edit "default"
        set comment "Default IPS sensor"
    next
end`;
      const results = runRule(IpsSensorRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-PROF-003: Web Filter Profile Required', () => {
    test('should pass when web filter profile is configured', () => {
      const config = `config webfilter profile
    edit "default"
        set options block-invalid-url
    next
end`;
      const results = runRule(WebFilterProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('FGT-PROF-004: Application List Required', () => {
    test('should pass when application list is configured', () => {
      const config = `config application list
    edit "default"
        set comment "Default application control"
    next
end`;
      const results = runRule(ApplicationListRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// All Rules Export Test
// ============================================================================

describe('FortiGate Rules Export', () => {
  test('should export all FortiGate rules', () => {
    expect(allFortinetRules.length).toBeGreaterThan(0);
    expect(allFortinetRules.every((r) => r.id.startsWith('FGT-'))).toBe(true);
  });

  test('should have unique rule IDs', () => {
    const ids = allFortinetRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allFortinetRules) {
      expect(rule.id).toBeDefined();
      expect(rule.selector).toBeDefined();
      expect(rule.metadata).toBeDefined();
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.check).toBeDefined();
    }
  });
});
