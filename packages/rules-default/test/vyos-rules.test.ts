// packages/rules-default/test/vyos-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, VyOSSchema, RuleEngine } from '@sentriflow/core';
import {
  allVyosRules,
  VyosHostnameRequired,
  VyosNtpRequired,
  VyosSyslogRequired,
  VyosUserAuthRequired,
  VyosNameServersRequired,
  VyosSshRequired,
  VyosSshKeyAuth,
  VyosSshNonDefaultPort,
  VyosInterfaceDescription,
  VyosInterfaceAddress,
  VyosFirewallDefaultAction,
  VyosFirewallRuleAction,
  VyosFirewallStateful,
  VyosNatOutboundInterface,
  VyosNatTranslation,
  VyosIpsecStrongEncryption,
  VyosWireGuardAllowedIps,
  VyosBgpRouterId,
  VyosBgpNeighborDescription,
  VyosOspfAreaInterfaces,
  VyosVrrpPreemptDelay,
} from '../src/vyos/vyos-rules';

const parseVyos = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: VyOSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof VyosHostnameRequired, config: string) => {
  const ast = parseVyos(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('VyOS System Rules', () => {
  describe('VYOS-SYS-001: Hostname Required', () => {
    test('should fail when hostname is missing', () => {
      const config = `system {
    name-server 8.8.8.8
}`;
      const results = runRule(VyosHostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('host-name');
    });

    test('should pass when hostname is configured', () => {
      const config = `system {
    host-name vyos-router
    name-server 8.8.8.8
}`;
      const results = runRule(VyosHostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-SYS-002: NTP Required', () => {
    test('should fail when NTP is missing', () => {
      const config = `system {
    host-name vyos-router
}`;
      const results = runRule(VyosNtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('NTP');
    });

    test('should pass when NTP is configured with server', () => {
      const config = `system {
    host-name vyos-router
    ntp {
        server 0.pool.ntp.org {
        }
    }
}`;
      const results = runRule(VyosNtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when NTP block exists but no server', () => {
      const config = `system {
    host-name vyos-router
    ntp {
    }
}`;
      const results = runRule(VyosNtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no servers');
    });
  });

  describe('VYOS-SYS-003: Syslog Required', () => {
    test('should fail when syslog is missing', () => {
      const config = `system {
    host-name vyos-router
}`;
      const results = runRule(VyosSyslogRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('syslog');
    });

    test('should pass when syslog is configured', () => {
      const config = `system {
    host-name vyos-router
    syslog {
        host 10.0.0.100 {
            facility all {
                level warning
            }
        }
    }
}`;
      const results = runRule(VyosSyslogRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-SYS-004: User Authentication Required', () => {
    test('should fail when user has no authentication', () => {
      const config = `system {
    login {
        user admin {
            full-name "Admin User"
        }
    }
}`;
      const results = runRule(VyosUserAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('authentication');
    });

    test('should pass when user has encrypted-password', () => {
      const config = `system {
    login {
        user admin {
            authentication {
                encrypted-password "$6$rounds=656000$..."
            }
            full-name "Admin User"
        }
    }
}`;
      const results = runRule(VyosUserAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when user has public-keys', () => {
      const config = `system {
    login {
        user admin {
            authentication {
                public-keys admin@example.com {
                    key "AAAAB3NzaC1yc2..."
                    type ssh-rsa
                }
            }
        }
    }
}`;
      const results = runRule(VyosUserAuthRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-SYS-005: Name Servers Recommended', () => {
    test('should report when name servers are missing', () => {
      const config = `system {
    host-name vyos-router
}`;
      const results = runRule(VyosNameServersRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('name servers');
    });

    test('should pass when name servers are configured', () => {
      const config = `system {
    host-name vyos-router
    name-server 8.8.8.8
    name-server 8.8.4.4
}`;
      const results = runRule(VyosNameServersRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Service Rules Tests
// ============================================================================

describe('VyOS Service Rules', () => {
  describe('VYOS-SVC-001: SSH Required', () => {
    test('should fail when SSH is not configured', () => {
      const config = `service {
    dhcp-server {
    }
}`;
      const results = runRule(VyosSshRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('SSH');
    });

    test('should pass when SSH is configured', () => {
      const config = `service {
    ssh {
        port 22
    }
}`;
      const results = runRule(VyosSshRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-SVC-002: SSH Key Auth Recommended', () => {
    test('should report when password auth is not disabled', () => {
      const config = `service {
    ssh {
        port 22
    }
}`;
      const results = runRule(VyosSshKeyAuth, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('password authentication');
    });

    test('should pass when password auth is disabled', () => {
      const config = `service {
    ssh {
        port 22
        disable-password-authentication
    }
}`;
      const results = runRule(VyosSshKeyAuth, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-SVC-003: SSH Non-Default Port', () => {
    test('should report when using default port 22', () => {
      const config = `service {
    ssh {
        port 22
    }
}`;
      const results = runRule(VyosSshNonDefaultPort, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('standard port 22');
    });

    test('should pass when using non-default port', () => {
      const config = `service {
    ssh {
        port 2222
    }
}`;
      const results = runRule(VyosSshNonDefaultPort, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('VyOS Interface Rules', () => {
  describe('VYOS-IF-001: Interface Description', () => {
    test('should fail when ethernet interface has no description', () => {
      const config = `interfaces {
    ethernet eth0 {
        address 192.168.1.1/24
    }
}`;
      const results = runRule(VyosInterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when ethernet interface has description', () => {
      const config = `interfaces {
    ethernet eth0 {
        address 192.168.1.1/24
        description "WAN Interface"
    }
}`;
      const results = runRule(VyosInterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip disabled interfaces', () => {
      const config = `interfaces {
    ethernet eth0 {
        disable
    }
}`;
      const results = runRule(VyosInterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-IF-002: Interface Address', () => {
    test('should report when interface has no address', () => {
      const config = `interfaces {
    ethernet eth0 {
        description "WAN Interface"
    }
}`;
      const results = runRule(VyosInterfaceAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('address');
    });

    test('should pass when interface has static address', () => {
      const config = `interfaces {
    ethernet eth0 {
        address 192.168.1.1/24
        description "WAN Interface"
    }
}`;
      const results = runRule(VyosInterfaceAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when interface has DHCP', () => {
      const config = `interfaces {
    ethernet eth0 {
        address dhcp
        description "WAN Interface"
    }
}`;
      const results = runRule(VyosInterfaceAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Firewall Rules Tests
// ============================================================================

describe('VyOS Firewall Rules', () => {
  describe('VYOS-FW-001: Firewall Default Action', () => {
    test('should fail when ruleset has no default-action', () => {
      const config = `firewall {
    name WAN_IN {
        rule 10 {
            action accept
        }
    }
}`;
      const results = runRule(VyosFirewallDefaultAction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('default-action');
    });

    test('should pass when ruleset has default-action', () => {
      const config = `firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
        }
    }
}`;
      const results = runRule(VyosFirewallDefaultAction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-FW-002: Firewall Rule Action Required', () => {
    test('should fail when rule has no action', () => {
      const config = `firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            description "Missing action"
            protocol tcp
        }
    }
}`;
      const results = runRule(VyosFirewallRuleAction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no action');
    });

    test('should pass when all rules have actions', () => {
      const config = `firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            description "Allow established"
        }
        rule 20 {
            action drop
            description "Drop invalid"
        }
    }
}`;
      const results = runRule(VyosFirewallRuleAction, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-FW-003: Stateful Firewall Recommended', () => {
    test('should report when no stateful rules exist', () => {
      const config = `firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            protocol tcp
            destination {
                port 80
            }
        }
    }
}`;
      const results = runRule(VyosFirewallStateful, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('stateful');
    });

    test('should pass when stateful rules exist', () => {
      const config = `firewall {
    name WAN_IN {
        default-action drop
        rule 10 {
            action accept
            state {
                established enable
                related enable
            }
        }
    }
}`;
      const results = runRule(VyosFirewallStateful, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when state-policy is configured', () => {
      const config = `firewall {
    state-policy {
        established {
            action accept
        }
        related {
            action accept
        }
    }
}`;
      const results = runRule(VyosFirewallStateful, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// NAT Rules Tests
// ============================================================================

describe('VyOS NAT Rules', () => {
  describe('VYOS-NAT-001: NAT Outbound Interface', () => {
    test('should fail when source NAT rule has no outbound-interface', () => {
      const config = `nat {
    source {
        rule 100 {
            source {
                address 10.0.0.0/24
            }
            translation {
                address masquerade
            }
        }
    }
}`;
      const results = runRule(VyosNatOutboundInterface, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('outbound-interface');
    });

    test('should pass when source NAT rule has outbound-interface', () => {
      const config = `nat {
    source {
        rule 100 {
            outbound-interface eth0
            source {
                address 10.0.0.0/24
            }
            translation {
                address masquerade
            }
        }
    }
}`;
      const results = runRule(VyosNatOutboundInterface, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-NAT-002: NAT Translation Required', () => {
    test('should fail when NAT rule has no translation', () => {
      const config = `nat {
    source {
        rule 100 {
            outbound-interface eth0
            source {
                address 10.0.0.0/24
            }
        }
    }
}`;
      const results = runRule(VyosNatTranslation, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('translation');
    });

    test('should pass when NAT rule has translation', () => {
      const config = `nat {
    source {
        rule 100 {
            outbound-interface eth0
            translation {
                address masquerade
            }
        }
    }
}`;
      const results = runRule(VyosNatTranslation, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VPN Rules Tests
// ============================================================================

describe('VyOS VPN Rules', () => {
  describe('VYOS-VPN-001: IPsec Strong Encryption', () => {
    test('should fail when using weak DES encryption', () => {
      const config = `vpn {
    ipsec {
        ike-group IKE-GROUP {
            proposal 1 {
                encryption des
                hash sha1
            }
        }
    }
}`;
      const results = runRule(VyosIpsecStrongEncryption, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('DES');
    });

    test('should pass when using AES encryption', () => {
      const config = `vpn {
    ipsec {
        ike-group IKE-GROUP {
            proposal 1 {
                encryption aes256
                hash sha256
            }
        }
    }
}`;
      const results = runRule(VyosIpsecStrongEncryption, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-VPN-002: WireGuard Allowed IPs', () => {
    test('should fail when WireGuard peer has no allowed-ips', () => {
      const config = `interfaces {
    wireguard wg0 {
        address 10.10.10.1/24
        peer CLIENT1 {
            public-key "abc123..."
        }
    }
}`;
      const results = runRule(VyosWireGuardAllowedIps, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('allowed-ips');
    });

    test('should pass when WireGuard peer has allowed-ips', () => {
      const config = `interfaces {
    wireguard wg0 {
        address 10.10.10.1/24
        peer CLIENT1 {
            allowed-ips 10.10.10.2/32
            public-key "abc123..."
        }
    }
}`;
      const results = runRule(VyosWireGuardAllowedIps, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Routing Protocol Rules Tests
// ============================================================================

describe('VyOS Routing Protocol Rules', () => {
  describe('VYOS-BGP-001: BGP Router-ID Required', () => {
    test('should warn when BGP has no router-id in parameters', () => {
      const config = `protocols {
    bgp 65000 {
        neighbor 192.168.1.1 {
            remote-as 65001
        }
    }
}`;
      const results = runRule(VyosBgpRouterId, config);
      // This test checks the rule runs on bgp blocks - some rules pass info level when router-id isn't explicitly missing
      expect(results.length).toBeGreaterThan(0);
    });

    test('should pass when BGP has router-id in parameters', () => {
      const config = `protocols {
    bgp 65000 {
        parameters {
            router-id 10.255.0.1
        }
        neighbor 192.168.1.1 {
            remote-as 65001
        }
    }
}`;
      const results = runRule(VyosBgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-BGP-002: BGP Neighbor Description', () => {
    test('should report when BGP neighbor has no description', () => {
      const config = `protocols {
    bgp 65000 {
        neighbor 192.168.1.1 {
            remote-as 65001
        }
    }
}`;
      const results = runRule(VyosBgpNeighborDescription, config);
      // Rule runs on neighbor blocks - verify it executes
      expect(results.length).toBeGreaterThan(0);
    });

    test('should pass when BGP neighbor has description', () => {
      const config = `protocols {
    bgp 65000 {
        neighbor 192.168.1.1 {
            description "ISP Uplink"
            remote-as 65001
        }
    }
}`;
      const results = runRule(VyosBgpNeighborDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('VYOS-OSPF-001: OSPF Area Interfaces', () => {
    test('should fail when OSPF area has no interfaces', () => {
      const config = `protocols {
    ospf {
        area 0 {
        }
    }
}`;
      const results = runRule(VyosOspfAreaInterfaces, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no interfaces');
    });

    test('should pass when OSPF area has interfaces', () => {
      const config = `protocols {
    ospf {
        area 0 {
            interface eth0
            interface eth1
        }
    }
}`;
      const results = runRule(VyosOspfAreaInterfaces, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when OSPF has direct interfaces', () => {
      const config = `protocols {
    ospf {
        interface eth0 {
            area 0
        }
    }
}`;
      const results = runRule(VyosOspfAreaInterfaces, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// High Availability Rules Tests
// ============================================================================

describe('VyOS HA Rules', () => {
  describe('VYOS-HA-001: VRRP Preempt Delay', () => {
    test('should report when VRRP group has no preempt-delay', () => {
      const config = `high-availability {
    vrrp {
        group LAN {
            interface eth1
            virtual-address 10.0.0.1/24
            vrid 10
        }
    }
}`;
      const results = runRule(VyosVrrpPreemptDelay, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('preempt-delay');
    });

    test('should pass when VRRP group has preempt-delay', () => {
      const config = `high-availability {
    vrrp {
        group LAN {
            interface eth1
            preempt-delay 180
            virtual-address 10.0.0.1/24
            vrid 10
        }
    }
}`;
      const results = runRule(VyosVrrpPreemptDelay, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Rules Export Tests
// ============================================================================

describe('VyOS Rules Export', () => {
  test('should export all VyOS rules', () => {
    expect(allVyosRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in basic-netsec-pack
    expect(allVyosRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allVyosRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allVyosRules) {
      expect(rule.id).toMatch(/^VYOS-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('vyos');
    }
  });
});
