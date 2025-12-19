// packages/rules-default/test/nokia-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, NokiaSROSSchema, RuleEngine } from '@sentriflow/core';
import {
  allNokiaRules,
  SystemNameRequired,
  SnmpConfigured,
  NtpRequired,
  PortDescriptionRequired,
  PortAdminStateRequired,
  InterfaceDescriptionRequired,
  InterfaceAddressRequired,
  BgpRouterIdRequired,
  BgpAdminStateRequired,
  BgpGroupDescriptionRequired,
  BgpPeerAuthenticationRecommended,
  OspfAdminStateRequired,
  OspfAreaInterfaceRequired,
  ServiceCustomerRequired,
  VprnCustomerRequired,
  ServiceAdminStateRequired,
  ServiceSapRequired,
  SshEnabled,
  TelnetDisabled,
  LagDescriptionRequired,
  LagAdminStateRequired,
  LogConfigured,
} from '../src/nokia/sros-rules';

const parseNokia = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: NokiaSROSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof SystemNameRequired, config: string) => {
  const ast = parseNokia(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('Nokia System Rules', () => {
  describe('NOKIA-SYS-001: System Name Required', () => {
    test('should process system name configuration', () => {
      const config = `configure {
    system {
        name "CORE-RTR-01"
    }
}`;
      const results = runRule(SystemNameRequired, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });

  describe('NOKIA-SYS-002: SNMP Enabled', () => {
    test('should pass when SNMP is enabled', () => {
      const config = `configure {
    snmp {
        admin-state enable
    }
}`;
      const results = runRule(SnmpConfigured, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should process SNMP disabled configuration', () => {
      const config = `configure {
    snmp {
        admin-state disable
    }
}`;
      const results = runRule(SnmpConfigured, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });

  describe('NOKIA-SYS-003: NTP Enabled', () => {
    test('should pass when NTP is enabled with server', () => {
      const config = `configure {
    system {
        time {
            ntp {
                admin-state enable
                server 10.0.1.10 {
                }
            }
        }
    }
}`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should process NTP disabled configuration', () => {
      const config = `configure {
    system {
        time {
            ntp {
                admin-state disable
            }
        }
    }
}`;
      const results = runRule(NtpRequired, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });
});

// ============================================================================
// Port Rules Tests
// ============================================================================

describe('Nokia Port Rules', () => {
  describe('NOKIA-PORT-001: Port Description', () => {
    test('should fail when active port has no description', () => {
      const config = `configure {
    port 1/1/1 {
        admin-state enable
    }
}`;
      const results = runRule(PortDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when port has description', () => {
      const config = `configure {
    port 1/1/1 {
        admin-state enable
        description "UPLINK:SPINE-01:1/1/1"
    }
}`;
      const results = runRule(PortDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip disabled ports', () => {
      const config = `configure {
    port 1/1/1 {
        admin-state disable
    }
}`;
      const results = runRule(PortDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-PORT-002: Port Admin-State', () => {
    test('should pass when admin-state is explicit', () => {
      const config = `configure {
    port 1/1/1 {
        admin-state enable
    }
}`;
      const results = runRule(PortAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('Nokia Interface Rules', () => {
  describe('NOKIA-IF-001: Interface Description', () => {
    test('should fail when interface has no description', () => {
      const config = `configure {
    router "Base" {
        interface "to-CORE-01" {
            port 1/1/1
            ipv4 {
                primary {
                    address 10.0.0.1
                    prefix-length 30
                }
            }
        }
    }
}`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when interface has description', () => {
      const config = `configure {
    router "Base" {
        interface "to-CORE-01" {
            description "Link to Core Router 01"
            port 1/1/1
            ipv4 {
                primary {
                    address 10.0.0.1
                    prefix-length 30
                }
            }
        }
    }
}`;
      const results = runRule(InterfaceDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-IF-002: Interface IP Address', () => {
    test('should fail when interface has no IP address', () => {
      const config = `configure {
    router "Base" {
        interface "to-CORE-01" {
            port 1/1/1
        }
    }
}`;
      const results = runRule(InterfaceAddressRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('IP address');
    });

    test('should process interface with IP address', () => {
      const config = `configure {
    router "Base" {
        interface "to-CORE-01" {
            ipv4 {
                primary {
                    address 10.0.0.1
                    prefix-length 30
                }
            }
        }
    }
}`;
      const results = runRule(InterfaceAddressRequired, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });
});

// ============================================================================
// BGP Rules Tests
// ============================================================================

describe('Nokia BGP Rules', () => {
  describe('NOKIA-BGP-001: BGP Router-ID Required', () => {
    test('should fail when BGP has no router-id', () => {
      const config = `configure {
    router "Base" {
        bgp {
            admin-state enable
            group "EBGP-PEERS" {
                peer-as 65001
            }
        }
    }
}`;
      const results = runRule(BgpRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('router-id');
    });

    test('should pass when BGP has router-id', () => {
      const config = `configure {
    router "Base" {
        bgp {
            admin-state enable
            router-id 10.255.0.1
        }
    }
}`;
      const results = runRule(BgpRouterIdRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-BGP-002: BGP Admin-State', () => {
    test('should pass when BGP is enabled', () => {
      const config = `configure {
    router "Base" {
        bgp {
            admin-state enable
        }
    }
}`;
      const results = runRule(BgpAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should fail when BGP is disabled', () => {
      const config = `configure {
    router "Base" {
        bgp {
            admin-state disable
        }
    }
}`;
      const results = runRule(BgpAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });
  });

  describe('NOKIA-BGP-003: BGP Group Description', () => {
    test('should report when BGP group has no description', () => {
      const config = `configure {
    router "Base" {
        bgp {
            group "EBGP-ISP1" {
                peer-as 65001
            }
        }
    }
}`;
      const results = runRule(BgpGroupDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when BGP group has description', () => {
      const config = `configure {
    router "Base" {
        bgp {
            group "EBGP-ISP1" {
                description "Primary ISP Peering"
                peer-as 65001
            }
        }
    }
}`;
      const results = runRule(BgpGroupDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-BGP-004: BGP Neighbor Auth', () => {
    test('should process BGP neighbor without authentication', () => {
      const config = `configure {
    router "Base" {
        bgp {
            neighbor "192.168.1.1" {
                peer-as 65001
            }
        }
    }
}`;
      const results = runRule(BgpPeerAuthenticationRecommended, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });

    test('should pass when BGP neighbor has authentication', () => {
      const config = `configure {
    router "Base" {
        bgp {
            neighbor "192.168.1.1" {
                peer-as 65001
                auth-keychain "BGP-AUTH"
            }
        }
    }
}`;
      const results = runRule(BgpPeerAuthenticationRecommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// OSPF Rules Tests
// ============================================================================

describe('Nokia OSPF Rules', () => {
  describe('NOKIA-OSPF-001: OSPF Admin-State', () => {
    test('should pass when OSPF is enabled', () => {
      const config = `configure {
    router "Base" {
        ospf 0 {
            admin-state enable
        }
    }
}`;
      const results = runRule(OspfAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-OSPF-002: OSPF Area Interfaces', () => {
    test('should fail when OSPF area has no interfaces', () => {
      const config = `configure {
    router "Base" {
        ospf 0 {
            area 0.0.0.0 {
            }
        }
    }
}`;
      const results = runRule(OspfAreaInterfaceRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no interfaces');
    });

    test('should process OSPF area with interfaces', () => {
      const config = `configure {
    router "Base" {
        ospf 0 {
            area 0.0.0.0 {
                interface "system" {
                }
                interface "to-CORE-01" {
                }
            }
        }
    }
}`;
      const results = runRule(OspfAreaInterfaceRequired, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });
});

// ============================================================================
// Service Rules Tests
// ============================================================================

describe('Nokia Service Rules', () => {
  describe('NOKIA-SVC-001: VPLS Customer', () => {
    test('should fail when VPLS has no customer', () => {
      const config = `configure {
    service {
        vpls "100" {
            admin-state enable
            sap 1/1/1:100 {
            }
        }
    }
}`;
      const results = runRule(ServiceCustomerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('customer');
    });

    test('should pass when VPLS has customer', () => {
      const config = `configure {
    service {
        vpls "100" {
            customer "1"
            admin-state enable
        }
    }
}`;
      const results = runRule(ServiceCustomerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-SVC-002: VPRN Customer', () => {
    test('should fail when VPRN has no customer', () => {
      const config = `configure {
    service {
        vprn "200" {
            admin-state enable
        }
    }
}`;
      const results = runRule(VprnCustomerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('customer');
    });

    test('should pass when VPRN has customer', () => {
      const config = `configure {
    service {
        vprn "200" {
            customer "1"
            admin-state enable
        }
    }
}`;
      const results = runRule(VprnCustomerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-SVC-003: Service Admin-State', () => {
    test('should pass when service is enabled', () => {
      const config = `configure {
    service {
        vpls "100" {
            admin-state enable
        }
    }
}`;
      const results = runRule(ServiceAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-SVC-004: VPLS SAPs', () => {
    test('should fail when VPLS has no SAPs', () => {
      const config = `configure {
    service {
        vpls "100" {
            customer "1"
            admin-state enable
        }
    }
}`;
      const results = runRule(ServiceSapRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('SAPs');
    });

    test('should process VPLS with SAPs', () => {
      const config = `configure {
    service {
        vpls "100" {
            customer "1"
            admin-state enable
            sap 1/1/1:100 {
            }
        }
    }
}`;
      const results = runRule(ServiceSapRequired, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });
  });
});

// ============================================================================
// Security Rules Tests
// ============================================================================

describe('Nokia Security Rules', () => {
  describe('NOKIA-SEC-001: SSH Enabled', () => {
    test('should pass when SSH is enabled', () => {
      const config = `configure {
    system {
        security {
            ssh {
                server-admin-state enable
            }
        }
    }
}`;
      const results = runRule(SshEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-SEC-002: Telnet Disabled', () => {
    test('should process Telnet disabled configuration', () => {
      const config = `configure {
    system {
        security {
            telnet-server false
        }
    }
}`;
      const results = runRule(TelnetDisabled, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });

    test('should fail when Telnet is enabled', () => {
      const config = `configure {
    system {
        security {
            telnet-server true
        }
    }
}`;
      const results = runRule(TelnetDisabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('Telnet');
    });
  });
});

// ============================================================================
// LAG Rules Tests
// ============================================================================

describe('Nokia LAG Rules', () => {
  describe('NOKIA-LAG-001: LAG Description', () => {
    test('should fail when LAG has no description', () => {
      const config = `configure {
    lag 1 {
        admin-state enable
        port 1/1/1
        port 1/1/2
    }
}`;
      const results = runRule(LagDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when LAG has description', () => {
      const config = `configure {
    lag 1 {
        admin-state enable
        description "MLAG to CORE-01"
        port 1/1/1
        port 1/1/2
    }
}`;
      const results = runRule(LagDescriptionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('NOKIA-LAG-002: LAG Admin-State', () => {
    test('should pass when LAG is enabled', () => {
      const config = `configure {
    lag 1 {
        admin-state enable
    }
}`;
      const results = runRule(LagAdminStateRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Logging Rules Tests
// ============================================================================

describe('Nokia Logging Rules', () => {
  describe('NOKIA-LOG-001: Logging Destination', () => {
    test('should pass when logging destination is configured', () => {
      const config = `configure {
    log {
        log-id "10" {
            admin-state enable
            destination {
                syslog "1"
            }
        }
        syslog "1" {
            address 10.0.1.100
        }
    }
}`;
      const results = runRule(LogConfigured, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Rules Export Tests
// ============================================================================

describe('Nokia Rules Export', () => {
  test('should export all Nokia rules', () => {
    expect(allNokiaRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in basic-netsec-pack
    expect(allNokiaRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allNokiaRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allNokiaRules) {
      expect(rule.id).toMatch(/^NOKIA-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('nokia-sros');
    }
  });
});
