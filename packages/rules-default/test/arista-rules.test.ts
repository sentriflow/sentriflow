// packages/rules-default/test/arista-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, AristaEOSSchema, RuleEngine } from '@sentriflow/core';
import {
  allAristaRules,
  MlagConfigComplete,
  MlagPortChannelDescription,
  VxlanSourceInterface,
  VxlanVniMappings,
  ManagementApiHttps,
  ManagementApiEnabled,
  InterfaceDescription,
  L3InterfaceIpAddress,
  BgpRouterId,
  EvpnConfigured,
  SpanningTreeMode,
  AaaConfigured,
  ManagementSshEnabled,
  VrfDescription,
} from '../src/arista/eos-rules';

const parseArista = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: AristaEOSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof MlagConfigComplete, config: string) => {
  const ast = parseArista(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// MLAG Rules Tests
// ============================================================================

describe('Arista MLAG Rules', () => {
  describe('ARI-MLAG-001: MLAG Config Complete', () => {
    test('should fail when MLAG is missing required settings', () => {
      const config = `mlag configuration
   domain-id MLAG_DOMAIN`;
      const results = runRule(MlagConfigComplete, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('incomplete');
    });

    test('should pass when MLAG has all required settings', () => {
      const config = `mlag configuration
   domain-id MLAG_DOMAIN
   local-interface Vlan4094
   peer-address 10.255.255.2
   peer-link Port-Channel1`;
      const results = runRule(MlagConfigComplete, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-MLAG-002: MLAG Port-Channel Description', () => {
    test('should warn when MLAG Port-Channel has no description', () => {
      const config = `interface Port-Channel10
   switchport mode trunk
   mlag 10`;
      const results = runRule(MlagPortChannelDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('description');
    });

    test('should pass when MLAG Port-Channel has description', () => {
      const config = `interface Port-Channel10
   description Server Connection via MLAG
   switchport mode trunk
   mlag 10`;
      const results = runRule(MlagPortChannelDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip non-MLAG Port-Channels', () => {
      const config = `interface Port-Channel1
   description Regular LAG
   switchport mode trunk`;
      const results = runRule(MlagPortChannelDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VXLAN Rules Tests
// ============================================================================

describe('Arista VXLAN Rules', () => {
  describe('ARI-VXLAN-001: VXLAN Source Interface', () => {
    test('should fail when VXLAN has no source-interface', () => {
      const config = `interface Vxlan1
   vxlan udp-port 4789
   vxlan vni 10010 vlan 10`;
      const results = runRule(VxlanSourceInterface, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('source-interface');
    });

    test('should pass when VXLAN has source-interface', () => {
      const config = `interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan vni 10010 vlan 10`;
      const results = runRule(VxlanSourceInterface, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-VXLAN-002: VXLAN VNI Mappings', () => {
    test('should warn when VXLAN has no VNI mappings', () => {
      const config = `interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789`;
      const results = runRule(VxlanVniMappings, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when VXLAN has VNI mappings', () => {
      const config = `interface Vxlan1
   vxlan source-interface Loopback1
   vxlan vni 10010 vlan 10
   vxlan vni 10020 vlan 20`;
      const results = runRule(VxlanVniMappings, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Management API Rules Tests
// ============================================================================

describe('Arista Management API Rules', () => {
  describe('ARI-API-001: Management API HTTPS', () => {
    test('should fail when API uses HTTP without HTTPS', () => {
      const config = `management api http-commands
   protocol http
   no shutdown`;
      const results = runRule(ManagementApiHttps, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('HTTPS');
    });

    test('should pass when API uses HTTPS', () => {
      const config = `management api http-commands
   protocol https
   no shutdown`;
      const results = runRule(ManagementApiHttps, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-API-002: Management API Enabled', () => {
    test('should report when API is shutdown', () => {
      const config = `management api http-commands
   shutdown`;
      const results = runRule(ManagementApiEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when API is enabled', () => {
      const config = `management api http-commands
   protocol https
   no shutdown`;
      const results = runRule(ManagementApiEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('Arista Interface Rules', () => {
  describe('ARI-INT-001: Interface Description', () => {
    test('should warn when active interface has no description', () => {
      const config = `interface Ethernet1
   no switchport
   ip address 10.0.0.1/30`;
      const results = runRule(InterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when interface has description', () => {
      const config = `interface Ethernet1
   description Uplink to Spine
   no switchport
   ip address 10.0.0.1/30`;
      const results = runRule(InterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip shutdown interfaces', () => {
      const config = `interface Ethernet1
   shutdown`;
      const results = runRule(InterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-INT-002: L3 Interface IP Address', () => {
    test('should warn when SVI has no IP', () => {
      const config = `interface Vlan10
   description Server Network`;
      const results = runRule(L3InterfaceIpAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when SVI has IP', () => {
      const config = `interface Vlan10
   description Server Network
   ip address 10.10.10.1/24`;
      const results = runRule(L3InterfaceIpAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when SVI has virtual-router address with IP', () => {
      const config = `interface Vlan10
   description Server Network
   ip address 10.10.10.1/24
   ip virtual-router address 10.10.10.254`;
      const results = runRule(L3InterfaceIpAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should pass when Loopback has IP', () => {
      const config = `interface Loopback0
   description Router-ID
   ip address 192.168.255.1/32`;
      const results = runRule(L3InterfaceIpAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// BGP Rules Tests
// ============================================================================

describe('Arista BGP Rules', () => {
  describe('ARI-BGP-001: BGP Router ID', () => {
    test('should warn when router-id is missing', () => {
      const config = `router bgp 65001
   neighbor SPINE peer group
   neighbor SPINE remote-as 65000`;
      const results = runRule(BgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when router-id is configured', () => {
      const config = `router bgp 65001
   router-id 192.168.255.1
   neighbor SPINE peer group`;
      const results = runRule(BgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-BGP-002: EVPN Configured', () => {
    test('should report when EVPN is not configured', () => {
      const config = `router bgp 65001
   router-id 192.168.255.1
   address-family ipv4
      neighbor SPINE activate`;
      const results = runRule(EvpnConfigured, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when EVPN address-family is configured', () => {
      const config = `router bgp 65001
   router-id 192.168.255.1
   address-family evpn
      neighbor SPINE activate`;
      const results = runRule(EvpnConfigured, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Spanning Tree Rules Tests
// ============================================================================

describe('Arista Spanning Tree Rules', () => {
  describe('ARI-STP-001: Spanning Tree Mode', () => {
    test('should report when spanning-tree mode is not set', () => {
      const config = `spanning-tree portfast bpduguard default`;
      const results = runRule(SpanningTreeMode, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when spanning-tree mode is set', () => {
      const config = `spanning-tree mode mstp`;
      const results = runRule(SpanningTreeMode, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Security Rules Tests
// ============================================================================

describe('Arista Security Rules', () => {
  describe('ARI-SEC-001: AAA Configured', () => {
    test('should pass when AAA is configured', () => {
      const config = `aaa authentication login default local`;
      const results = runRule(AaaConfigured, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('ARI-SEC-002: Management SSH Enabled', () => {
    test('should warn when SSH is shutdown', () => {
      const config = `management ssh
   shutdown`;
      const results = runRule(ManagementSshEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when SSH is enabled', () => {
      const config = `management ssh
   no shutdown`;
      const results = runRule(ManagementSshEnabled, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VRF Rules Tests
// ============================================================================

describe('Arista VRF Rules', () => {
  describe('ARI-VRF-001: VRF Description', () => {
    test('should warn when VRF has no description', () => {
      const config = `vrf instance TENANT_A`;
      const results = runRule(VrfDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when VRF has description', () => {
      const config = `vrf instance TENANT_A
   description Tenant A Production VRF`;
      const results = runRule(VrfDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should skip default and management VRFs', () => {
      const config = `vrf instance default`;
      const results = runRule(VrfDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// All Rules Export Test
// ============================================================================

describe('Arista Rules Export', () => {
  test('should export all Arista rules', () => {
    expect(allAristaRules.length).toBeGreaterThan(0);
    expect(allAristaRules.every((r) => r.id.startsWith('ARI-'))).toBe(true);
  });

  test('should have unique rule IDs', () => {
    const ids = allAristaRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allAristaRules) {
      expect(rule.id).toBeDefined();
      expect(rule.selector).toBeDefined();
      expect(rule.metadata).toBeDefined();
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.check).toBeDefined();
    }
  });

  test('all rules should have vendor set to arista-eos', () => {
    for (const rule of allAristaRules) {
      expect(rule.vendor).toBe('arista-eos');
    }
  });
});
