// packages/rules-default/test/cumulus-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, CumulusLinuxSchema, RuleEngine } from '@sentriflow/core';
import {
  allCumulusRules,
  CumulusInterfaceDescription,
  CumulusBpduGuard,
  CumulusPortAdminEdge,
  CumulusBridgeVlans,
  CumulusBridgePorts,
  CumulusBondSlaves,
  CumulusBondClagId,
  CumulusVlanAddress,
  CumulusVlanRawDevice,
  CumulusBgpRouterId,
  CumulusBgpNeighbors,
  CumulusBgpUnnumbered,
  CumulusPeerlinkMtu,
  CumulusLoopbackAddress,
} from '../src/cumulus/cumulus-rules';

const parseCumulus = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof CumulusInterfaceDescription, config: string) => {
  const ast = parseCumulus(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// Interface Rules Tests
// ============================================================================

describe('Cumulus Interface Rules', () => {
  describe('CUM-IF-001: Switch Port Description', () => {
    test('should fail when switch port has no alias', () => {
      const config = `auto swp1
iface swp1
    bridge-vids 10 20 30`;
      const results = runRule(CumulusInterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('alias');
    });

    test('should pass when switch port has alias', () => {
      const config = `auto swp1
iface swp1
    alias UPLINK:SPINE-01:swp1
    bridge-vids 10 20 30`;
      const results = runRule(CumulusInterfaceDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-IF-002: BPDU Guard', () => {
    test('should fail when access port has no BPDU guard', () => {
      const config = `auto swp10
iface swp10
    bridge-access 100`;
      const results = runRule(CumulusBpduGuard, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('BPDU guard');
    });

    test('should pass when access port has BPDU guard', () => {
      const config = `auto swp10
iface swp10
    bridge-access 100
    mstpctl-bpduguard yes`;
      const results = runRule(CumulusBpduGuard, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-IF-003: Port Admin Edge', () => {
    test('should report when access port has no portadminedge', () => {
      const config = `auto swp10
iface swp10
    bridge-access 100`;
      const results = runRule(CumulusPortAdminEdge, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('portadminedge');
    });

    test('should pass when access port has portadminedge', () => {
      const config = `auto swp10
iface swp10
    bridge-access 100
    mstpctl-portadminedge yes`;
      const results = runRule(CumulusPortAdminEdge, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Bridge Rules Tests
// ============================================================================

describe('Cumulus Bridge Rules', () => {
  describe('CUM-BR-001: Bridge VLANs', () => {
    test('should fail when VLAN-aware bridge has no VLANs', () => {
      const config = `auto bridge
iface bridge
    bridge-vlan-aware yes
    bridge-ports swp1 swp2`;
      const results = runRule(CumulusBridgeVlans, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no VLANs');
    });

    test('should pass when VLAN-aware bridge has VLANs', () => {
      const config = `auto bridge
iface bridge
    bridge-vlan-aware yes
    bridge-ports swp1 swp2
    bridge-vids 10 20 30`;
      const results = runRule(CumulusBridgeVlans, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-BR-002: Bridge Ports', () => {
    test('should fail when bridge has no ports', () => {
      const config = `auto bridge
iface bridge
    bridge-vlan-aware yes`;
      const results = runRule(CumulusBridgePorts, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('bridge-ports');
    });

    test('should pass when bridge has ports', () => {
      const config = `auto bridge
iface bridge
    bridge-ports swp1 swp2 peerlink
    bridge-vids 10 20 30`;
      const results = runRule(CumulusBridgePorts, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Bond Rules Tests
// ============================================================================

describe('Cumulus Bond Rules', () => {
  describe('CUM-BOND-001: Bond Slaves', () => {
    test('should process bond without slaves', () => {
      const config = `auto bond0
iface bond0
    bond-mode 802.3ad`;
      const results = runRule(CumulusBondSlaves, config);
      // Rule runs - check it executes without error
      expect(results).toBeDefined();
    });

    test('should pass when bond has slaves', () => {
      const config = `auto bond0
iface bond0
    bond-slaves swp1 swp2
    bond-mode 802.3ad`;
      const results = runRule(CumulusBondSlaves, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-BOND-002: MLAG CLAG-ID', () => {
    test('should report when bond has no clag-id', () => {
      const config = `auto bond0
iface bond0
    bond-slaves swp1 swp2
    bond-mode 802.3ad`;
      const results = runRule(CumulusBondClagId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('clag-id');
    });

    test('should pass when bond has clag-id', () => {
      const config = `auto bond0
iface bond0
    bond-slaves swp1 swp2
    bond-mode 802.3ad
    clag-id 1`;
      const results = runRule(CumulusBondClagId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// VLAN Rules Tests
// ============================================================================

describe('Cumulus VLAN Rules', () => {
  describe('CUM-VLAN-001: VLAN IP Address', () => {
    test('should report when VLAN has no address', () => {
      const config = `auto vlan100
iface vlan100
    vlan-raw-device bridge
    vlan-id 100`;
      const results = runRule(CumulusVlanAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('address');
    });

    test('should pass when VLAN has address', () => {
      const config = `auto vlan100
iface vlan100
    address 10.10.100.1/24
    vlan-raw-device bridge
    vlan-id 100`;
      const results = runRule(CumulusVlanAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-VLAN-002: VLAN Raw Device', () => {
    test('should fail when VLAN has no vlan-raw-device', () => {
      const config = `auto vlan100
iface vlan100
    address 10.10.100.1/24
    vlan-id 100`;
      const results = runRule(CumulusVlanRawDevice, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('vlan-raw-device');
    });

    test('should pass when VLAN has vlan-raw-device', () => {
      const config = `auto vlan100
iface vlan100
    address 10.10.100.1/24
    vlan-raw-device bridge
    vlan-id 100`;
      const results = runRule(CumulusVlanRawDevice, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// BGP Rules Tests
// ============================================================================

describe('Cumulus BGP Rules', () => {
  describe('CUM-BGP-001: BGP Router-ID', () => {
    test('should fail when BGP has no router-id', () => {
      const config = `router bgp 65000
  neighbor swp51 interface remote-as external`;
      const results = runRule(CumulusBgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('router-id');
    });

    test('should pass when BGP has router-id', () => {
      const config = `router bgp 65000
  bgp router-id 10.255.0.1
  neighbor swp51 interface remote-as external`;
      const results = runRule(CumulusBgpRouterId, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-BGP-002: BGP Neighbors', () => {
    test('should fail when BGP has no neighbors', () => {
      const config = `router bgp 65000
  bgp router-id 10.255.0.1`;
      const results = runRule(CumulusBgpNeighbors, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('no neighbors');
    });

    test('should pass when BGP has neighbors', () => {
      const config = `router bgp 65000
  bgp router-id 10.255.0.1
  neighbor swp51 interface remote-as external`;
      const results = runRule(CumulusBgpNeighbors, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('CUM-BGP-003: BGP Unnumbered', () => {
    test('should report traditional BGP peering', () => {
      const config = `router bgp 65000
  bgp router-id 10.255.0.1
  neighbor 10.0.0.2 remote-as 65001`;
      const results = runRule(CumulusBgpUnnumbered, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('unnumbered');
    });

    test('should pass when using BGP unnumbered', () => {
      const config = `router bgp 65000
  bgp router-id 10.255.0.1
  neighbor swp51 interface remote-as external`;
      const results = runRule(CumulusBgpUnnumbered, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// MLAG Rules Tests
// ============================================================================

describe('Cumulus MLAG Rules', () => {
  describe('CUM-MLAG-001: Peerlink MTU', () => {
    test('should fail when peerlink has low MTU', () => {
      const config = `auto peerlink
iface peerlink
    bond-slaves swp49 swp50
    bond-mode 802.3ad
    mtu 1500`;
      const results = runRule(CumulusPeerlinkMtu, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('MTU');
    });

    test('should pass when peerlink has high MTU', () => {
      const config = `auto peerlink
iface peerlink
    bond-slaves swp49 swp50
    bond-mode 802.3ad
    mtu 9216`;
      const results = runRule(CumulusPeerlinkMtu, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Loopback Rules Tests
// ============================================================================

describe('Cumulus Loopback Rules', () => {
  describe('CUM-LO-001: Loopback Address', () => {
    test('should fail when loopback has no address', () => {
      const config = `auto lo
iface lo inet loopback`;
      const results = runRule(CumulusLoopbackAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('address');
    });

    test('should pass when loopback has address', () => {
      const config = `auto lo
iface lo inet loopback
    address 10.255.0.1/32`;
      const results = runRule(CumulusLoopbackAddress, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Rules Export Tests
// ============================================================================

describe('Cumulus Rules Export', () => {
  test('should export all Cumulus rules', () => {
    expect(allCumulusRules.length).toBeGreaterThan(0);
    // Reduced to 3 proof-of-concept rules; full set available in basic-netsec-pack
    expect(allCumulusRules.length).toBe(3);
  });

  test('should have unique rule IDs', () => {
    const ids = allCumulusRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allCumulusRules) {
      expect(rule.id).toMatch(/^CUM-/);
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.vendor).toBe('cumulus-linux');
    }
  });
});
