// packages/core/test/parser-vendors-comprehensive.test.ts
// Comprehensive vendor-specific parser tests

import { describe, test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  SchemaAwareParser,
  IncrementalParser,
  detectVendor,
  CiscoIOSSchema,
  CiscoNXOSSchema,
  JuniperJunOSSchema,
  CumulusLinuxSchema,
} from '../src';

const fixturesPath = join(__dirname, 'fixtures');

// ============================================================================
// Cisco IOS Parser Tests
// ============================================================================

describe('Cisco IOS Parser - Comprehensive', () => {
  test('should parse basic interface fixture', () => {
    const config = readFileSync(
      join(fixturesPath, 'cisco-ios/basic-interface.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    // Should have multiple top-level sections
    const sections = ast.filter((n) => n.type === 'section');
    expect(sections.length).toBeGreaterThanOrEqual(4); // At least 4 interfaces

    // Check for specific interfaces
    const interfaceIds = sections.map((n) => n.id.toLowerCase());
    expect(interfaceIds.some((id) => id.includes('gigabitethernet0/0'))).toBe(true);
    expect(interfaceIds.some((id) => id.includes('loopback0'))).toBe(true);
  });

  test('should parse BGP configuration with address-family nesting', () => {
    const config = readFileSync(
      join(fixturesPath, 'cisco-ios/bgp-config.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    // Find router bgp section
    const bgpSection = ast.find(
      (n) => n.type === 'section' && n.id.toLowerCase().startsWith('router bgp')
    );
    expect(bgpSection).toBeDefined();

    // Check for nested address-family
    const addressFamily = bgpSection?.children.find(
      (c) => c.id.toLowerCase().startsWith('address-family')
    );
    expect(addressFamily).toBeDefined();
    expect(addressFamily?.type).toBe('section');
    expect(addressFamily?.blockDepth).toBe(1);
  });

  test('should handle Cisco IOS comments', () => {
    const config = `!
! This is a comment
interface GigabitEthernet0/0
 description Test
!
`;
    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped, only interface section
    const sections = ast.filter((n) => n.type === 'section');
    expect(sections.length).toBe(1);
  });

  test('should correctly nest interface children', () => {
    const config = `interface GigabitEthernet0/0
 description Uplink
 ip address 10.0.0.1 255.255.255.0
 no shutdown
`;
    const parser = new SchemaAwareParser({ vendor: CiscoIOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBe(1);
    expect(ast[0]?.children.length).toBe(3);

    const childIds = ast[0]?.children.map((c) => c.id.toLowerCase());
    expect(childIds).toContain('description uplink');
    expect(childIds?.some((id) => id.includes('ip address'))).toBe(true);
    expect(childIds?.some((id) => id.includes('no shutdown'))).toBe(true);
  });
});

// ============================================================================
// Cisco NX-OS Parser Tests
// ============================================================================

describe('Cisco NX-OS Parser - Comprehensive', () => {
  test('should parse feature config fixture', () => {
    const config = readFileSync(
      join(fixturesPath, 'cisco-nxos/feature-config.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: CiscoNXOSSchema });
    const ast = parser.parse(config);

    // Should have feature sections at top level
    const features = ast.filter(
      (n) => n.type === 'section' && n.id.toLowerCase().startsWith('feature')
    );
    expect(features.length).toBeGreaterThan(0);

    // Should have vrf context
    const vrfContext = ast.find(
      (n) => n.type === 'section' && n.id.toLowerCase().includes('vrf context')
    );
    expect(vrfContext).toBeDefined();

    // Should have vpc domain
    const vpcDomain = ast.find(
      (n) => n.type === 'section' && n.id.toLowerCase().includes('vpc domain')
    );
    expect(vpcDomain).toBeDefined();
  });

  test('should detect NX-OS from feature commands', () => {
    const config = `feature bgp
feature ospf
interface Ethernet1/1
 no switchport
`;
    const detected = detectVendor(config);
    expect(detected.id).toBe('cisco-nxos');
  });

  test('should parse NX-OS router bgp', () => {
    const config = `router bgp 65000
 router-id 192.168.255.1
 address-family ipv4 unicast
 neighbor 10.0.0.1 remote-as 65001
  address-family ipv4 unicast
`;
    const parser = new SchemaAwareParser({ vendor: CiscoNXOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBe(1);
    expect(ast[0]?.type).toBe('section');
    expect(ast[0]?.id).toMatch(/router bgp 65000/i);
  });
});

// ============================================================================
// Juniper JunOS Parser Tests
// ============================================================================

describe('Juniper JunOS Parser - Comprehensive', () => {
  test('should parse basic interface fixture', () => {
    const config = readFileSync(
      join(fixturesPath, 'juniper-junos/basic-interface.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Should have system and interfaces at top level
    const topLevelIds = ast.map((n) => n.id);
    expect(topLevelIds).toContain('system');
    expect(topLevelIds).toContain('interfaces');
  });

  test('should parse BGP config with deep nesting', () => {
    const config = readFileSync(
      join(fixturesPath, 'juniper-junos/bgp-config.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Find protocols section
    const protocols = ast.find((n) => n.id === 'protocols');
    expect(protocols).toBeDefined();

    // Check for bgp inside protocols
    const bgp = protocols?.children.find((c) => c.id === 'bgp');
    expect(bgp).toBeDefined();

    // Check for group inside bgp
    const groups = bgp?.children.filter((c) => c.id.toLowerCase().startsWith('group'));
    expect(groups?.length).toBeGreaterThan(0);
  });

  test('should parse firewall filter with terms', () => {
    const config = readFileSync(
      join(fixturesPath, 'juniper-junos/firewall-filter.txt'),
      'utf-8'
    );
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Should have firewall at top level
    const firewall = ast.find((n) => n.id === 'firewall');
    expect(firewall).toBeDefined();
    expect(firewall?.type).toBe('section');
  });

  test('should handle inline braces correctly', () => {
    const config = `system { host-name router1; }`;
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThan(0);
    // Should parse system section with host-name child
    const system = ast.find((n) => n.id === 'system');
    expect(system).toBeDefined();
  });

  test('should handle multi-line stanzas', () => {
    const config = `interfaces {
    ge-0/0/0 {
        description "Test Interface";
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`;
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBe(1);
    expect(ast[0]?.id).toBe('interfaces');

    // Check nesting depth
    const interfaces = ast[0];
    const ge000 = interfaces?.children.find((c) => c.id.includes('ge-0/0/0'));
    expect(ge000).toBeDefined();

    const unit0 = ge000?.children.find((c) => c.id.includes('unit 0'));
    expect(unit0).toBeDefined();
  });

  test('should handle JunOS comments', () => {
    const config = `# This is a comment
system {
    /* Multi-line comment */
    host-name router1;
}`;
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Comments should be skipped
    expect(ast.length).toBe(1);
    expect(ast[0]?.id).toBe('system');
  });

  test('should handle inactive statements', () => {
    const config = `interfaces {
    inactive: ge-0/0/1 {
        description "Disabled interface";
    }
    ge-0/0/0 {
        description "Active interface";
    }
}`;
    const parser = new SchemaAwareParser({ vendor: JuniperJunOSSchema });
    const ast = parser.parse(config);

    // Should parse both interfaces (inactive is not a comment in structure)
    const interfaces = ast.find((n) => n.id === 'interfaces');
    expect(interfaces).toBeDefined();
  });
});

// ============================================================================
// IncrementalParser Vendor Tests
// ============================================================================

describe('IncrementalParser with Multiple Vendors', () => {
  test('should cache vendor per document', () => {
    const ciscoConfig = `interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
    const junosConfig = `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`;

    const parser = new IncrementalParser({ vendor: 'auto' });

    // Parse Cisco config
    parser.parse('cisco-doc', ciscoConfig, 1);
    const ciscoVendor = parser.getCachedVendor('cisco-doc');
    expect(ciscoVendor?.id).toBe('cisco-ios');

    // Parse Juniper config
    parser.parse('junos-doc', junosConfig, 1);
    const junosVendor = parser.getCachedVendor('junos-doc');
    expect(junosVendor?.id).toBe('juniper-junos');

    // Both should remain cached with correct vendors
    expect(parser.getCachedVendor('cisco-doc')?.id).toBe('cisco-ios');
    expect(parser.getCachedVendor('junos-doc')?.id).toBe('juniper-junos');
  });

  test('should use explicit vendor when provided', () => {
    const config = `some ambiguous config`;

    const parser = new IncrementalParser();

    // Parse with explicit vendor
    parser.parse('doc1', config, 1, CiscoNXOSSchema);
    expect(parser.getCachedVendor('doc1')?.id).toBe('cisco-nxos');

    parser.parse('doc2', config, 1, JuniperJunOSSchema);
    expect(parser.getCachedVendor('doc2')?.id).toBe('juniper-junos');
  });

  test('should re-parse on vendor change', () => {
    const config = `interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;

    const parser = new IncrementalParser();

    // First parse with Cisco IOS
    const ast1 = parser.parse('doc', config, 1, CiscoIOSSchema);
    const stats1 = parser.getLastStats();
    expect(stats1?.fullParse).toBe(true);
    expect(stats1?.fullParseReason).toBe('no_cache');

    // Second parse with same vendor - should use cache
    const ast2 = parser.parse('doc', config, 2, CiscoIOSSchema);
    const stats2 = parser.getLastStats();
    expect(stats2?.changedRanges).toBe(0);

    // Third parse with different vendor - should trigger full re-parse
    const ast3 = parser.parse('doc', config, 3, CiscoNXOSSchema);
    const stats3 = parser.getLastStats();
    expect(stats3?.fullParse).toBe(true);
    expect(stats3?.fullParseReason).toBe('vendor_changed');
  });

  test('should include vendor in stats', () => {
    const config = `system {
    host-name router1;
}`;

    const parser = new IncrementalParser({ vendor: JuniperJunOSSchema });
    parser.parse('doc', config, 1);

    const stats = parser.getLastStats();
    expect(stats?.vendorId).toBe('juniper-junos');
  });
});

// ============================================================================
// Cross-Vendor Detection Tests
// ============================================================================

describe('Vendor Detection Edge Cases', () => {
  test('should detect Juniper from set commands', () => {
    const config = `set system host-name router1
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set protocols bgp group IBGP type internal
`;
    expect(detectVendor(config).id).toBe('juniper-junos');
  });

  test('should detect NX-OS from vpc domain', () => {
    const config = `vpc domain 100
 peer-switch
interface Ethernet1/1
`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should detect NX-OS from install feature-set', () => {
    const config = `install feature-set fabricpath
feature bgp
`;
    expect(detectVendor(config).id).toBe('cisco-nxos');
  });

  test('should default to Cisco IOS for ambiguous config', () => {
    const config = `hostname router1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
`;
    expect(detectVendor(config).id).toBe('cisco-ios');
  });

  test('should detect Juniper from routing-instances', () => {
    const config = `routing-instances {
    VRF-A {
        instance-type vrf;
    }
}`;
    expect(detectVendor(config).id).toBe('juniper-junos');
  });
});

// ============================================================================
// Cumulus Linux Parser Tests - VRF Context Sensitivity Fix
// ============================================================================

describe('Cumulus Linux Parser - VRF Context Sensitivity', () => {
  test('vrf mgmt as child of iface should be nested (CUMULUS_FIX.md)', () => {
    const config = `auto eth0
iface eth0 inet dhcp
    vrf mgmt`;
    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    // Find the iface eth0 section
    const ifaceNode = ast.find((n) => n.id.toLowerCase().includes('iface eth0'));
    expect(ifaceNode).toBeDefined();
    expect(ifaceNode?.type).toBe('section');

    // The vrf mgmt should be a child command, not a sibling section
    expect(ifaceNode?.children.length).toBe(1);
    const vrfChild = ifaceNode?.children[0];
    expect(vrfChild?.id).toBe('vrf mgmt');
    expect(vrfChild?.type).toBe('command');
  });

  test('standalone vrf block should be depth 0 section', () => {
    const config = `vrf RED
    vni 104001
!`;
    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    // VRF RED should be a top-level section
    const vrfNode = ast.find((n) => n.id === 'vrf RED');
    expect(vrfNode).toBeDefined();
    expect(vrfNode?.type).toBe('section');
    expect(vrfNode?.blockDepth).toBe(0);

    // vni should be a child
    expect(vrfNode?.children.length).toBe(1);
    const vniChild = vrfNode?.children[0];
    expect(vniChild?.id).toMatch(/vni 104001/i);
  });

  test('multiple iface stanzas with vrf should parse correctly', () => {
    const config = `auto eth0
iface eth0 inet dhcp
    vrf mgmt

auto swp1
iface swp1
    address 10.0.0.1/24`;

    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    // Should have two iface sections
    const ifaceNodes = ast.filter((n) => n.id.toLowerCase().includes('iface'));
    expect(ifaceNodes.length).toBe(2);

    // eth0 should have vrf mgmt as child
    const eth0 = ifaceNodes.find((n) => n.id.includes('eth0'));
    expect(eth0?.children.some((c) => c.id === 'vrf mgmt')).toBe(true);

    // swp1 should have address as child
    const swp1 = ifaceNodes.find((n) => n.id.includes('swp1'));
    expect(swp1?.children.some((c) => c.id.includes('address'))).toBe(true);
  });

  test('FRR router bgp with vrf should parse vrf as depth 1', () => {
    const config = `router bgp 65001
 vrf TENANT-A
 address-family ipv4 unicast
!`;

    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    // router bgp should be depth 0 section
    const bgpNode = ast.find((n) => n.id.toLowerCase().includes('router bgp'));
    expect(bgpNode).toBeDefined();
    expect(bgpNode?.blockDepth).toBe(0);

    // vrf TENANT-A should be depth 1 section (inside router bgp)
    const vrfNode = bgpNode?.children.find((c) => c.id.includes('vrf TENANT-A'));
    expect(vrfNode).toBeDefined();
    expect(vrfNode?.type).toBe('section');
    expect(vrfNode?.blockDepth).toBe(1);

    // address-family should also be depth 1 (sibling of vrf, both are children of router bgp)
    const afNode = bgpNode?.children.find((c) => c.id.toLowerCase().includes('address-family'));
    expect(afNode).toBeDefined();
    expect(afNode?.type).toBe('section');
    expect(afNode?.blockDepth).toBe(1);
  });

  test('should not treat indented depth-0 patterns as new blocks inside iface', () => {
    // This tests the general fix: any depth-0 pattern that's indented
    // inside iface/auto should be treated as a child command
    const config = `auto eth0
iface eth0
    vrf mgmt
    address 10.0.0.1/24`;

    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    const ifaceNode = ast.find((n) => n.id.toLowerCase().includes('iface eth0'));
    expect(ifaceNode?.children.length).toBe(2);

    // Both should be commands, not sections
    expect(ifaceNode?.children.every((c) => c.type === 'command')).toBe(true);
  });

  test('top-level vrf with no indent should be section', () => {
    const config = `vrf mgmt
    vni 10001
!
vrf TENANT-A
    vni 10002
!`;

    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    // Should have two vrf sections at top level
    const vrfSections = ast.filter((n) => n.id.toLowerCase().includes('vrf'));
    expect(vrfSections.length).toBe(2);

    // All should be sections with depth 0
    vrfSections.forEach((vrf) => {
      expect(vrf.type).toBe('section');
      expect(vrf.blockDepth).toBe(0);
    });
  });

  test('NCLU and NVUE commands should parse as top-level', () => {
    const config = `net add interface swp1 ip address 10.0.0.1/24
nv set interface swp2 ip address 10.0.0.2/24`;

    const parser = new SchemaAwareParser({ vendor: CumulusLinuxSchema });
    const ast = parser.parse(config);

    expect(ast.length).toBeGreaterThanOrEqual(2);

    const netAdd = ast.find((n) => n.id.includes('net add'));
    expect(netAdd).toBeDefined();

    const nvSet = ast.find((n) => n.id.includes('nv set'));
    expect(nvSet).toBeDefined();
  });
});
