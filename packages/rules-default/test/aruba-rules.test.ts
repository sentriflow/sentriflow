// packages/rules-default/test/aruba-rules.test.ts
// Tests for Aruba HPE rules (AOS-CX, AOS-Switch, WLC)

import { describe, it, expect } from 'bun:test';
import {
  SchemaAwareParser,
  ArubaAOSCXSchema,
  ArubaAOSSwitchSchema,
  ArubaWLCSchema,
  detectVendor
} from '@sentriflow/core';
import {
  allArubaRules,
  getRulesByArubaVendor,
  allAosCxRules,
  allAosSwitchRules,
  allWlcRules,
  allArubaCommonRules,
  // AOS-CX rules
  AosCxInterfaceDescription,
  AosCxTrunkAllowedVlans,
  AosCxAccessVlanAssigned,
  AosCxNativeVlanNotDefault,
  AosCxBpduGuardOnEdge,
  AosCxVlanName,
  // AOS-Switch rules
  AosSwitchVlanName,
  AosSwitchVlanHasPorts,
  AosSwitchTrunkLacp,
  // WLC rules
  WlcSsidEncryption,
  WlcVapAaaProfile,
  WlcVapSsidProfile,
  WlcRadiusHost,
  WlcRadiusKey,
  WlcApGroupVaps,
  // Common rules
  SnmpNotDefault,
} from '../src/aruba';
import * as fs from 'fs';
import * as path from 'path';

// =============================================================================
// Vendor Detection Tests
// =============================================================================

describe('Aruba Vendor Detection', () => {
  it('should detect AOS-CX from version string', () => {
    const config = `!Version ArubaOS-CX PL.10.11.0001
hostname "ARUBA-CX-SW01"
!
interface 1/1/1
    description Test
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-aoscx');
  });

  it('should detect AOS-CX from interface format', () => {
    const config = `hostname "ARUBA-CX-SW01"
interface 1/1/1
    vlan access 100
interface 1/1/2
    vlan trunk native 1
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-aoscx');
  });

  it('should detect AOS-Switch from configuration editor header', () => {
    const config = `; J9729A Configuration Editor; Created on release #WC.16.10
hostname "ARUBA-2920"
vlan 1
   name "DEFAULT_VLAN"
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-aosswitch');
  });

  it('should detect AOS-Switch from tagged/untagged VLAN syntax', () => {
    const config = `hostname "ARUBA-2920"
vlan 100
   name "Users"
   untagged 1-24
   tagged 25-48
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-aosswitch');
  });

  it('should detect WLC from WLAN SSID profile', () => {
    const config = `version 8.10.0.0
wlan ssid-profile "Corp-Secure"
    essid "CorpNetwork"
    opmode wpa3-sae-aes
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-wlc');
  });

  it('should detect WLC from AP group', () => {
    const config = `version 8.10.0.0
ap-group "Building-A"
    virtual-ap "Corp-VAP"
`;
    const vendor = detectVendor(config);
    expect(vendor.id).toBe('aruba-wlc');
  });
});

// =============================================================================
// Rule Count Tests
// =============================================================================

describe('Aruba Rule Collections', () => {
  it('should have common Aruba rules', () => {
    expect(allArubaCommonRules.length).toBeGreaterThan(0);
  });

  it('should have AOS-CX specific rules', () => {
    expect(allAosCxRules.length).toBeGreaterThan(0);
  });

  it('should have AOS-Switch specific rules', () => {
    expect(allAosSwitchRules.length).toBeGreaterThan(0);
  });

  it('should have WLC specific rules', () => {
    expect(allWlcRules.length).toBeGreaterThan(0);
  });

  it('should combine all rules in allArubaRules', () => {
    const total = allArubaCommonRules.length + allAosCxRules.length + allAosSwitchRules.length + allWlcRules.length;
    expect(allArubaRules.length).toBe(total);
  });

  it('should return correct rules for AOS-CX vendor', () => {
    const rules = getRulesByArubaVendor('aruba-aoscx');
    expect(rules.length).toBe(allArubaCommonRules.length + allAosCxRules.length);
  });

  it('should return correct rules for AOS-Switch vendor', () => {
    const rules = getRulesByArubaVendor('aruba-aosswitch');
    expect(rules.length).toBe(allArubaCommonRules.length + allAosSwitchRules.length);
  });

  it('should return correct rules for WLC vendor', () => {
    const rules = getRulesByArubaVendor('aruba-wlc');
    expect(rules.length).toBe(allArubaCommonRules.length + allWlcRules.length);
  });
});

// =============================================================================
// AOS-CX Rule Tests
// =============================================================================

describe('AOS-CX Rules', () => {
  const parser = new SchemaAwareParser({ vendor: ArubaAOSCXSchema });

  describe('AOSCX-IF-001: Interface Description', () => {
    it('should fail when physical interface lacks description', () => {
      const config = `interface 1/1/1
    no shutdown
    vlan access 100
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxInterfaceDescription.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when interface has description', () => {
      const config = `interface 1/1/1
    description Uplink:CORE-SW01
    no shutdown
    vlan access 100
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxInterfaceDescription.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });

    it('should skip VLAN interfaces', () => {
      const config = `interface vlan 100
    ip address 10.0.0.1/24
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface vlan'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxInterfaceDescription.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
        expect(result.message).toContain('Not a physical');
      }
    });
  });

  describe('AOSCX-L2-001: Trunk Allowed VLANs', () => {
    it('should fail when trunk has no allowed VLANs', () => {
      const config = `interface 1/1/1
    vlan trunk native 999
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxTrunkAllowedVlans.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when trunk has allowed VLANs', () => {
      const config = `interface 1/1/1
    vlan trunk native 999
    vlan trunk allowed 100,200
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxTrunkAllowedVlans.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('AOSCX-L2-002: Access VLAN Assigned', () => {
    it('should fail when access port is on VLAN 1', () => {
      const config = `interface 1/1/1
    no shutdown
    vlan access 1
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxAccessVlanAssigned.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('default VLAN 1');
      }
    });

    it('should pass when access port has proper VLAN', () => {
      const config = `interface 1/1/1
    no shutdown
    vlan access 100
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxAccessVlanAssigned.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('AOSCX-L2-003: Native VLAN Not Default', () => {
    it('should fail when native VLAN is 1', () => {
      const config = `interface 1/1/1
    vlan trunk native 1
    vlan trunk allowed 100,200
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxNativeVlanNotDefault.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when native VLAN is not 1', () => {
      const config = `interface 1/1/1
    vlan trunk native 999
    vlan trunk allowed 100,200
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('interface 1/1/1'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxNativeVlanNotDefault.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('AOSCX-VLAN-001: VLAN Name', () => {
    it('should fail when VLAN has no name', () => {
      const config = `vlan 100
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxVlanName.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when VLAN has name', () => {
      const config = `vlan 100
    name Users
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosCxVlanName.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });
});

// =============================================================================
// AOS-Switch Rule Tests
// =============================================================================

describe('AOS-Switch Rules', () => {
  const parser = new SchemaAwareParser({ vendor: ArubaAOSSwitchSchema });

  describe('AOSSW-L2-001: VLAN Name', () => {
    it('should fail when VLAN has no name', () => {
      const config = `vlan 100
   untagged 1-24
   exit
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchVlanName.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when VLAN has name', () => {
      const config = `vlan 100
   name "Users"
   untagged 1-24
   exit
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchVlanName.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('AOSSW-L2-002: VLAN Has Ports', () => {
    it('should fail when VLAN has no ports', () => {
      const config = `vlan 100
   name "Empty"
   exit
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchVlanHasPorts.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when VLAN has ports', () => {
      const config = `vlan 100
   name "Users"
   untagged 1-24
   tagged 25-48
   exit
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('vlan 100'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchVlanHasPorts.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('AOSSW-TRUNK-001: Trunk LACP', () => {
    it('should fail when trunk does not use LACP', () => {
      const config = `trunk 1-2 trk1 trunk
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('trunk'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchTrunkLacp.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when trunk uses LACP', () => {
      const config = `trunk 1-2 trk1 lacp
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('trunk'));
      expect(node).toBeDefined();
      if (node) {
        const result = AosSwitchTrunkLacp.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });
});

// =============================================================================
// WLC Rule Tests
// =============================================================================

describe('WLC Rules', () => {
  const parser = new SchemaAwareParser({ vendor: ArubaWLCSchema });

  describe('ARUWLC-WLAN-001: SSID Encryption', () => {
    it('should fail when SSID is open', () => {
      const config = `wlan ssid-profile "Guest-Open"
    essid "GuestWiFi"
    opmode opensystem
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan ssid-profile'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcSsidEncryption.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('open');
      }
    });

    it('should pass when SSID uses WPA3', () => {
      const config = `wlan ssid-profile "Corp-Secure"
    essid "CorpNetwork"
    opmode wpa3-sae-aes
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan ssid-profile'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcSsidEncryption.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });

    it('should pass when SSID uses WPA2', () => {
      const config = `wlan ssid-profile "Corp-Legacy"
    essid "CorpNetwork-Legacy"
    opmode wpa2-aes
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan ssid-profile'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcSsidEncryption.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('ARUWLC-VAP-001: Virtual-AP AAA Profile', () => {
    it('should fail when virtual-AP has no AAA profile', () => {
      const config = `wlan virtual-ap "Test-VAP"
    ssid-profile "Test-SSID"
    vlan 100
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan virtual-ap'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcVapAaaProfile.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when virtual-AP has AAA profile', () => {
      const config = `wlan virtual-ap "Corp-Secure-VAP"
    aaa-profile "Corp-Dot1x"
    ssid-profile "Corp-Secure"
    vlan 200
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan virtual-ap'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcVapAaaProfile.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('ARUWLC-VAP-002: Virtual-AP SSID Profile', () => {
    it('should fail when virtual-AP has no SSID profile', () => {
      const config = `wlan virtual-ap "Test-VAP"
    aaa-profile "Test-AAA"
    vlan 100
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan virtual-ap'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcVapSsidProfile.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when virtual-AP has SSID profile', () => {
      const config = `wlan virtual-ap "Corp-Secure-VAP"
    aaa-profile "Corp-Dot1x"
    ssid-profile "Corp-Secure"
    vlan 200
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('wlan virtual-ap'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcVapSsidProfile.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('ARUWLC-AAA-001: RADIUS Host', () => {
    it('should fail when RADIUS server has no host', () => {
      const config = `aaa authentication-server radius "Test-RADIUS"
    key "secret"
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('aaa authentication-server radius'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcRadiusHost.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when RADIUS server has host', () => {
      const config = `aaa authentication-server radius "RADIUS-SRV01"
    host 10.0.0.50
    key "SuperSecretKey"
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('aaa authentication-server radius'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcRadiusHost.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('ARUWLC-AAA-002: RADIUS Key', () => {
    it('should fail when RADIUS server has no key', () => {
      const config = `aaa authentication-server radius "Test-RADIUS"
    host 10.0.0.50
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('aaa authentication-server radius'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcRadiusKey.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when RADIUS server has key', () => {
      const config = `aaa authentication-server radius "RADIUS-SRV01"
    host 10.0.0.50
    key "SuperSecretKey"
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('aaa authentication-server radius'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcRadiusKey.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });

  describe('ARUWLC-AP-001: AP Group Virtual-APs', () => {
    it('should fail when AP group has no virtual-APs', () => {
      const config = `ap-group "Empty-Group"
    regulatory-domain-profile "US"
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('ap-group'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcApGroupVaps.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
      }
    });

    it('should pass when AP group has virtual-APs', () => {
      const config = `ap-group "Building-A"
    virtual-ap "Corp-Secure-VAP"
    virtual-ap "Guest-VAP"
    regulatory-domain-profile "US"
!`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('ap-group'));
      expect(node).toBeDefined();
      if (node) {
        const result = WlcApGroupVaps.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });
});

// =============================================================================
// Common Rule Tests
// =============================================================================

describe('Common Aruba Rules', () => {
  const parser = new SchemaAwareParser({ vendor: ArubaAOSCXSchema });

  describe('ARU-SEC-002: SNMP Not Default', () => {
    it('should fail when SNMP community is public', () => {
      const config = `snmp-server community public
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('snmp-server community'));
      expect(node).toBeDefined();
      if (node) {
        const result = SnmpNotDefault.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('public');
      }
    });

    it('should fail when SNMP community is private', () => {
      const config = `snmp-server community private
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('snmp-server community'));
      expect(node).toBeDefined();
      if (node) {
        const result = SnmpNotDefault.check(node, { getAst: () => ast });
        expect(result.passed).toBe(false);
        expect(result.message).toContain('private');
      }
    });

    it('should pass when SNMP community is custom', () => {
      const config = `snmp-server community SecureString123
`;
      const ast = parser.parse(config);
      const node = ast.find((n) => n.id.includes('snmp-server community'));
      expect(node).toBeDefined();
      if (node) {
        const result = SnmpNotDefault.check(node, { getAst: () => ast });
        expect(result.passed).toBe(true);
      }
    });
  });
});

// =============================================================================
// Parser Tests with Fixtures
// =============================================================================

describe('Aruba Parser with Fixtures', () => {
  const fixturesPath = path.join(__dirname, '../../core/test/fixtures');

  it('should parse AOS-CX basic interface fixture', () => {
    const fixturePath = path.join(fixturesPath, 'aruba-aoscx/basic-interface.txt');
    if (fs.existsSync(fixturePath)) {
      const config = fs.readFileSync(fixturePath, 'utf-8');
      const parser = new SchemaAwareParser({ vendor: ArubaAOSCXSchema });
      const ast = parser.parse(config);
      expect(ast.length).toBeGreaterThan(0);

      // Check for expected nodes
      const interfaces = ast.filter((n) => n.id.toLowerCase().startsWith('interface'));
      expect(interfaces.length).toBeGreaterThan(0);

      const vlans = ast.filter((n) => n.id.toLowerCase().startsWith('vlan'));
      expect(vlans.length).toBeGreaterThan(0);
    }
  });

  it('should parse AOS-Switch basic VLAN fixture', () => {
    const fixturePath = path.join(fixturesPath, 'aruba-aosswitch/basic-vlan.txt');
    if (fs.existsSync(fixturePath)) {
      const config = fs.readFileSync(fixturePath, 'utf-8');
      const parser = new SchemaAwareParser({ vendor: ArubaAOSSwitchSchema });
      const ast = parser.parse(config);
      expect(ast.length).toBeGreaterThan(0);

      // Check for expected nodes
      const vlans = ast.filter((n) => n.id.toLowerCase().startsWith('vlan'));
      expect(vlans.length).toBeGreaterThan(0);
    }
  });

  it('should parse WLC SSID profiles fixture', () => {
    const fixturePath = path.join(fixturesPath, 'aruba-wlc/ssid-profiles.txt');
    if (fs.existsSync(fixturePath)) {
      const config = fs.readFileSync(fixturePath, 'utf-8');
      const parser = new SchemaAwareParser({ vendor: ArubaWLCSchema });
      const ast = parser.parse(config);
      expect(ast.length).toBeGreaterThan(0);

      // Check for expected nodes
      const ssidProfiles = ast.filter((n) => n.id.toLowerCase().includes('ssid-profile'));
      expect(ssidProfiles.length).toBeGreaterThan(0);

      const apGroups = ast.filter((n) => n.id.toLowerCase().startsWith('ap-group'));
      expect(apGroups.length).toBeGreaterThan(0);
    }
  });
});
