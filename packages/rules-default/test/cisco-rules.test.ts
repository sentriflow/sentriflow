import { describe, expect, test } from 'bun:test';
import { SchemaAwareParser, RuleEngine } from '@sentriflow/core';
import {
    // Layer 2 Trunk
    TrunkNoDTP,
    TrunkNativeVlanNotOne,
    TrunkAllowedVlans,
    // Layer 2 Access
    AccessExplicitMode,
    AccessVlanNotOne,
    AccessBpduGuard,
    // VTP
    VtpConfiguration,
    // VLAN
    VlanNameRequired,
    // Management
    VtyNoTelnet,
    VtyExecTimeout,
    NoHttpServer,
    // Routing
    OspfRouterId,
    BgpRouterId,
    BgpAllNeighborsShutdown,
    // SNMP
    SnmpNoDefaultCommunity,
    SnmpNoRwAccess,
    // CDP/LLDP
    CdpDisabledOnExternal,
    LldpDisabledOnExternal,
    // FHRP
    FhrpAuthentication,
    // Service Hardening
    NoIpSourceRoute,
    EnableSecretStrong,
    // All
    allCiscoRules,
} from '../src/cisco/ios-rules';

// ============================================================================
// Layer 2 Trunk Port Tests
// ============================================================================

describe('Layer 2 Trunk Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-TRUNK-001: DTP Disabled on Non-Cisco Devices', () => {
        const rules = [TrunkNoDTP];

        test('should fail when trunk to server missing switchport nonegotiate', () => {
            const config = `
interface GigabitEthernet0/1
 description SERVER:ESX-HOST01:vmnic0
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-TRUNK-001');
            expect(failures[0]?.message).toContain('non-Cisco');
        });

        test('should pass when trunk to server has switchport nonegotiate', () => {
            const config = `
interface GigabitEthernet0/1
 description SERVER:ESX-HOST01:vmnic0
 switchport mode trunk
 switchport nonegotiate
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should pass when trunk to Cisco switch (uplink) without nonegotiate', () => {
            const config = `
interface GigabitEthernet0/1
 description UPLINK:CORE-SW01:Gi1/0/1
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should pass when trunk to Cisco switch (downlink) without nonegotiate', () => {
            const config = `
interface GigabitEthernet0/1
 description DOWNLINK:ACCESS-SW01:Gi0/1
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should skip shutdown interfaces', () => {
            const config = `
interface GigabitEthernet0/1
 description SERVER:ESX-HOST01:vmnic0
 switchport mode trunk
 shutdown
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should skip non-physical interfaces', () => {
            const config = `
interface Vlan100
 ip address 10.0.0.1 255.255.255.0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-TRUNK-002: Native VLAN Not 1', () => {
        const rules = [TrunkNativeVlanNotOne];

        test('should fail when trunk uses default native VLAN 1', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-TRUNK-002');
            expect(failures[0]?.message).toContain('default native VLAN 1');
        });

        test('should fail when trunk explicitly uses native VLAN 1', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk native vlan 1
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('explicitly uses native VLAN 1');
        });

        test('should pass when trunk uses non-1 native VLAN', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk native vlan 999
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-TRUNK-003: Allowed VLAN List', () => {
        const rules = [TrunkAllowedVlans];

        test('should fail when trunk has no allowed VLAN list', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-TRUNK-003');
            expect(failures[0]?.message).toContain('allows all VLANs');
        });

        test('should fail when trunk explicitly allows all VLANs', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan all
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('explicitly allows all VLANs');
        });

        test('should pass when trunk has explicit VLAN list', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,100-110
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// Layer 2 Access Port Tests
// ============================================================================

describe('Layer 2 Access Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-ACCESS-001: Explicit Access Mode', () => {
        const rules = [AccessExplicitMode];

        test('should fail when access VLAN set without explicit mode', () => {
            const config = `
interface GigabitEthernet0/1
 switchport access vlan 100
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-ACCESS-001');
            expect(failures[0]?.message).toContain('no explicit mode');
        });

        test('should pass when explicit access mode is set', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 100
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-ACCESS-002: VLAN Not 1', () => {
        const rules = [AccessVlanNotOne];

        test('should fail when access port has no VLAN (defaults to 1)', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-ACCESS-002');
            expect(failures[0]?.message).toContain('default VLAN 1');
        });

        test('should fail when access port explicitly uses VLAN 1', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 1
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('explicitly uses VLAN 1');
        });

        test('should pass when access port uses non-1 VLAN', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 100
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-ACCESS-004: BPDU Guard on PortFast', () => {
        const rules = [AccessBpduGuard];

        test('should fail when PortFast enabled without BPDU Guard', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 spanning-tree portfast
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-ACCESS-004');
            expect(failures[0]?.message).toContain('PortFast but no BPDU Guard');
        });

        test('should pass when PortFast has BPDU Guard', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
 spanning-tree portfast
 spanning-tree bpduguard enable
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should skip interfaces without PortFast', () => {
            const config = `
interface GigabitEthernet0/1
 switchport mode access
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// VTP Tests
// ============================================================================

describe('VTP Rules (NET-VLAN-004)', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();
    const rules = [VtpConfiguration];

    test('should fail when VTP version 1 is configured', () => {
        const config = `
vtp domain CORP
vtp mode server
vtp version 1
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(1);
        expect(failures[0]?.ruleId).toBe('NET-VLAN-004');
        expect(failures[0]?.message).toContain('version 1');
    });

    test('should pass when VTP version 2 is configured', () => {
        const config = `
vtp domain CORP
vtp mode transparent
vtp version 2
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('should pass when VTP version 3 is configured', () => {
        const config = `
vtp domain CORP
vtp mode server
vtp version 3
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });
});

// ============================================================================
// VLAN Tests
// ============================================================================

describe('VLAN Rules (NET-VLAN-001)', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();
    const rules = [VlanNameRequired];

    test('should fail when VLAN has empty name', () => {
        const config = `
vlan 110
 name
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(1);
        expect(failures[0]?.ruleId).toBe('NET-VLAN-001');
        expect(failures[0]?.message).toContain('VLAN 110');
        expect(failures[0]?.message).toContain('empty name');
    });

    test('should fail when VLAN has name keyword with only whitespace', () => {
        const config = `
vlan 200
 name
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(1);
        expect(failures[0]?.ruleId).toBe('NET-VLAN-001');
    });

    test('should pass when VLAN has valid name', () => {
        const config = `
vlan 100
 name USER_NETWORK
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('should pass when VLAN has no name configured', () => {
        const config = `
vlan 300
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('should detect multiple VLANs with empty names', () => {
        const config = `
vlan 10
 name
!
vlan 20
 name VALID_NAME
!
vlan 30
 name
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(2);
        expect(failures.some(f => f.message.includes('VLAN 10'))).toBe(true);
        expect(failures.some(f => f.message.includes('VLAN 30'))).toBe(true);
    });
});

// ============================================================================
// Management Plane Tests
// ============================================================================

describe('Management Plane Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-MGMT-001: SSH Only', () => {
        const rules = [VtyNoTelnet];

        test('should fail when VTY allows telnet', () => {
            const config = `
line vty 0 4
 transport input telnet
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-MGMT-001');
            expect(failures[0]?.message).toContain('Telnet');
        });

        test('should fail when VTY allows all transports', () => {
            const config = `
line vty 0 4
 transport input all
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
        });

        test('should fail when VTY allows both SSH and telnet', () => {
            const config = `
line vty 0 4
 transport input ssh telnet
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
        });

        test('should fail when VTY has no transport input configured', () => {
            const config = `
line vty 0 4
 password cisco
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('missing transport input');
        });

        test('should pass when VTY uses SSH only', () => {
            const config = `
line vty 0 4
 transport input ssh
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-MGMT-003: Exec Timeout', () => {
        const rules = [VtyExecTimeout];

        test('should fail when VTY has no exec-timeout', () => {
            const config = `
line vty 0 4
 transport input ssh
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-MGMT-003');
        });

        test('should fail when exec-timeout is disabled (0)', () => {
            const config = `
line vty 0 4
 exec-timeout 0 0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('disabled');
        });

        test('should fail when exec-timeout exceeds 15 minutes', () => {
            const config = `
line vty 0 4
 exec-timeout 30 0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('exceeds maximum 15 minutes');
        });

        test('should pass when exec-timeout is within limits', () => {
            const config = `
line vty 0 4
 exec-timeout 10 0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-MGMT-005: No HTTP Server', () => {
        const rules = [NoHttpServer];

        test('should fail when HTTP server is enabled', () => {
            const config = `
ip http server
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-MGMT-005');
            expect(failures[0]?.message).toContain('HTTP server is enabled');
        });

        test('should fail when HTTPS server is enabled', () => {
            const config = `
ip http secure-server
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('HTTPS server is enabled');
        });

        test('should pass when both HTTP and HTTPS are disabled', () => {
            const config = `
no ip http server
no ip http secure-server
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// Routing Protocol Tests
// ============================================================================

describe('Routing Protocol Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-ROUTE-001: Router-ID Required', () => {
        test('should fail when OSPF has no router-id', () => {
            const config = `
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, [OspfRouterId]);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-ROUTE-001');
            expect(failures[0]?.message).toContain('missing explicit router-id');
        });

        test('should pass when OSPF has router-id', () => {
            const config = `
router ospf 1
 router-id 10.255.0.1
 network 10.0.0.0 0.0.0.255 area 0
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, [OspfRouterId]);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should fail when BGP has no router-id', () => {
            const config = `
router bgp 65000
 neighbor 192.168.1.1 remote-as 65001
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, [BgpRouterId]);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('missing explicit router-id');
        });

        test('should pass when BGP has router-id', () => {
            const config = `
router bgp 65000
 bgp router-id 10.255.0.1
 neighbor 192.168.1.1 remote-as 65001
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, [BgpRouterId]);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-ROUTE-005: BGP All Neighbors Shutdown', () => {
        const rules = [BgpAllNeighborsShutdown];

        test('should fail when all BGP neighbors are shutdown', () => {
            const config = `
router bgp 65000
 bgp router-id 10.255.0.1
 neighbor 192.168.1.1 remote-as 65001
 neighbor 192.168.1.1 shutdown
 neighbor 192.168.2.1 remote-as 65002
 neighbor 192.168.2.1 shutdown
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-ROUTE-005');
            expect(failures[0]?.message).toContain('all');
            expect(failures[0]?.message).toContain('shutdown');
        });

        test('should pass when at least one BGP neighbor is active', () => {
            const config = `
router bgp 65000
 bgp router-id 10.255.0.1
 neighbor 192.168.1.1 remote-as 65001
 neighbor 192.168.1.1 shutdown
 neighbor 192.168.2.1 remote-as 65002
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should pass when no neighbors are shutdown', () => {
            const config = `
router bgp 65000
 bgp router-id 10.255.0.1
 neighbor 192.168.1.1 remote-as 65001
 neighbor 192.168.2.1 remote-as 65002
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should pass when no neighbors configured', () => {
            const config = `
router bgp 65000
 bgp router-id 10.255.0.1
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// SNMP Security Tests
// ============================================================================

describe('SNMP Security Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-SNMP-002: No Default Community Strings', () => {
        const rules = [SnmpNoDefaultCommunity];

        test('should fail when using "public" community', () => {
            const config = `
snmp-server community public RO
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-SNMP-002');
            expect(failures[0]?.message).toContain('public');
        });

        test('should fail when using "private" community', () => {
            const config = `
snmp-server community private RW
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('private');
        });

        test('should pass when using custom community string', () => {
            const config = `
snmp-server community C0mpl3xStr1ng! RO SNMP-ACL
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-SNMP-004: No RW Access', () => {
        const rules = [SnmpNoRwAccess];

        test('should fail when SNMP RW is configured', () => {
            const config = `
snmp-server community secretstring RW
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-SNMP-004');
            expect(failures[0]?.message).toContain('RW');
        });

        test('should pass when SNMP is RO only', () => {
            const config = `
snmp-server community secretstring RO
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// CDP/LLDP Tests
// ============================================================================

describe('CDP/LLDP Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-SVC-005: CDP Disabled on External', () => {
        const rules = [CdpDisabledOnExternal];

        test('should fail when external interface has CDP enabled', () => {
            const config = `
interface GigabitEthernet0/0
 description WAN:ISP:Circuit123
 ip address 203.0.113.1 255.255.255.252
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-SVC-005');
            expect(failures[0]?.message).toContain('External interface');
        });

        test('should pass when external interface has CDP disabled', () => {
            const config = `
interface GigabitEthernet0/0
 description WAN:ISP:Circuit123
 ip address 203.0.113.1 255.255.255.252
 no cdp enable
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should allow CDP on phone ports', () => {
            const config = `
interface GigabitEthernet0/1
 description ENDPOINT:PHONE-FLOOR1
 switchport mode access
 switchport voice vlan 200
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should fail on Aruba AP ports (uses LLDP, not CDP)', () => {
            const config = `
interface GigabitEthernet0/1
 description ENDPOINT:ARUBA-AP-FLOOR1
 switchport mode access
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('Aruba AP');
        });
    });

    describe('NET-SVC-006: LLDP Disabled on External', () => {
        const rules = [LldpDisabledOnExternal];

        test('should fail when external interface has LLDP enabled', () => {
            const config = `
interface GigabitEthernet0/0
 description WAN:ISP:Circuit123
 ip address 203.0.113.1 255.255.255.252
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-SVC-006');
        });

        test('should pass when external interface has LLDP disabled', () => {
            const config = `
interface GigabitEthernet0/0
 description WAN:ISP:Circuit123
 ip address 203.0.113.1 255.255.255.252
 no lldp transmit
 no lldp receive
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });

        test('should fail on Cisco AP ports (uses CDP, not LLDP)', () => {
            const config = `
interface GigabitEthernet0/1
 description ENDPOINT:CISCO-AP-FLOOR1
 switchport mode trunk
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('Cisco AP');
        });
    });
});

// ============================================================================
// FHRP Tests
// ============================================================================

describe('FHRP Rules (NET-FHRP-002)', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();
    const rules = [FhrpAuthentication];

    test('should fail when HSRP has no authentication', () => {
        const config = `
interface Vlan100
 ip address 10.10.100.2 255.255.255.0
 standby 100 ip 10.10.100.1
 standby 100 priority 110
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(1);
        expect(failures[0]?.ruleId).toBe('NET-FHRP-002');
        expect(failures[0]?.message).toContain('HSRP without authentication');
    });

    test('should pass when HSRP has authentication', () => {
        const config = `
interface Vlan100
 ip address 10.10.100.2 255.255.255.0
 standby version 2
 standby 100 ip 10.10.100.1
 standby 100 priority 110
 standby 100 authentication md5 key-string SecretKey
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });

    test('should skip interfaces without HSRP', () => {
        const config = `
interface Vlan100
 ip address 10.10.100.1 255.255.255.0
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, rules);
        const failures = results.filter(r => !r.passed);

        expect(failures).toHaveLength(0);
    });
});

// ============================================================================
// Service Hardening Tests
// ============================================================================

describe('Service Hardening Rules', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    describe('NET-SVC-002: No IP Source-Route', () => {
        const rules = [NoIpSourceRoute];

        test('should fail when ip source-route is enabled', () => {
            const config = `
ip source-route
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-SVC-002');
        });

        test('should pass when ip source-route is disabled', () => {
            const config = `
no ip source-route
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });

    describe('NET-AAA-003: Enable Secret Strong', () => {
        const rules = [EnableSecretStrong];

        test('should fail when enable password is used', () => {
            const config = `
enable password cisco123
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.ruleId).toBe('NET-AAA-003');
            expect(failures[0]?.message).toContain('enable secret');
        });

        test('should fail when enable password type 7 is used', () => {
            const config = `
enable password 7 094F471A1A0A
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(1);
            expect(failures[0]?.message).toContain('type 7');
        });

        test('should pass when enable secret is used', () => {
            const config = `
enable secret 9 $9$encrypted$hash
`;
            const nodes = parser.parse(config);
            const results = engine.run(nodes, rules);
            const failures = results.filter(r => !r.passed);

            expect(failures).toHaveLength(0);
        });
    });
});

// ============================================================================
// Integration Test
// ============================================================================

describe('Cisco Rules Integration', () => {
    const parser = new SchemaAwareParser();
    const engine = new RuleEngine();

    test('allCiscoRules array should contain all expected rules', () => {
        // Reduced to 3 proof-of-concept rules; full set available in basic-netsec-pack
        expect(allCiscoRules.length).toBe(3);
    });

    test('compliant configuration should pass all rules', () => {
        const config = `
!
vtp domain CORP-NETWORK
vtp mode transparent
vtp version 3
!
udld aggressive
!
no ip source-route
no ip http server
no ip http secure-server
!
enable secret 9 $9$encrypted$hash
!
interface GigabitEthernet0/1
 description UPLINK:CORE-SW01:Gi1/0/1
 switchport mode trunk
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30
!
interface GigabitEthernet0/2
 description ENDPOINT:VLAN100-FLOOR1
 switchport mode access
 switchport access vlan 100
 spanning-tree portfast
 spanning-tree bpduguard enable
 no cdp enable
 no lldp transmit
 no lldp receive
!
interface Vlan100
 ip address 10.10.100.2 255.255.255.0
 standby version 2
 standby 100 ip 10.10.100.1
 standby 100 authentication md5 key-string Secret
!
router ospf 1
 router-id 10.255.0.1
 network 10.0.0.0 0.0.0.255 area 0
!
router bgp 65000
 bgp router-id 10.255.0.1
 neighbor 192.168.1.1 remote-as 65001
!
snmp-server community C0mpl3xStr1ng RO SNMP-ACL
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
 access-class VTY-ACL in
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, allCiscoRules);
        const failures = results.filter(r => !r.passed);

        // Should have no errors
        const errors = failures.filter(f => f.level === 'error');
        expect(errors).toHaveLength(0);
    });

    test('non-compliant configuration should detect issues with kept rules', () => {
        // Note: Reduced to 3 proof-of-concept rules; full set available in basic-netsec-pack
        const config = `
!
enable password cisco123
!
interface GigabitEthernet0/1
 description SERVER:ESX-HOST01:vmnic0
 switchport mode trunk
!
interface GigabitEthernet0/2
 switchport mode access
 switchport access vlan 1
!
`;
        const nodes = parser.parse(config);
        const results = engine.run(nodes, allCiscoRules);
        const failures = results.filter(r => !r.passed);

        // Should detect issues from the 3 kept rules
        expect(failures.length).toBeGreaterThan(0);

        // Verify specific violations from kept rules are detected
        const ruleIds = new Set(failures.map(f => f.ruleId));
        // NET-TRUNK-001: DTP on trunk (kept)
        expect(ruleIds.has('NET-TRUNK-001')).toBe(true);
        // NET-AAA-003: Enable password instead of secret (kept)
        expect(ruleIds.has('NET-AAA-003')).toBe(true);
    });
});
