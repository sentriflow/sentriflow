// packages/core/test/parser.test.ts

import { describe, expect, test } from 'bun:test';
import { SchemaAwareParser } from '../src/parser/SchemaAwareParser';
import type { ConfigNode, NodeType } from '../src/types/ConfigNode';

describe('SchemaAwareParser', () => {
    test('should parse a simple flat configuration', () => {
        const config = `
line one
line two
line three
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(1);
        expect(ast[0]?.type).toBe('virtual_root');
        expect(ast[0]?.children).toHaveLength(3);
        expect(ast[0]?.children[0]?.rawText).toBe('line one');
        expect(ast[0]?.children[1]?.rawText).toBe('line two');
        expect(ast[0]?.children[2]?.rawText).toBe('line three');
    });

    test('should parse a simple hierarchical configuration by indentation', () => {
        const config = `
interface GigabitEthernet1
 description Uplink to Core
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet2
 description Access Port
 switchport mode access
 switchport access vlan 10
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(2);

        // Interface 1
        expect(ast[0]?.type).toBe('section');
        expect(ast[0]?.rawText).toBe('interface GigabitEthernet1');
        expect(ast[0]?.children).toHaveLength(3);
        expect(ast[0]?.children[0]?.rawText).toBe(' description Uplink to Core');
        expect(ast[0]?.children[1]?.rawText).toBe(' ip address 10.0.0.1 255.255.255.0');
        expect(ast[0]?.children[2]?.rawText).toBe(' no shutdown');

        // Interface 2
        expect(ast[1]?.type).toBe('section');
        expect(ast[1]?.rawText).toBe('interface GigabitEthernet2');
        expect(ast[1]?.children).toHaveLength(3);
        expect(ast[1]?.children[0]?.rawText).toBe(' description Access Port');
        expect(ast[1]?.children[1]?.rawText).toBe(' switchport mode access');
        expect(ast[1]?.children[2]?.rawText).toBe(' switchport access vlan 10');
    });

    test('should handle deeply nested configurations', () => {
        const config = `
router bgp 65000
 bgp router-id 1.1.1.1
 neighbor 192.168.1.1 remote-as 65001
  address-family ipv4 unicast
   redistribute connected
   neighbor 192.168.1.1 activate
  exit-address-family
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(1);
        const routerBgp = ast[0];
        expect(routerBgp?.type).toBe('section');
        expect(routerBgp?.rawText).toBe('router bgp 65000');
        expect(routerBgp?.children).toHaveLength(4);
        expect(routerBgp?.children[0]?.rawText).toBe(' bgp router-id 1.1.1.1');
        expect(routerBgp?.children[1]?.rawText).toBe(' neighbor 192.168.1.1 remote-as 65001');

        const addressFamily = routerBgp?.children[2];
        expect(addressFamily?.type).toBe('section');
        expect(addressFamily?.rawText).toBe('  address-family ipv4 unicast');
        expect(addressFamily?.children).toHaveLength(2);
        expect(addressFamily?.children[0]?.rawText).toBe('   redistribute connected');
        expect(addressFamily?.children[1]?.rawText).toBe('   neighbor 192.168.1.1 activate');
    });

    test('should handle mixed indentation and block starters', () => {
        const config = `
hostname MyRouter
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
 no shutdown
router ospf 1
 router-id 1.1.1.1
 network 1.1.1.1 0.0.0.0 area 0
line vty 0 4
  transport input ssh
  login local
! comment line
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        // hostname MyRouter (orphan command)
        expect(ast).toHaveLength(4); // hostname, interface, router, line
        expect(ast[0]?.type).toBe('virtual_root');
        expect(ast[0]?.children[0]?.rawText).toBe('hostname MyRouter');

        // interface Loopback0
        expect(ast[1]?.type).toBe('section');
        expect(ast[1]?.rawText).toBe('interface Loopback0');
        expect(ast[1]?.children).toHaveLength(2);
        expect(ast[1]?.children[0]?.rawText).toBe(' ip address 1.1.1.1 255.255.255.255');
        expect(ast[1]?.children[1]?.rawText).toBe(' no shutdown');

        // router ospf 1
        expect(ast[2]?.type).toBe('section');
        expect(ast[2]?.rawText).toBe('router ospf 1');
        expect(ast[2]?.children).toHaveLength(2);
        expect(ast[2]?.children[0]?.rawText).toBe(' router-id 1.1.1.1');
        expect(ast[2]?.children[1]?.rawText).toBe(' network 1.1.1.1 0.0.0.0 area 0');

        // line vty 0 4
        expect(ast[3]?.type).toBe('section');
        expect(ast[3]?.rawText).toBe('line vty 0 4');
        expect(ast[3]?.children).toHaveLength(2);
        expect(ast[3]?.children[0]?.rawText).toBe('  transport input ssh');
        expect(ast[3]?.children[1]?.rawText).toBe('  login local');
    });

    test('should handle configurations with varying leading whitespace', () => {
        const config = `
  interface GigabitEthernet1
   description Uplink
    ip address 10.0.0.1 255.255.255.0
interface GigabitEthernet2
 description Access
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(2);
        expect(ast[0]?.rawText).toBe('  interface GigabitEthernet1');
        expect(ast[0]?.children).toHaveLength(1);
        expect(ast[0]?.children[0]?.rawText).toBe('   description Uplink');
        // ip address is indented deeper than description, so it becomes a child of description
        expect(ast[0]?.children[0]?.children[0]?.rawText).toBe('    ip address 10.0.0.1 255.255.255.0');

        expect(ast[1]?.rawText).toBe('interface GigabitEthernet2');
        expect(ast[1]?.children).toHaveLength(1); // Added assertion for children length
        expect(ast[1]?.children[0]?.rawText).toBe(' description Access');
    });

    test('should handle empty input', () => {
        const parser = new SchemaAwareParser();
        const ast = parser.parse('');
        expect(ast).toHaveLength(0);
    });

    test('should handle input with only comments and empty lines', () => {
        const config = `
! This is a comment
        
! Another comment
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);
        expect(ast).toHaveLength(0);
    });

    test('should correctly set source and loc properties', () => {
        const config = `
line one
 line two
        `;
        const parser = new SchemaAwareParser({ startLine: 10, source: 'snippet' });
        const ast = parser.parse(config);

        expect(ast).toHaveLength(1); // Expecting one virtual root
        expect(ast[0]?.type).toBe('virtual_root');
        expect(ast[0]?.source).toBe('snippet');
        expect(ast[0]?.loc.startLine).toBe(11); // line one is at index 1 in split, plus startLine 10

        const lineOne = ast[0]?.children[0];
        expect(lineOne?.rawText).toBe('line one');
        expect(lineOne?.loc.startLine).toBe(11);
        expect(lineOne?.loc.endLine).toBe(11);
        expect(lineOne?.source).toBe('snippet');

        const lineTwo = lineOne?.children[0];
        expect(lineTwo?.rawText).toBe(' line two'); // This should have leading space
        expect(lineTwo?.loc.startLine).toBe(12);
        expect(lineTwo?.loc.endLine).toBe(12);
        expect(lineTwo?.source).toBe('snippet');
    });

    test('should correctly parse block starter at less indentation than previous child', () => {
        const config = `
interface GigabitEthernet1
 description A
  command-in-description
interface GigabitEthernet2
 description B
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(2);
        expect(ast[0]?.rawText).toBe('interface GigabitEthernet1');
        expect(ast[0]?.children).toHaveLength(1);
        expect(ast[0]?.children[0]?.rawText).toBe(' description A');
        expect(ast[0]?.children[0]?.children[0]?.rawText).toBe('  command-in-description'); // This is a child of 'description A'

        expect(ast[1]?.rawText).toBe('interface GigabitEthernet2');
        expect(ast[1]?.children).toHaveLength(1);
        expect(ast[1]?.children[0]?.rawText).toBe(' description B');
    });

    test('should handle non-indented children of sections (real-world config)', () => {
        // This tests the case where engineers don't indent commands under interfaces
        const config = `
interface Vlan110
description User vlan
ip address 192.168.0.126 255.255.255.128
interface Vlan120
description Server vlan
ip address 10.0.0.1 255.255.255.0
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(2);

        // Interface Vlan110 should have description and ip address as children
        expect(ast[0]?.type).toBe('section');
        expect(ast[0]?.rawText).toBe('interface Vlan110');
        expect(ast[0]?.children).toHaveLength(2);
        expect(ast[0]?.children[0]?.id).toBe('description User vlan');
        expect(ast[0]?.children[1]?.id).toBe('ip address 192.168.0.126 255.255.255.128');

        // Interface Vlan120 should have description and ip address as children
        expect(ast[1]?.type).toBe('section');
        expect(ast[1]?.rawText).toBe('interface Vlan120');
        expect(ast[1]?.children).toHaveLength(2);
        expect(ast[1]?.children[0]?.id).toBe('description Server vlan');
        expect(ast[1]?.children[1]?.id).toBe('ip address 10.0.0.1 255.255.255.0');
    });

    test('should handle BlockEnders like exit-address-family', () => {
        const config = `
router bgp 65000
address-family ipv4 unicast
network 10.0.0.0/8
exit-address-family
neighbor 1.1.1.1 remote-as 65001
        `;
        const parser = new SchemaAwareParser();
        const ast = parser.parse(config);

        expect(ast).toHaveLength(1);
        const routerBgp = ast[0];
        expect(routerBgp?.type).toBe('section');
        expect(routerBgp?.children).toHaveLength(3); // address-family, exit-address-family, neighbor

        // address-family should contain network
        const addressFamily = routerBgp?.children[0];
        expect(addressFamily?.type).toBe('section');
        expect(addressFamily?.id).toBe('address-family ipv4 unicast');
        expect(addressFamily?.children).toHaveLength(1);
        expect(addressFamily?.children[0]?.id).toBe('network 10.0.0.0/8');

        // exit-address-family should be sibling of address-family (child of router bgp)
        expect(routerBgp?.children[1]?.id).toBe('exit-address-family');

        // neighbor should also be child of router bgp
        expect(routerBgp?.children[2]?.id).toBe('neighbor 1.1.1.1 remote-as 65001');
    });
});
