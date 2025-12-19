// packages/core/src/parser/vendors/huawei-vrp.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Huawei VRP (Versatile Routing Platform) configuration schema.
 *
 * Huawei VRP uses indentation-based hierarchy similar to Cisco IOS,
 * with '#' as the section delimiter and 'quit' or 'return' to exit blocks.
 *
 * VRP View Hierarchy:
 * - User View: <Huawei> - Initial access, limited commands
 * - System View: [Huawei] - Global configuration (enter via 'system-view')
 * - Interface View: [Huawei-GigabitEthernet0/0/1] - Interface config
 * - Protocol View: [Huawei-ospf-1] - Routing protocol config
 * - AAA View: [Huawei-aaa] - AAA configuration
 *
 * Configuration structure:
 * - Top-level: interface, ospf, bgp, vlan, aaa, acl, user-interface, etc.
 * - Nested: area inside ospf, peer inside bgp, address-family inside bgp
 * - Deeply nested: rules inside ACL, local-user inside aaa
 *
 * Distinctive patterns:
 * - sysname for hostname (vs Cisco's hostname)
 * - Interface naming: GigabitEthernet X/Y/Z, XGigabitEthernet, 40GE, 100GE
 * - undo command for negation (vs Cisco's 'no')
 * - quit to exit views (vs Cisco's exit)
 * - '#' as section delimiter in config files
 * - display commands for show (vs Cisco's show)
 */
export const HuaweiVRPSchema: VendorSchema = {
  id: 'huawei-vrp',
  name: 'Huawei VRP',
  useBraceHierarchy: false,

  // Comments in VRP config files start with # or !
  // The # is also used as a section delimiter
  commentPatterns: [/^#$/, /^!/],
  sectionDelimiter: '#',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // Interface blocks - Huawei naming conventions
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // VLAN interface (Vlanif in Huawei)
    { pattern: /^interface\s+Vlanif\s*\d+/i, depth: 0 },

    // Routing protocol blocks
    { pattern: /^ospf\s+\d+/i, depth: 0 },
    { pattern: /^ospfv3\s+\d+/i, depth: 0 },
    { pattern: /^bgp\s+\d+/i, depth: 0 },
    { pattern: /^isis\s+\d+/i, depth: 0 },
    { pattern: /^rip\s+\d+/i, depth: 0 },
    { pattern: /^mpls$/i, depth: 0 },
    { pattern: /^mpls\s+ldp$/i, depth: 0 },
    { pattern: /^mpls\s+l2vpn$/i, depth: 0 },
    { pattern: /^mpls\s+te$/i, depth: 0 },

    // VLAN configuration
    { pattern: /^vlan\s+\d+/i, depth: 0 },
    { pattern: /^vlan\s+batch\s+/i, depth: 0 },

    // AAA and security
    { pattern: /^aaa$/i, depth: 0 },
    { pattern: /^acl\s+\d+/i, depth: 0 },
    { pattern: /^acl\s+name\s+\S+/i, depth: 0 },
    { pattern: /^acl\s+(number\s+)?\d+/i, depth: 0 },
    { pattern: /^traffic\s+classifier\s+\S+/i, depth: 0 },
    { pattern: /^traffic\s+behavior\s+\S+/i, depth: 0 },
    { pattern: /^traffic\s+policy\s+\S+/i, depth: 0 },

    // User and line configuration
    { pattern: /^user-interface\s+\S+/i, depth: 0 },
    { pattern: /^local-user\s+\S+/i, depth: 0 },

    // RADIUS and TACACS
    { pattern: /^radius-server\s+group\s+\S+/i, depth: 0 },
    { pattern: /^radius-server\s+template\s+\S+/i, depth: 0 },
    { pattern: /^hwtacacs-server\s+template\s+\S+/i, depth: 0 },

    // VPN and tunneling
    { pattern: /^ip\s+vpn-instance\s+\S+/i, depth: 0 },
    { pattern: /^ipsec\s+proposal\s+\S+/i, depth: 0 },
    { pattern: /^ipsec\s+policy\s+\S+/i, depth: 0 },
    { pattern: /^ike\s+proposal\s+\S+/i, depth: 0 },
    { pattern: /^ike\s+peer\s+\S+/i, depth: 0 },

    // SNMP configuration
    { pattern: /^snmp-agent$/i, depth: 0 },

    // NTP configuration
    { pattern: /^ntp-service$/i, depth: 0 },

    // SSH and SFTP
    { pattern: /^ssh\s+server$/i, depth: 0 },
    { pattern: /^sftp\s+server$/i, depth: 0 },

    // DHCP configuration
    { pattern: /^dhcp\s+enable$/i, depth: 0 },
    { pattern: /^ip\s+pool\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^qos$/i, depth: 0 },
    { pattern: /^qos\s+queue-profile\s+\S+/i, depth: 0 },
    { pattern: /^diffserv\s+domain\s+\S+/i, depth: 0 },

    // Multicast
    { pattern: /^multicast\s+routing-enable$/i, depth: 0 },
    { pattern: /^igmp-snooping$/i, depth: 0 },

    // Spanning Tree
    { pattern: /^stp$/i, depth: 0 },
    { pattern: /^stp\s+region-configuration$/i, depth: 0 },

    // Link aggregation
    { pattern: /^interface\s+Eth-Trunk\s*\d+/i, depth: 0 },

    // Port groups
    { pattern: /^port-group\s+\S+/i, depth: 0 },

    // Static routes (treated as blocks in some contexts)
    { pattern: /^ip\s+route-static\s+/i, depth: 0 },

    // Route policy
    { pattern: /^route-policy\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+ip-prefix\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+community-filter\s+/i, depth: 0 },
    { pattern: /^ip\s+as-path-filter\s+/i, depth: 0 },

    // NOTE: vrrp vrid is NOT a block starter - it's an interface-level command
    // Commands like "vrrp vrid 1 virtual-ip x.x.x.x" are children of interface blocks
    // Do NOT add vrrp vrid as a block starter here

    // BFD
    { pattern: /^bfd$/i, depth: 0 },

    // Netstream/Flow
    { pattern: /^netstream$/i, depth: 0 },
    { pattern: /^ip\s+netstream$/i, depth: 0 },

    // Stack configuration
    { pattern: /^stack$/i, depth: 0 },

    // LLDP
    { pattern: /^lldp$/i, depth: 0 },

    // ============ DEPTH 1: Inside protocol blocks ============

    // OSPF areas
    { pattern: /^area\s+[\d.]+/i, depth: 1 },

    // BGP address families
    { pattern: /^ipv4-family\s+\S+/i, depth: 1 },
    { pattern: /^ipv6-family\s+\S+/i, depth: 1 },
    { pattern: /^l2vpn-family\s+/i, depth: 1 },
    { pattern: /^vpls-family\s+/i, depth: 1 },

    // BGP peer groups
    { pattern: /^group\s+\S+/i, depth: 1 },

    // AAA schemes
    { pattern: /^authentication-scheme\s+\S+/i, depth: 1 },
    { pattern: /^authorization-scheme\s+\S+/i, depth: 1 },
    { pattern: /^accounting-scheme\s+\S+/i, depth: 1 },
    { pattern: /^domain\s+\S+/i, depth: 1 },
    { pattern: /^recording-scheme\s+\S+/i, depth: 1 },

    // ACL rules (numbered ACL depth)
    { pattern: /^rule\s+\d+/i, depth: 1 },

    // Route policy nodes
    { pattern: /^node\s+\d+/i, depth: 1 },

    // ============ DEPTH 2: Deeply nested blocks ============

    // VRF inside address-family
    { pattern: /^vpn-instance\s+\S+/i, depth: 2 },

    // Network inside OSPF area
    { pattern: /^network\s+[\d.]+/i, depth: 2 },
  ],

  blockEnders: [
    /^quit$/i,
    /^return$/i,
    // Exit from specific views
    /^q$/i,
  ],
};
