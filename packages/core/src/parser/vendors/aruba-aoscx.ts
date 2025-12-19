// packages/core/src/parser/vendors/aruba-aoscx.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Aruba AOS-CX configuration schema.
 *
 * AOS-CX is used on modern Aruba CX series switches (6100, 6200, 6300, 8xxx).
 * It uses a Cisco-like indent-based hierarchy with '!' as comment/delimiter.
 *
 * Key characteristics:
 * - Interface naming: slot/member/port format (e.g., 1/1/1, 1/1/2)
 * - VLAN interfaces: interface vlan 100
 * - LAGs: interface lag 100
 * - Port configuration: vlan access/trunk commands under interface
 *
 * Configuration structure:
 * - Top-level: interface, vlan, router, vrf, access-list, etc.
 * - Nested: address-family inside router protocols
 */
export const ArubaAOSCXSchema: VendorSchema = {
  id: 'aruba-aoscx',
  name: 'Aruba AOS-CX',
  useBraceHierarchy: false,

  commentPatterns: [/^!/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // Physical interfaces (slot/member/port format)
    { pattern: /^interface\s+\d+\/\d+\/\d+/i, depth: 0 },

    // VLAN interfaces
    { pattern: /^interface\s+vlan\s*\d+/i, depth: 0 },

    // LAG interfaces
    { pattern: /^interface\s+lag\s*\d+/i, depth: 0 },

    // Loopback interfaces
    { pattern: /^interface\s+loopback\s*\d+/i, depth: 0 },

    // Management interface
    { pattern: /^interface\s+mgmt/i, depth: 0 },

    // VLAN definitions
    { pattern: /^vlan\s+\d+/i, depth: 0 },

    // VRF definitions
    { pattern: /^vrf\s+\S+/i, depth: 0 },

    // Routing protocols
    { pattern: /^router\s+ospf\s+\d+/i, depth: 0 },
    { pattern: /^router\s+ospfv3\s+\d+/i, depth: 0 },
    { pattern: /^router\s+bgp\s+\d+/i, depth: 0 },

    // Access lists and prefix lists
    { pattern: /^access-list\s+ip\s+\S+/i, depth: 0 },
    { pattern: /^access-list\s+ipv6\s+\S+/i, depth: 0 },
    { pattern: /^access-list\s+mac\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },

    // Route maps
    { pattern: /^route-map\s+\S+/i, depth: 0 },

    // AAA configuration
    { pattern: /^aaa\s+authentication\s+\S+/i, depth: 0 },
    { pattern: /^aaa\s+authorization\s+\S+/i, depth: 0 },
    { pattern: /^aaa\s+accounting\s+\S+/i, depth: 0 },
    { pattern: /^aaa\s+group\s+server\s+\S+/i, depth: 0 },

    // RADIUS/TACACS+
    { pattern: /^radius-server\s+host\s+\S+/i, depth: 0 },
    { pattern: /^tacacs-server\s+host\s+\S+/i, depth: 0 },

    // SNMP
    { pattern: /^snmp-server\s+\S+/i, depth: 0 },

    // Spanning tree
    { pattern: /^spanning-tree\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^qos\s+\S+/i, depth: 0 },
    { pattern: /^class\s+\S+/i, depth: 0 },
    { pattern: /^policy\s+\S+/i, depth: 0 },

    // VSX (Virtual Switching Extension)
    { pattern: /^vsx\s*$/i, depth: 0 },
    { pattern: /^vsx-sync\s+\S+/i, depth: 0 },

    // User accounts
    { pattern: /^user\s+\S+/i, depth: 0 },

    // SSH configuration
    { pattern: /^ssh\s+\S+/i, depth: 0 },

    // NTP
    { pattern: /^ntp\s+\S+/i, depth: 0 },

    // Logging
    { pattern: /^logging\s+\S+/i, depth: 0 },

    // DHCP
    { pattern: /^dhcp-server\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Inside routing protocols ============

    { pattern: /^address-family\s+\S+/i, depth: 1 },
    { pattern: /^area\s+\S+/i, depth: 1 },
    { pattern: /^neighbor\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Inside address-family ============

    { pattern: /^vrf\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit-address-family$/i,
    /^exit-vrf$/i,
    /^exit$/i,
  ],
};
