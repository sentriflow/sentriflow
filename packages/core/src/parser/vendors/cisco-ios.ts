// packages/core/src/parser/vendors/cisco-ios.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Cisco IOS/IOS-XE configuration schema.
 *
 * Cisco IOS uses indentation-based hierarchy with specific exit commands
 * for nested blocks like address-family. The '!' character serves as
 * both a comment marker and section delimiter.
 *
 * Configuration structure:
 * - Top-level: interface, router, vlan, access-list, etc.
 * - Nested: address-family inside router bgp/ospf
 * - Deeply nested: vrf inside address-family
 */
export const CiscoIOSSchema: VendorSchema = {
  id: 'cisco-ios',
  name: 'Cisco IOS/IOS-XE',
  useBraceHierarchy: false,

  commentPatterns: [/^!/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // Interface blocks
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // Routing protocol blocks
    { pattern: /^router\s+(?!router-id)\S+/i, depth: 0 },

    // VLAN and L2
    { pattern: /^vlan\s+\d+/i, depth: 0 },

    // ACL and Security
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^access-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^route-map\s+\S+/i, depth: 0 },
    { pattern: /^crypto\s+map\s+\S+/i, depth: 0 },
    { pattern: /^crypto\s+isakmp\s+\S+/i, depth: 0 },
    { pattern: /^crypto\s+ipsec\s+\S+/i, depth: 0 },
    { pattern: /^crypto\s+pki\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^class-map\s+\S+/i, depth: 0 },
    { pattern: /^policy-map\s+\S+/i, depth: 0 },

    // Line and management
    { pattern: /^line\s+(vty|console|aux)\s+\S+/i, depth: 0 },
    { pattern: /^line\s+\d+/i, depth: 0 },

    // Object groups (ASA/IOS)
    { pattern: /^object-group\s+\S+/i, depth: 0 },
    { pattern: /^object\s+\S+/i, depth: 0 },

    // AAA
    { pattern: /^aaa\s+group\s+server\s+\S+/i, depth: 0 },

    // Voice
    { pattern: /^dial-peer\s+voice\s+\S+/i, depth: 0 },
    { pattern: /^voice\s+register\s+\S+/i, depth: 0 },
    { pattern: /^telephony-service/i, depth: 0 },
    { pattern: /^ephone-dn\s+\S+/i, depth: 0 },
    { pattern: /^ephone\s+\S+/i, depth: 0 },

    // VRF
    { pattern: /^ip\s+vrf\s+\S+/i, depth: 0 },
    { pattern: /^vrf\s+definition\s+\S+/i, depth: 0 },

    // Other common blocks
    { pattern: /^key\s+chain\s+\S+/i, depth: 0 },
    { pattern: /^track\s+\d+/i, depth: 0 },
    { pattern: /^redundancy/i, depth: 0 },
    { pattern: /^controller\s+\S+/i, depth: 0 },
    { pattern: /^archive/i, depth: 0 },
    { pattern: /^ip\s+sla\s+\d+/i, depth: 0 },
    { pattern: /^tacacs\s+server\s+\S+/i, depth: 0 },
    { pattern: /^radius\s+server\s+\S+/i, depth: 0 },
    { pattern: /^snmp-server\s+view\s+\S+/i, depth: 0 },
    { pattern: /^banner\s+(motd|login|exec)/i, depth: 0 },
    { pattern: /^control-plane/i, depth: 0 },
    { pattern: /^ip\s+ips\s+signature-category/i, depth: 0 },

    // ============ DEPTH 1: Inside routing protocols ============

    { pattern: /^address-family\s+\S+/i, depth: 1 },
    { pattern: /^af-interface\s+\S+/i, depth: 1 },
    { pattern: /^topology\s+\S+/i, depth: 1 },
    { pattern: /^service-family\s+\S+/i, depth: 1 },
    { pattern: /^class\s+\S+/i, depth: 1 },
    { pattern: /^category\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Inside address-family ============

    { pattern: /^vrf\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit-address-family$/i,
    /^exit-af-interface$/i,
    /^exit-af-topology$/i,
    /^exit-service-family$/i,
    /^exit-sf-topology$/i,
    /^exit-vrf$/i,
    /^exit$/i,
  ],
};
