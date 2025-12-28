// packages/core/src/parser/vendors/cisco-nxos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Cisco NX-OS configuration schema.
 *
 * NX-OS (Nexus Operating System) is used on Cisco Nexus data center switches.
 * It shares similarities with IOS but has unique features:
 * - Feature-based activation (feature bgp, feature ospf)
 * - VDC (Virtual Device Context) support
 * - Different VRF syntax (vrf member vs ip vrf)
 * - Role-based CLI
 *
 * Configuration structure follows IOS patterns but with NX-OS extensions.
 */
export const CiscoNXOSSchema: VendorSchema = {
  id: 'cisco-nxos',
  name: 'Cisco NX-OS',
  useBraceHierarchy: false,

  commentPatterns: [/^!/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks (NX-OS specific) ============

    // NX-OS specific features
    { pattern: /^feature\s+\S+/i, depth: 0 },
    { pattern: /^vdc\s+\S+/i, depth: 0 },
    { pattern: /^install\s+feature-set\s+\S+/i, depth: 0 },

    // Port-channel and vPC (NX-OS specific)
    { pattern: /^vpc\s+domain\s+\d+/i, depth: 0 },

    // FabricPath (NX-OS specific)
    { pattern: /^fabricpath\s+domain\s+\S+/i, depth: 0 },

    // OTV (Overlay Transport Virtualization)
    { pattern: /^otv\s+site-identifier\s+\S+/i, depth: 0 },

    // Interface blocks (same as IOS)
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // Routing protocol blocks
    { pattern: /^router\s+(?!router-id)\S+/i, depth: 0 },

    // VLAN
    { pattern: /^vlan\s+\d+/i, depth: 0 },

    // ACL (NX-OS uses similar syntax)
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^mac\s+access-list\s+\S+/i, depth: 0 },

    // Route-map and prefix-list
    { pattern: /^route-map\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+prefix-list\s+\S+/i, depth: 0 },

    // QoS (NX-OS Modular QoS CLI)
    { pattern: /^class-map\s+\S+/i, depth: 0 },
    { pattern: /^policy-map\s+\S+/i, depth: 0 },

    // Line and management
    { pattern: /^line\s+(vty|console)\s+\S+/i, depth: 0 },

    // AAA
    { pattern: /^aaa\s+group\s+server\s+\S+/i, depth: 0 },

    // VRF definition (NX-OS style)
    { pattern: /^vrf\s+context\s+\S+/i, depth: 0 },

    // Zone-based firewall
    { pattern: /^zone\s+\S+/i, depth: 0 },

    // Control plane
    { pattern: /^control-plane/i, depth: 0 },

    // Spanning tree (MST configuration)
    { pattern: /^spanning-tree\s+mst\s+configuration/i, depth: 0 },

    // Role-based CLI
    { pattern: /^role\s+name\s+\S+/i, depth: 0 },

    // SNMP server
    { pattern: /^snmp-server\s+user\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Inside routing protocols ============

    { pattern: /^address-family\s+\S+/i, depth: 1 },
    { pattern: /^vrf\s+member\s+\S+/i, depth: 1 },
    // VRF sub-context inside router bgp (e.g., "vrf TENANT-A")
    // Uses negative lookahead (?!member\s) to avoid matching "vrf member X"
    // This removes the ordering dependency with the vrf member pattern above
    { pattern: /^vrf\s+(?!member\s)\S+/i, depth: 1 },
    { pattern: /^template\s+peer\s+\S+/i, depth: 1 },
    { pattern: /^neighbor\s+\S+/i, depth: 1 },
    { pattern: /^class\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Inside neighbor / address-family ============

    // address-family inside neighbor block
    { pattern: /^address-family\s+\S+/i, depth: 2 },

    // Inside policy-map class (QoS)
    { pattern: /^police\s+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit-address-family$/i,
    /^exit-vrf$/i,
    /^exit$/i,
  ],
};
