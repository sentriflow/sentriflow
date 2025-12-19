// packages/core/src/parser/vendors/aruba-aosswitch.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Aruba AOS-Switch (ProVision) configuration schema.
 *
 * AOS-Switch is used on legacy ProCurve/Aruba switches (2530, 2930, 3810, etc.).
 * It uses a VLAN-centric configuration model where ports are assigned to VLANs
 * rather than VLANs being assigned to ports.
 *
 * Key characteristics:
 * - VLAN-centric: VLANs contain port lists with tagged/untagged designations
 * - Port ranges: 1-24, 25-48, A1-A24 (for stacking)
 * - Trunks: LAG configuration using 'trunk' command
 * - Comments: Both ';' and '!' can be comments
 *
 * Configuration structure:
 * - VLANs are the primary configuration unit
 * - Ports are referenced within VLAN definitions
 * - Less hierarchical than Cisco/AOS-CX
 */
export const ArubaAOSSwitchSchema: VendorSchema = {
  id: 'aruba-aosswitch',
  name: 'Aruba AOS-Switch (ProVision)',
  useBraceHierarchy: false,

  commentPatterns: [/^;/, /^!/],
  sectionDelimiter: undefined, // Uses 'exit' to end blocks

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // VLAN definitions (primary configuration unit)
    { pattern: /^vlan\s+\d+/i, depth: 0 },

    // Interface configuration (less common, but supported)
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // Trunk (LAG) configuration
    { pattern: /^trunk\s+\S+/i, depth: 0 },

    // Spanning tree configuration
    { pattern: /^spanning-tree\s+\S+/i, depth: 0 },

    // Routing protocols
    { pattern: /^router\s+ospf\s*\d*/i, depth: 0 },
    { pattern: /^router\s+rip/i, depth: 0 },

    // IP routing
    { pattern: /^ip\s+route\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+routing/i, depth: 0 },

    // RADIUS/TACACS+ servers
    { pattern: /^radius-server\s+\S+/i, depth: 0 },
    { pattern: /^tacacs-server\s+\S+/i, depth: 0 },

    // AAA configuration
    { pattern: /^aaa\s+\S+/i, depth: 0 },

    // Port access (802.1X)
    { pattern: /^aaa\s+port-access\s+\S+/i, depth: 0 },

    // SNMP configuration
    { pattern: /^snmp-server\s+\S+/i, depth: 0 },

    // Console configuration
    { pattern: /^console\s+\S+/i, depth: 0 },

    // Telnet/SSH configuration
    { pattern: /^telnet-server\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+ssh\s*$/i, depth: 0 },

    // Time/NTP configuration
    { pattern: /^timesync\s+\S+/i, depth: 0 },
    { pattern: /^sntp\s+\S+/i, depth: 0 },

    // Logging configuration
    { pattern: /^logging\s+\S+/i, depth: 0 },

    // Manager/Operator passwords
    { pattern: /^password\s+\S+/i, depth: 0 },

    // Access control lists
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },

    // IGMP/Multicast
    { pattern: /^igmp\s+\S+/i, depth: 0 },

    // LLDP
    { pattern: /^lldp\s+\S+/i, depth: 0 },

    // Loop protection
    { pattern: /^loop-protect\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^qos\s+\S+/i, depth: 0 },

    // DHCP snooping
    { pattern: /^dhcp-snooping\s*$/i, depth: 0 },

    // Banner
    { pattern: /^banner\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Nested blocks (rare in AOS-Switch) ============

    { pattern: /^area\s+\S+/i, depth: 1 },
  ],

  blockEnders: [
    /^exit$/i,
  ],
};
