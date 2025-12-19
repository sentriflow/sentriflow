// packages/core/src/parser/vendors/extreme-voss.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Extreme Networks VOSS (VSP Operating System Software) configuration schema.
 *
 * VOSS is used on Extreme Networks VSP (Virtual Services Platform) switches.
 * It uses a Cisco-like CLI syntax with indentation-based hierarchy and
 * multiple command modes (User EXEC, Privileged EXEC, Global Configuration,
 * Interface Configuration, etc.).
 *
 * Key characteristics:
 * - **Mode-based**: Similar to Cisco IOS with different CLI modes
 * - **Indentation-based hierarchy**: Nested configuration under blocks
 * - **Interface naming**: Uses GigabitEthernet slot/port (e.g., 1/1, 1/2)
 * - **Comments**: Lines starting with # or ! are comments
 * - **VLAN creation**: vlan create <id> type port-mstprstp <instance>
 * - **SPB/SPBM**: Shortest Path Bridging support
 *
 * Configuration structure:
 * - Global Configuration: configure terminal
 * - Interface mode: interface GigabitEthernet 1/1
 * - VLAN mode: vlan create, vlan members
 * - Router mode: router isis, router bgp
 *
 * Example config:
 * ```
 * !
 * ! VOSS Configuration
 * !
 * snmp-server name "vsp-switch-01"
 * !
 * vlan create 10 type port-mstprstp 0
 * vlan create 20 type port-mstprstp 0
 * vlan members 10 1/1-1/4 portmember
 * !
 * interface GigabitEthernet 1/1
 *    no shutdown
 *    default-vlan-id 10
 * exit
 * !
 * router isis
 *    spbm 1 b-vid 4051-4052 primary 4051
 *    no shutdown
 * exit
 * !
 * ```
 */
export const ExtremeVOSSSchema: VendorSchema = {
  id: 'extreme-voss',
  name: 'Extreme Networks VOSS',
  useBraceHierarchy: false,

  commentPatterns: [/^!/, /^#/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // Interface blocks
    { pattern: /^interface\s+GigabitEthernet\s+\S+/i, depth: 0 },
    { pattern: /^interface\s+Port-Channel\s+\S+/i, depth: 0 },
    { pattern: /^interface\s+Loopback\s+\S+/i, depth: 0 },
    { pattern: /^interface\s+Vlan\s+\d+/i, depth: 0 },
    { pattern: /^interface\s+mgmtEthernet\s+\S+/i, depth: 0 },
    { pattern: /^interface\s+mlt\s+\d+/i, depth: 0 },

    // Routing protocols
    { pattern: /^router\s+isis/i, depth: 0 },
    { pattern: /^router\s+bgp\s+\d+/i, depth: 0 },
    { pattern: /^router\s+ospf/i, depth: 0 },
    { pattern: /^router\s+rip/i, depth: 0 },
    { pattern: /^router\s+vrf\s+\S+/i, depth: 0 },

    // VLAN configuration
    { pattern: /^vlan\s+create\s+\d+/i, depth: 0 },
    { pattern: /^vlan\s+i-sid\s+\d+/i, depth: 0 },
    { pattern: /^vlan\s+members\s+\d+/i, depth: 0 },

    // MLT (Multi-Link Trunking)
    { pattern: /^mlt\s+\d+/i, depth: 0 },

    // LACP
    { pattern: /^lacp\s+\S+/i, depth: 0 },

    // SPBM (Shortest Path Bridging MAC)
    { pattern: /^spbm\s+\d+/i, depth: 0 },

    // I-SID (Instance Service ID)
    { pattern: /^i-sid\s+\d+/i, depth: 0 },

    // IP routing
    { pattern: /^ip\s+route\s+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+route-map\s+\S+/i, depth: 0 },

    // AAA and Security
    { pattern: /^aaa\s+\S+/i, depth: 0 },
    { pattern: /^radius\s+server\s+\S+/i, depth: 0 },
    { pattern: /^tacacs\s+server\s+\S+/i, depth: 0 },

    // ACLs
    { pattern: /^filter\s+acl\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+access-list\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^qos\s+\S+/i, depth: 0 },

    // Spanning Tree
    { pattern: /^spanning-tree\s+\S+/i, depth: 0 },

    // SNMP
    { pattern: /^snmp-server\s+\S+/i, depth: 0 },

    // NTP
    { pattern: /^ntp\s+server\s+/i, depth: 0 },

    // Logging
    { pattern: /^logging\s+\S+/i, depth: 0 },

    // SSH/Telnet
    { pattern: /^ssh\s+\S+/i, depth: 0 },

    // System
    { pattern: /^sys\s+\S+/i, depth: 0 },
    { pattern: /^boot\s+\S+/i, depth: 0 },

    // Fabric Connect/DVR
    { pattern: /^dvr\s+\S+/i, depth: 0 },
    { pattern: /^cfm\s+\S+/i, depth: 0 },

    // VRRP
    { pattern: /^ip\s+vrrp\s+\S+/i, depth: 0 },

    // Line/Console
    { pattern: /^line\s+\S+/i, depth: 0 },

    // LLDP
    { pattern: /^lldp\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Inside blocks ============

    // Address family inside BGP
    { pattern: /^address-family\s+\S+/i, depth: 1 },

    // Area inside OSPF/ISIS
    { pattern: /^area\s+\S+/i, depth: 1 },

    // SPBM config inside ISIS
    { pattern: /^spbm\s+\d+/i, depth: 1 },

    // Neighbor inside BGP
    { pattern: /^neighbor\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Deeper nesting ============

    { pattern: /^redistribute\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit$/i,
    /^end$/i,
    /^back$/i,
  ],
};
