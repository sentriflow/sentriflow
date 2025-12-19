// packages/core/src/parser/vendors/extreme-exos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Extreme Networks ExtremeXOS (EXOS) configuration schema.
 *
 * ExtremeXOS uses a flat, command-based configuration syntax where
 * each configuration command is a standalone line. Unlike Cisco-style
 * configs, EXOS uses explicit command keywords (create, configure,
 * enable, disable) rather than indentation-based hierarchy.
 *
 * Key characteristics:
 * - **Flat structure**: Most commands are standalone (create vlan, configure vlan)
 * - **Explicit actions**: Commands start with verbs (create, configure, enable, disable)
 * - **VLAN-centric**: VLANs are named objects, not just numbers
 * - **Port notation**: Uses slot:port format (e.g., 1:1, 2:24)
 * - **Comments**: Lines starting with # are comments
 *
 * Configuration structure:
 * - No true nested blocks (unlike Cisco interface mode)
 * - VLANs, ports, protocols configured with explicit commands
 * - ACLs defined separately and applied to VLANs/ports
 *
 * Example config:
 * ```
 * # Basic EXOS configuration
 * configure snmp sysname "exos-switch-01"
 * create vlan "Management" tag 10
 * configure vlan Management ipaddress 10.0.10.1/24
 * configure vlan Management add ports 1:1-1:4 untagged
 * enable vlan Management
 * enable sharing 1:1 grouping 1:1-1:2 algorithm address-based L3_L4
 * configure sntp-client primary server 10.0.0.1 vr VR-Default
 * enable sntp-client
 * ```
 */
export const ExtremeEXOSSchema: VendorSchema = {
  id: 'extreme-exos',
  name: 'Extreme Networks EXOS',
  useBraceHierarchy: false,

  commentPatterns: [/^#/],
  sectionDelimiter: undefined, // EXOS doesn't use section delimiters

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============
    // EXOS is mostly flat, but some constructs can be treated as logical sections

    // VLAN configuration (virtual block based on VLAN name)
    // Note: These are conceptual groupings, not actual block syntax
    { pattern: /^create\s+vlan\s+/i, depth: 0 },

    // Access-list/ACL (can be multi-line with continuation)
    { pattern: /^create\s+access-list\s+/i, depth: 0 },
    { pattern: /^configure\s+access-list\s+/i, depth: 0 },

    // Policy configuration
    { pattern: /^create\s+policy\s+/i, depth: 0 },
    { pattern: /^configure\s+policy\s+/i, depth: 0 },

    // Routing protocols
    { pattern: /^configure\s+ospf\s+/i, depth: 0 },
    { pattern: /^configure\s+ospfv3\s+/i, depth: 0 },
    { pattern: /^configure\s+bgp\s+/i, depth: 0 },
    { pattern: /^configure\s+rip\s+/i, depth: 0 },
    { pattern: /^configure\s+ripng\s+/i, depth: 0 },
    { pattern: /^configure\s+isis\s+/i, depth: 0 },
    { pattern: /^configure\s+pim\s+/i, depth: 0 },
    { pattern: /^configure\s+igmp\s+/i, depth: 0 },
    { pattern: /^configure\s+mld\s+/i, depth: 0 },

    // Virtual router (VR) configuration
    { pattern: /^create\s+vr\s+/i, depth: 0 },
    { pattern: /^configure\s+vr\s+/i, depth: 0 },

    // LAG/Sharing groups
    { pattern: /^enable\s+sharing\s+/i, depth: 0 },

    // Stacking
    { pattern: /^enable\s+stacking\s+/i, depth: 0 },
    { pattern: /^configure\s+stacking\s+/i, depth: 0 },

    // EAPS (Ethernet Automatic Protection Switching)
    { pattern: /^create\s+eaps\s+/i, depth: 0 },
    { pattern: /^configure\s+eaps\s+/i, depth: 0 },

    // STP configuration
    { pattern: /^configure\s+stp\s+/i, depth: 0 },
    { pattern: /^configure\s+stpd\s+/i, depth: 0 },

    // QoS
    { pattern: /^create\s+qosprofile\s+/i, depth: 0 },
    { pattern: /^configure\s+qosprofile\s+/i, depth: 0 },

    // MLAG/MLAG (Multi-chassis LAG)
    { pattern: /^create\s+mlag\s+peer\s+/i, depth: 0 },
    { pattern: /^configure\s+mlag\s+peer\s+/i, depth: 0 },

    // SNMP configuration
    { pattern: /^configure\s+snmp\s+/i, depth: 0 },
    { pattern: /^configure\s+snmpv3\s+/i, depth: 0 },

    // AAA/RADIUS/TACACS
    { pattern: /^configure\s+radius\s+/i, depth: 0 },
    { pattern: /^configure\s+tacacs\s+/i, depth: 0 },
    { pattern: /^configure\s+aaa\s+/i, depth: 0 },

    // Management
    { pattern: /^configure\s+management\s+/i, depth: 0 },
    { pattern: /^configure\s+ssh2\s+/i, depth: 0 },
    { pattern: /^configure\s+telnet\s+/i, depth: 0 },

    // SNTP/NTP
    { pattern: /^configure\s+sntp-client\s+/i, depth: 0 },
    { pattern: /^configure\s+ntp\s+/i, depth: 0 },

    // Syslog
    { pattern: /^configure\s+syslog\s+/i, depth: 0 },
    { pattern: /^configure\s+log\s+/i, depth: 0 },

    // Port mirroring
    { pattern: /^create\s+mirror\s+/i, depth: 0 },
    { pattern: /^configure\s+mirror\s+/i, depth: 0 },

    // VLAN stacking (QinQ)
    { pattern: /^configure\s+vlan\s+\S+\s+add\s+ports\s+/i, depth: 0 },

    // VPLS
    { pattern: /^create\s+vpls\s+/i, depth: 0 },
    { pattern: /^configure\s+vpls\s+/i, depth: 0 },

    // MPLS
    { pattern: /^configure\s+mpls\s+/i, depth: 0 },

    // Port configuration
    { pattern: /^configure\s+ports?\s+\S+/i, depth: 0 },

    // VLAN IP address configuration
    { pattern: /^configure\s+vlan\s+\S+\s+ipaddress\s+/i, depth: 0 },

    // ============ DEPTH 1: Inside conceptual blocks ============
    // EXOS doesn't really have nested syntax, but some ACL/policy rules
    // can span multiple lines with entry numbers

    { pattern: /^entry\s+\d+\s+/i, depth: 1 },
  ],

  blockEnders: [
    // EXOS doesn't have block enders in the traditional sense
    // Commands are standalone
    // Including these for compatibility with the parser
  ],
};
