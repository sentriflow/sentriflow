// packages/core/src/parser/vendors/arista-eos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Arista EOS (Extensible Operating System) configuration schema.
 *
 * Arista EOS is heavily based on Cisco IOS-like syntax but includes
 * unique features and constructs specific to Arista switches:
 *
 * - **MLAG (Multi-Chassis Link Aggregation)**: peer-link, domain-id
 * - **VXLAN**: vxlan vni, vxlan flood vtep
 * - **eAPI**: management api http-commands
 * - **Daemon**: custom daemon configurations
 * - **Event-handler**: event-driven automation
 * - **CVX (CloudVision Exchange)**: CVX service integration
 * - **Traffic policies**: hardware counters, queuing
 *
 * Configuration structure:
 * - Uses indentation-based hierarchy (like Cisco IOS)
 * - '!' serves as comment marker and section delimiter
 * - exit/end commands to close blocks
 * - No braces for hierarchy
 *
 * Example config:
 * ```
 * hostname arista-leaf-01
 * !
 * interface Ethernet1
 *    description Uplink to Spine
 *    mtu 9214
 *    no switchport
 *    ip address 10.0.0.1/30
 * !
 * mlag configuration
 *    domain-id MLAG_DOMAIN
 *    local-interface Vlan4094
 *    peer-address 10.0.0.2
 *    peer-link Port-Channel1
 * !
 * ```
 */
export const AristaEOSSchema: VendorSchema = {
  id: 'arista-eos',
  name: 'Arista EOS',
  useBraceHierarchy: false,

  commentPatterns: [/^!/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // Interface blocks (all interface types)
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // Routing protocols
    { pattern: /^router\s+(?!router-id)\S+/i, depth: 0 },

    // VLAN configuration
    { pattern: /^vlan\s+\d+/i, depth: 0 },

    // ACL and Security
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^mac\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^route-map\s+\S+/i, depth: 0 },
    { pattern: /^as-path\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^community-list\s+\S+/i, depth: 0 },

    // QoS
    { pattern: /^class-map\s+\S+/i, depth: 0 },
    { pattern: /^policy-map\s+\S+/i, depth: 0 },
    { pattern: /^control-plane/i, depth: 0 },

    // Line and management
    { pattern: /^line\s+(vty|console)\s+\S+/i, depth: 0 },
    { pattern: /^line\s+\d+/i, depth: 0 },

    // AAA
    { pattern: /^aaa\s+\S+/i, depth: 0 },
    { pattern: /^tacacs-server\s+\S+/i, depth: 0 },
    { pattern: /^radius-server\s+\S+/i, depth: 0 },

    // VRF
    { pattern: /^vrf\s+instance\s+\S+/i, depth: 0 },
    { pattern: /^vrf\s+definition\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+routing\s+vrf\s+\S+/i, depth: 0 },

    // ============ Arista-specific top-level blocks ============

    // MLAG configuration
    { pattern: /^mlag\s+configuration/i, depth: 0 },

    // VXLAN configuration
    { pattern: /^interface\s+Vxlan\d*/i, depth: 0 },

    // Management API (eAPI)
    { pattern: /^management\s+api\s+\S+/i, depth: 0 },
    { pattern: /^management\s+ssh/i, depth: 0 },
    { pattern: /^management\s+telnet/i, depth: 0 },
    { pattern: /^management\s+security/i, depth: 0 },
    { pattern: /^management\s+console/i, depth: 0 },
    { pattern: /^management\s+cvx/i, depth: 0 },

    // Daemon configuration
    { pattern: /^daemon\s+\S+/i, depth: 0 },

    // Event handler
    { pattern: /^event-handler\s+\S+/i, depth: 0 },

    // CVX (CloudVision Exchange)
    { pattern: /^cvx/i, depth: 0 },

    // Spanning tree
    { pattern: /^spanning-tree\s+\S+/i, depth: 0 },

    // Port-channel
    { pattern: /^port-channel\s+\S+/i, depth: 0 },

    // Monitor session (SPAN)
    { pattern: /^monitor\s+session\s+\S+/i, depth: 0 },

    // Tap aggregation
    { pattern: /^tap\s+aggregation/i, depth: 0 },

    // Traffic policy
    { pattern: /^traffic-policy\s+\S+/i, depth: 0 },

    // Peer filter
    { pattern: /^peer-filter\s+\S+/i, depth: 0 },

    // Hardware counters
    { pattern: /^hardware\s+counter\s+\S+/i, depth: 0 },

    // Queue monitor
    { pattern: /^queue-monitor\s+\S+/i, depth: 0 },

    // SFlow
    { pattern: /^sflow\s+\S*/i, depth: 0 },

    // LLDP
    { pattern: /^lldp\s+\S*/i, depth: 0 },

    // BFD
    { pattern: /^bfd/i, depth: 0 },

    // PTP (Precision Time Protocol)
    { pattern: /^ptp/i, depth: 0 },

    // MPLS
    { pattern: /^mpls\s+\S+/i, depth: 0 },

    // IP virtual-router
    { pattern: /^ip\s+virtual-router\s+\S+/i, depth: 0 },

    // Multicast
    { pattern: /^ip\s+multicast-routing/i, depth: 0 },
    { pattern: /^ip\s+pim\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+igmp\s+snooping/i, depth: 0 },

    // EVPN
    { pattern: /^router\s+bgp\s+\d+/i, depth: 0 },

    // Loopback, SVI, Port-Channel interfaces
    { pattern: /^interface\s+Loopback\d+/i, depth: 0 },
    { pattern: /^interface\s+Vlan\d+/i, depth: 0 },
    { pattern: /^interface\s+Port-Channel\d+/i, depth: 0 },
    { pattern: /^interface\s+Management\d+/i, depth: 0 },

    // Other common blocks
    { pattern: /^key\s+chain\s+\S+/i, depth: 0 },
    { pattern: /^track\s+\d+/i, depth: 0 },
    { pattern: /^ip\s+sla\s+\d+/i, depth: 0 },
    { pattern: /^snmp-server\s+\S+/i, depth: 0 },
    { pattern: /^banner\s+(motd|login|exec)/i, depth: 0 },
    { pattern: /^logging\s+\S+/i, depth: 0 },
    { pattern: /^ntp\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Inside routing protocols ============

    { pattern: /^address-family\s+\S+/i, depth: 1 },
    { pattern: /^vrf\s+\S+/i, depth: 1 },
    { pattern: /^neighbor\s+\S+/i, depth: 1 },
    { pattern: /^network\s+\S+/i, depth: 1 },
    { pattern: /^class\s+\S+/i, depth: 1 },
    { pattern: /^redistribute\s+\S+/i, depth: 1 },

    // EVPN address family
    { pattern: /^address-family\s+evpn/i, depth: 1 },

    // ============ DEPTH 2: Inside address-family ============

    { pattern: /^neighbor\s+\S+\s+activate/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit-address-family$/i,
    /^exit-vrf$/i,
    /^exit$/i,
    /^end$/i,
  ],
};
