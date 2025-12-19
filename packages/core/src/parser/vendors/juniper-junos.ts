// packages/core/src/parser/vendors/juniper-junos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Juniper JunOS configuration schema.
 *
 * JunOS uses a hierarchical configuration model with curly braces { }
 * to define configuration blocks. This is fundamentally different from
 * Cisco's indentation-based approach.
 *
 * Key characteristics:
 * - Brace-based hierarchy: blocks are delimited by { }
 * - Set-style commands: "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24"
 * - Hierarchical display: indented with braces
 * - Comments: # for line comments, multi-line comments with markers
 * - Semicolons terminate statements
 *
 * Configuration structure:
 * ```
 * system {
 *     host-name router1;
 * }
 * interfaces {
 *     ge-0/0/0 {
 *         unit 0 {
 *             family inet {
 *                 address 10.0.0.1/24;
 *             }
 *         }
 *     }
 * }
 * ```
 */
export const JuniperJunOSSchema: VendorSchema = {
  id: 'juniper-junos',
  name: 'Juniper JunOS',
  useBraceHierarchy: true,

  commentPatterns: [
    /^#/,
    /^\/\*.*\*\/$/,
    /^inactive:/,
  ],
  sectionDelimiter: '}',

  blockStarters: [
    // ============ DEPTH 0: Top-level stanzas ============

    // System configuration
    { pattern: /^system\s*\{?$/i, depth: 0 },
    { pattern: /^version\s+/i, depth: 0 },

    // Chassis configuration
    { pattern: /^chassis\s*\{?$/i, depth: 0 },

    // Interfaces
    { pattern: /^interfaces\s*\{?$/i, depth: 0 },

    // SNMP
    { pattern: /^snmp\s*\{?$/i, depth: 0 },

    // Routing options (static routes, router-id, AS)
    { pattern: /^routing-options\s*\{?$/i, depth: 0 },

    // Protocols (BGP, OSPF, ISIS, MPLS, etc.)
    { pattern: /^protocols\s*\{?$/i, depth: 0 },

    // Policy options (prefix-lists, policy-statements, communities)
    { pattern: /^policy-options\s*\{?$/i, depth: 0 },

    // Class of Service (QoS)
    { pattern: /^class-of-service\s*\{?$/i, depth: 0 },

    // Firewall filters
    { pattern: /^firewall\s*\{?$/i, depth: 0 },

    // Security (SRX specific)
    { pattern: /^security\s*\{?$/i, depth: 0 },

    // Routing instances (VRF equivalent)
    { pattern: /^routing-instances\s*\{?$/i, depth: 0 },

    // VLANs (EX/QFX switches)
    { pattern: /^vlans\s*\{?$/i, depth: 0 },

    // Bridge domains (MX/EX)
    { pattern: /^bridge-domains\s*\{?$/i, depth: 0 },

    // Groups (configuration groups/templates)
    { pattern: /^groups\s*\{?$/i, depth: 0 },

    // Event options
    { pattern: /^event-options\s*\{?$/i, depth: 0 },

    // Services (NAT, stateful firewall, IDS)
    { pattern: /^services\s*\{?$/i, depth: 0 },

    // Access (802.1X, MAC authentication)
    { pattern: /^access\s*\{?$/i, depth: 0 },

    // Ethernet switching options
    { pattern: /^ethernet-switching-options\s*\{?$/i, depth: 0 },

    // Virtual chassis
    { pattern: /^virtual-chassis\s*\{?$/i, depth: 0 },

    // Forwarding options
    { pattern: /^forwarding-options\s*\{?$/i, depth: 0 },

    // Multi-chassis (MC-LAG)
    { pattern: /^multi-chassis\s*\{?$/i, depth: 0 },

    // ============ DEPTH 1: Inside top-level stanzas ============

    // Interface names (inside interfaces {})
    { pattern: /^(ge|xe|et|ae|lo|me|vme|irb|vlan|em|fxp|gr|lt|mt|ps|reth|st|vcp)-[\d\/:.]+\s*\{?$/i, depth: 1 },

    // Protocol definitions (inside protocols {})
    { pattern: /^bgp\s*\{?$/i, depth: 1 },
    { pattern: /^ospf\s*\{?$/i, depth: 1 },
    { pattern: /^ospf3\s*\{?$/i, depth: 1 },
    { pattern: /^isis\s*\{?$/i, depth: 1 },
    { pattern: /^ldp\s*\{?$/i, depth: 1 },
    { pattern: /^rsvp\s*\{?$/i, depth: 1 },
    { pattern: /^mpls\s*\{?$/i, depth: 1 },
    { pattern: /^pim\s*\{?$/i, depth: 1 },
    { pattern: /^igmp\s*\{?$/i, depth: 1 },
    { pattern: /^lldp\s*\{?$/i, depth: 1 },
    { pattern: /^lacp\s*\{?$/i, depth: 1 },
    { pattern: /^rstp\s*\{?$/i, depth: 1 },
    { pattern: /^mstp\s*\{?$/i, depth: 1 },
    { pattern: /^vstp\s*\{?$/i, depth: 1 },
    { pattern: /^evpn\s*\{?$/i, depth: 1 },
    { pattern: /^bfd\s*\{?$/i, depth: 1 },

    // Policy statements (inside policy-options {})
    { pattern: /^policy-statement\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^prefix-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^community\s+\S+\s*/i, depth: 1 },
    { pattern: /^as-path\s+\S+\s*/i, depth: 1 },
    { pattern: /^as-path-group\s+\S+\s*\{?$/i, depth: 1 },

    // Firewall filters (inside firewall {})
    { pattern: /^filter\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^policer\s+\S+\s*\{?$/i, depth: 1 },

    // Routing instances (inside routing-instances {})
    { pattern: /^[\w-]+\s*\{$/i, depth: 1 },

    // Security zones and policies (inside security {})
    { pattern: /^zones\s*\{?$/i, depth: 1 },
    { pattern: /^policies\s*\{?$/i, depth: 1 },
    { pattern: /^nat\s*\{?$/i, depth: 1 },
    { pattern: /^ike\s*\{?$/i, depth: 1 },
    { pattern: /^ipsec\s*\{?$/i, depth: 1 },
    { pattern: /^idp\s*\{?$/i, depth: 1 },
    { pattern: /^utm\s*\{?$/i, depth: 1 },
    { pattern: /^screen\s*\{?$/i, depth: 1 },

    // System components (inside system {})
    { pattern: /^login\s*\{?$/i, depth: 1 },
    { pattern: /^services\s*\{?$/i, depth: 1 },
    { pattern: /^syslog\s*\{?$/i, depth: 1 },
    { pattern: /^ntp\s*\{?$/i, depth: 1 },
    { pattern: /^authentication-order\s*/i, depth: 1 },
    { pattern: /^radius-server\s*\{?$/i, depth: 1 },
    { pattern: /^tacplus-server\s*\{?$/i, depth: 1 },
    { pattern: /^name-server\s*/i, depth: 1 },

    // ============ DEPTH 2: Nested inside depth-1 blocks ============

    // Interface units (inside interface {})
    { pattern: /^unit\s+\d+\s*\{?$/i, depth: 2 },

    // BGP groups (inside bgp {})
    { pattern: /^group\s+\S+\s*\{?$/i, depth: 2 },

    // OSPF/ISIS areas (inside ospf/isis {})
    { pattern: /^area\s+[\d.]+\s*\{?$/i, depth: 2 },
    { pattern: /^level\s+\d+\s*\{?$/i, depth: 2 },

    // Policy terms (inside policy-statement {})
    { pattern: /^term\s+\S+\s*\{?$/i, depth: 2 },

    // Filter terms (inside filter {})
    // Note: shares pattern with policy terms

    // Security zone definitions (inside zones {})
    { pattern: /^security-zone\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^functional-zone\s+\S+\s*\{?$/i, depth: 2 },

    // NAT rules (inside nat {})
    { pattern: /^source\s*\{?$/i, depth: 2 },
    { pattern: /^destination\s*\{?$/i, depth: 2 },
    { pattern: /^static\s*\{?$/i, depth: 2 },

    // ============ DEPTH 3: Deeply nested blocks ============

    // Address family (inside interface unit {})
    { pattern: /^family\s+(inet|inet6|mpls|ethernet-switching|ccc|vpls|bridge|iso)\s*\{?$/i, depth: 3 },

    // BGP neighbors (inside group {})
    { pattern: /^neighbor\s+[\d.:a-fA-F]+\s*\{?$/i, depth: 3 },

    // Policy from/then blocks (inside term {})
    { pattern: /^from\s*\{?$/i, depth: 3 },
    { pattern: /^then\s*\{?$/i, depth: 3 },
    { pattern: /^to\s*\{?$/i, depth: 3 },

    // OSPF interfaces (inside area {})
    { pattern: /^interface\s+\S+\s*\{?$/i, depth: 3 },

    // Rule sets (inside NAT source/destination {})
    { pattern: /^rule-set\s+\S+\s*\{?$/i, depth: 3 },

    // ============ DEPTH 4: Very deeply nested ============

    // Address entries (inside family inet {})
    { pattern: /^address\s+[\d.\/]+\s*\{?$/i, depth: 4 },

    // NAT rules (inside rule-set {})
    { pattern: /^rule\s+\S+\s*\{?$/i, depth: 4 },
  ],

  blockEnders: [
    /^\}$/,
    /^\}\s*$/,
  ],
};
