// packages/core/src/parser/vendors/nokia-sros.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Nokia SR OS (Service Router Operating System) configuration schema.
 *
 * Nokia SR OS uses a hierarchical command tree with indentation-based structure.
 * The CLI is organized with `configure` as the root for all configuration contexts.
 *
 * SR OS CLI Hierarchy:
 * - Root: A:router# - Initial CLI prompt
 * - Configure: A:router>config# - Configuration mode (enter via `configure`)
 * - Router: A:router>config>router# - IP routing configuration
 * - System: A:router>config>system# - System-level settings
 * - Port: A:router>config>port# - Physical port configuration
 * - Service: A:router>config>service# - Service configuration (VPLS, VPRN, etc.)
 *
 * Configuration structure:
 * - Top-level: configure, router, system, port, service, lag, etc.
 * - Nested: interface inside router, security inside system
 * - Deeply nested: bgp inside router, static-routes inside router
 *
 * Distinctive patterns:
 * - Port notation: slot/mda/port (e.g., 1/1/1, 1/2/3)
 * - Named interfaces: interface "name" or interface <name>
 * - admin-state for enable/disable (admin-state up, admin-state disable)
 * - exit to go back one level, exit all to return to root
 * - shutdown for disabling (in some contexts)
 * - # as comment character
 * - echo command for comments in config files
 *
 * Example configuration:
 * ```
 * configure
 *     system
 *         name "SR-Router-1"
 *         snmp
 *             admin-state enable
 *         exit
 *     exit
 *     router "Base"
 *         interface "to-peer1"
 *             address 10.0.0.1/30
 *             port 1/1/1
 *         exit
 *         bgp
 *             admin-state enable
 *             router-id 10.10.10.1
 *         exit
 *     exit
 *     port 1/1/1
 *         admin-state enable
 *         description "To-Peer1"
 *         ethernet
 *             mode network
 *         exit
 *     exit
 * exit
 * ```
 */
export const NokiaSROSSchema: VendorSchema = {
  id: 'nokia-sros',
  name: 'Nokia SR OS',
  useBraceHierarchy: false,

  // Comments in SR OS config files start with #
  // echo statements are also used as documentation
  commentPatterns: [/^#/, /^echo\s+".*"$/],
  sectionDelimiter: undefined,

  blockStarters: [
    // ============ DEPTH 0: Top-level configuration blocks ============

    // Main configuration context
    { pattern: /^configure$/i, depth: 0 },

    // System configuration
    { pattern: /^system$/i, depth: 0 },

    // Router configuration (Base or named VRF/VPRN)
    { pattern: /^router\s+"?[^"]*"?$/i, depth: 0 },
    { pattern: /^router$/i, depth: 0 },

    // Port configuration (physical ports)
    { pattern: /^port\s+\d+\/\d+\/\d+/i, depth: 0 },
    { pattern: /^port\s+\S+/i, depth: 0 },

    // LAG (Link Aggregation Group)
    { pattern: /^lag\s+\d+/i, depth: 0 },

    // Service configuration (VPLS, VPRN, Epipe, etc.)
    { pattern: /^service$/i, depth: 0 },

    // Card and MDA configuration
    { pattern: /^card\s+\d+/i, depth: 0 },

    // Log configuration
    { pattern: /^log$/i, depth: 0 },

    // Filter configuration (IP filters, MAC filters)
    { pattern: /^filter$/i, depth: 0 },

    // QoS configuration
    { pattern: /^qos$/i, depth: 0 },

    // Policy configuration (route policies)
    { pattern: /^policy-options$/i, depth: 0 },

    // MPLS configuration
    { pattern: /^mpls$/i, depth: 0 },

    // RSVP configuration
    { pattern: /^rsvp$/i, depth: 0 },

    // LDP configuration
    { pattern: /^ldp$/i, depth: 0 },

    // Multicast configuration
    { pattern: /^multicast$/i, depth: 0 },

    // ============ DEPTH 1: Inside configure or major blocks ============

    // System sub-blocks
    { pattern: /^name\s+"[^"]*"$/i, depth: 1 },
    { pattern: /^snmp$/i, depth: 1 },
    { pattern: /^security$/i, depth: 1 },
    { pattern: /^time$/i, depth: 1 },
    { pattern: /^login-control$/i, depth: 1 },
    { pattern: /^management-interface$/i, depth: 1 },
    { pattern: /^netconf$/i, depth: 1 },
    { pattern: /^grpc$/i, depth: 1 },
    { pattern: /^cpm-filter$/i, depth: 1 },
    { pattern: /^management-access-filter$/i, depth: 1 },
    { pattern: /^aaa$/i, depth: 1 },

    // Router sub-blocks (interfaces, protocols)
    { pattern: /^interface\s+"?[^"]*"?$/i, depth: 1 },
    { pattern: /^bgp$/i, depth: 1 },
    { pattern: /^ospf\s*\d*$/i, depth: 1 },
    { pattern: /^ospf3\s*\d*$/i, depth: 1 },
    { pattern: /^isis\s*\d*$/i, depth: 1 },
    { pattern: /^rip$/i, depth: 1 },
    { pattern: /^static-routes$/i, depth: 1 },
    { pattern: /^static-route-entry\s+/i, depth: 1 },
    { pattern: /^ecmp$/i, depth: 1 },
    { pattern: /^aggregation$/i, depth: 1 },

    // Port sub-blocks
    { pattern: /^ethernet$/i, depth: 1 },
    { pattern: /^network$/i, depth: 1 },
    { pattern: /^access$/i, depth: 1 },

    // Service types (VPLS, VPRN, Epipe, IES)
    { pattern: /^vpls\s+\d+/i, depth: 1 },
    { pattern: /^vprn\s+\d+/i, depth: 1 },
    { pattern: /^epipe\s+\d+/i, depth: 1 },
    { pattern: /^ies\s+\d+/i, depth: 1 },
    { pattern: /^customer\s+\d+/i, depth: 1 },

    // Card sub-blocks
    { pattern: /^mda\s+\d+/i, depth: 1 },

    // Log sub-blocks
    { pattern: /^log-id\s+\d+/i, depth: 1 },
    { pattern: /^syslog\s+\d+/i, depth: 1 },
    { pattern: /^snmp-trap-group\s+\d+/i, depth: 1 },
    { pattern: /^file-id\s+\d+/i, depth: 1 },

    // Filter sub-blocks
    { pattern: /^ip-filter\s*\d*/i, depth: 1 },
    { pattern: /^ipv6-filter\s*\d*/i, depth: 1 },
    { pattern: /^mac-filter\s*\d*/i, depth: 1 },

    // QoS sub-blocks
    { pattern: /^sap-ingress\s+\d+/i, depth: 1 },
    { pattern: /^sap-egress\s+\d+/i, depth: 1 },
    { pattern: /^network\s+\d+/i, depth: 1 },
    { pattern: /^scheduler-policy\s+"[^"]*"/i, depth: 1 },

    // Policy sub-blocks
    { pattern: /^prefix-list\s+"[^"]*"/i, depth: 1 },
    { pattern: /^community\s+"[^"]*"/i, depth: 1 },
    { pattern: /^as-path\s+"[^"]*"/i, depth: 1 },
    { pattern: /^policy-statement\s+"[^"]*"/i, depth: 1 },

    // ============ DEPTH 2: Deeply nested blocks ============

    // BGP groups and neighbors
    { pattern: /^group\s+"[^"]*"/i, depth: 2 },
    { pattern: /^neighbor\s+[\d.:a-fA-F]+/i, depth: 2 },

    // OSPF areas
    { pattern: /^area\s+[\d.]+/i, depth: 2 },

    // ISIS levels
    { pattern: /^level\s+\d+/i, depth: 2 },

    // Filter entries
    { pattern: /^entry\s+\d+/i, depth: 2 },

    // Service SAPs (Service Access Points)
    { pattern: /^sap\s+\S+/i, depth: 2 },

    // Service spoke-sdp and mesh-sdp
    { pattern: /^spoke-sdp\s+\d+:\d+/i, depth: 2 },
    { pattern: /^mesh-sdp\s+\d+:\d+/i, depth: 2 },

    // Policy entries
    { pattern: /^entry\s+\d+/i, depth: 2 },
    { pattern: /^default-action\s+/i, depth: 2 },

    // Interface sub-blocks in services
    { pattern: /^interface\s+"[^"]*"/i, depth: 2 },

    // QoS queue configuration
    { pattern: /^queue\s+\d+/i, depth: 2 },

    // ============ DEPTH 3: Very deeply nested ============

    // BGP family inside group
    { pattern: /^family\s+\S+/i, depth: 3 },

    // Address family configuration
    { pattern: /^address-family\s+\S+/i, depth: 3 },

    // Interface inside area (OSPF)
    { pattern: /^interface\s+"[^"]*"/i, depth: 3 },

    // Match and action in filters
    { pattern: /^match$/i, depth: 3 },
    { pattern: /^action$/i, depth: 3 },

    // From/to/action in policies
    { pattern: /^from$/i, depth: 3 },
    { pattern: /^to$/i, depth: 3 },

    // ============ DEPTH 4: Maximum nesting ============

    // Protocol settings inside address-family
    { pattern: /^unicast$/i, depth: 4 },
    { pattern: /^multicast$/i, depth: 4 },
  ],

  blockEnders: [
    /^exit$/i,
    /^exit\s+all$/i,
    // back command (alias for exit in some contexts)
    /^back$/i,
  ],
};
