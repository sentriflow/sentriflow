// packages/core/src/parser/vendors/paloalto-panos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Palo Alto PAN-OS configuration schema.
 *
 * PAN-OS uses a hierarchical configuration model that can be viewed in multiple formats:
 * 1. XML format (native storage format)
 * 2. Set command format (CLI style, similar to JunOS)
 * 3. Hierarchical CLI format (indentation/brace based)
 *
 * This schema primarily targets the hierarchical CLI format and set command format.
 *
 * Key characteristics:
 * - Hierarchical structure with brace-based blocks in display mode
 * - Set commands: "set deviceconfig system hostname firewall1"
 * - Network zones, security policies, NAT rules
 * - Object-based configuration (address objects, service objects)
 * - Panorama-specific constructs (device-groups, templates)
 *
 * Configuration structure (hierarchical format):
 * ```
 * deviceconfig {
 *     system {
 *         hostname firewall1;
 *     }
 * }
 * network {
 *     interface {
 *         ethernet {
 *             ethernet1/1 {
 *                 layer3 {
 *                     ip {
 *                         10.0.0.1/24;
 *                     }
 *                 }
 *             }
 *         }
 *     }
 * }
 * ```
 *
 * Set command format:
 * ```
 * set deviceconfig system hostname firewall1
 * set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24
 * set rulebase security rules allow-web from trust to untrust application web-browsing action allow
 * ```
 */
export const PaloAltoPANOSSchema: VendorSchema = {
  id: 'paloalto-panos',
  name: 'Palo Alto PAN-OS',
  useBraceHierarchy: true,

  commentPatterns: [
    /^#/,                    // Hash comments (set command format)
    /^\/\//,                 // Double-slash comments
    /^\/\*.*\*\/$/,          // Block comments
    /^!.*$/,                 // Exclamation comments (some CLI modes)
  ],
  sectionDelimiter: '}',

  blockStarters: [
    // ============ DEPTH 0: Top-level configuration stanzas ============

    // Device configuration (system settings, management)
    { pattern: /^deviceconfig\s*\{?$/i, depth: 0 },

    // Network configuration (interfaces, zones, routing)
    { pattern: /^network\s*\{?$/i, depth: 0 },

    // Objects (address, service, application groups)
    { pattern: /^address\s*\{?$/i, depth: 0 },
    { pattern: /^address-group\s*\{?$/i, depth: 0 },
    { pattern: /^service\s*\{?$/i, depth: 0 },
    { pattern: /^service-group\s*\{?$/i, depth: 0 },
    { pattern: /^application\s*\{?$/i, depth: 0 },
    { pattern: /^application-group\s*\{?$/i, depth: 0 },
    { pattern: /^application-filter\s*\{?$/i, depth: 0 },

    // Security rulebase (policies)
    { pattern: /^rulebase\s*\{?$/i, depth: 0 },

    // Zone configuration
    { pattern: /^zone\s*\{?$/i, depth: 0 },

    // Shared objects (Panorama)
    { pattern: /^shared\s*\{?$/i, depth: 0 },

    // Device groups (Panorama)
    { pattern: /^device-group\s*\{?$/i, depth: 0 },

    // Templates (Panorama)
    { pattern: /^template\s*\{?$/i, depth: 0 },
    { pattern: /^template-stack\s*\{?$/i, depth: 0 },

    // Profiles (security, logging, etc.)
    { pattern: /^profiles\s*\{?$/i, depth: 0 },

    // Log settings
    { pattern: /^log-settings\s*\{?$/i, depth: 0 },

    // User-ID
    { pattern: /^user-identification\s*\{?$/i, depth: 0 },
    { pattern: /^user-id-agent\s*\{?$/i, depth: 0 },

    // GlobalProtect
    { pattern: /^global-protect\s*\{?$/i, depth: 0 },

    // High availability
    { pattern: /^high-availability\s*\{?$/i, depth: 0 },

    // VSYS (virtual system)
    { pattern: /^vsys\s*\{?$/i, depth: 0 },
    { pattern: /^vsys\d+\s*\{?$/i, depth: 0 },

    // Mgt-config (management configuration)
    { pattern: /^mgt-config\s*\{?$/i, depth: 0 },

    // Set command format (flat configuration)
    { pattern: /^set\s+deviceconfig\s+/i, depth: 0 },
    { pattern: /^set\s+network\s+/i, depth: 0 },
    { pattern: /^set\s+rulebase\s+/i, depth: 0 },
    { pattern: /^set\s+address\s+/i, depth: 0 },
    { pattern: /^set\s+service\s+/i, depth: 0 },
    { pattern: /^set\s+zone\s+/i, depth: 0 },

    // ============ DEPTH 1: Inside top-level stanzas ============

    // Inside deviceconfig
    { pattern: /^system\s*\{?$/i, depth: 1 },
    { pattern: /^setting\s*\{?$/i, depth: 1 },
    { pattern: /^management\s*\{?$/i, depth: 1 },
    { pattern: /^high-availability\s*\{?$/i, depth: 1 },

    // Inside network
    { pattern: /^interface\s*\{?$/i, depth: 1 },
    { pattern: /^virtual-router\s*\{?$/i, depth: 1 },
    { pattern: /^virtual-wire\s*\{?$/i, depth: 1 },
    { pattern: /^vlan\s*\{?$/i, depth: 1 },
    { pattern: /^ike\s*\{?$/i, depth: 1 },
    { pattern: /^ipsec\s*\{?$/i, depth: 1 },
    { pattern: /^tunnel\s*\{?$/i, depth: 1 },
    { pattern: /^qos\s*\{?$/i, depth: 1 },
    { pattern: /^dns-proxy\s*\{?$/i, depth: 1 },
    { pattern: /^dhcp\s*\{?$/i, depth: 1 },

    // Inside rulebase
    { pattern: /^security\s*\{?$/i, depth: 1 },
    { pattern: /^nat\s*\{?$/i, depth: 1 },
    { pattern: /^pbf\s*\{?$/i, depth: 1 },               // Policy-based forwarding
    { pattern: /^qos\s*\{?$/i, depth: 1 },
    { pattern: /^decryption\s*\{?$/i, depth: 1 },
    { pattern: /^tunnel-inspect\s*\{?$/i, depth: 1 },
    { pattern: /^application-override\s*\{?$/i, depth: 1 },
    { pattern: /^authentication\s*\{?$/i, depth: 1 },
    { pattern: /^dos\s*\{?$/i, depth: 1 },

    // Inside profiles
    { pattern: /^virus\s*\{?$/i, depth: 1 },
    { pattern: /^spyware\s*\{?$/i, depth: 1 },
    { pattern: /^vulnerability\s*\{?$/i, depth: 1 },
    { pattern: /^url-filtering\s*\{?$/i, depth: 1 },
    { pattern: /^file-blocking\s*\{?$/i, depth: 1 },
    { pattern: /^wildfire-analysis\s*\{?$/i, depth: 1 },
    { pattern: /^data-filtering\s*\{?$/i, depth: 1 },
    { pattern: /^dos-protection\s*\{?$/i, depth: 1 },
    { pattern: /^decryption\s*\{?$/i, depth: 1 },
    { pattern: /^gtp\s*\{?$/i, depth: 1 },
    { pattern: /^sctp\s*\{?$/i, depth: 1 },

    // Zone definitions (inside zone)
    { pattern: /^\S+\s*\{$/i, depth: 1 },  // Named zones like "trust {", "untrust {"

    // ============ DEPTH 2: Nested inside depth-1 blocks ============

    // Interface types (inside interface)
    { pattern: /^ethernet\s*\{?$/i, depth: 2 },
    { pattern: /^loopback\s*\{?$/i, depth: 2 },
    { pattern: /^tunnel\s*\{?$/i, depth: 2 },
    { pattern: /^aggregate-ethernet\s*\{?$/i, depth: 2 },
    { pattern: /^vlan\s*\{?$/i, depth: 2 },

    // Virtual router components
    { pattern: /^routing-table\s*\{?$/i, depth: 2 },
    { pattern: /^protocol\s*\{?$/i, depth: 2 },
    { pattern: /^ecmp\s*\{?$/i, depth: 2 },
    { pattern: /^multicast\s*\{?$/i, depth: 2 },

    // Rules container
    { pattern: /^rules\s*\{?$/i, depth: 2 },

    // Pre/Post rules (Panorama)
    { pattern: /^pre-rulebase\s*\{?$/i, depth: 2 },
    { pattern: /^post-rulebase\s*\{?$/i, depth: 2 },

    // IKE/IPsec components
    { pattern: /^gateway\s*\{?$/i, depth: 2 },
    { pattern: /^crypto-profiles\s*\{?$/i, depth: 2 },

    // ============ DEPTH 3: Deeply nested blocks ============

    // Specific interface (e.g., ethernet1/1)
    { pattern: /^ethernet\d+\/\d+\s*\{?$/i, depth: 3 },
    { pattern: /^ae\d+\s*\{?$/i, depth: 3 },            // Aggregate interface
    { pattern: /^loopback\.\d+\s*\{?$/i, depth: 3 },
    { pattern: /^tunnel\.\d+\s*\{?$/i, depth: 3 },

    // Individual rules (inside rules)
    { pattern: /^[\w-]+\s*\{$/i, depth: 3 },  // Named rules

    // Routing protocols (inside protocol)
    { pattern: /^bgp\s*\{?$/i, depth: 3 },
    { pattern: /^ospf\s*\{?$/i, depth: 3 },
    { pattern: /^ospfv3\s*\{?$/i, depth: 3 },
    { pattern: /^rip\s*\{?$/i, depth: 3 },
    { pattern: /^static-route\s*\{?$/i, depth: 3 },
    { pattern: /^redist-profile\s*\{?$/i, depth: 3 },

    // Crypto profiles types
    { pattern: /^ike-crypto-profiles\s*\{?$/i, depth: 3 },
    { pattern: /^ipsec-crypto-profiles\s*\{?$/i, depth: 3 },
    { pattern: /^global-protect-app-crypto-profiles\s*\{?$/i, depth: 3 },

    // ============ DEPTH 4: Very deeply nested ============

    // Interface mode configuration
    { pattern: /^layer3\s*\{?$/i, depth: 4 },
    { pattern: /^layer2\s*\{?$/i, depth: 4 },
    { pattern: /^virtual-wire\s*\{?$/i, depth: 4 },
    { pattern: /^tap\s*\{?$/i, depth: 4 },
    { pattern: /^ha\s*\{?$/i, depth: 4 },

    // BGP components
    { pattern: /^peer-group\s*\{?$/i, depth: 4 },
    { pattern: /^dampening-profile\s*\{?$/i, depth: 4 },
    { pattern: /^auth-profile\s*\{?$/i, depth: 4 },

    // OSPF areas
    { pattern: /^area\s*\{?$/i, depth: 4 },

    // ============ DEPTH 5: Deepest nesting ============

    // IP configuration (inside layer3)
    { pattern: /^ip\s*\{?$/i, depth: 5 },
    { pattern: /^ipv6\s*\{?$/i, depth: 5 },
    { pattern: /^ndp-proxy\s*\{?$/i, depth: 5 },
    { pattern: /^arp\s*\{?$/i, depth: 5 },

    // BGP peer
    { pattern: /^peer\s*\{?$/i, depth: 5 },

    // OSPF interfaces
    { pattern: /^interface\s+\S+\s*\{?$/i, depth: 5 },
  ],

  blockEnders: [
    /^\}$/,
    /^\}\s*$/,
    /^exit$/i,
    /^quit$/i,
  ],
};
