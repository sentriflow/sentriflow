// packages/core/src/parser/vendors/fortinet-fortigate.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Fortinet FortiGate (FortiOS) configuration schema.
 *
 * FortiOS uses a distinctive configuration syntax with:
 * 1. "config" to start configuration blocks
 * 2. "edit" to create/modify named entries within a table
 * 3. "next" to end an edit entry
 * 4. "end" to close a config block
 *
 * Key characteristics:
 * - Hierarchical structure using config/edit/next/end
 * - "set" commands for setting values
 * - "unset" commands for removing values
 * - Comments start with #
 * - No braces - uses keywords for hierarchy
 *
 * Configuration structure:
 * ```
 * config system global
 *     set hostname "FW-01"
 *     set timezone "America/New_York"
 * end
 *
 * config system interface
 *     edit "port1"
 *         set ip 192.168.1.1 255.255.255.0
 *         set allowaccess ping https ssh
 *         set type physical
 *     next
 *     edit "port2"
 *         set ip 10.0.0.1 255.255.255.0
 *         set allowaccess ping
 *     next
 * end
 *
 * config firewall policy
 *     edit 1
 *         set srcintf "port1"
 *         set dstintf "port2"
 *         set srcaddr "all"
 *         set dstaddr "all"
 *         set action accept
 *         set schedule "always"
 *         set service "ALL"
 *     next
 * end
 * ```
 *
 * FortiOS sections include:
 * - config system global - Global system settings
 * - config system interface - Network interfaces
 * - config system admin - Admin users and access
 * - config firewall policy - Security policies
 * - config firewall address - Address objects
 * - config firewall service custom - Service objects
 * - config vpn ipsec phase1-interface - IPsec VPN tunnels
 * - config router static - Static routing
 * - config router bgp - BGP routing
 * - config log syslogd setting - Logging
 * - config user local - Local users
 * - config user group - User groups
 * - config webfilter profile - Web filtering profiles
 * - config antivirus profile - Antivirus profiles
 * - config ips sensor - IPS profiles
 */
export const FortinetFortiGateSchema: VendorSchema = {
  id: 'fortinet-fortigate',
  name: 'Fortinet FortiGate (FortiOS)',
  useBraceHierarchy: false,

  commentPatterns: [
    /^#/,                    // Hash comments
    /^\/\//,                 // Double-slash comments (some versions)
  ],
  sectionDelimiter: 'end',

  blockStarters: [
    // ============ DEPTH 0: Top-level config blocks ============

    // System configuration
    { pattern: /^config\s+system\s+global$/i, depth: 0 },
    { pattern: /^config\s+system\s+interface$/i, depth: 0 },
    { pattern: /^config\s+system\s+admin$/i, depth: 0 },
    { pattern: /^config\s+system\s+dns$/i, depth: 0 },
    { pattern: /^config\s+system\s+ntp$/i, depth: 0 },
    { pattern: /^config\s+system\s+snmp\s+\S+/i, depth: 0 },
    { pattern: /^config\s+system\s+settings$/i, depth: 0 },
    { pattern: /^config\s+system\s+ha$/i, depth: 0 },
    { pattern: /^config\s+system\s+zone$/i, depth: 0 },
    { pattern: /^config\s+system\s+dhcp\s+server$/i, depth: 0 },
    { pattern: /^config\s+system\s+replacemsg\s+\S+/i, depth: 0 },
    { pattern: /^config\s+system\s+accprofile$/i, depth: 0 },
    { pattern: /^config\s+system\s+api-user$/i, depth: 0 },
    { pattern: /^config\s+system\s+automation-\S+/i, depth: 0 },
    { pattern: /^config\s+system\s+virtual-wan-link$/i, depth: 0 },
    { pattern: /^config\s+system\s+sdwan$/i, depth: 0 },
    { pattern: /^config\s+system\s+\S+/i, depth: 0 },  // Catch-all for system config

    // Firewall configuration
    { pattern: /^config\s+firewall\s+policy$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+policy6$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+address$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+address6$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+addrgrp$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+addrgrp6$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+service\s+custom$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+service\s+group$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+schedule\s+\S+/i, depth: 0 },
    { pattern: /^config\s+firewall\s+vip$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+vip6$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+ippool$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+ippool6$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+central-snat-map$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+shaper\s+\S+/i, depth: 0 },
    { pattern: /^config\s+firewall\s+shaping-policy$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+ssl-ssh-profile$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+profile-group$/i, depth: 0 },
    { pattern: /^config\s+firewall\s+\S+/i, depth: 0 },  // Catch-all for firewall config

    // VPN configuration
    { pattern: /^config\s+vpn\s+ipsec\s+phase1-interface$/i, depth: 0 },
    { pattern: /^config\s+vpn\s+ipsec\s+phase2-interface$/i, depth: 0 },
    { pattern: /^config\s+vpn\s+ssl\s+settings$/i, depth: 0 },
    { pattern: /^config\s+vpn\s+ssl\s+web\s+\S+/i, depth: 0 },
    { pattern: /^config\s+vpn\s+\S+/i, depth: 0 },  // Catch-all for VPN config

    // Router configuration
    { pattern: /^config\s+router\s+static$/i, depth: 0 },
    { pattern: /^config\s+router\s+static6$/i, depth: 0 },
    { pattern: /^config\s+router\s+policy$/i, depth: 0 },
    { pattern: /^config\s+router\s+bgp$/i, depth: 0 },
    { pattern: /^config\s+router\s+ospf$/i, depth: 0 },
    { pattern: /^config\s+router\s+ospf6$/i, depth: 0 },
    { pattern: /^config\s+router\s+rip$/i, depth: 0 },
    { pattern: /^config\s+router\s+access-list$/i, depth: 0 },
    { pattern: /^config\s+router\s+prefix-list$/i, depth: 0 },
    { pattern: /^config\s+router\s+route-map$/i, depth: 0 },
    { pattern: /^config\s+router\s+\S+/i, depth: 0 },  // Catch-all for router config

    // Logging configuration
    { pattern: /^config\s+log\s+syslogd\s+setting$/i, depth: 0 },
    { pattern: /^config\s+log\s+syslogd\d?\s+\S+/i, depth: 0 },
    { pattern: /^config\s+log\s+fortianalyzer\s+\S+/i, depth: 0 },
    { pattern: /^config\s+log\s+disk\s+\S+/i, depth: 0 },
    { pattern: /^config\s+log\s+memory\s+\S+/i, depth: 0 },
    { pattern: /^config\s+log\s+\S+/i, depth: 0 },  // Catch-all for log config

    // User and authentication configuration
    { pattern: /^config\s+user\s+local$/i, depth: 0 },
    { pattern: /^config\s+user\s+group$/i, depth: 0 },
    { pattern: /^config\s+user\s+ldap$/i, depth: 0 },
    { pattern: /^config\s+user\s+radius$/i, depth: 0 },
    { pattern: /^config\s+user\s+tacacs\+$/i, depth: 0 },
    { pattern: /^config\s+user\s+fsso$/i, depth: 0 },
    { pattern: /^config\s+user\s+\S+/i, depth: 0 },  // Catch-all for user config

    // Security profiles
    { pattern: /^config\s+antivirus\s+profile$/i, depth: 0 },
    { pattern: /^config\s+webfilter\s+profile$/i, depth: 0 },
    { pattern: /^config\s+webfilter\s+urlfilter$/i, depth: 0 },
    { pattern: /^config\s+webfilter\s+content$/i, depth: 0 },
    { pattern: /^config\s+webfilter\s+ftgd-local-cat$/i, depth: 0 },
    { pattern: /^config\s+ips\s+sensor$/i, depth: 0 },
    { pattern: /^config\s+ips\s+\S+/i, depth: 0 },
    { pattern: /^config\s+application\s+list$/i, depth: 0 },
    { pattern: /^config\s+application\s+\S+/i, depth: 0 },
    { pattern: /^config\s+dlp\s+\S+/i, depth: 0 },
    { pattern: /^config\s+spamfilter\s+\S+/i, depth: 0 },
    { pattern: /^config\s+emailfilter\s+\S+/i, depth: 0 },
    { pattern: /^config\s+icap\s+\S+/i, depth: 0 },
    { pattern: /^config\s+voip\s+profile$/i, depth: 0 },
    { pattern: /^config\s+waf\s+profile$/i, depth: 0 },
    { pattern: /^config\s+dnsfilter\s+profile$/i, depth: 0 },
    { pattern: /^config\s+videofilter\s+profile$/i, depth: 0 },
    { pattern: /^config\s+file-filter\s+profile$/i, depth: 0 },
    { pattern: /^config\s+ssh-filter\s+profile$/i, depth: 0 },
    { pattern: /^config\s+cifs\s+profile$/i, depth: 0 },

    // Certificate configuration
    { pattern: /^config\s+certificate\s+\S+/i, depth: 0 },
    { pattern: /^config\s+vpn\s+certificate\s+\S+/i, depth: 0 },

    // Wireless configuration
    { pattern: /^config\s+wireless-controller\s+\S+/i, depth: 0 },

    // Switch controller (FortiSwitch integration)
    { pattern: /^config\s+switch-controller\s+\S+/i, depth: 0 },

    // Endpoint control
    { pattern: /^config\s+endpoint-control\s+\S+/i, depth: 0 },

    // Global/generic config blocks
    { pattern: /^config\s+\S+/i, depth: 0 },  // Generic config block starter

    // ============ DEPTH 1: Edit entries within config blocks ============

    // Edit with quoted name (most common in FortiOS)
    { pattern: /^edit\s+"[^"]+"/i, depth: 1 },
    { pattern: /^edit\s+'[^']+'/i, depth: 1 },
    // Edit with unquoted name or number (e.g., policy IDs)
    { pattern: /^edit\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Nested config within edit blocks ============

    // Nested config blocks inside edit entries (e.g., BGP neighbor config)
    { pattern: /^config\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^end$/i,     // Closes config block
    /^next$/i,    // Closes edit entry
  ],
};
