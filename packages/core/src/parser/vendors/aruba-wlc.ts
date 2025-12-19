// packages/core/src/parser/vendors/aruba-wlc.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * Aruba ArubaOS WLC (Wireless LAN Controller) configuration schema.
 *
 * ArubaOS is used on Aruba Mobility Controllers (7xxx, 9xxx series) and
 * Mobility Masters. It uses a profile-based architecture with hierarchical
 * configuration.
 *
 * Key characteristics:
 * - Profile-based: WLAN profiles, AAA profiles, AP groups, RF profiles
 * - Quoted names: Profile names use double quotes (e.g., "Corp-SSID")
 * - Context-based: Configuration blocks with '!' delimiters
 * - Inheritance: Profiles reference other profiles
 *
 * Configuration structure:
 * - WLAN SSID profiles define wireless network settings
 * - Virtual-AP profiles combine SSID + AAA + other settings
 * - AP groups apply virtual-APs to sets of access points
 * - AAA profiles define authentication/authorization
 */
export const ArubaWLCSchema: VendorSchema = {
  id: 'aruba-wlc',
  name: 'Aruba ArubaOS WLC',
  useBraceHierarchy: false,

  commentPatterns: [/^!/],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level profile blocks ============

    // WLAN SSID profiles
    { pattern: /^wlan\s+ssid-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^wlan\s+ssid-profile\s+\S+/i, depth: 0 },

    // WLAN Virtual-AP profiles (combine SSID + AAA)
    { pattern: /^wlan\s+virtual-ap\s+"[^"]+"/i, depth: 0 },
    { pattern: /^wlan\s+virtual-ap\s+\S+/i, depth: 0 },

    // WLAN handoff profile
    { pattern: /^wlan\s+handoff-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^wlan\s+handoff-profile\s+\S+/i, depth: 0 },

    // WLAN HT/VHT SSID profile
    { pattern: /^wlan\s+ht-ssid-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^wlan\s+ht-ssid-profile\s+\S+/i, depth: 0 },

    // AAA profiles
    { pattern: /^aaa\s+profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+profile\s+\S+/i, depth: 0 },

    // AAA authentication servers
    { pattern: /^aaa\s+authentication-server\s+radius\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+authentication-server\s+radius\s+\S+/i, depth: 0 },
    { pattern: /^aaa\s+authentication-server\s+tacacs\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+authentication-server\s+tacacs\s+\S+/i, depth: 0 },
    { pattern: /^aaa\s+authentication-server\s+ldap\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+authentication-server\s+ldap\s+\S+/i, depth: 0 },

    // AAA server groups
    { pattern: /^aaa\s+server-group\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+server-group\s+\S+/i, depth: 0 },

    // AAA authentication (method lists)
    { pattern: /^aaa\s+authentication\s+\S+/i, depth: 0 },

    // AP groups
    { pattern: /^ap-group\s+"[^"]+"/i, depth: 0 },
    { pattern: /^ap-group\s+\S+/i, depth: 0 },

    // AP name (specific AP config)
    { pattern: /^ap-name\s+"[^"]+"/i, depth: 0 },
    { pattern: /^ap-name\s+\S+/i, depth: 0 },

    // AP system profile
    { pattern: /^ap\s+system-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^ap\s+system-profile\s+\S+/i, depth: 0 },

    // RF profiles (ARM, dot11a, dot11g)
    { pattern: /^rf\s+arm-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^rf\s+arm-profile\s+\S+/i, depth: 0 },
    { pattern: /^rf\s+dot11a-radio-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^rf\s+dot11a-radio-profile\s+\S+/i, depth: 0 },
    { pattern: /^rf\s+dot11g-radio-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^rf\s+dot11g-radio-profile\s+\S+/i, depth: 0 },
    { pattern: /^rf\s+ht-radio-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^rf\s+ht-radio-profile\s+\S+/i, depth: 0 },

    // User roles
    { pattern: /^user-role\s+"[^"]+"/i, depth: 0 },
    { pattern: /^user-role\s+\S+/i, depth: 0 },

    // Netdestination (network object groups)
    { pattern: /^netdestination\s+\S+/i, depth: 0 },
    { pattern: /^netdestination6\s+\S+/i, depth: 0 },

    // IP access lists
    { pattern: /^ip\s+access-list\s+session\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+access-list\s+eth\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+access-list\s+extended\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+access-list\s+standard\s+\S+/i, depth: 0 },

    // Controller interfaces
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // VLANs
    { pattern: /^vlan\s+\d+/i, depth: 0 },
    { pattern: /^vlan-name\s+\S+/i, depth: 0 },

    // VLAN pool
    { pattern: /^vlan-pool\s+"[^"]+"/i, depth: 0 },
    { pattern: /^vlan-pool\s+\S+/i, depth: 0 },

    // Controller IP
    { pattern: /^controller-ip\s+\S+/i, depth: 0 },

    // IDS profile
    { pattern: /^ids\s+\S+-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^ids\s+\S+-profile\s+\S+/i, depth: 0 },

    // Firewall policies
    { pattern: /^firewall\s+\S+/i, depth: 0 },

    // Captive portal profile
    { pattern: /^aaa\s+captive-portal\s+"[^"]+"/i, depth: 0 },
    { pattern: /^aaa\s+captive-portal\s+\S+/i, depth: 0 },

    // Regulatory domain
    { pattern: /^regulatory-domain-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^regulatory-domain-profile\s+\S+/i, depth: 0 },

    // Mesh cluster profile
    { pattern: /^mesh\s+cluster-profile\s+"[^"]+"/i, depth: 0 },
    { pattern: /^mesh\s+cluster-profile\s+\S+/i, depth: 0 },

    // SNMP configuration
    { pattern: /^snmp-server\s+\S+/i, depth: 0 },

    // NTP
    { pattern: /^ntp\s+\S+/i, depth: 0 },

    // Logging
    { pattern: /^logging\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Nested within profiles ============

    // Authentication methods within AAA profiles
    { pattern: /^authentication-\S+/i, depth: 1 },

    // References within virtual-AP
    { pattern: /^ssid-profile\s+"[^"]+"/i, depth: 1 },
    { pattern: /^ssid-profile\s+\S+/i, depth: 1 },
    { pattern: /^aaa-profile\s+"[^"]+"/i, depth: 1 },
    { pattern: /^aaa-profile\s+\S+/i, depth: 1 },

    // Dot1x within AAA
    { pattern: /^dot1x-\S+/i, depth: 1 },

    // Server references within server-group
    { pattern: /^auth-server\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Deeply nested ============

    { pattern: /^server\s+\S+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit$/i,
  ],
};
