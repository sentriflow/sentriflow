// packages/core/src/parser/vendors/mikrotik-routeros.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * MikroTik RouterOS configuration schema.
 *
 * RouterOS uses a unique path-based configuration syntax where hierarchy
 * is denoted by forward slashes (/interface, /ip address, etc.).
 *
 * Key characteristics:
 * - Path declarations: /interface, /ip address, /system identity
 * - Commands: add, set, remove, enable, disable
 * - Property syntax: key=value (no spaces around =)
 * - Find expressions: [ find default-name=ether1 ]
 * - Comments: # at line start
 * - Inline comments: comment="description" property
 *
 * Configuration structure (compact export format):
 * ```
 * # RouterOS Configuration Export
 * /interface ethernet
 * set [ find default-name=ether1 ] name=WAN comment="ISP Uplink"
 * set [ find default-name=ether2 ] name=LAN
 *
 * /ip address
 * add address=192.168.1.1/24 interface=LAN
 * add address=10.0.0.2/30 interface=WAN
 *
 * /ip firewall filter
 * add chain=input action=accept connection-state=established,related
 * add chain=input action=drop in-interface=WAN
 *
 * /system identity
 * set name=MikroTik-Router
 * ```
 *
 * RouterOS supports both compact (default since v6rc1) and verbose export formats.
 * This schema primarily targets the compact export format.
 */
export const MikroTikRouterOSSchema: VendorSchema = {
  id: 'mikrotik-routeros',
  name: 'MikroTik RouterOS',
  useBraceHierarchy: false, // Path-based, not brace-based

  commentPatterns: [
    /^#/, // Standard comments (# comment)
  ],

  sectionDelimiter: undefined, // No explicit delimiter - new path starts new block

  blockStarters: [
    // ============ DEPTH 0: Top-level path declarations ============
    // These are the main configuration sections in RouterOS

    // Interface configuration
    { pattern: /^\/interface\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ethernet\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+vlan\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+bridge\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+bridge\s+port\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+bridge\s+vlan\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+bridge\s+settings\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+bonding\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+wireguard\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+wireguard\s+peers\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+wireless\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+wireless\s+security-profiles\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+eoip\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+gre\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ipip\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+vxlan\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+l2tp-client\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+pptp-client\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+sstp-client\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ovpn-client\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+pppoe-client\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+lte\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+list\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+list\s+member\s*$/i, depth: 0 },

    // IP configuration
    { pattern: /^\/ip\s+address\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+route\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+filter\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+nat\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+mangle\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+raw\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+address-list\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+layer7-protocol\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+service-port\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+firewall\s+connection\s+tracking\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dns\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dns\s+static\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dhcp-server\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dhcp-server\s+network\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dhcp-server\s+lease\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+dhcp-client\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+pool\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+service\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+neighbor\s+discovery-settings\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+arp\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+settings\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+cloud\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s+peer\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s+profile\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s+proposal\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s+policy\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ipsec\s+identity\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+ssh\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+socks\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+proxy\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+hotspot\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+smb\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+upnp\s*$/i, depth: 0 },
    { pattern: /^\/ip\s+traffic-flow\s*$/i, depth: 0 },

    // IPv6 configuration
    { pattern: /^\/ipv6\s+address\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+route\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+firewall\s+filter\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+firewall\s+nat\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+firewall\s+mangle\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+firewall\s+address-list\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+nd\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+nd\s+prefix\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+dhcp-client\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+dhcp-server\s*$/i, depth: 0 },
    { pattern: /^\/ipv6\s+settings\s*$/i, depth: 0 },

    // Routing protocols
    { pattern: /^\/routing\s+bgp\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+bgp\s+connection\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+bgp\s+template\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+bgp\s+network\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+ospf\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+ospf\s+instance\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+ospf\s+area\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+ospf\s+interface-template\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+ospf-v3\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+rip\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+filter\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+filter\s+rule\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+bfd\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+bfd\s+configuration\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+id\s*$/i, depth: 0 },
    { pattern: /^\/routing\s+table\s*$/i, depth: 0 },

    // System configuration
    { pattern: /^\/system\s+identity\s*$/i, depth: 0 },
    { pattern: /^\/system\s+logging\s*$/i, depth: 0 },
    { pattern: /^\/system\s+logging\s+action\s*$/i, depth: 0 },
    { pattern: /^\/system\s+ntp\s+client\s*$/i, depth: 0 },
    { pattern: /^\/system\s+ntp\s+server\s*$/i, depth: 0 },
    { pattern: /^\/system\s+ntp\s+client\s+servers\s*$/i, depth: 0 },
    { pattern: /^\/system\s+clock\s*$/i, depth: 0 },
    { pattern: /^\/system\s+scheduler\s*$/i, depth: 0 },
    { pattern: /^\/system\s+script\s*$/i, depth: 0 },
    { pattern: /^\/system\s+resource\s*$/i, depth: 0 },
    { pattern: /^\/system\s+health\s*$/i, depth: 0 },
    { pattern: /^\/system\s+note\s*$/i, depth: 0 },
    { pattern: /^\/system\s+routerboard\s*$/i, depth: 0 },
    { pattern: /^\/system\s+routerboard\s+settings\s*$/i, depth: 0 },
    { pattern: /^\/system\s+package\s*$/i, depth: 0 },
    { pattern: /^\/system\s+package\s+update\s*$/i, depth: 0 },
    { pattern: /^\/system\s+backup\s*$/i, depth: 0 },
    { pattern: /^\/system\s+watchdog\s*$/i, depth: 0 },
    { pattern: /^\/system\s+upgrade\s*$/i, depth: 0 },
    { pattern: /^\/system\s+leds\s*$/i, depth: 0 },
    { pattern: /^\/system\s+leds\s+settings\s*$/i, depth: 0 },

    // User management
    { pattern: /^\/user\s*$/i, depth: 0 },
    { pattern: /^\/user\s+group\s*$/i, depth: 0 },
    { pattern: /^\/user\s+ssh-keys\s*$/i, depth: 0 },
    { pattern: /^\/user\s+active\s*$/i, depth: 0 },
    { pattern: /^\/user\s+aaa\s*$/i, depth: 0 },

    // QoS and queues
    { pattern: /^\/queue\s+simple\s*$/i, depth: 0 },
    { pattern: /^\/queue\s+tree\s*$/i, depth: 0 },
    { pattern: /^\/queue\s+type\s*$/i, depth: 0 },
    { pattern: /^\/queue\s+interface\s*$/i, depth: 0 },

    // SNMP
    { pattern: /^\/snmp\s*$/i, depth: 0 },
    { pattern: /^\/snmp\s+community\s*$/i, depth: 0 },

    // Certificates
    { pattern: /^\/certificate\s*$/i, depth: 0 },

    // PPP configuration
    { pattern: /^\/ppp\s+profile\s*$/i, depth: 0 },
    { pattern: /^\/ppp\s+secret\s*$/i, depth: 0 },
    { pattern: /^\/ppp\s+aaa\s*$/i, depth: 0 },
    { pattern: /^\/ppp\s+l2tp-secret\s*$/i, depth: 0 },

    // MPLS
    { pattern: /^\/mpls\s*$/i, depth: 0 },
    { pattern: /^\/mpls\s+ldp\s*$/i, depth: 0 },
    { pattern: /^\/mpls\s+interface\s*$/i, depth: 0 },

    // Radius
    { pattern: /^\/radius\s*$/i, depth: 0 },
    { pattern: /^\/radius\s+incoming\s*$/i, depth: 0 },

    // Tools
    { pattern: /^\/tool\s+bandwidth-server\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+netwatch\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+e-mail\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+graphing\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+mac-server\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+mac-server\s+mac-winbox\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+mac-server\s+ping\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+romon\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+sms\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+sniffer\s*$/i, depth: 0 },
    { pattern: /^\/tool\s+traffic-generator\s*$/i, depth: 0 },

    // CAPsMAN (wireless controller)
    { pattern: /^\/caps-man\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+manager\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+interface\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+configuration\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+provisioning\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+channel\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+datapath\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+security\s*$/i, depth: 0 },
    { pattern: /^\/caps-man\s+access-list\s*$/i, depth: 0 },

    // Container (RouterOS 7+)
    { pattern: /^\/container\s*$/i, depth: 0 },
    { pattern: /^\/container\s+config\s*$/i, depth: 0 },
    { pattern: /^\/container\s+envs\s*$/i, depth: 0 },
    { pattern: /^\/container\s+mounts\s*$/i, depth: 0 },

    // Disk/File
    { pattern: /^\/disk\s*$/i, depth: 0 },
    { pattern: /^\/file\s*$/i, depth: 0 },

    // Port and special
    { pattern: /^\/port\s*$/i, depth: 0 },
    { pattern: /^\/special-login\s*$/i, depth: 0 },
    { pattern: /^\/lcd\s*$/i, depth: 0 },
    { pattern: /^\/partitions\s*$/i, depth: 0 },

    // Layer 2 features
    { pattern: /^\/interface\s+ethernet\s+switch\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ethernet\s+switch\s+port\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ethernet\s+switch\s+vlan\s*$/i, depth: 0 },
    { pattern: /^\/interface\s+ethernet\s+switch\s+rule\s*$/i, depth: 0 },

    // Generic path fallback (any /category pattern)
    { pattern: /^\/[a-z][a-z0-9-]*(\s+[a-z][a-z0-9-]*)*\s*$/i, depth: 0 },

    // ============ DEPTH 1: Commands inside path blocks ============
    // These are the action commands that appear under path declarations

    { pattern: /^add\s+/i, depth: 1 },
    { pattern: /^set\s+/i, depth: 1 },
    { pattern: /^remove\s+/i, depth: 1 },
    { pattern: /^enable\s+/i, depth: 1 },
    { pattern: /^disable\s+/i, depth: 1 },
    { pattern: /^move\s+/i, depth: 1 },
    { pattern: /^print\s*/i, depth: 1 },
    { pattern: /^export\s*/i, depth: 1 },
  ],

  blockEnders: [
    // New path declaration ends the current block
    /^\/[a-z]/i,
  ],
};
