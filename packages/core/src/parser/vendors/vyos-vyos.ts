// packages/core/src/parser/vendors/vyos-vyos.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * VyOS/Ubiquiti EdgeOS configuration schema.
 *
 * VyOS (and Ubiquiti EdgeOS which is based on Vyatta/VyOS) uses a hierarchical
 * configuration model that can be displayed in multiple formats:
 * 1. Set command format (CLI style): "set interfaces ethernet eth0 address 192.168.1.1/24"
 * 2. Hierarchical display format with braces: "interfaces { ethernet eth0 { ... } }"
 *
 * Key characteristics:
 * - Brace-based hierarchy in display mode (like JunOS)
 * - Set-style commands: "set interfaces ethernet eth0 address 192.168.1.1/24"
 * - Delete commands: "delete interfaces ethernet eth0 address 192.168.1.1/24"
 * - Comments: Block comments or added via "comment" command
 * - Interface naming: eth0, eth1, bond0, br0, wg0, vti0, pppoe0, tun0
 * - Zone-based firewall with named rulesets
 * - VPN support: IPsec, OpenVPN, WireGuard, L2TP
 *
 * Configuration structure (hierarchical format):
 * ```
 * interfaces {
 *     ethernet eth0 {
 *         address 192.168.1.1/24
 *         description "WAN Interface"
 *         hw-id 00:0c:29:xx:xx:xx
 *     }
 *     loopback lo {
 *     }
 * }
 * system {
 *     host-name vyos-router
 *     login {
 *         user vyos {
 *             authentication {
 *                 encrypted-password "$6$..."
 *             }
 *         }
 *     }
 * }
 * ```
 *
 * Set command format:
 * ```
 * set interfaces ethernet eth0 address '192.168.1.1/24'
 * set interfaces ethernet eth0 description 'WAN Interface'
 * set system host-name vyos-router
 * set firewall name WAN_IN default-action drop
 * set firewall name WAN_IN rule 10 action accept
 * set firewall name WAN_IN rule 10 state established enable
 * ```
 */
export const VyOSSchema: VendorSchema = {
  id: 'vyos',
  name: 'VyOS/EdgeOS',
  useBraceHierarchy: true,

  commentPatterns: [
    /^\/\*.*\*\/$/,              // Block comments /* ... */
    /^\/\*.*$/,                  // Multi-line comment start /* ...
    /^.*\*\/$/,                  // Multi-line comment end ... */
    /^#/,                        // Hash comments (some modes)
  ],
  sectionDelimiter: '}',

  blockStarters: [
    // ============ DEPTH 0: Top-level configuration stanzas ============

    // System configuration (hostname, login, dns, ntp, syslog)
    { pattern: /^system\s*\{?$/i, depth: 0 },

    // Interfaces (ethernet, loopback, bonding, bridge, wireguard, etc.)
    { pattern: /^interfaces\s*\{?$/i, depth: 0 },

    // Firewall configuration (zones, groups, rules)
    { pattern: /^firewall\s*\{?$/i, depth: 0 },

    // NAT configuration
    { pattern: /^nat\s*\{?$/i, depth: 0 },

    // Routing protocols
    { pattern: /^protocols\s*\{?$/i, depth: 0 },

    // Policy (route-map, prefix-list, as-path, community-list)
    { pattern: /^policy\s*\{?$/i, depth: 0 },

    // Service configuration (dhcp-server, dns, ssh, https, etc.)
    { pattern: /^service\s*\{?$/i, depth: 0 },

    // VPN configuration (ipsec, openvpn, l2tp, pptp, wireguard)
    { pattern: /^vpn\s*\{?$/i, depth: 0 },

    // High availability (VRRP, conntrack-sync)
    { pattern: /^high-availability\s*\{?$/i, depth: 0 },

    // QoS (traffic shaping, policies)
    { pattern: /^traffic-policy\s*\{?$/i, depth: 0 },
    { pattern: /^qos\s*\{?$/i, depth: 0 },

    // Container (podman/docker containers in VyOS 1.4+)
    { pattern: /^container\s*\{?$/i, depth: 0 },

    // Load balancing (WAN load balancing, reverse proxy)
    { pattern: /^load-balancing\s*\{?$/i, depth: 0 },

    // VRRP (standalone in older versions)
    { pattern: /^vrrp\s*\{?$/i, depth: 0 },

    // PKI (certificates, CA)
    { pattern: /^pki\s*\{?$/i, depth: 0 },

    // Set command format (flat configuration)
    { pattern: /^set\s+system\s+/i, depth: 0 },
    { pattern: /^set\s+interfaces\s+/i, depth: 0 },
    { pattern: /^set\s+firewall\s+/i, depth: 0 },
    { pattern: /^set\s+nat\s+/i, depth: 0 },
    { pattern: /^set\s+protocols\s+/i, depth: 0 },
    { pattern: /^set\s+policy\s+/i, depth: 0 },
    { pattern: /^set\s+service\s+/i, depth: 0 },
    { pattern: /^set\s+vpn\s+/i, depth: 0 },
    { pattern: /^set\s+high-availability\s+/i, depth: 0 },
    { pattern: /^set\s+traffic-policy\s+/i, depth: 0 },
    { pattern: /^set\s+qos\s+/i, depth: 0 },
    { pattern: /^set\s+container\s+/i, depth: 0 },
    { pattern: /^set\s+load-balancing\s+/i, depth: 0 },
    { pattern: /^set\s+pki\s+/i, depth: 0 },

    // Delete commands (same structure as set)
    { pattern: /^delete\s+/i, depth: 0 },

    // ============ DEPTH 1: Inside top-level stanzas ============

    // Inside system
    { pattern: /^host-name\s+/i, depth: 1 },
    { pattern: /^login\s*\{?$/i, depth: 1 },
    { pattern: /^name-server\s+/i, depth: 1 },
    { pattern: /^ntp\s*\{?$/i, depth: 1 },
    { pattern: /^syslog\s*\{?$/i, depth: 1 },
    { pattern: /^time-zone\s+/i, depth: 1 },
    { pattern: /^console\s*\{?$/i, depth: 1 },
    { pattern: /^config-management\s*\{?$/i, depth: 1 },
    { pattern: /^conntrack\s*\{?$/i, depth: 1 },
    { pattern: /^domain-name\s+/i, depth: 1 },
    { pattern: /^flow-accounting\s*\{?$/i, depth: 1 },
    { pattern: /^options\s*\{?$/i, depth: 1 },
    { pattern: /^static-host-mapping\s*\{?$/i, depth: 1 },
    { pattern: /^task-scheduler\s*\{?$/i, depth: 1 },

    // Inside interfaces - interface types
    { pattern: /^ethernet\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^loopback\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^bonding\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^bridge\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^wireguard\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^openvpn\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^vti\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^tunnel\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^l2tpv3\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^pppoe\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^vxlan\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^macsec\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^pseudo-ethernet\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^wireless\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^wwan\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^dummy\s+\S+\s*\{?$/i, depth: 1 },

    // Inside firewall
    { pattern: /^all-ping\s+/i, depth: 1 },
    { pattern: /^broadcast-ping\s+/i, depth: 1 },
    { pattern: /^config-trap\s+/i, depth: 1 },
    { pattern: /^group\s*\{?$/i, depth: 1 },
    { pattern: /^ipv6-name\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^ipv6-src-route\s+/i, depth: 1 },
    { pattern: /^ip-src-route\s+/i, depth: 1 },
    { pattern: /^log-martians\s+/i, depth: 1 },
    { pattern: /^name\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^options\s*\{?$/i, depth: 1 },
    { pattern: /^receive-redirects\s+/i, depth: 1 },
    { pattern: /^send-redirects\s+/i, depth: 1 },
    { pattern: /^source-validation\s+/i, depth: 1 },
    { pattern: /^state-policy\s*\{?$/i, depth: 1 },
    { pattern: /^syn-cookies\s+/i, depth: 1 },
    { pattern: /^twa-hazards-protection\s+/i, depth: 1 },
    { pattern: /^zone\s+\S+\s*\{?$/i, depth: 1 },
    // VyOS 1.4+ firewall structure
    { pattern: /^ipv4\s*\{?$/i, depth: 1 },
    { pattern: /^ipv6\s*\{?$/i, depth: 1 },

    // Inside nat
    { pattern: /^source\s*\{?$/i, depth: 1 },
    { pattern: /^destination\s*\{?$/i, depth: 1 },
    { pattern: /^nptv6\s*\{?$/i, depth: 1 },

    // Inside protocols
    { pattern: /^bgp\s*\{?$/i, depth: 1 },
    { pattern: /^ospf\s*\{?$/i, depth: 1 },
    { pattern: /^ospfv3\s*\{?$/i, depth: 1 },
    { pattern: /^rip\s*\{?$/i, depth: 1 },
    { pattern: /^ripng\s*\{?$/i, depth: 1 },
    { pattern: /^isis\s*\{?$/i, depth: 1 },
    { pattern: /^static\s*\{?$/i, depth: 1 },
    { pattern: /^bfd\s*\{?$/i, depth: 1 },
    { pattern: /^igmp-proxy\s*\{?$/i, depth: 1 },
    { pattern: /^mpls\s*\{?$/i, depth: 1 },
    { pattern: /^nhrp\s*\{?$/i, depth: 1 },
    { pattern: /^pim\s*\{?$/i, depth: 1 },
    { pattern: /^rpki\s*\{?$/i, depth: 1 },
    { pattern: /^segment-routing\s*\{?$/i, depth: 1 },

    // Inside policy
    { pattern: /^access-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^access-list6\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^as-path-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^community-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^extcommunity-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^large-community-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^prefix-list\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^prefix-list6\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^route-map\s+\S+\s*\{?$/i, depth: 1 },
    { pattern: /^local-route\s*\{?$/i, depth: 1 },
    { pattern: /^local-route6\s*\{?$/i, depth: 1 },

    // Inside service
    { pattern: /^dhcp-server\s*\{?$/i, depth: 1 },
    { pattern: /^dhcpv6-server\s*\{?$/i, depth: 1 },
    { pattern: /^dhcp-relay\s*\{?$/i, depth: 1 },
    { pattern: /^dhcpv6-relay\s*\{?$/i, depth: 1 },
    { pattern: /^dns\s*\{?$/i, depth: 1 },
    { pattern: /^https\s*\{?$/i, depth: 1 },
    { pattern: /^ssh\s*\{?$/i, depth: 1 },
    { pattern: /^snmp\s*\{?$/i, depth: 1 },
    { pattern: /^lldp\s*\{?$/i, depth: 1 },
    { pattern: /^ntp\s*\{?$/i, depth: 1 },
    { pattern: /^router-advert\s*\{?$/i, depth: 1 },
    { pattern: /^tftp-server\s*\{?$/i, depth: 1 },
    { pattern: /^mdns\s*\{?$/i, depth: 1 },
    { pattern: /^monitoring\s*\{?$/i, depth: 1 },
    { pattern: /^webproxy\s*\{?$/i, depth: 1 },
    { pattern: /^broadcast-relay\s*\{?$/i, depth: 1 },
    { pattern: /^ids\s*\{?$/i, depth: 1 },
    { pattern: /^ipoe-server\s*\{?$/i, depth: 1 },
    { pattern: /^pppoe-server\s*\{?$/i, depth: 1 },
    { pattern: /^console-server\s*\{?$/i, depth: 1 },

    // Inside vpn
    { pattern: /^ipsec\s*\{?$/i, depth: 1 },
    { pattern: /^l2tp\s*\{?$/i, depth: 1 },
    { pattern: /^pptp\s*\{?$/i, depth: 1 },
    { pattern: /^openconnect\s*\{?$/i, depth: 1 },
    { pattern: /^sstp\s*\{?$/i, depth: 1 },

    // Inside high-availability
    { pattern: /^vrrp\s*\{?$/i, depth: 1 },

    // ============ DEPTH 2: Nested inside depth-1 blocks ============

    // Inside login
    { pattern: /^user\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^radius\s*\{?$/i, depth: 2 },
    { pattern: /^tacacs\s*\{?$/i, depth: 2 },

    // Inside NTP
    { pattern: /^server\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^allow-client\s*\{?$/i, depth: 2 },

    // Inside syslog
    { pattern: /^global\s*\{?$/i, depth: 2 },
    { pattern: /^host\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^console\s*\{?$/i, depth: 2 },

    // Inside interface definitions (vif, address, firewall bindings)
    { pattern: /^vif\s+\d+\s*\{?$/i, depth: 2 },
    { pattern: /^vif-s\s+\d+\s*\{?$/i, depth: 2 },  // QinQ outer VLAN

    // Inside firewall group
    { pattern: /^address-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^ipv6-address-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^network-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^ipv6-network-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^interface-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^mac-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^port-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^domain-group\s+\S+\s*\{?$/i, depth: 2 },

    // Inside firewall ruleset (name/ipv6-name)
    { pattern: /^default-action\s+/i, depth: 2 },
    { pattern: /^enable-default-log\s*$/i, depth: 2 },
    { pattern: /^rule\s+\d+\s*\{?$/i, depth: 2 },

    // Inside firewall zone
    { pattern: /^default-action\s+/i, depth: 2 },
    { pattern: /^from\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^interface\s+/i, depth: 2 },
    { pattern: /^local-zone\s*$/i, depth: 2 },

    // Inside NAT source/destination
    { pattern: /^rule\s+\d+\s*\{?$/i, depth: 2 },

    // Inside BGP (VyOS 1.4+ uses 'system-as' inside bgp block)
    { pattern: /^address-family\s*\{?$/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^peer-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^parameters\s*\{?$/i, depth: 2 },
    { pattern: /^listen\s*\{?$/i, depth: 2 },

    // Inside OSPF
    { pattern: /^area\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^default-information\s*\{?$/i, depth: 2 },
    { pattern: /^interface\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^passive-interface\s+/i, depth: 2 },
    { pattern: /^parameters\s*\{?$/i, depth: 2 },
    { pattern: /^redistribute\s*\{?$/i, depth: 2 },
    { pattern: /^refresh\s*\{?$/i, depth: 2 },
    { pattern: /^timers\s*\{?$/i, depth: 2 },

    // Inside static routes
    { pattern: /^route\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^route6\s+\S+\s*\{?$/i, depth: 2 },

    // Inside DHCP server
    { pattern: /^shared-network-name\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^high-availability\s*\{?$/i, depth: 2 },
    { pattern: /^hostfile-update\s*\{?$/i, depth: 2 },

    // Inside DNS
    { pattern: /^forwarding\s*\{?$/i, depth: 2 },
    { pattern: /^dynamic\s*\{?$/i, depth: 2 },

    // Inside IPsec
    { pattern: /^esp-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^ike-group\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^interface\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^site-to-site\s*\{?$/i, depth: 2 },
    { pattern: /^profile\s+\S+\s*\{?$/i, depth: 2 },
    { pattern: /^remote-access\s*\{?$/i, depth: 2 },

    // Inside L2TP/PPTP remote access VPN
    { pattern: /^remote-access\s*\{?$/i, depth: 2 },

    // Inside VRRP
    { pattern: /^group\s+\S+\s*\{?$/i, depth: 2 },

    // Inside route-map
    { pattern: /^rule\s+\d+\s*\{?$/i, depth: 2 },

    // Inside prefix-list
    { pattern: /^rule\s+\d+\s*\{?$/i, depth: 2 },

    // Inside SSH
    { pattern: /^access-control\s*\{?$/i, depth: 2 },
    { pattern: /^dynamic-protection\s*\{?$/i, depth: 2 },

    // ============ DEPTH 3: Deeply nested blocks ============

    // Inside user authentication
    { pattern: /^authentication\s*\{?$/i, depth: 3 },
    { pattern: /^public-keys\s+\S+\s*\{?$/i, depth: 3 },

    // Inside VIF (VLAN subinterface)
    { pattern: /^vif-c\s+\d+\s*\{?$/i, depth: 3 },  // QinQ inner VLAN

    // Inside DHCP shared-network
    { pattern: /^subnet\s+\S+\s*\{?$/i, depth: 3 },

    // Inside BGP address-family
    { pattern: /^ipv4-unicast\s*\{?$/i, depth: 3 },
    { pattern: /^ipv6-unicast\s*\{?$/i, depth: 3 },
    { pattern: /^l2vpn-evpn\s*\{?$/i, depth: 3 },

    // Inside BGP neighbor
    { pattern: /^address-family\s*\{?$/i, depth: 3 },

    // Inside OSPF area
    { pattern: /^area-type\s*\{?$/i, depth: 3 },
    { pattern: /^network\s+\S+\s*$/i, depth: 3 },
    { pattern: /^range\s+\S+\s*\{?$/i, depth: 3 },
    { pattern: /^virtual-link\s+\S+\s*\{?$/i, depth: 3 },

    // Inside static route
    { pattern: /^next-hop\s+\S+\s*\{?$/i, depth: 3 },
    { pattern: /^blackhole\s*\{?$/i, depth: 3 },

    // Inside IPsec esp-group/ike-group
    { pattern: /^proposal\s+\d+\s*\{?$/i, depth: 3 },

    // Inside IPsec site-to-site
    { pattern: /^peer\s+\S+\s*\{?$/i, depth: 3 },

    // Inside firewall rule (match conditions and actions)
    { pattern: /^source\s*\{?$/i, depth: 3 },
    { pattern: /^destination\s*\{?$/i, depth: 3 },
    { pattern: /^state\s*\{?$/i, depth: 3 },
    { pattern: /^tcp\s*\{?$/i, depth: 3 },
    { pattern: /^icmp\s*\{?$/i, depth: 3 },
    { pattern: /^time\s*\{?$/i, depth: 3 },
    { pattern: /^recent\s*\{?$/i, depth: 3 },
    { pattern: /^log\s*\{?$/i, depth: 3 },
    { pattern: /^limit\s*\{?$/i, depth: 3 },

    // Inside NAT rule
    { pattern: /^source\s*\{?$/i, depth: 3 },
    { pattern: /^destination\s*\{?$/i, depth: 3 },
    { pattern: /^translation\s*\{?$/i, depth: 3 },

    // Inside zone from
    { pattern: /^firewall\s*\{?$/i, depth: 3 },

    // Inside route-map rule
    { pattern: /^match\s*\{?$/i, depth: 3 },
    { pattern: /^set\s*\{?$/i, depth: 3 },
    { pattern: /^on-match\s*\{?$/i, depth: 3 },

    // Inside SNMP
    { pattern: /^community\s+\S+\s*\{?$/i, depth: 3 },
    { pattern: /^trap-target\s+\S+\s*\{?$/i, depth: 3 },
    { pattern: /^v3\s*\{?$/i, depth: 3 },

    // ============ DEPTH 4: Very deeply nested ============

    // Inside DHCP subnet
    { pattern: /^static-mapping\s+\S+\s*\{?$/i, depth: 4 },
    { pattern: /^range\s+\d+\s*\{?$/i, depth: 4 },

    // Inside IPsec peer
    { pattern: /^tunnel\s+\d+\s*\{?$/i, depth: 4 },
    { pattern: /^vti\s*\{?$/i, depth: 4 },
    { pattern: /^authentication\s*\{?$/i, depth: 4 },
    { pattern: /^connection-type\s+/i, depth: 4 },

    // Inside BGP neighbor address-family
    { pattern: /^ipv4-unicast\s*\{?$/i, depth: 4 },
    { pattern: /^ipv6-unicast\s*\{?$/i, depth: 4 },

    // Inside SNMPv3
    { pattern: /^user\s+\S+\s*\{?$/i, depth: 4 },
    { pattern: /^group\s+\S+\s*\{?$/i, depth: 4 },
    { pattern: /^view\s+\S+\s*\{?$/i, depth: 4 },

    // ============ DEPTH 5: Deepest nesting ============

    // Inside IPsec tunnel
    { pattern: /^local\s*\{?$/i, depth: 5 },
    { pattern: /^remote\s*\{?$/i, depth: 5 },
    { pattern: /^protocol\s*\{?$/i, depth: 5 },
  ],

  blockEnders: [
    /^\}$/,
    /^\}\s*$/,
  ],
};
