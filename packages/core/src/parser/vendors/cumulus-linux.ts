// packages/core/src/parser/vendors/cumulus-linux.ts

import type { VendorSchema } from '../VendorSchema';

/**
 * NVIDIA Cumulus Linux configuration schema.
 *
 * Cumulus Linux is a Linux-based network operating system that supports
 * multiple configuration formats:
 *
 * 1. NCLU (Network Command Line Utility) - Legacy CLI (Cumulus 3.x-4.x)
 *    - Commands: net add, net del, net commit
 *    - Example: "net add interface swp1 ip address 10.0.0.1/24"
 *
 * 2. NVUE (NVIDIA User Experience) - Modern CLI (Cumulus 5.x+)
 *    - Commands: nv set, nv unset, nv config apply
 *    - Example: "nv set interface swp1 ip address 10.0.0.1/24"
 *
 * 3. /etc/network/interfaces - Debian ifupdown2 format
 *    - Stanzas: auto, iface, bridge-ports, bridge-vids
 *    - Example:
 *      auto swp1
 *      iface swp1
 *          address 10.0.0.1/24
 *
 * 4. /etc/frr/frr.conf - FRR routing daemon (Cisco-like syntax)
 *    - Blocks: router bgp, router ospf, interface
 *    - Example:
 *      router bgp 65001
 *       bgp router-id 10.0.0.1
 *       neighbor swp1 interface remote-as external
 *
 * Interface naming conventions:
 * - swp1-swpN: Switch ports (front panel)
 * - eth0: Management interface
 * - lo: Loopback
 * - bridge, br_default: Bridge interfaces
 * - bond0-bondN: Bond/LAG interfaces
 * - vlan10, vlan20: VLAN interfaces (SVIs)
 * - peerlink: MLAG peer link
 *
 * This schema handles:
 * - NCLU/NVUE set-style commands (single line, depth 0)
 * - /etc/network/interfaces stanzas (auto/iface blocks)
 * - FRR routing configuration (router blocks with address-family)
 */
export const CumulusLinuxSchema: VendorSchema = {
  id: 'cumulus-linux',
  name: 'NVIDIA Cumulus Linux',
  useBraceHierarchy: false,

  commentPatterns: [
    /^#/,           // Hash comments (interfaces file, FRR, NCLU output)
    /^!/,           // Bang comments (FRR style)
  ],
  sectionDelimiter: '!',

  blockStarters: [
    // ============ DEPTH 0: Top-level blocks ============

    // NCLU commands (net add/del) - single line commands
    { pattern: /^net\s+add\s+/i, depth: 0 },
    { pattern: /^net\s+del\s+/i, depth: 0 },

    // NVUE commands (nv set/unset) - single line commands
    { pattern: /^nv\s+set\s+/i, depth: 0 },
    { pattern: /^nv\s+unset\s+/i, depth: 0 },
    { pattern: /^nv\s+config\s+/i, depth: 0 },

    // /etc/network/interfaces format (ifupdown2)
    { pattern: /^auto\s+\S+/i, depth: 0 },
    { pattern: /^iface\s+\S+/i, depth: 0 },
    { pattern: /^allow-hotplug\s+\S+/i, depth: 0 },
    { pattern: /^source\s+/i, depth: 0 },
    { pattern: /^source-directory\s+/i, depth: 0 },

    // FRR routing configuration blocks
    { pattern: /^router\s+bgp\s+\d+/i, depth: 0 },
    { pattern: /^router\s+ospf/i, depth: 0 },
    { pattern: /^router\s+ospf6/i, depth: 0 },
    { pattern: /^router\s+rip/i, depth: 0 },
    { pattern: /^router\s+ripng/i, depth: 0 },
    { pattern: /^router\s+isis\s+\S+/i, depth: 0 },
    { pattern: /^router\s+pim/i, depth: 0 },

    // FRR global configuration
    { pattern: /^frr\s+defaults\s+/i, depth: 0 },
    { pattern: /^frr\s+version\s+/i, depth: 0 },
    { pattern: /^hostname\s+\S+/i, depth: 0 },
    { pattern: /^log\s+/i, depth: 0 },
    { pattern: /^service\s+/i, depth: 0 },
    { pattern: /^debug\s+/i, depth: 0 },
    { pattern: /^no\s+debug\s+/i, depth: 0 },

    // FRR interface configuration
    { pattern: /^interface\s+\S+/i, depth: 0 },

    // FRR route-map, prefix-list, access-list
    { pattern: /^route-map\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ipv6\s+prefix-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+access-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+community-list\s+\S+/i, depth: 0 },
    { pattern: /^ip\s+as-path\s+access-list\s+\S+/i, depth: 0 },

    // FRR VRF configuration
    { pattern: /^vrf\s+\S+/i, depth: 0 },

    // FRR line configuration
    { pattern: /^line\s+vty/i, depth: 0 },

    // EVPN configuration
    { pattern: /^advertise-all-vni/i, depth: 0 },

    // PBR (Policy Based Routing)
    { pattern: /^pbr-map\s+\S+/i, depth: 0 },
    { pattern: /^nexthop-group\s+\S+/i, depth: 0 },

    // ============ DEPTH 1: Inside router blocks ============

    // BGP address families
    { pattern: /^address-family\s+ipv4\s+unicast/i, depth: 1 },
    { pattern: /^address-family\s+ipv6\s+unicast/i, depth: 1 },
    { pattern: /^address-family\s+l2vpn\s+evpn/i, depth: 1 },
    { pattern: /^address-family\s+ipv4\s+vpn/i, depth: 1 },
    { pattern: /^address-family\s+ipv6\s+vpn/i, depth: 1 },
    { pattern: /^address-family\s+ipv4\s+labeled-unicast/i, depth: 1 },
    { pattern: /^address-family\s+ipv6\s+labeled-unicast/i, depth: 1 },
    { pattern: /^address-family\s+ipv4\s+multicast/i, depth: 1 },
    { pattern: /^address-family\s+ipv6\s+multicast/i, depth: 1 },
    { pattern: /^address-family\s+ipv4\s+flowspec/i, depth: 1 },
    { pattern: /^address-family\s+ipv6\s+flowspec/i, depth: 1 },

    // BGP neighbor configuration (can be at depth 0 or 1 depending on context)
    { pattern: /^neighbor\s+\S+\s+/i, depth: 1 },

    // OSPF area configuration
    { pattern: /^area\s+\S+/i, depth: 1 },

    // VRF inside router
    { pattern: /^vrf\s+\S+/i, depth: 1 },

    // ============ DEPTH 2: Inside address-family ============

    // Network statements, redistribute, neighbor activation inside AF
    { pattern: /^network\s+/i, depth: 2 },
    { pattern: /^redistribute\s+/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s+activate/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s+route-map/i, depth: 2 },
    { pattern: /^neighbor\s+\S+\s+soft-reconfiguration/i, depth: 2 },
    { pattern: /^advertise-all-vni/i, depth: 2 },
    { pattern: /^advertise\s+/i, depth: 2 },
    { pattern: /^vni\s+\d+/i, depth: 2 },
  ],

  blockEnders: [
    /^exit-address-family$/i,
    /^exit-vrf$/i,
    /^exit$/i,
  ],
};
