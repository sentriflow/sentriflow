// packages/rule-helpers/src/cumulus/helpers.ts
// NVIDIA Cumulus Linux-specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, parseIp, prefixToMask } from '../common/helpers';

/**
 * Check if a node represents an NCLU command (net add/del)
 */
export const isNcluCommand = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('net ');
};

/**
 * Check if a node represents an NVUE command (nv set/unset)
 */
export const isNvueCommand = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('nv ');
};

/**
 * Check if a node represents an ifupdown2 interface stanza
 */
export const isIfaceStanza = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('iface ');
};

/**
 * Check if a node represents an auto interface stanza
 */
export const isAutoStanza = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('auto ');
};

/**
 * Check if interface is a switch port (swpN)
 */
export const isSwitchPort = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return /swp\d+/.test(name);
};

/**
 * Check if interface is a bond interface
 */
export const isBondInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return /bond\d+/.test(name);
};

/**
 * Check if interface is a bridge interface
 */
export const isBridgeInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('bridge') || name === 'br_default' || /^br\d+$/.test(name);
};

/**
 * Check if interface is a VLAN interface (SVI)
 */
export const isVlanInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return /vlan\d+/.test(name) || /_vlan\d+$/.test(name);
};

/**
 * Check if interface is the management interface
 */
export const isManagementInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name === 'eth0' || name === 'mgmt';
};

/**
 * Check if interface is a loopback
 */
export const isLoopback = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name === 'lo' || name.startsWith('loopback');
};

/**
 * Check if interface is a peerlink (MLAG)
 */
export const isPeerlink = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('peerlink');
};

/**
 * Check if an iface stanza has VLAN-aware bridge configuration
 */
export const isVlanAwareBridge = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bridge-vlan-aware') &&
    child.id.toLowerCase().includes('yes')
  );
};

/**
 * Get interface name from an iface or auto stanza
 */
export const getInterfaceName = (node: ConfigNode): string => {
  const parts = node.id.split(/\s+/);
  return parts[1] || node.id;
};

/**
 * Check if interface has an IP address configured
 */
export const hasAddress = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('address ')
  );
};

/**
 * Check if interface has a description/alias configured
 */
export const hasDescription = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('alias ')
  );
};

/**
 * Check if bridge has bridge-ports configured
 */
export const hasBridgePorts = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('bridge-ports ')
  );
};

/**
 * Check if bridge has bridge-vids (VLANs) configured
 */
export const hasBridgeVids = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('bridge-vids ')
  );
};

/**
 * Check if interface has MTU configured
 */
export const hasMtu = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('mtu ')
  );
};

/**
 * Check if interface has link-speed configured
 */
export const hasLinkSpeed = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('link-speed ')
  );
};

/**
 * Check if bond has bond-slaves configured
 */
export const hasBondSlaves = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('bond-slaves ')
  );
};

/**
 * Check if bond has clag-id configured
 */
export const hasClagId = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clag-id ')
  );
};

/**
 * Check if interface has STP bpdu-guard enabled
 */
export const hasBpduGuard = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bpduguard') &&
    child.id.toLowerCase().includes('yes')
  );
};

/**
 * Check if interface has STP portadminedge (portfast equivalent)
 */
export const hasPortAdminEdge = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('portadminedge') &&
    child.id.toLowerCase().includes('yes')
  );
};

/**
 * Find all iface stanzas in a configuration tree
 */
export const findIfaceStanzas = (root: ConfigNode): ConfigNode[] => {
  const result: ConfigNode[] = [];
  const traverse = (node: ConfigNode) => {
    if (isIfaceStanza(node)) {
      result.push(node);
    }
    for (const child of node.children) {
      traverse(child);
    }
  };
  traverse(root);
  return result;
};

/**
 * Find a stanza by name within a node's children
 */
export const findStanza = (
  node: ConfigNode,
  stanzaName: string
): ConfigNode | undefined => {
  return node.children.find(
    (child) => child.id.toLowerCase() === stanzaName.toLowerCase()
  );
};

/**
 * Find all stanzas starting with a prefix
 */
export const findStanzasByPrefix = (node: ConfigNode, prefix: string): ConfigNode[] => {
  return node.children.filter((child) =>
    child.id.toLowerCase().startsWith(prefix.toLowerCase())
  );
};

/**
 * Parse Cumulus address format (e.g., "10.0.0.1/24")
 */
export const parseCumulusAddress = (
  address: string
): { ip: number; prefix: number; mask: number } | null => {
  const parts = address.split('/');
  if (parts.length !== 2) return null;
  const [ipStr, prefixStr] = parts;
  if (!ipStr || !prefixStr) {
    return null;
  }

  const ip = parseIp(ipStr);
  const prefix = parseInt(prefixStr, 10);

  if (ip === null || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return null;
  }

  return {
    ip,
    prefix,
    mask: prefixToMask(prefix),
  };
};

/**
 * Check if a router bgp block has router-id configured
 */
export const hasBgpRouterId = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('bgp router-id ')
  );
};

/**
 * Check if a router bgp block has neighbors configured
 */
export const hasBgpNeighbors = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('neighbor ')
  );
};

/**
 * Get BGP neighbor address/interface from a neighbor command
 */
export const getBgpNeighborAddress = (neighborCmd: string): string => {
  const parts = neighborCmd.split(/\s+/);
  // Format: "neighbor <addr|interface> ..."
  return parts[1] || '';
};

/**
 * Check if CLAG/MLAG is configured in an interface
 */
export const hasClagConfig = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('clag')
  );
};

/**
 * Check if EVPN is configured
 */
export const hasEvpnConfig = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('l2vpn evpn') ||
    child.id.toLowerCase().includes('advertise-all-vni')
  );
};

// ============================================================================
// Management Plane Helpers
// ============================================================================

/**
 * Check if management interface is in management VRF
 * After the CUMULUS_FIX.md parser fix, vrf mgmt is correctly parsed as a child command of iface stanzas.
 */
export const hasManagementVrf = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('vrf mgmt') ||
    child.id.toLowerCase() === 'vrf mgmt'
  );
};

/**
 * Check if a VRF stanza is management VRF
 */
export const isManagementVrf = (interfaceName: string): boolean => {
  return interfaceName.toLowerCase() === 'mgmt';
};

// ============================================================================
// MLAG/CLAG Helpers
// ============================================================================

/**
 * Check if peerlink.4094 sub-interface for CLAG control
 */
export const isPeerlinkSubinterface = (interfaceName: string): boolean => {
  return interfaceName.toLowerCase().includes('peerlink.4094');
};

/**
 * Check if clagd-peer-ip is configured
 */
export const hasClagdPeerIp = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clagd-peer-ip ')
  );
};

/**
 * Check if clagd-backup-ip is configured
 */
export const hasClagdBackupIp = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clagd-backup-ip ')
  );
};

/**
 * Check if clagd-sys-mac is configured
 */
export const hasClagdSysMac = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clagd-sys-mac ')
  );
};

/**
 * Check if clagd-priority is configured
 */
export const hasClagdPriority = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clagd-priority ')
  );
};

/**
 * Validate clagd-sys-mac is in reserved range 44:38:39:ff:xx:xx
 */
export const isValidClagdSysMac = (node: ConfigNode): boolean => {
  const sysMacCmd = node.children.find((child) =>
    child.id.toLowerCase().startsWith('clagd-sys-mac ')
  );
  if (!sysMacCmd) return false;

  const match = sysMacCmd.id.match(/clagd-sys-mac\s+([0-9a-fA-F:]+)/i);
  if (!match?.[1]) return false;

  const mac = match[1].toLowerCase();
  // Reserved range: 44:38:39:ff:00:00 to 44:38:39:ff:ff:ff
  // Also accept 44:38:39:be:ef:xx for legacy
  return mac.startsWith('44:38:39:ff:') || mac.startsWith('44:38:39:be:ef:');
};

/**
 * Check if VRR (Virtual Router Redundancy) is configured
 */
export const hasVrrConfig = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('address-virtual ')
  );
};

// ============================================================================
// VLAN Helpers
// ============================================================================

/**
 * Get bridge-access VLAN ID from interface
 */
export const getBridgeAccessVlan = (node: ConfigNode): number | null => {
  const accessCmd = node.children.find((child) =>
    child.id.toLowerCase().startsWith('bridge-access ')
  );
  if (!accessCmd) return null;

  const match = accessCmd.id.match(/bridge-access\s+(\d+)/i);
  if (!match?.[1]) return null;

  return parseInt(match[1], 10);
};

/**
 * Get bridge-vids VLANs from bridge interface
 */
export const getBridgeVids = (node: ConfigNode): number[] => {
  const vidsCmd = node.children.find((child) =>
    child.id.toLowerCase().startsWith('bridge-vids ')
  );
  if (!vidsCmd) return [];

  const match = vidsCmd.id.match(/bridge-vids\s+(.+)/i);
  if (!match?.[1]) return [];

  return match[1]
    .split(/\s+/)
    .map((v) => parseInt(v, 10))
    .filter((v) => !isNaN(v));
};

/**
 * Get bridge-pvid (native VLAN) from bridge interface
 */
export const getBridgePvid = (node: ConfigNode): number | null => {
  const pvidCmd = node.children.find((child) =>
    child.id.toLowerCase().startsWith('bridge-pvid ')
  );
  if (!pvidCmd) return null;

  const match = pvidCmd.id.match(/bridge-pvid\s+(\d+)/i);
  if (!match?.[1]) return null;

  return parseInt(match[1], 10);
};

// ============================================================================
// VNI/VXLAN Helpers
// ============================================================================

/**
 * Check if interface is a VNI (VXLAN) interface
 */
export const isVniInterface = (interfaceName: string): boolean => {
  return /^vni\d+$/i.test(interfaceName) || /^vni[a-zA-Z]+$/i.test(interfaceName);
};

/**
 * Check if vxlan-local-tunnelip is configured on loopback
 */
export const hasVxlanLocalTunnelip = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('vxlan-local-tunnelip ')
  );
};

/**
 * Check if clagd-vxlan-anycast-ip is configured for MLAG+VXLAN
 */
export const hasVxlanAnycastIp = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('clagd-vxlan-anycast-ip ')
  );
};

/**
 * Check if bridge-arp-nd-suppress is enabled on VNI
 */
export const hasArpNdSuppress = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bridge-arp-nd-suppress') &&
    child.id.toLowerCase().includes('on')
  );
};

/**
 * Check if bridge-learning is disabled on VNI
 */
export const hasBridgeLearningOff = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bridge-learning') &&
    child.id.toLowerCase().includes('off')
  );
};

/**
 * Check if mstpctl-portbpdufilter is enabled on VNI
 */
export const hasPortBpduFilter = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('portbpdufilter') &&
    child.id.toLowerCase().includes('yes')
  );
};

/**
 * Check if vxlan-id is configured
 */
export const hasVxlanId = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().startsWith('vxlan-id ')
  );
};

// ============================================================================
// BGP Helpers
// ============================================================================

/**
 * Check if BGP authentication (password) is configured for a neighbor
 */
export const hasBgpNeighborPassword = (node: ConfigNode, neighborAddr: string): boolean => {
  if (!node?.children || !neighborAddr) return false;
  return node.children.some((child) => {
    const id = child?.id?.toLowerCase();
    return id?.startsWith(`neighbor ${neighborAddr.toLowerCase()} password`) ?? false;
  });
};

/**
 * Check if BGP peer-group has password configured
 */
export const hasBgpPeerGroupPassword = (node: ConfigNode, peerGroup: string): boolean => {
  if (!node?.children || !peerGroup) return false;
  return node.children.some((child) => {
    const id = child?.id?.toLowerCase();
    return id?.startsWith(`neighbor ${peerGroup.toLowerCase()} password`) ?? false;
  });
};

/**
 * Check if BGP maximum-prefix is configured for neighbor
 */
export const hasBgpMaximumPrefix = (node: ConfigNode, neighborAddr: string): boolean => {
  if (!node?.children || !neighborAddr) return false;
  return node.children.some((child) => {
    const id = child?.id?.toLowerCase();
    return id?.includes(`neighbor ${neighborAddr.toLowerCase()}`) && id?.includes('maximum-prefix');
  });
};

/**
 * Check if BFD is enabled for BGP neighbor
 */
export const hasBgpBfd = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) =>
    child?.id?.toLowerCase().includes(' bfd') ?? false
  );
};

/**
 * Check if BGP multipath is configured
 */
export const hasBgpMultipath = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bgp bestpath as-path multipath-relax') ||
    child.id.toLowerCase().includes('maximum-paths')
  );
};

/**
 * Get BGP peer groups from router bgp block
 */
export const getBgpPeerGroups = (node: ConfigNode): string[] => {
  const groups: string[] = [];
  for (const child of node.children) {
    const match = child.id.match(/neighbor\s+(\S+)\s+peer-group\s*$/i);
    if (match?.[1]) {
      groups.push(match[1]);
    }
  }
  return groups;
};

/**
 * Check if prefix-list is applied to BGP neighbor (inbound)
 */
export const hasBgpPrefixListIn = (node: ConfigNode, neighborOrGroup: string): boolean => {
  return node.children.some((child) => {
    const id = child.id.toLowerCase();
    return (
      id.includes(`neighbor ${neighborOrGroup.toLowerCase()}`) &&
      id.includes('prefix-list') &&
      id.includes(' in')
    );
  });
};

// ============================================================================
// Interface MTU Helpers
// ============================================================================

/**
 * Get MTU value from interface
 */
export const getMtu = (node: ConfigNode): number | null => {
  const mtuCmd = node.children.find((child) =>
    child.id.toLowerCase().startsWith('mtu ')
  );
  if (!mtuCmd) return null;

  const match = mtuCmd.id.match(/mtu\s+(\d+)/i);
  if (!match?.[1]) return null;

  return parseInt(match[1], 10);
};

/**
 * Check if interface is an uplink (swp5x pattern common for uplinks)
 */
export const isUplinkInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  // Common patterns: swp51, swp52, swp53, swp54 for uplinks to spine
  return /swp5[0-9]/.test(name);
};

// ============================================================================
// Storm Control Helpers
// ============================================================================

/**
 * Check if storm control is configured on interface
 */
export const hasStormControl = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('storm-control')
  );
};

// ============================================================================
// Port Isolation Helpers
// ============================================================================

/**
 * Check if bridge-port-isolation is enabled
 */
export const hasPortIsolation = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('bridge-port-isolation') &&
    child.id.toLowerCase().includes('on')
  );
};

// ============================================================================
// Root Guard Helpers
// ============================================================================

/**
 * Check if root guard (portrestrictedtcn) is enabled
 */
export const hasRootGuard = (node: ConfigNode): boolean => {
  return node.children.some((child) =>
    child.id.toLowerCase().includes('portrestrictedtcn') &&
    child.id.toLowerCase().includes('yes')
  );
};
