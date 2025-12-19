// packages/rule-helpers/src/aruba/helpers.ts
// Aruba-specific helper functions used across Aruba rules

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

/**
 * Extract the interface name from an interface stanza id.
 * @param node The interface ConfigNode
 * @returns The interface identifier without the leading keyword
 */
export const getInterfaceName = (node: ConfigNode): string | undefined => {
  const match = node.id.match(/interface\s+(.+)/i);
  const ifName = match?.[1]?.trim();
  return ifName && ifName.length > 0 ? ifName : undefined;
};

// =============================================================================
// AOS-CX Helpers
// =============================================================================

/**
 * Check if an AOS-CX interface is a physical port (slot/member/port format).
 * @param interfaceName The interface identifier
 * @returns true if it's a physical port (e.g., 1/1/1)
 */
export const isAosCxPhysicalPort = (interfaceName: string): boolean => {
  return /^\d+\/\d+\/\d+$/.test(interfaceName.trim());
};

/**
 * Check if an AOS-CX interface is a LAG.
 * @param interfaceName The interface identifier
 * @returns true if it's a LAG interface
 */
export const isAosCxLag = (interfaceName: string): boolean => {
  return /^lag\s*\d+$/i.test(interfaceName.trim());
};

/**
 * Check if an AOS-CX interface is a VLAN interface.
 * @param interfaceName The interface identifier
 * @returns true if it's a VLAN interface
 */
export const isAosCxVlanInterface = (interfaceName: string): boolean => {
  return /^vlan\s*\d+$/i.test(interfaceName.trim());
};

/**
 * Check if an AOS-CX interface is configured as trunk mode.
 * @param node The interface ConfigNode
 * @returns true if the interface has trunk VLAN configuration
 */
export const isAosCxTrunk = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'vlan trunk');
};

/**
 * Check if an AOS-CX interface is configured as access mode.
 * @param node The interface ConfigNode
 * @returns true if the interface has access VLAN configuration
 */
export const isAosCxAccess = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'vlan access');
};

/**
 * Get the access VLAN ID from an AOS-CX interface.
 * @param node The interface ConfigNode
 * @returns The VLAN ID, or null if not configured
 */
export const getAosCxVlanAccess = (node: ConfigNode): number | null => {
  const cmd = getChildCommand(node, 'vlan access');
  if (!cmd) return null;
  const match = cmd.id.match(/vlan\s+access\s+(\d+)/i);
  const vlanId = match?.[1];
  if (!vlanId) {
    return null;
  }
  return parseInt(vlanId, 10);
};

/**
 * Get the native VLAN ID from an AOS-CX trunk interface.
 * @param node The interface ConfigNode
 * @returns The native VLAN ID, or null if not configured
 */
export const getAosCxTrunkNative = (node: ConfigNode): number | null => {
  const cmd = getChildCommand(node, 'vlan trunk native');
  if (!cmd) return null;
  const match = cmd.id.match(/vlan\s+trunk\s+native\s+(\d+)/i);
  const vlanId = match?.[1];
  if (!vlanId) {
    return null;
  }
  return parseInt(vlanId, 10);
};

/**
 * Get allowed VLANs from an AOS-CX trunk interface.
 * @param node The interface ConfigNode
 * @returns Array of allowed VLAN IDs, or empty array if not configured
 */
export const getAosCxTrunkAllowed = (node: ConfigNode): number[] => {
  const cmd = getChildCommand(node, 'vlan trunk allowed');
  if (!cmd) return [];
  const match = cmd.id.match(/vlan\s+trunk\s+allowed\s+([\d,]+)/i);
  const vlanList = match?.[1];
  if (!vlanList) return [];
  return vlanList
    .split(',')
    .map((v) => parseInt(v.trim(), 10))
    .filter((v) => !isNaN(v));
};

/**
 * Check if an AOS-CX interface has BPDU guard enabled.
 * @param node The interface ConfigNode
 * @returns true if BPDU guard is configured
 */
export const hasAosCxBpduGuard = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'spanning-tree bpdu-guard');
};

/**
 * Check if an AOS-CX interface is an admin-edge port.
 * @param node The interface ConfigNode
 * @returns true if admin-edge is configured
 */
export const isAosCxEdgePort = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'spanning-tree port-type admin-edge');
};

/**
 * Check if an AOS-CX interface has root-guard enabled.
 * @param node The interface ConfigNode
 * @returns true if root-guard is configured
 */
export const hasAosCxRootGuard = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'spanning-tree root-guard');
};

/**
 * Check if an AOS-CX interface has loop-protect enabled.
 * @param node The interface ConfigNode
 * @returns true if loop-protect is configured
 */
export const hasAosCxLoopProtect = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'loop-protect');
};

/**
 * Check if an AOS-CX interface has storm-control configured.
 * @param node The interface ConfigNode
 * @returns true if any storm-control setting is configured
 */
export const hasAosCxStormControl = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'storm-control');
};

/**
 * Check if an AOS-CX interface has DHCP snooping trust configured.
 * @param node The interface ConfigNode
 * @returns true if dhcp-snooping trust is configured
 */
export const hasAosCxDhcpSnooping = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'dhcp-snooping');
};

/**
 * Check if an AOS-CX interface has ARP inspection trust configured.
 * @param node The interface ConfigNode
 * @returns true if ip arp inspection trust is configured
 */
export const hasAosCxArpInspection = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'ip arp inspection');
};

/**
 * Check if an AOS-CX interface has IP source guard (source-binding) configured.
 * @param node The interface ConfigNode
 * @returns true if ip source-binding is configured
 */
export const hasAosCxIpSourceGuard = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'ip source-binding');
};

/**
 * Check if an AOS-CX interface has port security configured.
 * @param node The interface ConfigNode
 * @returns true if port-access port-security is configured
 */
export const hasAosCxPortSecurity = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'port-access port-security');
};

/**
 * Check if an AOS-CX interface has 802.1X authenticator configured.
 * @param node The interface ConfigNode
 * @returns true if dot1x authenticator is configured
 */
export const hasAosCxDot1x = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'aaa authentication port-access dot1x');
};

/**
 * Check if an AOS-CX interface has MAC authentication configured.
 * @param node The interface ConfigNode
 * @returns true if mac-auth is configured
 */
export const hasAosCxMacAuth = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'aaa authentication port-access mac-auth');
};

/**
 * Get MSTP region name from global config.
 * @param node The spanning-tree config-name node
 * @returns The region name, or undefined
 */
export const getAosCxMstpRegionName = (node: ConfigNode): string | undefined => {
  const match = node.id.match(/spanning-tree\s+config-name\s+(\S+)/i);
  return match?.[1];
};

/**
 * Check if an AOS-CX interface has MACsec configured.
 * @param node The interface ConfigNode
 * @returns true if MACsec policy is applied
 */
export const hasAosCxMacsec = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'apply macsec policy') || hasChildCommand(node, 'apply mka policy');
};

// =============================================================================
// AOS-Switch Helpers
// =============================================================================

/**
 * Parse port range string to array of port numbers.
 * Handles formats like "1-24", "25,26,27", "1-24,48"
 * @param portStr The port range string
 * @returns Array of individual port numbers
 */
export const parsePortRange = (portStr: string): number[] => {
  const ports: number[] = [];
  const parts = portStr.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes('-')) {
      const [startRaw, endRaw] = trimmed
        .split('-')
        .map((n) => parseInt(n.trim(), 10));
      if (
        startRaw === undefined ||
        endRaw === undefined ||
        isNaN(startRaw) ||
        isNaN(endRaw)
      ) {
        continue;
      }
      for (let i = startRaw; i <= endRaw; i++) {
        ports.push(i);
      }
    } else {
      const num = parseInt(trimmed, 10);
      if (!isNaN(num)) {
        ports.push(num);
      }
    }
  }

  return ports;
};

/**
 * Get tagged ports from an AOS-Switch VLAN node.
 * @param node The VLAN ConfigNode
 * @returns Array of tagged port numbers
 */
export const getVlanTaggedPorts = (node: ConfigNode): (number | string)[] => {
  const cmd = getChildCommand(node, 'tagged');
  if (!cmd) return [];
  const match = cmd.id.match(/tagged\s+(.*)/i);
  const taggedList = match?.[1];
  if (!taggedList) return [];

  const result: (number | string)[] = [];
  const parts = taggedList.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (/^trk\d+$/i.test(trimmed)) {
      result.push(trimmed.toLowerCase());
    } else if (trimmed.includes('-')) {
      result.push(...parsePortRange(trimmed));
    } else {
      const num = parseInt(trimmed, 10);
      if (!isNaN(num)) {
        result.push(num);
      }
    }
  }

  return result;
};

/**
 * Get untagged ports from an AOS-Switch VLAN node.
 * @param node The VLAN ConfigNode
 * @returns Array of untagged port numbers
 */
export const getVlanUntaggedPorts = (node: ConfigNode): (number | string)[] => {
  const cmd = getChildCommand(node, 'untagged');
  if (!cmd) return [];
  const match = cmd.id.match(/untagged\s+(.*)/i);
  const untaggedList = match?.[1];
  if (!untaggedList) return [];

  const result: (number | string)[] = [];
  const parts = untaggedList.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (/^trk\d+$/i.test(trimmed)) {
      result.push(trimmed.toLowerCase());
    } else if (trimmed.includes('-')) {
      result.push(...parsePortRange(trimmed));
    } else {
      const num = parseInt(trimmed, 10);
      if (!isNaN(num)) {
        result.push(num);
      }
    }
  }

  return result;
};

/**
 * Get the VLAN name from an AOS-Switch VLAN node.
 * @param node The VLAN ConfigNode
 * @returns The VLAN name, or undefined if not set
 */
export const getAosSwitchVlanName = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'name');
  if (!cmd) return undefined;
  const match = cmd.id.match(/name\s+["']?([^"']+)["']?/i);
  const name = match?.[1];
  return name?.trim();
};

/**
 * Check if AOS-Switch has manager password configured.
 * @param nodes Array of top-level ConfigNodes (AST children)
 * @returns true if manager password is configured
 */
export const hasManagerPassword = (nodes: ConfigNode[]): boolean => {
  return nodes.some((n) => n.id.toLowerCase().startsWith('password manager'));
};

/**
 * Check if AOS-Switch has operator password configured.
 * @param nodes Array of top-level ConfigNodes (AST children)
 * @returns true if operator password is configured
 */
export const hasOperatorPassword = (nodes: ConfigNode[]): boolean => {
  return nodes.some((n) => n.id.toLowerCase().startsWith('password operator'));
};

// =============================================================================
// WLC Helpers
// =============================================================================

/**
 * Get the WLAN encryption mode from an SSID profile.
 * @param node The SSID profile ConfigNode
 * @returns The opmode value (e.g., 'wpa3-sae-aes', 'wpa2-aes', 'opensystem'), or null
 */
export const getWlanEncryption = (node: ConfigNode): string | null => {
  const cmd = getChildCommand(node, 'opmode');
  if (!cmd) return null;
  const match = cmd.id.match(/opmode\s+(\S+)/i);
  const mode = match?.[1];
  return mode ? mode.toLowerCase() : null;
};

/**
 * Check if a WLAN SSID profile has secure encryption (WPA2/WPA3).
 * @param node The SSID profile ConfigNode
 * @returns true if encryption is WPA2 or WPA3
 */
export const hasSecureEncryption = (node: ConfigNode): boolean => {
  const opmode = getWlanEncryption(node);
  if (!opmode) return false;
  return opmode.includes('wpa2') || opmode.includes('wpa3') || opmode.includes('aes');
};

/**
 * Check if a WLAN SSID profile is open (no encryption).
 * @param node The SSID profile ConfigNode
 * @returns true if the SSID is open/unencrypted
 */
export const isOpenSsid = (node: ConfigNode): boolean => {
  const opmode = getWlanEncryption(node);
  return opmode === 'opensystem' || opmode === 'open';
};

/**
 * Get the ESSID from a WLAN SSID profile.
 * @param node The SSID profile ConfigNode
 * @returns The ESSID value, or undefined
 */
export const getEssid = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'essid');
  if (!cmd) return undefined;
  const match = cmd.id.match(/essid\s+["']?([^"'\n]+)["']?/i);
  const essid = match?.[1];
  return essid?.trim();
};

/**
 * Get the AAA profile reference from a virtual-AP profile.
 * @param node The virtual-AP ConfigNode
 * @returns The AAA profile name, or undefined
 */
export const getVapAaaProfile = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'aaa-profile');
  if (!cmd) return undefined;
  const match = cmd.id.match(/aaa-profile\s+["']?([^"'\n]+)["']?/i);
  const profile = match?.[1];
  return profile?.trim();
};

/**
 * Get the SSID profile reference from a virtual-AP profile.
 * @param node The virtual-AP ConfigNode
 * @returns The SSID profile name, or undefined
 */
export const getVapSsidProfile = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'ssid-profile');
  if (!cmd) return undefined;
  const match = cmd.id.match(/ssid-profile\s+["']?([^"'\n]+)["']?/i);
  const profile = match?.[1];
  return profile?.trim();
};

/**
 * Get virtual-APs from an AP group.
 * @param node The AP group ConfigNode
 * @returns Array of virtual-AP names
 */
export const getApGroupVirtualAps = (node: ConfigNode): string[] => {
  const vaps: string[] = [];
  for (const child of node.children) {
    const match = child.id.match(/virtual-ap\s+["']?([^"'\n]+)["']?/i);
    const vapName = match?.[1];
    if (vapName) {
      vaps.push(vapName);
    }
  }
  return vaps;
};

/**
 * Check if RADIUS server has a key configured.
 * @param node The RADIUS server ConfigNode
 * @returns true if a key is configured
 */
export const hasRadiusKey = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'key');
};

/**
 * Get the RADIUS server host address.
 * @param node The RADIUS server ConfigNode
 * @returns The host IP/hostname, or undefined
 */
export const getRadiusHost = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'host');
  if (!cmd) return undefined;
  const match = cmd.id.match(/host\s+(\S+)/i);
  const host = match?.[1];
  return host?.trim();
};

/**
 * Extract profile name from a profile definition node.
 * Handles both quoted and unquoted names.
 * @param nodeId The node identifier string
 * @returns The profile name, or undefined
 */
export const extractProfileName = (nodeId: string): string | undefined => {
  // Match patterns like: wlan ssid-profile "Name" or aaa profile "Name"
  const match = nodeId.match(/(?:ssid-profile|virtual-ap|profile|server-group|ap-group|arm-profile)\s+["']?([^"'\n]+)["']?$/i);
  const profile = match?.[1];
  return profile ? profile.trim() : undefined;
};

/**
 * Check if a WLAN SSID profile uses WPA3.
 * @param node The SSID profile ConfigNode
 * @returns true if encryption is WPA3
 */
export const hasWpa3Encryption = (node: ConfigNode): boolean => {
  const opmode = getWlanEncryption(node);
  if (!opmode) return false;
  return opmode.includes('wpa3');
};

/**
 * Check if a WLAN SSID profile uses WPA3-Enterprise.
 * @param node The SSID profile ConfigNode
 * @returns true if encryption is WPA3-Enterprise
 */
export const hasWpa3Enterprise = (node: ConfigNode): boolean => {
  const opmode = getWlanEncryption(node);
  if (!opmode) return false;
  return opmode.includes('wpa3') && !opmode.includes('sae');
};

/**
 * Check if a WLAN SSID profile uses WPA3-SAE (Personal).
 * @param node The SSID profile ConfigNode
 * @returns true if encryption is WPA3-SAE
 */
export const hasWpa3Sae = (node: ConfigNode): boolean => {
  const opmode = getWlanEncryption(node);
  if (!opmode) return false;
  return opmode.includes('wpa3') && opmode.includes('sae');
};

/**
 * Check if Protected Management Frames (PMF/802.11w) is enabled.
 * @param node The SSID profile ConfigNode
 * @returns 'required' | 'optional' | null
 */
export const getPmfMode = (node: ConfigNode): 'required' | 'optional' | null => {
  const cmd = getChildCommand(node, 'mgmt-frame-protection');
  if (!cmd) return null;
  const id = cmd.id.toLowerCase();
  if (id.includes('required')) return 'required';
  if (id.includes('optional')) return 'optional';
  return null;
};

/**
 * Check if SSID profile is configured for 6 GHz band.
 * @param node The SSID profile ConfigNode
 * @returns true if 6ghz band is configured
 */
export const is6GhzSsid = (node: ConfigNode): boolean => {
  const cmd = getChildCommand(node, 'band');
  if (!cmd) return false;
  return cmd.id.toLowerCase().includes('6ghz');
};

/**
 * Get max clients limit from SSID profile.
 * @param node The SSID profile ConfigNode
 * @returns The max clients value, or null
 */
export const getMaxClients = (node: ConfigNode): number | null => {
  const cmd = getChildCommand(node, 'max-clients');
  if (!cmd) return null;
  const match = cmd.id.match(/max-clients\s+(\d+)/i);
  return match?.[1] ? parseInt(match[1], 10) : null;
};

/**
 * Check if CPsec (Control Plane Security) is enabled on WLC.
 * @param node The control-plane-security ConfigNode
 * @returns true if cpsec is enabled
 */
export const hasCpsecEnabled = (node: ConfigNode): boolean => {
  return !node.id.toLowerCase().includes('disable');
};

/**
 * Check if whitelist-db is enabled for AP authorization.
 * @param node The cpsec ConfigNode
 * @returns true if whitelist-db is enabled
 */
export const hasWhitelistDb = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'whitelist-db enable');
};

// =============================================================================
// Common Aruba Helpers
// =============================================================================

/**
 * Find a child stanza by exact name match.
 * @param node The parent ConfigNode
 * @param stanzaName The stanza name to find
 * @returns The matching child node, or undefined
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
 * Find all stanzas matching a pattern within a node's children.
 * @param node The parent ConfigNode
 * @param pattern The regex pattern to match
 * @returns Array of matching child nodes
 */
export const findStanzas = (node: ConfigNode, pattern: RegExp): ConfigNode[] => {
  return node.children.filter((child) => pattern.test(child.id.toLowerCase()));
};

/**
 * Check if an interface/node has a description configured.
 * @param node The ConfigNode
 * @returns true if a description command exists
 */
export const hasDescription = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'description');
};

/**
 * Get the description from a node.
 * @param node The ConfigNode
 * @returns The description text, or undefined
 */
export const getDescription = (node: ConfigNode): string | undefined => {
  const cmd = getChildCommand(node, 'description');
  if (!cmd) return undefined;
  const match = cmd.id.match(/description\s+["']?(.+?)["']?$/i);
  const description = match?.[1];
  return description?.trim();
};
