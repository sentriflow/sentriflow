// packages/rule-helpers/src/vyos/helpers.ts
// VyOS/EdgeOS-specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, parseIp, prefixToMask } from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands, parseIp } from '../common/helpers';

/**
 * Check if a VyOS interface is disabled (has "disable" statement)
 */
export const isDisabled = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => child?.id?.toLowerCase().trim() === 'disable');
};

/**
 * Check if interface is a physical ethernet port (ethX)
 */
export const isPhysicalVyosPort = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  // VyOS physical ethernet interfaces: ethernet ethX
  // Match patterns like "ethernet eth0", "ethernet eth1", etc.
  if (name.startsWith('ethernet eth')) {
    return true;
  }
  // Also match just "ethX" if encountered directly
  return /^eth\d+$/.test(name);
};

/**
 * Check if interface is a loopback
 */
export const isLoopback = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('loopback') || name === 'lo';
};

/**
 * Check if interface is a bonding interface
 */
export const isBondingInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('bonding') || /^bond\d+$/.test(name);
};

/**
 * Check if interface is a bridge interface
 */
export const isBridgeInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('bridge') || /^br\d+$/.test(name);
};

/**
 * Check if interface is a WireGuard interface
 */
export const isWireGuardInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.includes('wireguard') || /^wg\d+$/.test(name);
};

/**
 * Check if interface is a tunnel interface
 */
export const isTunnelInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return (
    name.includes('tunnel') ||
    name.includes('vti') ||
    name.includes('vxlan') ||
    /^(tun|vti|vxlan)\d+$/.test(name)
  );
};

/**
 * Parse VyOS address format (e.g., "10.0.0.1/24")
 * @param address The address string with CIDR notation
 * @returns Object with ip number, prefix length, and mask, or null if invalid
 */
export const parseVyosAddress = (
  address: string
): { ip: number; prefix: number; mask: number } | null => {
  // Remove quotes if present
  const cleanAddress = address.replace(/['"]/g, '');
  const parts = cleanAddress.split('/');
  if (parts.length !== 2) return null;

  const ipPart = parts[0];
  const prefixPart = parts[1];
  if (!ipPart || !prefixPart) return null;

  const ip = parseIp(ipPart);
  const prefix = parseInt(prefixPart, 10);

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
 * Find a stanza by name within a node's children
 * @param node The parent ConfigNode
 * @param stanzaName The stanza name to find
 * @returns The matching child node, or undefined
 */
export const findStanza = (
  node: ConfigNode,
  stanzaName: string
): ConfigNode | undefined => {
  if (!node?.children) return undefined;
  return node.children.find(
    (child) => child?.id?.toLowerCase() === stanzaName.toLowerCase()
  );
};

/**
 * Find stanza by prefix (starts with)
 * @param node The parent ConfigNode
 * @param prefix The prefix to match
 * @returns The matching child node, or undefined
 */
export const findStanzaByPrefix = (
  node: ConfigNode,
  prefix: string
): ConfigNode | undefined => {
  if (!node?.children) return undefined;
  return node.children.find((child) =>
    child?.id?.toLowerCase().startsWith(prefix.toLowerCase())
  );
};

/**
 * Find all stanzas matching a pattern within a node's children
 * @param node The parent ConfigNode
 * @param pattern The regex pattern to match
 * @returns Array of matching child nodes
 */
export const findStanzas = (node: ConfigNode, pattern: RegExp): ConfigNode[] => {
  if (!node?.children) return [];
  return node.children.filter((child) => child?.id && pattern.test(child.id.toLowerCase()));
};

/**
 * Find all stanzas starting with a prefix
 * @param node The parent ConfigNode
 * @param prefix The prefix to match
 * @returns Array of matching child nodes
 */
export const findStanzasByPrefix = (node: ConfigNode, prefix: string): ConfigNode[] => {
  if (!node?.children) return [];
  return node.children.filter((child) =>
    child?.id?.toLowerCase().startsWith(prefix.toLowerCase())
  );
};

/**
 * Get all ethernet interfaces from the interfaces node
 * @param interfacesNode The interfaces ConfigNode
 * @returns Array of ethernet interface nodes
 */
export const getEthernetInterfaces = (interfacesNode: ConfigNode): ConfigNode[] => {
  if (!interfacesNode?.children) return [];
  return interfacesNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('ethernet eth')
  );
};

/**
 * Get VIF (VLAN) subinterfaces from an interface node
 * @param interfaceNode The interface ConfigNode
 * @returns Array of vif nodes
 */
export const getVifInterfaces = (interfaceNode: ConfigNode): ConfigNode[] => {
  if (!interfaceNode?.children) return [];
  return interfaceNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('vif')
  );
};

/**
 * Check if a firewall ruleset has a default action set
 * @param rulesetNode The firewall ruleset (name X) ConfigNode
 * @returns The default action ('drop', 'accept', 'reject') or undefined
 */
export const getFirewallDefaultAction = (
  rulesetNode: ConfigNode
): 'drop' | 'accept' | 'reject' | undefined => {
  if (!rulesetNode?.children) return undefined;
  for (const child of rulesetNode.children) {
    const id = child?.id?.toLowerCase().trim();
    if (!id) continue;
    if (id.startsWith('default-action')) {
      if (id.includes('drop')) return 'drop';
      if (id.includes('accept')) return 'accept';
      if (id.includes('reject')) return 'reject';
    }
  }
  return undefined;
};

/**
 * Get all firewall rules from a ruleset
 * @param rulesetNode The firewall ruleset ConfigNode
 * @returns Array of rule nodes
 */
export const getFirewallRules = (rulesetNode: ConfigNode): ConfigNode[] => {
  if (!rulesetNode?.children) return [];
  return rulesetNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('rule')
  );
};

/**
 * Get the action of a firewall rule
 * @param ruleNode The firewall rule ConfigNode
 * @returns The action ('drop', 'accept', 'reject') or undefined
 */
export const getFirewallRuleAction = (
  ruleNode: ConfigNode
): 'drop' | 'accept' | 'reject' | undefined => {
  if (!ruleNode?.children) return undefined;
  for (const child of ruleNode.children) {
    const id = child?.id?.toLowerCase().trim();
    if (!id) continue;
    if (id.startsWith('action')) {
      if (id.includes('drop')) return 'drop';
      if (id.includes('accept')) return 'accept';
      if (id.includes('reject')) return 'reject';
    }
  }
  return undefined;
};

/**
 * Check if a NAT rule has translation configured
 * @param ruleNode The NAT rule ConfigNode
 * @returns true if translation is configured
 */
export const hasNatTranslation = (ruleNode: ConfigNode): boolean => {
  if (!ruleNode?.children) return false;
  return ruleNode.children.some((child) =>
    child?.id?.toLowerCase().startsWith('translation')
  );
};

/**
 * Check if SSH service is configured in a service node
 * @param serviceNode The service ConfigNode
 * @returns true if SSH is configured
 */
export const hasSshService = (serviceNode: ConfigNode): boolean => {
  if (!serviceNode?.children) return false;
  return serviceNode.children.some((child) =>
    child?.id?.toLowerCase().startsWith('ssh')
  );
};

/**
 * Get SSH configuration from service node
 * @param serviceNode The service ConfigNode
 * @returns The SSH configuration node, or undefined
 */
export const getSshConfig = (serviceNode: ConfigNode): ConfigNode | undefined => {
  if (!serviceNode?.children) return undefined;
  return serviceNode.children.find((child) =>
    child?.id?.toLowerCase().startsWith('ssh')
  );
};

/**
 * Check if DHCP server is configured
 * @param serviceNode The service ConfigNode
 * @returns true if DHCP server is configured
 */
export const hasDhcpServer = (serviceNode: ConfigNode): boolean => {
  if (!serviceNode?.children) return false;
  return serviceNode.children.some((child) =>
    child?.id?.toLowerCase().startsWith('dhcp-server')
  );
};

/**
 * Get DNS forwarding configuration
 * @param serviceNode The service ConfigNode
 * @returns The DNS configuration node, or undefined
 */
export const getDnsConfig = (serviceNode: ConfigNode): ConfigNode | undefined => {
  if (!serviceNode?.children) return undefined;
  return serviceNode.children.find((child) =>
    child?.id?.toLowerCase().startsWith('dns')
  );
};

/**
 * Check if a system node has NTP configured
 * @param systemNode The system ConfigNode
 * @returns true if NTP is configured
 */
export const hasNtpConfig = (systemNode: ConfigNode): boolean => {
  if (!systemNode?.children) return false;
  return systemNode.children.some((child) =>
    child?.id?.toLowerCase().startsWith('ntp')
  );
};

/**
 * Check if a system node has syslog configured
 * @param systemNode The system ConfigNode
 * @returns true if syslog is configured
 */
export const hasSyslogConfig = (systemNode: ConfigNode): boolean => {
  if (!systemNode?.children) return false;
  return systemNode.children.some((child) =>
    child?.id?.toLowerCase().startsWith('syslog')
  );
};

/**
 * Get the login configuration from system node
 * @param systemNode The system ConfigNode
 * @returns The login configuration node, or undefined
 */
export const getLoginConfig = (systemNode: ConfigNode): ConfigNode | undefined => {
  if (!systemNode?.children) return undefined;
  return systemNode.children.find((child) =>
    child?.id?.toLowerCase().startsWith('login')
  );
};

/**
 * Get all user configurations from login node
 * @param loginNode The login ConfigNode
 * @returns Array of user nodes
 */
export const getUserConfigs = (loginNode: ConfigNode): ConfigNode[] => {
  if (!loginNode?.children) return [];
  return loginNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('user')
  );
};

/**
 * Get all interfaces that are members of a switch (switch-port)
 * These interfaces don't need individual IP addresses as the switch has the address
 * @param interfacesNode The interfaces ConfigNode
 * @returns Set of interface names (e.g., 'eth1', 'eth2') that are switch members
 */
export const getSwitchPortMembers = (interfacesNode: ConfigNode): Set<string> => {
  const members = new Set<string>();
  if (!interfacesNode?.children) return members;

  // Find all switch interfaces (switch switchX)
  const switches = interfacesNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('switch ')
  );

  for (const switchNode of switches) {
    if (!switchNode?.children) continue;
    // Find switch-port section
    const switchPort = switchNode.children.find((child) =>
      child?.id?.toLowerCase() === 'switch-port'
    );

    if (switchPort?.children) {
      // Find all interface members (interface ethX)
      for (const child of switchPort.children) {
        const match = child?.id?.toLowerCase().match(/^interface\s+(eth\d+)$/);
        if (match?.[1]) {
          members.add(match[1]);
        }
      }
    }
  }

  return members;
};

/**
 * Get all interfaces that are members of a bridge
 * These interfaces don't need individual IP addresses as the bridge has the address
 * @param interfacesNode The interfaces ConfigNode
 * @returns Set of interface names that are bridge members
 */
export const getBridgeMembers = (interfacesNode: ConfigNode): Set<string> => {
  const members = new Set<string>();
  if (!interfacesNode?.children) return members;

  // Find all bridge interfaces (bridge brX)
  const bridges = interfacesNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('bridge ')
  );

  for (const bridgeNode of bridges) {
    if (!bridgeNode?.children) continue;
    // Find member section
    const memberSection = bridgeNode.children.find((child) =>
      child?.id?.toLowerCase() === 'member'
    );

    if (memberSection?.children) {
      // Find all interface members within the member section
      for (const child of memberSection.children) {
        const match = child?.id?.toLowerCase().match(/^interface\s+(\S+)$/);
        if (match?.[1]) {
          members.add(match[1]);
        }
      }
    }
  }

  return members;
};

/**
 * Get all interfaces that are members of a bonding group
 * These interfaces don't need individual IP addresses as the bond has the address
 * @param interfacesNode The interfaces ConfigNode
 * @returns Set of interface names that are bonding members
 */
export const getBondingMembers = (interfacesNode: ConfigNode): Set<string> => {
  const members = new Set<string>();
  if (!interfacesNode?.children) return members;

  // Find all bonding interfaces (bonding bondX)
  const bonds = interfacesNode.children.filter((child) =>
    child?.id?.toLowerCase().startsWith('bonding ')
  );

  for (const bondNode of bonds) {
    if (!bondNode?.children) continue;
    // Find member section
    const memberSection = bondNode.children.find((child) =>
      child?.id?.toLowerCase() === 'member'
    );

    if (memberSection?.children) {
      // Find all interface members within the member section
      for (const child of memberSection.children) {
        const match = child?.id?.toLowerCase().match(/^interface\s+(\S+)$/);
        if (match?.[1]) {
          members.add(match[1]);
        }
      }
    }
  }

  return members;
};
