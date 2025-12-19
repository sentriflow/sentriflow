// packages/rule-helpers/src/mikrotik/helpers.ts
// MikroTik RouterOS-specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { parseIp, prefixToMask } from '../common/helpers';

/**
 * Check if a MikroTik resource is disabled (has disabled=yes property)
 */
export const isDisabledResource = (nodeOrCommand: ConfigNode | string): boolean => {
  const id = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const lower = id.toLowerCase();
  return (
    /\bdisabled=yes\b/i.test(lower) ||
    /\bdisabled="?yes"?\b/i.test(lower)
  );
};

/**
 * Check if interface is a physical ethernet port (ether1, ether2, etc.)
 */
export const isPhysicalInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  // MikroTik physical ethernet interfaces: ether1, ether2, etc.
  // Also match sfp1, sfp-sfpplus1, combo1, etc.
  return /^ether\d+$/.test(name) ||
         /^sfp\d+$/.test(name) ||
         /^sfp-sfpplus\d+$/.test(name) ||
         /^combo\d+$/.test(name) ||
         /^qsfp\d+$/.test(name);
};

/**
 * Check if interface is a loopback
 */
export const isLoopback = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name === 'lo' || name.startsWith('loopback');
};

/**
 * Check if interface is a bridge
 */
export const isBridgeInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.startsWith('bridge') || /^br\d+$/.test(name);
};

/**
 * Check if interface is a VLAN
 */
export const isVlanInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.startsWith('vlan') || /^vlan\d+$/.test(name);
};

/**
 * Check if interface is a bonding (LAG)
 */
export const isBondingInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.startsWith('bonding') || /^bond\d+$/.test(name);
};

/**
 * Check if interface is WireGuard
 */
export const isWireGuardInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return name.startsWith('wireguard') || /^wg\d+$/.test(name);
};

/**
 * Check if interface is a tunnel type
 */
export const isTunnelInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return (
    name.startsWith('eoip') ||
    name.startsWith('gre') ||
    name.startsWith('ipip') ||
    name.startsWith('vxlan') ||
    name.startsWith('l2tp') ||
    name.startsWith('pptp') ||
    name.startsWith('sstp') ||
    name.startsWith('ovpn') ||
    name.startsWith('pppoe')
  );
};

/**
 * Parse a MikroTik property value from a command string
 * Example: parseProperty("add address=192.168.1.1/24 interface=LAN", "address") returns "192.168.1.1/24"
 */
export const parseProperty = (commandStr: string, propertyName: string): string | undefined => {
  // Match property=value or property="value" or property='value'
  const regex = new RegExp(`\\b${propertyName}=(?:"([^"]+)"|'([^']+)'|(\\S+))`, 'i');
  const match = commandStr.match(regex);
  if (match) {
    return match[1] || match[2] || match[3];
  }
  return undefined;
};

/**
 * Check if a command/node has a specific property
 */
export const hasProperty = (nodeOrCommand: ConfigNode | string, propertyName: string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const regex = new RegExp(`\\b${propertyName}=`, 'i');
  return regex.test(str);
};

/**
 * Get the firewall chain from a firewall rule command
 */
export const getFirewallChain = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'chain');
};

/**
 * Get the firewall action from a firewall rule command
 */
export const getFirewallAction = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'action');
};

/**
 * Get the interface from a command
 */
export const getInterface = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  // Try 'interface=' first, then 'in-interface=' or 'out-interface='
  return parseProperty(str, 'interface') ||
         parseProperty(str, 'in-interface') ||
         parseProperty(str, 'out-interface');
};

/**
 * Get the comment from a command
 */
export const getComment = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'comment');
};

/**
 * Get the name property from a command
 */
export const getName = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'name');
};

/**
 * Check if a command is an 'add' command
 */
export const isAddCommand = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return /^add\s+/i.test(str.trim());
};

/**
 * Check if a command is a 'set' command
 */
export const isSetCommand = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return /^set\s+/i.test(str.trim());
};

/**
 * Get all 'add' commands from a node's children
 */
export const getAddCommands = (node: ConfigNode): ConfigNode[] => {
  return node.children.filter((child) => isAddCommand(child));
};

/**
 * Get all 'set' commands from a node's children
 */
export const getSetCommands = (node: ConfigNode): ConfigNode[] => {
  return node.children.filter((child) => isSetCommand(child));
};

/**
 * Check if a path block matches a specific path
 * Example: isPathBlock(node, '/ip firewall filter') checks if node.id matches
 */
export const isPathBlock = (node: ConfigNode, path: string): boolean => {
  const nodeId = node.id.toLowerCase().trim();
  const targetPath = path.toLowerCase().trim();
  return nodeId === targetPath || nodeId.startsWith(targetPath + ' ');
};

/**
 * Find a child node that matches a path pattern
 */
export const findPathBlock = (node: ConfigNode, pathPrefix: string): ConfigNode | undefined => {
  return node.children.find((child) =>
    child.id.toLowerCase().trim().startsWith(pathPrefix.toLowerCase())
  );
};

/**
 * Find all child nodes that match a path pattern
 */
export const findPathBlocks = (node: ConfigNode, pathPrefix: string): ConfigNode[] => {
  return node.children.filter((child) =>
    child.id.toLowerCase().trim().startsWith(pathPrefix.toLowerCase())
  );
};

/**
 * Parse MikroTik address format (e.g., "192.168.1.1/24")
 * @param address The address string with CIDR notation
 * @returns Object with ip number, prefix length, and mask, or null if invalid
 */
export const parseMikroTikAddress = (
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
 * Get connection states from a firewall rule
 * Example: "connection-state=established,related" returns ['established', 'related']
 */
export const getConnectionStates = (nodeOrCommand: ConfigNode | string): string[] => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const states = parseProperty(str, 'connection-state');
  if (!states) return [];
  return states.split(',').map((s) => s.trim().toLowerCase());
};

/**
 * Check if a firewall rule has stateful tracking (established,related)
 */
export const hasStatefulTracking = (nodeOrCommand: ConfigNode | string): boolean => {
  const states = getConnectionStates(nodeOrCommand);
  return states.includes('established') || states.includes('related');
};

/**
 * Get service port from /ip service command
 */
export const getServicePort = (nodeOrCommand: ConfigNode | string): number | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const port = parseProperty(str, 'port');
  if (port) {
    const parsed = parseInt(port, 10);
    return isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
};

/**
 * Check if a service is disabled
 */
export const isServiceDisabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const disabled = parseProperty(str, 'disabled');
  return disabled?.toLowerCase() === 'yes';
};

/**
 * Get all firewall rules from a firewall path block
 */
export const getFirewallRules = (firewallNode: ConfigNode): ConfigNode[] => {
  return firewallNode.children.filter((child) => isAddCommand(child));
};

/**
 * Get NAT type from a NAT rule
 */
export const getNatAction = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'action');
};

/**
 * Get out-interface from a NAT rule
 */
export const getOutInterface = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'out-interface');
};

/**
 * Get in-interface from a rule
 */
export const getInInterface = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'in-interface');
};

/**
 * Check if identity (hostname) is configured in a system identity block
 */
export const getSystemIdentity = (node: ConfigNode): string | undefined => {
  // Look for "set name=..." in /system identity
  for (const child of node.children) {
    if (isSetCommand(child)) {
      const name = getName(child);
      if (name) return name;
    }
  }
  return undefined;
};

/**
 * Check if NTP client is enabled
 */
export const isNtpEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  return enabled?.toLowerCase() === 'yes';
};

/**
 * Get NTP servers from /system ntp client servers block
 */
export const getNtpServers = (ntpNode: ConfigNode): string[] => {
  const servers: string[] = [];
  for (const child of ntpNode.children) {
    if (isAddCommand(child)) {
      const address = parseProperty(child.id, 'address');
      if (address) servers.push(address);
    }
  }
  return servers;
};

/**
 * Check if SSH strong-crypto is enabled
 */
export const isSshStrongCrypto = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const strongCrypto = parseProperty(str, 'strong-crypto');
  return strongCrypto?.toLowerCase() === 'yes';
};

/**
 * Get SSH host key type
 */
export const getSshHostKeyType = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'host-key-type');
};

/**
 * Get SNMP community security level
 */
export const getSnmpSecurity = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'security');
};

/**
 * Get SNMP community name
 */
export const getSnmpCommunityName = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'name');
};

/**
 * Check if SNMP has authentication protocol configured
 */
export const hasSnmpAuthProtocol = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return hasProperty(str, 'authentication-protocol');
};

/**
 * Check if SNMP has encryption protocol configured
 */
export const hasSnmpEncryptionProtocol = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return hasProperty(str, 'encryption-protocol');
};

/**
 * Get allowed interface list property
 */
export const getAllowedInterfaceList = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'allowed-interface-list');
};

/**
 * Get discover interface list from neighbor discovery settings
 */
export const getDiscoverInterfaceList = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'discover-interface-list');
};

/**
 * Check if a feature is enabled (common pattern)
 */
export const isEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  return enabled?.toLowerCase() === 'yes';
};

/**
 * Check if MAC-Ping is enabled
 */
export const isMacPingEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  // Default is enabled if not explicitly disabled
  return enabled?.toLowerCase() !== 'no';
};

/**
 * Get BGP TCP-MD5 key (checks if authentication is configured)
 */
export const getBgpTcpMd5Key = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'tcp-md5-key');
};

/**
 * Get BGP remote AS
 */
export const getBgpRemoteAs = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  // RouterOS 7 uses remote.as, RouterOS 6 uses remote-as
  return parseProperty(str, 'remote.as') || parseProperty(str, 'remote-as');
};

/**
 * Get BGP max prefix limit
 */
export const getBgpMaxPrefixLimit = (nodeOrCommand: ConfigNode | string): number | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  // RouterOS 7: input.limit-process-routes-ipv4
  // RouterOS 6: max-prefix-limit
  const limit = parseProperty(str, 'input.limit-process-routes-ipv4') ||
                parseProperty(str, 'max-prefix-limit');
  if (limit) {
    const parsed = parseInt(limit, 10);
    return isNaN(parsed) ? undefined : parsed;
  }
  return undefined;
};

/**
 * Check if BGP has input filter
 */
export const hasBgpInputFilter = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  // RouterOS 7: input.filter
  // RouterOS 6: in-filter
  return hasProperty(str, 'input.filter') || hasProperty(str, 'in-filter');
};

/**
 * Check if BGP has output filter
 */
export const hasBgpOutputFilter = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  // RouterOS 7: output.filter
  // RouterOS 6: out-filter
  return hasProperty(str, 'output.filter') || hasProperty(str, 'out-filter');
};

/**
 * Get OSPF authentication type
 */
export const getOspfAuth = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'auth');
};

/**
 * Get OSPF authentication key
 */
export const getOspfAuthKey = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'auth-key') || parseProperty(str, 'authentication-key');
};

/**
 * Get VRRP authentication type
 */
export const getVrrpAuth = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'authentication');
};

/**
 * Get VRRP password
 */
export const getVrrpPassword = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'password');
};

/**
 * Get IPsec encryption algorithm
 */
export const getIpsecEncAlgorithm = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'enc-algorithm') || parseProperty(str, 'enc-algorithms');
};

/**
 * Get IPsec hash algorithm
 */
export const getIpsecHashAlgorithm = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'hash-algorithm') || parseProperty(str, 'auth-algorithms');
};

/**
 * Get IPsec DH group
 */
export const getIpsecDhGroup = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'dh-group') || parseProperty(str, 'pfs-group');
};

/**
 * Check if bridge has VLAN filtering enabled
 */
export const hasBridgeVlanFiltering = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const vlanFiltering = parseProperty(str, 'vlan-filtering');
  return vlanFiltering?.toLowerCase() === 'yes';
};

/**
 * Get bridge frame types
 */
export const getBridgeFrameTypes = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'frame-types');
};

/**
 * Check if syslog (remote logging) is configured
 */
export const getSyslogTarget = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'target');
};

/**
 * Get syslog remote address
 */
export const getSyslogRemote = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'remote');
};

/**
 * Get address list name from a rule
 */
export const getAddressList = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'address-list');
};

/**
 * Get source address list from a rule
 */
export const getSrcAddressList = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'src-address-list');
};

/**
 * Get destination address list from a rule
 */
export const getDstAddressList = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'dst-address-list');
};

/**
 * Check if firewall rule has logging enabled
 */
export const hasFirewallLogging = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const log = parseProperty(str, 'log');
  return log?.toLowerCase() === 'yes';
};

/**
 * Get log prefix from a firewall rule
 */
export const getLogPrefix = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'log-prefix');
};

/**
 * Get connection limit from a rule
 */
export const getConnectionLimit = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'connection-limit');
};

/**
 * Get limit (rate limit) from a rule
 */
export const getRateLimit = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'limit');
};

/**
 * Get TCP flags from a firewall rule
 */
export const getTcpFlags = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'tcp-flags');
};

/**
 * Get destination port from a rule
 */
export const getDstPort = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'dst-port');
};

/**
 * Get protocol from a rule
 */
export const getProtocol = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'protocol');
};

/**
 * Check if IP cloud DDNS is enabled
 */
export const isCloudDdnsEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const ddnsEnabled = parseProperty(str, 'ddns-enabled');
  return ddnsEnabled?.toLowerCase() === 'yes';
};

/**
 * Check if IP proxy is enabled
 */
export const isProxyEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  return enabled?.toLowerCase() === 'yes';
};

/**
 * Check if IP SOCKS is enabled
 */
export const isSocksEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  return enabled?.toLowerCase() === 'yes';
};

/**
 * Check if UPnP is enabled
 */
export const isUpnpEnabled = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const enabled = parseProperty(str, 'enabled');
  return enabled?.toLowerCase() === 'yes';
};

/**
 * Check if DNS allows remote requests
 */
export const isDnsAllowRemoteRequests = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const allowRemote = parseProperty(str, 'allow-remote-requests');
  return allowRemote?.toLowerCase() === 'yes';
};

/**
 * Get system note content
 */
export const getSystemNote = (nodeOrCommand: ConfigNode | string): string | undefined => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  return parseProperty(str, 'note');
};

/**
 * Check if system note is shown at login
 */
export const isNoteShowAtLogin = (nodeOrCommand: ConfigNode | string): boolean => {
  const str = typeof nodeOrCommand === 'string' ? nodeOrCommand : nodeOrCommand.id;
  const showAtLogin = parseProperty(str, 'show-at-login');
  return showAtLogin?.toLowerCase() === 'yes';
};
