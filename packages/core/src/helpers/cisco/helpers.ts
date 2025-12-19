// packages/rule-helpers/src/cisco/helpers.ts
// Cisco IOS/IOS-XE specific helper functions
// Based on Cisco Best Practices: docs/Cisco-best-practices.md

import type { ConfigNode } from '../../types/ConfigNode';
import {
  hasChildCommand,
  getChildCommand,
  equalsIgnoreCase,
  includesIgnoreCase,
  startsWithIgnoreCase,
  parseInteger,
} from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

/**
 * Check if interface is shutdown
 */
export const isShutdown = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    return equalsIgnoreCase(child.id.trim(), 'shutdown');
  });
};

/**
 * Check if interface is a physical port (not Loopback, Vlan, Null, etc.)
 */
export const isPhysicalPort = (interfaceName: string): boolean => {
  return (
    !includesIgnoreCase(interfaceName, 'loopback') &&
    !includesIgnoreCase(interfaceName, 'null') &&
    !includesIgnoreCase(interfaceName, 'vlan') &&
    !includesIgnoreCase(interfaceName, 'tunnel') &&
    !includesIgnoreCase(interfaceName, 'port-channel') &&
    !includesIgnoreCase(interfaceName, 'bvi') &&
    !includesIgnoreCase(interfaceName, 'nve')
  );
};

/**
 * Check if interface name suggests it's a trunk/uplink based on description
 */
export const isLikelyTrunk = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    return (
      includesIgnoreCase(descText, 'uplink') ||
      includesIgnoreCase(descText, 'downlink') ||
      includesIgnoreCase(descText, 'isl') ||
      includesIgnoreCase(descText, 'trunk') ||
      includesIgnoreCase(descText, 'po-member')
    );
  }
  return hasChildCommand(node, 'switchport mode trunk');
};

/**
 * Check if interface is configured as trunk
 */
export const isTrunkPort = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'switchport mode trunk');
};

/**
 * Check if interface is configured as access
 */
export const isAccessPort = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'switchport mode access');
};

/**
 * Check if description suggests external-facing interface
 */
export const isExternalFacing = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    return (
      includesIgnoreCase(descText, 'wan:') ||
      includesIgnoreCase(descText, 'external') ||
      includesIgnoreCase(descText, 'internet') ||
      includesIgnoreCase(descText, 'isp') ||
      includesIgnoreCase(descText, 'dmz') ||
      includesIgnoreCase(descText, 'perimeter')
    );
  }
  return false;
};

/**
 * Check if description suggests user endpoint port
 */
export const isEndpointPort = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    return (
      includesIgnoreCase(descText, 'endpoint:') ||
      includesIgnoreCase(descText, 'user:') ||
      includesIgnoreCase(descText, 'workstation') ||
      includesIgnoreCase(descText, 'desktop') ||
      includesIgnoreCase(descText, 'desk')
    );
  }
  // Also check if it's an access port without uplink indicators
  return isAccessPort(node) && !isLikelyTrunk(node);
};

/**
 * Check if description suggests phone or AP
 */
export const isPhoneOrAP = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    return (
      includesIgnoreCase(descText, 'phone') ||
      includesIgnoreCase(descText, 'voice') ||
      includesIgnoreCase(descText, 'cisco-ap') ||
      includesIgnoreCase(descText, 'aruba-ap') ||
      includesIgnoreCase(descText, 'ap-') ||
      includesIgnoreCase(descText, '-ap')
    );
  }
  // Check for voice vlan which indicates phone
  return hasChildCommand(node, 'switchport voice vlan');
};

/**
 * Check if trunk is connected to a non-Cisco device (server, storage, non-Cisco switch)
 * These require switchport nonegotiate since the other end doesn't speak DTP
 */
export const isTrunkToNonCisco = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    // Non-Cisco endpoints that need nonegotiate
    if (
      includesIgnoreCase(descText, 'server:') ||
      includesIgnoreCase(descText, 'storage:') ||
      includesIgnoreCase(descText, 'esx') ||
      includesIgnoreCase(descText, 'vmware') ||
      includesIgnoreCase(descText, 'hyperv') ||
      includesIgnoreCase(descText, 'hyper-v') ||
      includesIgnoreCase(descText, 'linux') ||
      includesIgnoreCase(descText, 'appliance') ||
      includesIgnoreCase(descText, 'firewall') ||
      includesIgnoreCase(descText, 'loadbalancer') ||
      includesIgnoreCase(descText, 'lb:') ||
      includesIgnoreCase(descText, 'nas:') ||
      includesIgnoreCase(descText, 'san:')
    ) {
      return true;
    }
    // Cisco switch connections - DTP is fine
    if (
      includesIgnoreCase(descText, 'uplink:') ||
      includesIgnoreCase(descText, 'downlink:') ||
      includesIgnoreCase(descText, 'isl:') ||
      includesIgnoreCase(descText, 'po-member:')
    ) {
      return false;
    }
  }
  // No description - can't determine, don't flag
  return false;
};

// ============================================================================
// Management Plane Helpers
// ============================================================================

/**
 * Check if AAA new-model is configured (global command)
 */
export const isAaaNewModel = (node: ConfigNode): boolean => {
  return equalsIgnoreCase(node.id.trim(), 'aaa new-model');
};

/**
 * Check if password uses strong encryption type (Type 8/9, scrypt, sha256)
 * Type 7 is easily reversible, Type 5 (MD5) is deprecated
 */
export const hasStrongPasswordType = (node: ConfigNode): boolean => {
  const rawText = node.rawText;
  // Strong: algorithm-type sha256, algorithm-type scrypt, secret (type 5+)
  // Weak: password (type 0 or 7)
  if (includesIgnoreCase(rawText, 'algorithm-type sha256') || includesIgnoreCase(rawText, 'algorithm-type scrypt')) {
    return true;
  }
  if (includesIgnoreCase(rawText, ' secret ')) {
    // secret uses MD5 (type 5) minimum, better than password
    return true;
  }
  return false;
};

/**
 * Check if username uses weak password type (Type 7 or plaintext)
 */
export const hasWeakUsernamePassword = (node: ConfigNode): boolean => {
  const rawText = node.rawText;
  // Check for "password 7" or just "password" without algorithm-type
  if (includesIgnoreCase(rawText, ' password ')) {
    if (includesIgnoreCase(rawText, 'algorithm-type sha256') || includesIgnoreCase(rawText, 'algorithm-type scrypt')) {
      return false;
    }
    return true;
  }
  return false;
};

/**
 * Get SSH version from configuration
 */
export const getSshVersion = (node: ConfigNode): number | null => {
  if (includesIgnoreCase(node.rawText, 'ip ssh version')) {
    const match = node.params.find((p) => p === '1' || p === '2');
    if (match) {
      return parseInteger(match);
    }
  }
  return null;
};

/**
 * Check if SNMP community is a well-known default
 */
export const isDefaultSnmpCommunity = (community: string): boolean => {
  const defaultCommunities = [
    'public',
    'private',
    'community',
    'snmp',
    'admin',
    'cisco',
    'secret',
    'test',
    'default',
  ];
  return defaultCommunities.some((dc) => equalsIgnoreCase(community, dc));
};

/**
 * Check if SNMP v3 is configured
 */
export const isSnmpV3User = (node: ConfigNode): boolean => {
  return startsWithIgnoreCase(node.id, 'snmp-server user');
};

/**
 * Check if SNMP v3 uses auth-priv
 */
export const hasSnmpV3AuthPriv = (node: ConfigNode): boolean => {
  return includesIgnoreCase(node.rawText, 'auth') && includesIgnoreCase(node.rawText, 'priv');
};

/**
 * Get VTY line range from node
 */
export const getVtyLineRange = (node: ConfigNode): { start: number; end: number } | null => {
  const params = node.params;
  // line vty 0 15
  if (params.length >= 4) {
    const startStr = params[2];
    const endStr = params[3];
    const start = startStr ? parseInteger(startStr) : null;
    const end = endStr ? parseInteger(endStr) : null;
    if (start !== null && end !== null) {
      return { start, end };
    }
  }
  // line vty 0
  if (params.length >= 3) {
    const startStr = params[2];
    const start = startStr ? parseInteger(startStr) : null;
    if (start !== null) {
      return { start, end: start };
    }
  }
  return null;
};

/**
 * Check if VTY has access-class configured
 */
export const hasVtyAccessClass = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'access-class');
};

/**
 * Check if NTP authentication is enabled
 */
export const hasNtpAuthentication = (node: ConfigNode): boolean => {
  return includesIgnoreCase(node.rawText, 'ntp authenticate') || includesIgnoreCase(node.rawText, 'ntp authentication-key');
};

// ============================================================================
// Control Plane Helpers
// ============================================================================

/**
 * Check if OSPF authentication is configured on interface
 */
export const hasOspfAuthentication = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'ip ospf authentication') ||
         hasChildCommand(node, 'ip ospf message-digest-key');
};

/**
 * Check if EIGRP authentication is configured on interface
 */
export const hasEigrpAuthentication = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'ip authentication mode eigrp') &&
         hasChildCommand(node, 'ip authentication key-chain eigrp');
};

/**
 * Check if BGP neighbor has password configured
 */
export const hasBgpNeighborPassword = (neighborCommands: ConfigNode[]): boolean => {
  return neighborCommands.some((cmd) =>
    includesIgnoreCase(cmd.id, 'password')
  );
};

/**
 * Check if BGP neighbor has TTL security (GTSM) configured
 */
export const hasBgpTtlSecurity = (neighborCommands: ConfigNode[]): boolean => {
  return neighborCommands.some((cmd) =>
    includesIgnoreCase(cmd.id, 'ttl-security')
  );
};

/**
 * Check if BGP neighbor has maximum-prefix configured
 */
export const hasBgpMaxPrefix = (neighborCommands: ConfigNode[]): boolean => {
  return neighborCommands.some((cmd) =>
    includesIgnoreCase(cmd.id, 'maximum-prefix')
  );
};

/**
 * Check if BGP has log-neighbor-changes enabled
 */
export const hasBgpLogNeighborChanges = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'bgp log-neighbor-changes');
};

/**
 * Get all BGP neighbors from router bgp section
 */
export const getBgpNeighbors = (node: ConfigNode): Map<string, ConfigNode[]> => {
  const neighbors = new Map<string, ConfigNode[]>();

  for (const child of node.children) {
    if (startsWithIgnoreCase(child.id, 'neighbor')) {
      const neighborIp = child.params[1];
      if (neighborIp) {
        const existing = neighbors.get(neighborIp) || [];
        existing.push(child);
        neighbors.set(neighborIp, existing);
      }
    }
  }

  return neighbors;
};

/**
 * Check if HSRP has MD5 authentication
 */
export const hasHsrpMd5Auth = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    return startsWithIgnoreCase(child.id, 'standby') && includesIgnoreCase(child.id, 'authentication md5');
  });
};

/**
 * Check if VRRP has authentication
 */
export const hasVrrpAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    return startsWithIgnoreCase(child.id, 'vrrp') && includesIgnoreCase(child.id, 'authentication');
  });
};

// ============================================================================
// Data Plane Helpers
// ============================================================================

/**
 * Check if interface has uRPF (unicast RPF) enabled
 */
export const hasUrpf = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'ip verify unicast source reachable-via');
};

/**
 * Get uRPF mode (rx = strict, any = loose)
 */
export const getUrpfMode = (node: ConfigNode): 'strict' | 'loose' | null => {
  const cmd = getChildCommand(node, 'ip verify unicast source reachable-via');
  if (cmd) {
    if (includesIgnoreCase(cmd.rawText, 'reachable-via rx')) {
      return 'strict';
    }
    if (includesIgnoreCase(cmd.rawText, 'reachable-via any')) {
      return 'loose';
    }
  }
  return null;
};

/**
 * Check if IP redirects are disabled
 */
export const hasNoIpRedirects = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'no ip redirects');
};

/**
 * Check if IP unreachables are disabled
 */
export const hasNoIpUnreachables = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'no ip unreachables');
};

/**
 * Check if IP proxy-arp is disabled
 */
export const hasNoProxyArp = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'no ip proxy-arp');
};

/**
 * Check if IP directed-broadcast is disabled
 */
export const hasNoDirectedBroadcast = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'no ip directed-broadcast');
};

/**
 * Check if interface is a WAN/Internet-facing interface
 */
export const isWanInterface = (node: ConfigNode): boolean => {
  const desc = getChildCommand(node, 'description');
  if (desc) {
    const descText = desc.rawText;
    return (
      includesIgnoreCase(descText, 'wan') ||
      includesIgnoreCase(descText, 'internet') ||
      includesIgnoreCase(descText, 'isp') ||
      includesIgnoreCase(descText, 'external') ||
      includesIgnoreCase(descText, 'outside') ||
      includesIgnoreCase(descText, 'border') ||
      includesIgnoreCase(descText, 'edge')
    );
  }
  return false;
};

/**
 * Check if interface is a loopback
 */
export const isLoopbackInterface = (interfaceName: string): boolean => {
  return includesIgnoreCase(interfaceName, 'loopback');
};

/**
 * Check if interface is a tunnel
 */
export const isTunnelInterface = (interfaceName: string): boolean => {
  return includesIgnoreCase(interfaceName, 'tunnel');
};

/**
 * Check if interface is a VLAN SVI
 */
export const isVlanInterface = (interfaceName: string): boolean => {
  return startsWithIgnoreCase(interfaceName, 'interface vlan');
};

// ============================================================================
// Service Hardening Helpers
// ============================================================================

/**
 * Check if service password-encryption is enabled
 */
export const hasPasswordEncryption = (node: ConfigNode): boolean => {
  return equalsIgnoreCase(node.id.trim(), 'service password-encryption');
};

/**
 * Check if TCP keepalives are enabled
 */
export const hasTcpKeepalives = (node: ConfigNode): boolean => {
  const cmd = node.id.trim();
  return equalsIgnoreCase(cmd, 'service tcp-keepalives-in') || equalsIgnoreCase(cmd, 'service tcp-keepalives-out');
};

/**
 * Check if service is a dangerous/unnecessary service that should be disabled
 */
export const isDangerousService = (node: ConfigNode): boolean => {
  const cmd = node.id.trim();
  const dangerousServices = [
    'service tcp-small-servers',
    'service udp-small-servers',
    'ip finger',
    'service finger',
    'ip bootp server',
    'service config',
    'ip http server',
    'service pad',
    'boot network',
    'service call-home',
  ];
  return dangerousServices.some((svc) => equalsIgnoreCase(cmd, svc));
};

/**
 * Check if Smart Install (vstack) is enabled
 */
export const isSmartInstallEnabled = (node: ConfigNode): boolean => {
  // "vstack" without "no" means it's enabled
  return equalsIgnoreCase(node.id.trim(), 'vstack');
};
