// packages/rule-helpers/src/nokia/helpers.ts
// Nokia SR OS specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

/**
 * Check if admin-state is enabled (admin-state enable or admin-state up)
 * Nokia SR OS uses admin-state for enabling/disabling most components
 */
export const isAdminStateEnabled = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  // Check direct children first (more common case)
  const directCheck = node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText === 'admin-state enable' || rawText === 'admin-state up';
  });
  if (directCheck) return true;

  // Also check if admin-state is in the node's own rawText (for compact configs)
  const nodeText = node?.rawText?.toLowerCase() ?? '';
  return nodeText.includes('admin-state enable') || nodeText.includes('admin-state up');
};

/**
 * Check if admin-state is disabled (admin-state disable or no admin-state command)
 */
export const isAdminStateDisabled = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  // Check direct children first
  const directCheck = node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText === 'admin-state disable';
  });
  if (directCheck) return true;

  // Also check node's own rawText
  return node?.rawText?.toLowerCase().includes('admin-state disable') ?? false;
};

/**
 * Check if component is shutdown (has shutdown command)
 */
export const isShutdown = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText === 'shutdown';
  });
};

/**
 * Check if interface/component is enabled (has admin-state enable and no shutdown)
 */
export const isEnabled = (node: ConfigNode): boolean => {
  const hasAdminStateEnabled = isAdminStateEnabled(node);
  const hasShutdown = isShutdown(node);
  return hasAdminStateEnabled && !hasShutdown;
};

/**
 * Check if a port is a physical port (not LAG, loopback, or system)
 * Nokia port format: slot/mda/port (e.g., 1/1/1, 1/2/3)
 */
export const isPhysicalPort = (portName: string): boolean => {
  const name = portName.toLowerCase();
  // Match slot/mda/port pattern
  return /^\d+\/\d+\/\d+/.test(name);
};

/**
 * Check if a port is a LAG (Link Aggregation Group)
 * Nokia LAG format: lag-N or lag N
 */
export const isLagPort = (portName: string): boolean => {
  const name = portName.toLowerCase();
  return name.includes('lag');
};

/**
 * Check if interface is a system interface (loopback, system)
 */
export const isSystemInterface = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return (
    name.includes('system') ||
    name.includes('loopback') ||
    name === '"system"'
  );
};

/**
 * Get port mode (network or access)
 */
export const getPortMode = (node: ConfigNode): 'network' | 'access' | undefined => {
  if (!node?.children) return undefined;
  // Look for ethernet mode configuration
  const ethernetNode = node.children.find((child) =>
    child?.id?.toLowerCase() === 'ethernet'
  );

  if (ethernetNode?.children) {
    const modeCmd = ethernetNode.children.find((child) => {
      const rawText = child?.rawText?.toLowerCase().trim();
      return rawText?.startsWith('mode');
    });

    if (modeCmd?.rawText) {
      if (modeCmd.rawText.toLowerCase().includes('network')) {
        return 'network';
      }
      if (modeCmd.rawText.toLowerCase().includes('access')) {
        return 'access';
      }
    }
  }
  return undefined;
};

/**
 * Check if port is in network mode
 */
export const isNetworkPort = (node: ConfigNode): boolean => {
  return getPortMode(node) === 'network';
};

/**
 * Check if port is in access mode
 */
export const isAccessPort = (node: ConfigNode): boolean => {
  return getPortMode(node) === 'access';
};

/**
 * Check if port has description configured
 */
export const hasDescription = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'description');
};

/**
 * Get port/interface description
 */
export const getDescription = (node: ConfigNode): string | undefined => {
  const descCmd = getChildCommand(node, 'description');
  if (descCmd?.rawText) {
    // Nokia descriptions are often quoted
    const match = descCmd.rawText.match(/description\s+"([^"]+)"|description\s+(\S+)/i);
    if (match) {
      return match[1] || match[2];
    }
  }
  return undefined;
};

/**
 * Get system name from system block
 */
export const getSystemName = (node: ConfigNode): string | undefined => {
  if (!node?.children) return undefined;
  const nameCmd = node.children.find((child) => {
    return child?.id?.toLowerCase().startsWith('name');
  });

  if (nameCmd?.rawText) {
    // Nokia system name is quoted: name "Router-Name"
    const match = nameCmd.rawText.match(/name\s+"([^"]+)"/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

/**
 * Check if interface has IP address configured
 */
export const hasIpAddress = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('address') ?? false;
  });
};

/**
 * Get interface IP address
 */
export const getIpAddress = (node: ConfigNode): string | undefined => {
  if (!node?.children) return undefined;
  const addrCmd = node.children.find((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('address') ?? false;
  });

  if (addrCmd?.rawText) {
    // Match IPv4 or IPv6 address with optional prefix
    const match = addrCmd.rawText.match(/address\s+([\d./:a-fA-F]+)/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

/**
 * Check if port is assigned to interface
 */
export const hasPortAssignment = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('port') ?? false;
  });
};

/**
 * Get port assignment
 */
export const getPortAssignment = (node: ConfigNode): string | undefined => {
  if (!node?.children) return undefined;
  const portCmd = node.children.find((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('port') ?? false;
  });

  if (portCmd?.rawText) {
    const match = portCmd.rawText.match(/port\s+([\d/]+)/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

/**
 * Check if BGP has router-id configured
 */
export const hasBgpRouterId = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'router-id');
};

/**
 * Get BGP router-id
 */
export const getBgpRouterId = (node: ConfigNode): string | undefined => {
  const routerIdCmd = getChildCommand(node, 'router-id');
  if (routerIdCmd?.rawText) {
    const match = routerIdCmd.rawText.match(/router-id\s+([\d.]+)/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

/**
 * Find a stanza by name in the configuration tree
 */
export const findStanza = (node: ConfigNode, stanzaName: string): ConfigNode | undefined => {
  if (node?.id?.toLowerCase().startsWith(stanzaName.toLowerCase())) {
    return node;
  }
  if (!node?.children) return undefined;
  for (const child of node.children) {
    const found = findStanza(child, stanzaName);
    if (found) return found;
  }
  return undefined;
};

/**
 * Find all stanzas by name in the configuration tree
 */
export const findStanzas = (node: ConfigNode, stanzaName: string): ConfigNode[] => {
  const results: ConfigNode[] = [];
  if (node?.id?.toLowerCase().startsWith(stanzaName.toLowerCase())) {
    results.push(node);
  }
  if (!node?.children) return results;
  for (const child of node.children) {
    results.push(...findStanzas(child, stanzaName));
  }
  return results;
};

/**
 * Check if SAP (Service Access Point) is configured
 */
export const hasSap = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('sap') ?? false;
  });
};

/**
 * Get SAP identifier
 */
export const getSapId = (node: ConfigNode): string | undefined => {
  if (!node?.children) return undefined;
  const sapCmd = node.children.find((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('sap') ?? false;
  });

  if (sapCmd?.rawText) {
    // SAP format: sap port:vlan (e.g., sap 1/1/1:100)
    const match = sapCmd.rawText.match(/sap\s+([\d/:]+)/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

/**
 * Check if SNMP is configured (snmp block with admin-state)
 */
export const isSnmpEnabled = (node: ConfigNode): boolean => {
  if (!node?.id) return false;
  if (node.id.toLowerCase() === 'snmp') {
    return isAdminStateEnabled(node);
  }
  return false;
};

/**
 * Check if NTP is configured
 */
export const hasNtpServer = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim() ?? '';
    return rawText.includes('ntp-server') || rawText.includes('server');
  });
};

/**
 * Check if SSH is enabled in security settings
 */
export const isSshEnabled = (node: ConfigNode): boolean => {
  if (!node?.id || !node?.children) return false;
  if (node.id.toLowerCase().includes('security') || node.id.toLowerCase().includes('management-interface')) {
    return node.children.some((child) => {
      const rawText = child?.rawText?.toLowerCase().trim() ?? '';
      return rawText.includes('ssh') && !rawText.includes('no ssh');
    });
  }
  return false;
};

/**
 * Check if Telnet is enabled (security concern)
 */
export const isTelnetEnabled = (node: ConfigNode): boolean => {
  if (!node?.id || !node?.children) return false;
  if (node.id.toLowerCase().includes('security') || node.id.toLowerCase().includes('management-interface')) {
    return node.children.some((child) => {
      const rawText = child?.rawText?.toLowerCase().trim() ?? '';
      return rawText.includes('telnet') && !rawText.includes('no telnet');
    });
  }
  return false;
};

/**
 * Check if authentication is configured
 */
export const hasAuthentication = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    if (!rawText) {
      return false;
    }
    return (
      rawText.includes('authentication') ||
      rawText.includes('auth-key') ||
      rawText.includes('password')
    );
  });
};

/**
 * Get interface name from quoted or unquoted format
 * Nokia uses: interface "name" or interface name
 */
export const getInterfaceName = (node: ConfigNode): string => {
  if (!node?.id) return '';
  const match = node.id.match(/interface\s+"([^"]+)"|interface\s+(\S+)/i);
  const quoted = match?.[1];
  const unquoted = match?.[2];
  if (quoted) return quoted;
  if (unquoted) return unquoted;
  return node.id.replace(/^interface\s+/i, '').trim();
};

/**
 * Get router name from router block
 * Nokia uses: router "Base" or router vprn-name
 */
export const getRouterName = (node: ConfigNode): string => {
  if (!node?.id) return 'Base';
  const match = node.id.match(/router\s+"([^"]+)"|router\s+(\S+)/i);
  const quoted = match?.[1];
  const unquoted = match?.[2];
  if (quoted) return quoted;
  if (unquoted) return unquoted;
  return 'Base';
};

/**
 * Check if BGP peer has description
 */
export const hasPeerDescription = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'description');
};

/**
 * Get service type from service block
 */
export const getServiceType = (node: ConfigNode): 'vpls' | 'vprn' | 'epipe' | 'ies' | undefined => {
  if (!node?.id) return undefined;
  const id = node.id.toLowerCase();
  if (id.includes('vpls')) return 'vpls';
  if (id.includes('vprn')) return 'vprn';
  if (id.includes('epipe')) return 'epipe';
  if (id.includes('ies')) return 'ies';
  return undefined;
};

/**
 * Get service ID from service block
 */
export const getServiceId = (node: ConfigNode): string | undefined => {
  if (!node?.id) return undefined;
  const match = node.id.match(/(vpls|vprn|epipe|ies)\s+(\d+)/i);
  const serviceId = match?.[2];
  if (serviceId) {
    return serviceId;
  }
  return undefined;
};

/**
 * Check if customer is assigned to service
 */
export const hasCustomer = (node: ConfigNode): boolean => {
  if (!node?.children) return false;
  return node.children.some((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('customer') ?? false;
  });
};

/**
 * Get customer ID
 */
export const getCustomerId = (node: ConfigNode): string | undefined => {
  if (!node?.children) return undefined;
  const customerCmd = node.children.find((child) => {
    const rawText = child?.rawText?.toLowerCase().trim();
    return rawText?.startsWith('customer') ?? false;
  });

  if (customerCmd?.rawText) {
    const match = customerCmd.rawText.match(/customer\s+(\d+)/i);
    if (match) {
      return match[1];
    }
  }
  return undefined;
};

// ============================================================================
// Management Plane Security Helpers
// ============================================================================

/**
 * Recursively search for a pattern in node and its descendants
 */
const searchNodeRecursively = (
  node: ConfigNode,
  predicate: (rawText: string) => boolean
): boolean => {
  const rawText = node?.rawText?.toLowerCase().trim() ?? '';
  if (predicate(rawText)) {
    return true;
  }
  if (!node?.children) return false;
  return node.children.some((child) => searchNodeRecursively(child, predicate));
};

/**
 * Check if TACACS+ is configured for AAA
 */
export const hasTacacsConfig = (node: ConfigNode): boolean => {
  // Check for tacplus in aaa remote-servers
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('tacplus') || rawText.includes('tacacs')
  );
};

/**
 * Check if RADIUS is configured for AAA
 */
export const hasRadiusConfig = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('radius'));
};

/**
 * Check if SSH version 2 is configured
 */
export const hasSshV2 = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText === 'version 2' || rawText.includes('version 2')
  );
};

/**
 * Check if SSHv1 is explicitly enabled (security concern)
 */
export const hasSshV1 = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText === 'version 1' ||
    (rawText.includes('version') && rawText.includes('1') && !rawText.includes('2'))
  );
};

/**
 * Check if weak SSH ciphers are configured
 */
export const hasWeakSshCipher = (node: ConfigNode): boolean => {
  const weakCiphers = ['3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'rijndael-cbc'];
  return searchNodeRecursively(node, (rawText) =>
    weakCiphers.some((cipher) => rawText.includes(cipher))
  );
};

/**
 * Check if SNMPv3 with privacy is configured
 */
export const hasSnmpV3Privacy = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('security-level privacy') ||
    rawText.includes('usm') ||
    (rawText.includes('snmpv3') && rawText.includes('privacy'))
  );
};

/**
 * Check if default SNMP community strings are used
 */
export const hasDefaultSnmpCommunity = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('community public') ||
    rawText.includes('community private') ||
    rawText.includes('community "public"') ||
    rawText.includes('community "private"')
  );
};

/**
 * Check if NTP authentication is enabled
 */
export const hasNtpAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('authentication-check') ||
    rawText.includes('authentication-key') ||
    rawText.includes('message-digest')
  );
};

/**
 * Check if management access filter is configured
 */
export const hasManagementAccessFilter = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('management-access-filter')
  );
};

/**
 * Check if MAF has default-action deny
 */
export const hasMafDefaultDeny = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('default-action deny') || rawText === 'default-action deny'
  );
};

// ============================================================================
// Control Plane Security Helpers
// ============================================================================

/**
 * Check if OSPF authentication is configured (auth-keychain or authentication-key)
 */
export const hasOspfAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('auth-keychain') ||
    rawText.includes('authentication-key') ||
    rawText.includes('message-digest-key')
  );
};

/**
 * Check if IS-IS authentication is configured
 */
export const hasIsisAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('auth-keychain') || rawText.includes('authentication-key')
  );
};

/**
 * Check if LDP authentication is configured
 */
export const hasLdpAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('auth-keychain') || rawText.includes('authentication-key')
  );
};

/**
 * Check if RSVP authentication is configured
 */
export const hasRsvpAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('auth-keychain') || rawText.includes('authentication-key')
  );
};

// ============================================================================
// BGP Security Helpers
// ============================================================================

/**
 * Check if BGP authentication is configured (auth-keychain or authentication-key)
 */
export const hasBgpAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('auth-keychain') ||
    rawText.includes('authentication-key') ||
    rawText.includes('password')
  );
};

/**
 * Check if BGP TTL security (GTSM) is configured
 */
export const hasBgpTtlSecurity = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('ttl-security'));
};

/**
 * Check if BGP prefix-limit is configured
 */
export const hasBgpPrefixLimit = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('prefix-limit'));
};

/**
 * Check if BGP graceful restart is configured
 */
export const hasBgpGracefulRestart = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('graceful-restart'));
};

/**
 * Check if BGP import/export policies are configured
 */
export const hasBgpPolicies = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('import') || rawText.includes('export')
  );
};

/**
 * Check if BGP group is external type
 */
export const isBgpExternalGroup = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('type external'));
};

// ============================================================================
// CPM Filter Helpers
// ============================================================================

/**
 * Check if CPM filter is configured
 */
export const hasCpmFilter = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('cpm-filter'));
};

/**
 * Check if CPM filter has default-action drop
 */
export const hasCpmFilterDefaultDrop = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('default-action drop'));
};

/**
 * Check if protocol protection is enabled
 */
export const hasProtocolProtection = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('protocol-protection') || rawText.includes('cpu-protection')
  );
};

// ============================================================================
// Data Plane Security Helpers
// ============================================================================

/**
 * Check if uRPF is configured
 */
export const hasUrpf = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('urpf-check'));
};

/**
 * Get uRPF mode (strict, loose, or undefined)
 */
export const getUrpfMode = (node: ConfigNode): 'strict' | 'loose' | undefined => {
  // Search recursively for urpf-check and mode
  let mode: 'strict' | 'loose' | undefined;
  const findMode = (n: ConfigNode): void => {
    const rawText = n?.rawText?.toLowerCase() ?? '';
    if (rawText.includes('urpf-check')) {
      if (rawText.includes('strict')) {
        mode = 'strict';
      } else if (rawText.includes('loose')) {
        mode = 'loose';
      }
    }
    if (rawText.includes('mode strict')) {
      mode = 'strict';
    } else if (rawText.includes('mode loose')) {
      mode = 'loose';
    }
    if (n?.children) {
      n.children.forEach(findMode);
    }
  };
  findMode(node);
  return mode;
};

/**
 * Check if IP filter is applied
 */
export const hasIpFilter = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('ip-filter') ||
    rawText.includes('ingress filter') ||
    rawText.includes('egress filter')
  );
};

// ============================================================================
// Logging Helpers
// ============================================================================

/**
 * Check if syslog is configured
 */
export const hasSyslog = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.startsWith('syslog') || rawText.includes('syslog')
  );
};

/**
 * Check if SNMP trap group is configured
 */
export const hasSnmpTrapGroup = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('snmp-trap-group'));
};

/**
 * Check if event-control is configured
 */
export const hasEventControl = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('event-control'));
};

/**
 * Check if accounting policy is configured
 */
export const hasAccountingPolicy = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('accounting-policy'));
};

// ============================================================================
// High Availability Helpers
// ============================================================================

/**
 * Check if BFD is enabled on interface
 */
export const hasBfd = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('bfd-liveness') || rawText.includes('bfd')
  );
};

/**
 * Check if MC-LAG is configured
 */
export const hasMcLag = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) =>
    rawText.includes('mc-lag') || rawText.includes('multi-chassis')
  );
};

/**
 * Check if MC-LAG authentication is configured
 */
export const hasMcLagAuthentication = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('authentication-key'));
};

/**
 * Check if LACP is configured
 */
export const hasLacp = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('lacp'));
};

// ============================================================================
// Service Security Helpers
// ============================================================================

/**
 * Check if VPRN has route-distinguisher configured
 */
export const hasRouteDistinguisher = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('route-distinguisher'));
};

/**
 * Check if VPRN has vrf-target configured
 */
export const hasVrfTarget = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('vrf-target'));
};

/**
 * Check if GRT leaking is configured (potential security concern)
 */
export const hasGrtLeaking = (node: ConfigNode): boolean => {
  return searchNodeRecursively(node, (rawText) => rawText.includes('grt-leaking'));
};

/**
 * Get BGP neighbor IP address from neighbor node
 */
export const getBgpNeighborIp = (node: ConfigNode): string => {
  if (!node?.id) return '';
  const match = node.id.match(/neighbor\s+"?([^"]+)"?|neighbor\s+([\d.:a-fA-F]+)/i);
  if (match) {
    return match[1] ?? match[2] ?? node.id.replace(/^neighbor\s+/i, '').trim();
  }
  return node.id.replace(/^neighbor\s+/i, '').trim();
};

/**
 * Get BGP group name from group node
 */
export const getBgpGroupName = (node: ConfigNode): string => {
  if (!node?.id) return '';
  const match = node.id.match(/group\s+"([^"]+)"/i);
  if (match?.[1]) {
    return match[1];
  }
  return node.id.replace(/^group\s+/i, '').replace(/"/g, '').trim();
};
