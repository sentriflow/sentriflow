// packages/rule-helpers/src/juniper/helpers.ts
// Juniper JunOS-specific helper functions
// Based on Juniper Best Practices: docs/Juniper-best-practices.md

import type { ConfigNode } from '../../types/ConfigNode';
import {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
  parseIp,
  prefixToMask,
  equalsIgnoreCase,
  includesIgnoreCase,
  startsWithIgnoreCase,
  parseInteger,
} from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands, parseIp } from '../common/helpers';

/**
 * Check if a JunOS interface is disabled (has "disable" statement)
 */
export const isDisabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => equalsIgnoreCase(child.id.trim(), 'disable'));
};

/**
 * Check if interface is a physical port (not lo0, irb, etc.)
 */
export const isPhysicalJunosPort = (interfaceName: string): boolean => {
  // Physical interfaces in JunOS: ge-, xe-, et-, ae- (aggregated), etc.
  return (
    startsWithIgnoreCase(interfaceName, 'ge-') ||
    startsWithIgnoreCase(interfaceName, 'xe-') ||
    startsWithIgnoreCase(interfaceName, 'et-') ||
    startsWithIgnoreCase(interfaceName, 'ae') ||
    startsWithIgnoreCase(interfaceName, 'em') ||
    startsWithIgnoreCase(interfaceName, 'fxp')
  );
};

/**
 * Check if interface is a loopback
 */
export const isLoopback = (interfaceName: string): boolean => {
  return startsWithIgnoreCase(interfaceName, 'lo') || equalsIgnoreCase(interfaceName, 'lo0');
};

/**
 * Check if interface is an IRB (Integrated Routing and Bridging) interface
 */
export const isIrbInterface = (interfaceName: string): boolean => {
  return startsWithIgnoreCase(interfaceName, 'irb');
};

/**
 * Parse JunOS address format (e.g., "10.0.0.1/24")
 * @param address The address string with CIDR notation
 * @returns Object with ip number, prefix length, and mask, or null if invalid
 */
export const parseJunosAddress = (
  address: string
): { ip: number; prefix: number; mask: number } | null => {
  const parts = address.split('/');
  if (parts.length !== 2) return null;

  const ipPart = parts[0];
  const prefixPart = parts[1];
  if (!ipPart || !prefixPart) return null;

  const ip = parseIp(ipPart);
  const prefix = parseInteger(prefixPart);

  if (ip === null || prefix === null || prefix < 0 || prefix > 32) {
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
  return node.children.find(
    (child) => equalsIgnoreCase(child.id, stanzaName)
  );
};

/**
 * Find all stanzas matching a pattern within a node's children
 * @param node The parent ConfigNode
 * @param pattern The regex pattern to match
 * @returns Array of matching child nodes
 */
export const findStanzas = (node: ConfigNode, pattern: RegExp): ConfigNode[] => {
  // Note: Pattern is expected to have 'i' flag for case-insensitive matching
  return node.children.filter((child) => pattern.test(child.id));
};

/**
 * Get all interface units from a JunOS interface node
 * @param interfaceNode The interface ConfigNode
 * @returns Array of unit nodes
 */
export const getInterfaceUnits = (interfaceNode: ConfigNode): ConfigNode[] => {
  return interfaceNode.children.filter((child) =>
    startsWithIgnoreCase(child.id, 'unit')
  );
};

/**
 * Check if a policy-statement has a "then reject" or "then accept" action
 * @param termNode The term ConfigNode
 * @returns 'accept' | 'reject' | 'next' | undefined
 */
export const getTermAction = (
  termNode: ConfigNode
): 'accept' | 'reject' | 'next' | undefined => {
  // First check for inline "then action" commands (e.g., "then reject;")
  for (const child of termNode.children) {
    const id = child.id.trim();
    if (equalsIgnoreCase(id, 'then accept') || equalsIgnoreCase(id, 'then accept;')) return 'accept';
    if (equalsIgnoreCase(id, 'then reject') || equalsIgnoreCase(id, 'then reject;')) return 'reject';
    if (startsWithIgnoreCase(id, 'then next')) return 'next';
  }

  // Then check for nested "then" stanza with children
  const thenStanza = findStanza(termNode, 'then');
  if (!thenStanza) return undefined;

  for (const child of thenStanza.children) {
    const id = child.id.trim();
    if (equalsIgnoreCase(id, 'accept') || equalsIgnoreCase(id, 'accept;')) return 'accept';
    if (equalsIgnoreCase(id, 'reject') || equalsIgnoreCase(id, 'reject;')) return 'reject';
    if (startsWithIgnoreCase(id, 'next')) return 'next';
  }

  return undefined;
};

/**
 * Check if a firewall filter term has a "then discard" or "then reject" action
 * @param termNode The term ConfigNode
 * @returns true if the term discards/rejects traffic
 */
export const isFilterTermDrop = (termNode: ConfigNode): boolean => {
  // First check for inline "then action" commands (e.g., "then discard;")
  for (const child of termNode.children) {
    const id = child.id.trim();
    if (
      equalsIgnoreCase(id, 'then discard') ||
      equalsIgnoreCase(id, 'then discard;') ||
      equalsIgnoreCase(id, 'then reject') ||
      equalsIgnoreCase(id, 'then reject;')
    ) {
      return true;
    }
  }

  // Then check for nested "then" stanza with children
  const thenStanza = findStanza(termNode, 'then');
  if (!thenStanza) return false;

  for (const child of thenStanza.children) {
    const id = child.id.trim();
    if (equalsIgnoreCase(id, 'discard') || equalsIgnoreCase(id, 'discard;') || equalsIgnoreCase(id, 'reject') || equalsIgnoreCase(id, 'reject;')) {
      return true;
    }
  }

  return false;
};

// ============================================================================
// JUNOS-MGMT: Management Plane Security Helpers
// ============================================================================

/**
 * Check if SSH v2 only is configured (protocol-version v2)
 * JUNOS-MGMT-003: SSH must be version 2 only
 */
export const isSshV2Only = (servicesNode: ConfigNode): boolean => {
  const ssh = findStanza(servicesNode, 'ssh');
  if (!ssh) return false;

  for (const child of ssh.children) {
    if (includesIgnoreCase(child.id, 'protocol-version') && includesIgnoreCase(child.id, 'v2') && !includesIgnoreCase(child.id, 'v1')) {
      return true;
    }
  }
  return false;
};

/**
 * Check if SSH root login is denied
 * JUNOS-MGMT-003: SSH root-login must be deny
 */
export const isSshRootLoginDenied = (servicesNode: ConfigNode): boolean => {
  const ssh = findStanza(servicesNode, 'ssh');
  if (!ssh) return false;

  for (const child of ssh.children) {
    if (includesIgnoreCase(child.id, 'root-login') && includesIgnoreCase(child.id, 'deny')) {
      return true;
    }
  }
  return false;
};

/**
 * Check if telnet service is configured (insecure)
 * JUNOS-MGMT-002: Telnet should be disabled
 */
export const hasTelnetService = (servicesNode: ConfigNode): boolean => {
  return hasChildCommand(servicesNode, 'telnet');
};

/**
 * Check if finger service is configured (insecure)
 * JUNOS-MGMT-002: Finger should be disabled
 */
export const hasFingerService = (servicesNode: ConfigNode): boolean => {
  return hasChildCommand(servicesNode, 'finger');
};

/**
 * Check if FTP service is configured (insecure)
 * JUNOS-MGMT-002: FTP should be disabled
 */
export const hasFtpService = (servicesNode: ConfigNode): boolean => {
  return hasChildCommand(servicesNode, 'ftp');
};

/**
 * Check if xnm-clear-text service is configured (insecure)
 * JUNOS-MGMT-002: xnm-clear-text should be disabled
 */
export const hasXnmClearText = (servicesNode: ConfigNode): boolean => {
  return hasChildCommand(servicesNode, 'xnm-clear-text');
};

/**
 * Check if HTTP web management is configured (insecure)
 * JUNOS-MGMT-002: HTTP web management should be disabled
 */
export const hasHttpWebManagement = (servicesNode: ConfigNode): boolean => {
  const webMgmt = findStanza(servicesNode, 'web-management');
  if (!webMgmt) return false;
  return hasChildCommand(webMgmt, 'http');
};

/**
 * Get insecure services list from a services node
 */
export const getInsecureServices = (servicesNode: ConfigNode): string[] => {
  const insecure: string[] = [];
  if (hasTelnetService(servicesNode)) insecure.push('telnet');
  if (hasFingerService(servicesNode)) insecure.push('finger');
  if (hasFtpService(servicesNode)) insecure.push('ftp');
  if (hasXnmClearText(servicesNode)) insecure.push('xnm-clear-text');
  if (hasHttpWebManagement(servicesNode)) insecure.push('web-management http');
  return insecure;
};

/**
 * Check if TACACS+ is configured
 * JUNOS-MGMT-004: AAA should use TACACS+ or RADIUS
 */
export const hasTacacsServer = (systemNode: ConfigNode): boolean => {
  return hasChildCommand(systemNode, 'tacplus-server');
};

/**
 * Check if RADIUS is configured
 * JUNOS-MGMT-004: AAA should use TACACS+ or RADIUS
 */
export const hasRadiusServer = (systemNode: ConfigNode): boolean => {
  return hasChildCommand(systemNode, 'radius-server');
};

/**
 * Check if authentication-order is configured
 * JUNOS-MGMT-004: Authentication order should be configured
 */
export const hasAuthenticationOrder = (systemNode: ConfigNode): boolean => {
  return hasChildCommand(systemNode, 'authentication-order');
};

/**
 * Check if SNMPv3 is configured (preferred over v1/v2c)
 * JUNOS-MGMT-005: SNMPv3 with authPriv is recommended
 */
export const hasSnmpV3 = (snmpNode: ConfigNode): boolean => {
  return hasChildCommand(snmpNode, 'v3');
};

/**
 * Check if NTP authentication is configured
 * JUNOS-MGMT-006: NTP should have authentication
 */
export const hasNtpAuthentication = (ntpNode: ConfigNode): boolean => {
  return (
    hasChildCommand(ntpNode, 'authentication-key') && hasChildCommand(ntpNode, 'trusted-key')
  );
};

/**
 * Check if login banner is configured
 * JUNOS-MGMT-007: Login banner should be configured
 */
export const hasLoginBanner = (systemNode: ConfigNode): boolean => {
  const login = findStanza(systemNode, 'login');
  if (!login) return false;
  return hasChildCommand(login, 'message');
};

/**
 * Check if console log-out-on-disconnect is configured
 * JUNOS-MGMT-008: Console security
 */
export const hasConsoleLogoutOnDisconnect = (systemNode: ConfigNode): boolean => {
  const ports = findStanza(systemNode, 'ports');
  if (!ports) return false;
  const console = findStanza(ports, 'console');
  if (!console) return false;
  return hasChildCommand(console, 'log-out-on-disconnect');
};

/**
 * Check if auxiliary port is disabled
 * JUNOS-MGMT-008: Auxiliary port should be disabled
 */
export const isAuxPortDisabled = (systemNode: ConfigNode): boolean => {
  const ports = findStanza(systemNode, 'ports');
  if (!ports) return false;
  const aux = findStanza(ports, 'auxiliary');
  if (!aux) return true; // Not configured = good
  return hasChildCommand(aux, 'disable');
};

/**
 * Check login retry options configuration
 * JUNOS-MGMT-003: Login retry limits should be configured
 */
export const hasLoginRetryOptions = (systemNode: ConfigNode): boolean => {
  const login = findStanza(systemNode, 'login');
  if (!login) return false;
  return hasChildCommand(login, 'retry-options');
};

// ============================================================================
// JUNOS-CTRL: Control Plane Security Helpers
// ============================================================================

/**
 * Check if OSPF interface has authentication configured
 * JUNOS-CTRL-001: OSPF authentication
 */
export const hasOspfInterfaceAuth = (interfaceNode: ConfigNode): boolean => {
  return hasChildCommand(interfaceNode, 'authentication');
};

/**
 * Check if OSPF area has any authenticated interfaces
 */
export const hasOspfAreaAuth = (areaNode: ConfigNode): boolean => {
  const interfaces = findStanzas(areaNode, /^interface/i);
  return interfaces.some((iface) => hasOspfInterfaceAuth(iface));
};

/**
 * Check if IS-IS interface has hello authentication
 * JUNOS-CTRL-001: IS-IS authentication
 */
export const hasIsisInterfaceAuth = (interfaceNode: ConfigNode): boolean => {
  return hasChildCommand(interfaceNode, 'hello-authentication');
};

/**
 * Check if VRRP group has authentication
 * JUNOS-CTRL-002: VRRP authentication
 */
export const hasVrrpAuth = (vrrpGroupNode: ConfigNode): boolean => {
  return hasChildCommand(vrrpGroupNode, 'authentication');
};

/**
 * Check if BFD is configured for an interface or neighbor
 * JUNOS-CTRL-003: BFD should be enabled for fast failure detection
 */
export const hasBfd = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'bfd-liveness-detection');
};

// ============================================================================
// JUNOS-DATA: Data Plane Security Helpers
// ============================================================================

/**
 * Check if interface has rpf-check (uRPF) enabled
 * JUNOS-DATA-002: uRPF should be enabled
 */
export const hasRpfCheck = (unitNode: ConfigNode): boolean => {
  // Check under family inet
  const familyInet = findStanza(unitNode, 'family inet');
  if (familyInet) {
    return hasChildCommand(familyInet, 'rpf-check');
  }
  return hasChildCommand(unitNode, 'rpf-check');
};

/**
 * Check if interface has no-redirects configured
 * JUNOS-DATA-001: ICMP redirects should be disabled
 */
export const hasNoRedirects = (unitNode: ConfigNode): boolean => {
  const familyInet = findStanza(unitNode, 'family inet');
  if (familyInet) {
    return hasChildCommand(familyInet, 'no-redirects');
  }
  return hasChildCommand(unitNode, 'no-redirects');
};

// ============================================================================
// JUNOS-BGP: BGP Security Helpers
// ============================================================================

/**
 * Check if BGP neighbor has authentication-key configured
 * JUNOS-BGP-001: BGP peers should have MD5 authentication
 */
export const hasBgpNeighborAuth = (neighborNode: ConfigNode): boolean => {
  return (
    hasChildCommand(neighborNode, 'authentication-key') ||
    hasChildCommand(neighborNode, 'authentication-key-chain')
  );
};

/**
 * Check if BGP group has authentication configured
 */
export const hasBgpGroupAuth = (groupNode: ConfigNode): boolean => {
  return (
    hasChildCommand(groupNode, 'authentication-key') ||
    hasChildCommand(groupNode, 'authentication-key-chain')
  );
};

/**
 * Check if BGP group has TTL security configured (GTSM)
 * JUNOS-BGP-002: TTL security for eBGP peers
 */
export const hasBgpTtlSecurity = (groupNode: ConfigNode): boolean => {
  return hasChildCommand(groupNode, 'ttl') || hasChildCommand(groupNode, 'multihop');
};

/**
 * Check if BGP group has prefix-limit configured
 * JUNOS-BGP-003: Maximum prefix limits
 */
export const hasBgpPrefixLimit = (groupNode: ConfigNode): boolean => {
  // Check under family inet unicast
  const family = findStanza(groupNode, 'family');
  if (!family) {
    // Also check direct children for "family inet"
    for (const child of groupNode.children) {
      if (startsWithIgnoreCase(child.id, 'family')) {
        const hasLimit = hasChildCommand(child, 'prefix-limit');
        if (hasLimit) return true;
        // Check nested unicast
        for (const nested of child.children) {
          if (hasChildCommand(nested, 'prefix-limit')) return true;
        }
      }
    }
    return false;
  }
  return hasChildCommand(family, 'prefix-limit');
};

/**
 * Check if BGP group has import/export policies configured
 * JUNOS-BGP-004: Prefix filtering
 */
export const hasBgpPolicies = (groupNode: ConfigNode): boolean => {
  return hasChildCommand(groupNode, 'import') || hasChildCommand(groupNode, 'export');
};

/**
 * Check if BGP group type is external (eBGP)
 */
export const isBgpGroupExternal = (groupNode: ConfigNode): boolean => {
  return groupNode.children.some((child) => includesIgnoreCase(child.id, 'type external'));
};

/**
 * Check if graceful-restart is configured
 * JUNOS-BGP-007: Graceful restart for non-disruptive failover
 */
export const hasGracefulRestart = (routingOptionsNode: ConfigNode): boolean => {
  return hasChildCommand(routingOptionsNode, 'graceful-restart');
};

// ============================================================================
// JUNOS-RE: Routing Engine Protection Helpers
// ============================================================================

/**
 * Check if loopback interface has input filter
 * JUNOS-RE-001: Protect-RE filter should be applied to lo0
 */
export const hasLoopbackInputFilter = (interfacesNode: ConfigNode): boolean => {
  const lo0 = findStanza(interfacesNode, 'lo0');
  if (!lo0) return false;

  // Check unit 0
  const unit0 = findStanza(lo0, 'unit 0');
  if (!unit0) return false;

  // Check family inet for filter input
  const familyInet = findStanza(unit0, 'family inet');
  if (!familyInet) return false;

  if (hasChildCommand(familyInet, 'filter input')) {
    return true;
  }

  const filterSection = findStanza(familyInet, 'filter');
  if (!filterSection) return false;

  return hasChildCommand(filterSection, 'input');
};

// ============================================================================
// JUNOS-ZONE: Zone-Based Security Helpers (SRX)
// ============================================================================

/**
 * Check if security zones are configured
 * JUNOS-ZONE-001: Security zones should be configured
 */
export const hasSecurityZones = (securityNode: ConfigNode): boolean => {
  return hasChildCommand(securityNode, 'zones');
};

/**
 * Check if zone has screen configured
 * JUNOS-ZONE-003: Security screens should be enabled
 */
export const hasZoneScreen = (zoneNode: ConfigNode): boolean => {
  return hasChildCommand(zoneNode, 'screen');
};

/**
 * Get zone name from a security-zone node
 */
export const getZoneName = (zoneNode: ConfigNode): string | undefined => {
  const match = zoneNode.id.match(/security-zone\s+(\S+)/i);
  return match?.[1];
};

/**
 * Check if security policies are configured
 * JUNOS-ZONE-002: Security policies should be configured
 */
export const hasSecurityPolicies = (securityNode: ConfigNode): boolean => {
  return hasChildCommand(securityNode, 'policies');
};

/**
 * Check if policy has logging enabled
 */
export const hasPolicyLogging = (policyNode: ConfigNode): boolean => {
  const thenStanza = findStanza(policyNode, 'then');
  if (!thenStanza) return false;
  return hasChildCommand(thenStanza, 'log');
};

// ============================================================================
// JUNOS-VPN: IPsec VPN Helpers
// ============================================================================

/**
 * Check if IKE proposal uses strong DH group (group14 or higher)
 * JUNOS-VPN-001: Use strong DH groups
 */
export const hasStrongDhGroup = (proposalNode: ConfigNode): boolean => {
  for (const child of proposalNode.children) {
    if (includesIgnoreCase(child.id, 'dh-group')) {
      // Weak groups: group1, group2, group5
      if (includesIgnoreCase(child.id, 'group1') && !includesIgnoreCase(child.id, 'group14')) return false;
      if (includesIgnoreCase(child.id, 'group2') && !includesIgnoreCase(child.id, 'group21')) return false;
      if (includesIgnoreCase(child.id, 'group5')) return false;
      // Strong groups: group14, group15, group16, group19, group20, group21
      if (
        includesIgnoreCase(child.id, 'group14') ||
        includesIgnoreCase(child.id, 'group15') ||
        includesIgnoreCase(child.id, 'group16') ||
        includesIgnoreCase(child.id, 'group19') ||
        includesIgnoreCase(child.id, 'group20') ||
        includesIgnoreCase(child.id, 'group21')
      ) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Check if IPsec proposal uses strong encryption (AES-256)
 * JUNOS-VPN-001: Use strong encryption
 */
export const hasStrongEncryption = (proposalNode: ConfigNode): boolean => {
  for (const child of proposalNode.children) {
    if (includesIgnoreCase(child.id, 'encryption-algorithm')) {
      if (includesIgnoreCase(child.id, 'aes-256') || includesIgnoreCase(child.id, 'aes-gcm-256')) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Check if IKE gateway has dead-peer-detection
 */
export const hasDpdEnabled = (gatewayNode: ConfigNode): boolean => {
  return hasChildCommand(gatewayNode, 'dead-peer-detection');
};

// ============================================================================
// JUNOS-DDOS: DDoS Protection Helpers
// ============================================================================

/**
 * Check if DDoS protection is configured
 * JUNOS-DDOS-001: Control plane DDoS protection
 */
export const hasDdosProtection = (systemNode: ConfigNode): boolean => {
  return hasChildCommand(systemNode, 'ddos-protection');
};

// ============================================================================
// JUNOS-HA: High Availability Helpers
// ============================================================================

/**
 * Check if GRES (Graceful Routing Engine Switchover) is configured
 * JUNOS-HA-002: GRES for dual-RE systems
 */
export const hasGres = (chassisNode: ConfigNode): boolean => {
  const redundancy = findStanza(chassisNode, 'redundancy');
  if (!redundancy) return false;
  return hasChildCommand(redundancy, 'graceful-switchover');
};

/**
 * Check if NSR (Nonstop Active Routing) is configured
 * JUNOS-HA-003: NSR for protocol state synchronization
 */
export const hasNsr = (routingOptionsNode: ConfigNode): boolean => {
  return hasChildCommand(routingOptionsNode, 'nonstop-routing');
};

/**
 * Check if chassis cluster is configured (SRX HA)
 * JUNOS-HA-001: Chassis cluster for SRX
 */
export const hasChassisCluster = (chassisNode: ConfigNode): boolean => {
  return hasChildCommand(chassisNode, 'cluster');
};

// ============================================================================
// JUNOS-LOG: Logging Helpers
// ============================================================================

/**
 * Check if remote syslog host is configured
 * JUNOS-LOG-001: Remote syslog should be configured
 */
export const hasRemoteSyslog = (syslogNode: ConfigNode): boolean => {
  return hasChildCommand(syslogNode, 'host');
};

/**
 * Check if syslog file archiving is configured
 */
export const hasSyslogArchive = (syslogNode: ConfigNode): boolean => {
  return hasChildCommand(syslogNode, 'archive');
};

/**
 * Check if security logging is configured (SRX)
 * JUNOS-LOG-002: Security logging
 */
export const hasSecurityLogging = (securityNode: ConfigNode): boolean => {
  return hasChildCommand(securityNode, 'log');
};

/**
 * Check if J-Flow/NetFlow sampling is configured
 * JUNOS-LOG-003: Flow monitoring
 */
export const hasFlowMonitoring = (forwardingOptionsNode: ConfigNode): boolean => {
  return hasChildCommand(forwardingOptionsNode, 'sampling');
};

// ============================================================================
// RPKI Helpers
// ============================================================================

/**
 * Check if RPKI validation is configured
 * JUNOS-BGP-006: RPKI origin validation
 */
export const hasRpkiValidation = (routingOptionsNode: ConfigNode): boolean => {
  return hasChildCommand(routingOptionsNode, 'validation');
};

// ============================================================================
// Security Screens Helpers
// ============================================================================

/**
 * Check if screen has TCP protections
 */
export const hasScreenTcpProtection = (screenNode: ConfigNode): boolean => {
  return hasChildCommand(screenNode, 'tcp');
};

/**
 * Check if screen has IP protections
 */
export const hasScreenIpProtection = (screenNode: ConfigNode): boolean => {
  return hasChildCommand(screenNode, 'ip');
};

/**
 * Check if screen has ICMP protections
 */
export const hasScreenIcmpProtection = (screenNode: ConfigNode): boolean => {
  return hasChildCommand(screenNode, 'icmp');
};
