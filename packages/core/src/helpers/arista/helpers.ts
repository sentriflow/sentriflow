// packages/rule-helpers/src/arista/helpers.ts
// Arista EOS-specific helper functions
// Based on Arista Best Practices: docs/Arista-best-practices.md

import type { ConfigNode } from '../../types/ConfigNode';
import {
  hasChildCommand,
  getChildCommand,
  parseIp,
  equalsIgnoreCase,
  includesIgnoreCase,
  startsWithIgnoreCase,
  parseInteger,
} from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands, parseIp } from '../common/helpers';

// ============================================================================
// Management Plane Security Helpers
// ============================================================================

/**
 * Check if password uses SHA-512 encryption (strong)
 * @param node The config node containing password
 * @returns true if using sha512 encryption
 */
export const hasStrongPasswordEncryption = (node: ConfigNode): boolean => {
  return includesIgnoreCase(node.id, 'sha512') || includesIgnoreCase(node.id, '$6$');
};

/**
 * Check if password is plaintext (cleartext)
 * @param node The config node containing password
 * @returns true if password appears to be plaintext
 */
export const hasPlaintextPassword = (node: ConfigNode): boolean => {
  // Check for cleartext password patterns
  if (includesIgnoreCase(node.id, 'secret 0 ') || includesIgnoreCase(node.id, 'password 0 ')) {
    return true;
  }
  // Check for enable password without encryption type
  if (/^enable\s+password\s+[^$]/i.test(node.id)) {
    return true;
  }
  return false;
};

/**
 * Check if service password-encryption is enabled
 * @param ast The full AST array
 * @returns true if service password-encryption is configured
 */
export const hasServicePasswordEncryption = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    equalsIgnoreCase(node.id, 'service password-encryption')
  );
};

/**
 * Check if SSH version 2 is configured
 * @param ast The full AST array
 * @returns true if SSH v2 is configured
 */
export const hasSshVersion2 = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ip\s+ssh\s+version\s+2/i.test(node.id)
  );
};

/**
 * Check for weak SSH ciphers
 * @param ast The full AST array
 * @returns Array of weak ciphers found
 */
export const getWeakSshCiphers = (ast: ConfigNode[]): string[] => {
  const weakCiphers = ['3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'blowfish-cbc'];
  const found: string[] = [];

  for (const node of ast) {
    if (/^ip\s+ssh\s+ciphers/i.test(node.id)) {
      for (const cipher of weakCiphers) {
        if (includesIgnoreCase(node.id, cipher)) {
          found.push(cipher);
        }
      }
    }
  }
  return found;
};

/**
 * Check if telnet management is disabled
 * @param ast The full AST array
 * @returns true if telnet is properly disabled
 */
export const isTelnetDisabled = (ast: ConfigNode[]): boolean => {
  if (!ast) return true;
  // Check for 'no management telnet' or management telnet with shutdown
  const noMgmtTelnet = ast.some((node) =>
    node?.id && /^no\s+management\s+telnet/i.test(node.id)
  );

  if (noMgmtTelnet) return true;

  // Check if management telnet section exists and is shutdown
  const mgmtTelnet = ast.find((node) =>
    node?.id && /^management\s+telnet/i.test(node.id)
  );

  if (mgmtTelnet?.children) {
    return mgmtTelnet.children.some((child) =>
      child?.id && equalsIgnoreCase(child.id, 'shutdown')
    );
  }

  // Telnet is disabled by default in EOS
  return true;
};

/**
 * Check if HTTP server is disabled (insecure)
 * @param ast The full AST array
 * @returns true if HTTP server is disabled
 */
export const isHttpServerDisabled = (ast: ConfigNode[]): boolean => {
  const hasNoHttp = ast.some((node) =>
    /^no\s+ip\s+http\s+server/i.test(node.id)
  );
  const hasHttp = ast.some((node) =>
    /^ip\s+http\s+server/i.test(node.id) && !/^no\s+/i.test(node.id)
  );
  return hasNoHttp || !hasHttp;
};

/**
 * Check for SNMPv1/v2c community strings (insecure)
 * @param ast The full AST array
 * @returns Array of insecure community configurations found
 */
export const getInsecureSnmpCommunities = (ast: ConfigNode[]): string[] => {
  const insecure: string[] = [];
  const defaultCommunities = ['public', 'private', 'community'];

  for (const node of ast) {
    if (/^snmp-server\s+community\s+/i.test(node.id)) {
      const match = node.id.match(/snmp-server\s+community\s+(\S+)/i);
      if (match?.[1]) {
        const community = match[1];
        if (defaultCommunities.some((dc) => equalsIgnoreCase(community, dc))) {
          insecure.push(`Default community "${match[1]}"`);
        } else {
          insecure.push(`SNMPv2c community configured`);
        }
      }
    }
  }
  return insecure;
};

/**
 * Check if SNMPv3 is properly configured with auth and priv
 * @param ast The full AST array
 * @returns true if SNMPv3 with priv mode is configured
 */
export const hasSnmpV3AuthPriv = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^snmp-server\s+group\s+\S+\s+v3\s+priv/i.test(node.id) ||
    /^snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+\s+\S+\s+priv/i.test(node.id)
  );
};

/**
 * Check if NTP authentication is enabled
 * @param ast The full AST array
 * @returns true if NTP authentication is configured
 */
export const hasNtpAuthentication = (ast: ConfigNode[]): boolean => {
  const hasAuthenticate = ast.some((node) =>
    /^ntp\s+authenticate$/i.test(node.id)
  );
  const hasTrustedKey = ast.some((node) =>
    /^ntp\s+trusted-key\s+/i.test(node.id)
  );
  return hasAuthenticate && hasTrustedKey;
};

/**
 * Check if AAA authentication login is configured
 * @param ast The full AST array
 * @returns true if AAA authentication login is configured
 */
export const hasAaaAuthenticationLogin = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^aaa\s+authentication\s+login\s+/i.test(node.id)
  );
};

/**
 * Check if TACACS+ is configured
 * @param ast The full AST array
 * @returns true if TACACS+ server is configured
 */
export const hasTacacsServer = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^tacacs-server\s+host\s+/i.test(node.id)
  );
};

/**
 * Check if AAA accounting is configured
 * @param ast The full AST array
 * @returns true if AAA accounting is configured
 */
export const hasAaaAccounting = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^aaa\s+accounting\s+/i.test(node.id)
  );
};

/**
 * Check if Management VRF is configured
 * @param ast The full AST array
 * @returns true if management VRF is properly configured
 */
export const hasManagementVrf = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^vrf\s+instance\s+MGMT/i.test(node.id) ||
    /^vrf\s+instance\s+management/i.test(node.id)
  );
};

/**
 * Check if login banner reveals system information (non-compliant)
 * @param ast The full AST array
 * @returns Array of information disclosure issues found
 */
export const getBannerInfoDisclosure = (ast: ConfigNode[]): string[] => {
  const issues: string[] = [];
  const sensitivePatterns = [
    { pattern: /version\s+\d+/i, desc: 'software version' },
    { pattern: /arista/i, desc: 'vendor name' },
    { pattern: /eos/i, desc: 'OS name' },
    { pattern: /@\S+\.\S+/i, desc: 'email address' },
    { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, desc: 'IP address' },
  ];

  for (const node of ast) {
    if (/^banner\s+(login|motd)/i.test(node.id)) {
      const bannerText = node.rawText || node.id;
      for (const { pattern, desc } of sensitivePatterns) {
        if (pattern.test(bannerText)) {
          issues.push(`Banner contains ${desc}`);
        }
      }
    }
  }
  return issues;
};

/**
 * Check if console idle timeout is configured
 * @param ast The full AST array
 * @returns The timeout value in minutes, or undefined if not set
 */
export const getConsoleIdleTimeout = (ast: ConfigNode[]): number | undefined => {
  if (!ast) return undefined;
  for (const node of ast) {
    if (node?.id && /^management\s+console/i.test(node.id)) {
      if (!node?.children) continue;
      for (const child of node.children) {
        const match = child?.id?.match(/idle-timeout\s+(\d+)/i);
        if (match?.[1]) {
          return parseInteger(match[1]) ?? undefined;
        }
      }
    }
  }
  return undefined;
};

/**
 * Check if ZTP (Zero Touch Provisioning) is disabled
 * @param ast The full AST array
 * @returns true if ZTP is disabled
 */
export const isZtpDisabled = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^no\s+zerotouch\s+enable/i.test(node.id) ||
    equalsIgnoreCase(node.id, 'zerotouch cancel')
  );
};

// ============================================================================
// Control Plane Security Helpers
// ============================================================================

/**
 * Check if Control Plane ACL is configured
 * @param ast The full AST array
 * @returns true if system control-plane ACL is configured
 */
export const hasControlPlaneAcl = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^system\s+control-plane/i.test(node.id)
  );
};

/**
 * Check if CoPP (Control Plane Policing) is customized
 * @param ast The full AST array
 * @returns true if CoPP policy is customized
 */
export const hasCoppPolicy = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^policy-map\s+type\s+copp/i.test(node.id)
  );
};

/**
 * Check if interface has ICMP redirects disabled
 * @param interfaceNode The interface ConfigNode
 * @returns true if ip redirects are disabled
 */
export const hasNoIpRedirects = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^no\s+ip\s+redirects/i.test(child.id)
  );
};

/**
 * Check if interface has ICMP unreachables disabled
 * @param interfaceNode The interface ConfigNode
 * @returns true if ip unreachables are disabled
 */
export const hasNoIpUnreachables = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^no\s+ip\s+unreachables/i.test(child.id)
  );
};

/**
 * Check if routing protocol has authentication configured
 * @param routerNode The router ConfigNode (OSPF, IS-IS, etc.)
 * @returns true if authentication is configured
 */
export const hasRoutingProtocolAuth = (routerNode: ConfigNode): boolean => {
  if (!routerNode?.id || !routerNode?.children) return false;
  // Check for OSPF authentication
  if (/^router\s+ospf/i.test(routerNode.id)) {
    return routerNode.children.some((child) =>
      child?.id && /authentication/i.test(child.id)
    );
  }

  // Check for IS-IS authentication
  if (/^router\s+isis/i.test(routerNode.id)) {
    return routerNode.children.some((child) =>
      child?.id && /authentication/i.test(child.id)
    );
  }

  return false;
};

/**
 * Check if BFD (Bidirectional Forwarding Detection) is configured
 * @param ast The full AST array
 * @returns true if BFD is configured
 */
export const hasBfd = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^bfd\s+/i.test(node.id)
  );
};

// ============================================================================
// Data Plane Security Helpers
// ============================================================================

/**
 * Check if interface has storm control configured
 * @param interfaceNode The interface ConfigNode
 * @returns Object with storm control status for each type
 */
export const getStormControlStatus = (interfaceNode: ConfigNode): { broadcast: boolean; multicast: boolean; unicast: boolean } => {
  if (!interfaceNode?.children) return { broadcast: false, multicast: false, unicast: false };
  return {
    broadcast: interfaceNode.children.some((child) =>
      child?.id && /^storm-control\s+broadcast/i.test(child.id)
    ),
    multicast: interfaceNode.children.some((child) =>
      child?.id && /^storm-control\s+multicast/i.test(child.id)
    ),
    unicast: interfaceNode.children.some((child) =>
      child?.id && /^storm-control\s+unknown-unicast/i.test(child.id)
    ),
  };
};

/**
 * Check if DHCP snooping is enabled
 * @param ast The full AST array
 * @returns true if DHCP snooping is configured
 */
export const hasDhcpSnooping = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ip\s+dhcp\s+snooping$/i.test(node.id)
  );
};

/**
 * Check if interface is DHCP snooping trusted
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface is DHCP snooping trusted
 */
export const isDhcpSnoopingTrust = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^ip\s+dhcp\s+snooping\s+trust/i.test(child.id)
  );
};

/**
 * Check if Dynamic ARP Inspection is enabled
 * @param ast The full AST array
 * @returns true if DAI is configured
 */
export const hasDynamicArpInspection = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ip\s+arp\s+inspection\s+vlan/i.test(node.id)
  );
};

/**
 * Check if interface is ARP inspection trusted
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface is ARP inspection trusted
 */
export const isArpInspectionTrust = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^ip\s+arp\s+inspection\s+trust/i.test(child.id)
  );
};

/**
 * Check if IP Source Guard is enabled on interface
 * @param interfaceNode The interface ConfigNode
 * @returns true if IP verify source is configured
 */
export const hasIpSourceGuard = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^ip\s+verify\s+source/i.test(child.id)
  );
};

/**
 * Check if port security is enabled on interface
 * @param interfaceNode The interface ConfigNode
 * @returns true if port security is configured
 */
export const hasPortSecurity = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^switchport\s+port-security/i.test(child.id)
  );
};

// ============================================================================
// BGP Security Helpers
// ============================================================================

/**
 * Check if BGP neighbor has MD5/password authentication
 * @param routerBgpNode The router bgp ConfigNode
 * @param neighborIp Optional specific neighbor IP to check
 * @returns Array of neighbors without authentication
 */
export const getBgpNeighborsWithoutAuth = (routerBgpNode: ConfigNode, neighborIp?: string): string[] => {
  const neighborsWithoutAuth: string[] = [];
  if (!routerBgpNode?.children) return neighborsWithoutAuth;
  const neighborConfigs = new Map<string, { hasPassword: boolean }>();

  for (const child of routerBgpNode.children) {
    const neighborMatch = child?.id?.match(/^neighbor\s+(\S+)/i);
    if (neighborMatch?.[1]) {
      const ip = neighborMatch[1];
      if (!neighborConfigs.has(ip)) {
        neighborConfigs.set(ip, { hasPassword: false });
      }

      if (child?.id && /password/i.test(child.id)) {
        const config = neighborConfigs.get(ip);
        if (config) {
          config.hasPassword = true;
        }
      }
    }
  }

  for (const [ip, config] of neighborConfigs) {
    if (!config.hasPassword) {
      if (!neighborIp || ip === neighborIp) {
        neighborsWithoutAuth.push(ip);
      }
    }
  }

  return neighborsWithoutAuth;
};

/**
 * Check if BGP neighbor has TTL security (GTSM) configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns Array of neighbors without TTL security
 */
export const getBgpNeighborsWithoutTtlSecurity = (routerBgpNode: ConfigNode): string[] => {
  const neighborsWithoutTtl: string[] = [];
  if (!routerBgpNode?.children) return neighborsWithoutTtl;
  const neighborConfigs = new Map<string, { hasTtl: boolean; isEbgp: boolean }>();
  const localAs = routerBgpNode?.id?.match(/router\s+bgp\s+(\d+)/i)?.[1];

  for (const child of routerBgpNode.children) {
    const neighborMatch = child?.id?.match(/^neighbor\s+(\S+)\s+remote-as\s+(\d+)/i);
    if (neighborMatch?.[1] && neighborMatch?.[2]) {
      const ip = neighborMatch[1];
      const remoteAs = neighborMatch[2];
      neighborConfigs.set(ip, {
        hasTtl: false,
        isEbgp: localAs !== remoteAs
      });
    }

    const ttlMatch = child?.id?.match(/^neighbor\s+(\S+)\s+ttl\s+maximum-hops/i);
    if (ttlMatch?.[1]) {
      const config = neighborConfigs.get(ttlMatch[1]);
      if (config) {
        config.hasTtl = true;
      }
    }
  }

  for (const [ip, config] of neighborConfigs) {
    if (config.isEbgp && !config.hasTtl) {
      neighborsWithoutTtl.push(ip);
    }
  }

  return neighborsWithoutTtl;
};

/**
 * Check if BGP neighbor has maximum-routes configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns Array of neighbors without max-prefix limit
 */
export const getBgpNeighborsWithoutMaxRoutes = (routerBgpNode: ConfigNode): string[] => {
  const neighborsWithoutMax: string[] = [];
  if (!routerBgpNode?.children) return neighborsWithoutMax;
  const neighborConfigs = new Map<string, boolean>();

  for (const child of routerBgpNode.children) {
    const neighborMatch = child?.id?.match(/^neighbor\s+(\S+)\s+remote-as/i);
    if (neighborMatch?.[1]) {
      neighborConfigs.set(neighborMatch[1], false);
    }

    const maxMatch = child?.id?.match(/^neighbor\s+(\S+)\s+maximum-routes/i);
    if (maxMatch?.[1]) {
      neighborConfigs.set(maxMatch[1], true);
    }
  }

  for (const [ip, hasMax] of neighborConfigs) {
    if (!hasMax) {
      neighborsWithoutMax.push(ip);
    }
  }

  return neighborsWithoutMax;
};

/**
 * Check if BGP has graceful restart configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if graceful restart is configured
 */
export const hasBgpGracefulRestart = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  return routerBgpNode.children.some((child) =>
    child?.id && /^bgp\s+graceful-restart/i.test(child.id)
  );
};

/**
 * Check if BGP has log-neighbor-changes configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if log-neighbor-changes is configured
 */
export const hasBgpLogNeighborChanges = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  return routerBgpNode.children.some((child) =>
    child?.id && /^bgp\s+log-neighbor-changes/i.test(child.id)
  );
};

// ============================================================================
// RPKI Helpers
// ============================================================================

/**
 * Check if RPKI is configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if RPKI cache is configured
 */
export const hasRpkiConfiguration = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  return routerBgpNode.children.some((child) =>
    child?.id && /^rpki\s+cache/i.test(child.id)
  );
};

/**
 * Check if RPKI origin validation is enabled
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if origin validation is configured
 */
export const hasRpkiOriginValidation = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  return routerBgpNode.children.some((child) =>
    child?.id && /^rpki\s+origin-validation/i.test(child.id)
  );
};

// ============================================================================
// Anti-Spoofing Helpers
// ============================================================================

/**
 * Check if interface has uRPF (unicast RPF) configured
 * @param interfaceNode The interface ConfigNode
 * @returns Object with uRPF mode if configured
 */
export const getUrpfMode = (interfaceNode: ConfigNode): { enabled: boolean; mode?: 'strict' | 'loose' } => {
  if (!interfaceNode?.children) return { enabled: false };
  for (const child of interfaceNode.children) {
    if (child?.id && /^ip\s+verify\s+unicast\s+source\s+reachable-via\s+rx/i.test(child.id)) {
      return { enabled: true, mode: 'strict' };
    }
    if (child?.id && /^ip\s+verify\s+unicast\s+source\s+reachable-via\s+any/i.test(child.id)) {
      return { enabled: true, mode: 'loose' };
    }
  }
  return { enabled: false };
};

// ============================================================================
// MLAG Helpers (existing, enhanced)
// ============================================================================

/**
 * Check if MLAG dual-primary detection is configured
 * @param mlagNode The MLAG configuration node
 * @returns true if dual-primary detection is configured
 */
export const hasMlagDualPrimaryDetection = (mlagNode: ConfigNode): boolean => {
  return hasChildCommand(mlagNode, 'dual-primary detection');
};

/**
 * Check if MLAG reload delays are configured
 * @param mlagNode The MLAG configuration node
 * @returns Object with reload delay configuration status
 */
export const getMlagReloadDelays = (mlagNode: ConfigNode): { mlag: boolean; nonMlag: boolean } => {
  return {
    mlag: hasChildCommand(mlagNode, 'reload-delay mlag'),
    nonMlag: hasChildCommand(mlagNode, 'reload-delay non-mlag'),
  };
};

// ============================================================================
// VXLAN/EVPN Helpers (existing, enhanced)
// ============================================================================

/**
 * Check if EVPN peers have password authentication
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if EVPN peer group has password
 */
export const hasEvpnPeerAuth = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  // Look for EVPN peer group with password
  let evpnPeerGroup: string | undefined;

  for (const child of routerBgpNode.children) {
    // Find EVPN address family activation
    if (child?.id && /^address-family\s+evpn/i.test(child.id)) {
      if (!child?.children) continue;
      for (const subchild of child.children) {
        const match = subchild?.id?.match(/neighbor\s+(\S+)\s+activate/i);
        if (match?.[1]) {
          evpnPeerGroup = match[1];
        }
      }
    }
  }

  if (!evpnPeerGroup) return false;

  // Check if peer group has password
  return routerBgpNode.children.some((child) =>
    child?.id && includesIgnoreCase(child.id, `neighbor ${evpnPeerGroup}`) &&
    includesIgnoreCase(child.id, 'password')
  );
};

// ============================================================================
// Logging/Monitoring Helpers
// ============================================================================

/**
 * Check if logging is configured with specific level
 * @param ast The full AST array
 * @param minLevel Minimum required logging level
 * @returns true if logging meets minimum level requirement
 */
export const hasLoggingLevel = (ast: ConfigNode[], minLevel: string): boolean => {
  const levels = ['emergencies', 'alerts', 'critical', 'errors', 'warnings', 'notifications', 'informational', 'debugging'];
  const minIndex = levels.indexOf(minLevel.toLowerCase());

  for (const node of ast) {
    const match = node.id.match(/^logging\s+(?:buffered|trap)\s+(\S+)/i);
    if (match?.[1]) {
      const configuredIndex = levels.indexOf(match[1].toLowerCase());
      if (configuredIndex >= minIndex) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Check if logging source interface is configured
 * @param ast The full AST array
 * @returns true if logging source-interface is configured
 */
export const hasLoggingSourceInterface = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^logging\s+source-interface/i.test(node.id)
  );
};

/**
 * Check if event-monitor is enabled
 * @param ast The full AST array
 * @returns true if event-monitor is configured
 */
export const hasEventMonitor = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^event-monitor$/i.test(node.id)
  );
};

// ============================================================================
// High Availability Helpers
// ============================================================================

/**
 * Check if VRRP has authentication configured
 * @param interfaceNode The interface ConfigNode
 * @returns true if VRRP authentication is configured
 */
export const hasVrrpAuthentication = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^vrrp\s+\d+\s+authentication/i.test(child.id)
  );
};

/**
 * Check if virtual-router MAC is configured (for MLAG VARP)
 * @param ast The full AST array
 * @returns true if ip virtual-router mac-address is configured
 */
export const hasVirtualRouterMac = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ip\s+virtual-router\s+mac-address/i.test(node.id)
  );
};

// ============================================================================
// Interface Type Helpers (extending existing)
// ============================================================================

/**
 * Check if interface is a WAN/external facing interface
 * Based on description containing WAN, Internet, ISP, External keywords
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface appears to be external facing
 */
export const isExternalInterface = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  const description = interfaceNode.children.find((child) =>
    child?.id && startsWithIgnoreCase(child.id, 'description ')
  );

  if (description?.id) {
    return (
      includesIgnoreCase(description.id, 'wan') ||
      includesIgnoreCase(description.id, 'internet') ||
      includesIgnoreCase(description.id, 'isp') ||
      includesIgnoreCase(description.id, 'external') ||
      includesIgnoreCase(description.id, 'uplink') ||
      includesIgnoreCase(description.id, 'peering')
    );
  }

  return false;
};

/**
 * Check if interface is an access (edge/endpoint) port
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface is configured as access port
 */
export const isAccessPort = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^switchport\s+mode\s+access/i.test(child.id)
  );
};

/**
 * Check if interface is a trunk port
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface is configured as trunk port
 */
export const isTrunkPort = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^switchport\s+mode\s+trunk/i.test(child.id)
  );
};

/**
 * Check if MLAG is configured
 * @param ast The full AST array
 * @returns true if mlag configuration block exists
 */
export const hasMlagConfiguration = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    startsWithIgnoreCase(node.id, 'mlag configuration')
  );
};

/**
 * Get MLAG configuration node
 * @param ast The full AST array
 * @returns The MLAG configuration node, or undefined
 */
export const getMlagConfiguration = (
  ast: ConfigNode[]
): ConfigNode | undefined => {
  return ast.find((node) =>
    startsWithIgnoreCase(node.id, 'mlag configuration')
  );
};

/**
 * Check if MLAG has required settings (domain-id, peer-link, peer-address)
 * @param mlagNode The MLAG configuration node
 * @returns Object with status of each MLAG requirement
 */
export const checkMlagRequirements = (
  mlagNode: ConfigNode
): { hasDomainId: boolean; hasPeerLink: boolean; hasPeerAddress: boolean; hasLocalInterface: boolean } => {
  return {
    hasDomainId: hasChildCommand(mlagNode, 'domain-id'),
    hasPeerLink: hasChildCommand(mlagNode, 'peer-link'),
    hasPeerAddress: hasChildCommand(mlagNode, 'peer-address'),
    hasLocalInterface: hasChildCommand(mlagNode, 'local-interface'),
  };
};

/**
 * Check if management API (eAPI) is configured
 * @param ast The full AST array
 * @returns true if management api http-commands is configured
 */
export const hasManagementApi = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    startsWithIgnoreCase(node.id, 'management api')
  );
};

/**
 * Get management API configuration nodes
 * @param ast The full AST array
 * @returns Array of management API configuration nodes
 */
export const getManagementApiNodes = (ast: ConfigNode[]): ConfigNode[] => {
  return ast.filter((node) =>
    startsWithIgnoreCase(node.id, 'management api')
  );
};

/**
 * Check if management API has HTTPS enabled (secure)
 * @param apiNode The management api configuration node
 * @returns true if HTTPS transport is configured
 */
export const hasHttpsTransport = (apiNode: ConfigNode): boolean => {
  if (!apiNode?.children) return false;
  // Check for "protocol https" or "no shutdown" with https
  const hasProtocolHttps = apiNode.children.some((child) =>
    child?.id && includesIgnoreCase(child.id, 'protocol https')
  );
  const hasTransportHttps = apiNode.children.some((child) =>
    child?.id && includesIgnoreCase(child.id, 'transport https')
  );
  return hasProtocolHttps || hasTransportHttps;
};

/**
 * Check if an interface is a VXLAN interface
 * @param node The interface ConfigNode
 * @returns true if it's a VXLAN interface
 */
export const isVxlanInterface = (node: ConfigNode): boolean => {
  return /^interface\s+Vxlan\d*/i.test(node.id);
};

/**
 * Check if an interface is an MLAG peer-link (typically Port-Channel)
 * @param node The interface ConfigNode
 * @param mlagNode The MLAG configuration node (optional)
 * @returns true if this interface is configured as MLAG peer-link
 */
export const isMlagPeerLink = (
  node: ConfigNode,
  mlagNode?: ConfigNode
): boolean => {
  if (!mlagNode) return false;
  const peerLink = getChildCommand(mlagNode, 'peer-link');
  if (!peerLink) return false;

  // Extract interface name from peer-link command
  const match = peerLink.id.match(/peer-link\s+(\S+)/i);
  if (!match) return false;

  const peerLinkInterface = match[1];
  if (!peerLinkInterface) return false;
  return includesIgnoreCase(node.id, peerLinkInterface);
};

/**
 * Get all VXLAN VNI mappings from a Vxlan interface
 * @param vxlanNode The Vxlan interface ConfigNode
 * @returns Array of VNI mappings
 */
export const getVxlanVniMappings = (
  vxlanNode: ConfigNode
): { vni: string; vlan?: string }[] => {
  const mappings: { vni: string; vlan?: string }[] = [];
  if (!vxlanNode?.children) return mappings;

  for (const child of vxlanNode.children) {
    const vniMatch = child?.id?.match(/vxlan\s+vni\s+(\d+)\s+vlan\s+(\d+)/i);
    if (vniMatch) {
      const vni = vniMatch[1];
      if (!vni) {
        continue;
      }
      const vlan = vniMatch[2];
      mappings.push({ vni, vlan });
      continue;
    }

    const simpleMatch = child?.id?.match(/vxlan\s+vni\s+(\d+)/i);
    if (simpleMatch) {
      const vni = simpleMatch[1];
      if (!vni) {
        continue;
      }
      mappings.push({ vni });
    }
  }

  return mappings;
};

/**
 * Check if VXLAN has source interface configured
 * @param vxlanNode The Vxlan interface ConfigNode
 * @returns true if vxlan source-interface is configured
 */
export const hasVxlanSourceInterface = (vxlanNode: ConfigNode): boolean => {
  return hasChildCommand(vxlanNode, 'vxlan source-interface');
};

/**
 * Check if interface has MLAG ID configured
 * @param interfaceNode The interface ConfigNode
 * @returns The MLAG ID if configured, undefined otherwise
 */
export const getMlagId = (interfaceNode: ConfigNode): string | undefined => {
  if (!interfaceNode?.children) return undefined;
  const mlagCmd = interfaceNode.children.find((child) =>
    child?.id && /^mlag\s+\d+/i.test(child.id)
  );
  if (!mlagCmd) return undefined;

  const match = mlagCmd.id.match(/mlag\s+(\d+)/i);
  return match ? match[1] : undefined;
};

/**
 * Check if interface is a Port-Channel
 * @param node The interface ConfigNode
 * @returns true if it's a Port-Channel interface
 */
export const isPortChannel = (node: ConfigNode): boolean => {
  return /^interface\s+Port-Channel\d+/i.test(node.id);
};

/**
 * Check if interface is a Loopback
 * @param node The interface ConfigNode
 * @returns true if it's a Loopback interface
 */
export const isLoopback = (node: ConfigNode): boolean => {
  return /^interface\s+Loopback\d+/i.test(node.id);
};

/**
 * Check if interface is an SVI (VLAN interface)
 * @param node The interface ConfigNode
 * @returns true if it's a VLAN SVI
 */
export const isSvi = (node: ConfigNode): boolean => {
  return /^interface\s+Vlan\d+/i.test(node.id);
};

/**
 * Check if interface is a Management interface
 * @param node The interface ConfigNode
 * @returns true if it's a Management interface
 */
export const isManagementInterface = (node: ConfigNode): boolean => {
  return /^interface\s+Management\d+/i.test(node.id);
};

/**
 * Check if interface is an Ethernet port
 * @param node The interface ConfigNode
 * @returns true if it's an Ethernet interface
 */
export const isEthernetInterface = (node: ConfigNode): boolean => {
  return /^interface\s+Ethernet\d+/i.test(node.id);
};

/**
 * Check if daemon is configured
 * @param ast The full AST array
 * @param daemonName Optional specific daemon name to check
 * @returns true if daemon(s) are configured
 */
export const hasDaemon = (ast: ConfigNode[], daemonName?: string): boolean => {
  if (daemonName) {
    return ast.some((node) =>
      equalsIgnoreCase(node.id, `daemon ${daemonName}`)
    );
  }
  return ast.some((node) => startsWithIgnoreCase(node.id, 'daemon '));
};

/**
 * Check if event-handler is configured
 * @param ast The full AST array
 * @returns true if event-handler(s) are configured
 */
export const hasEventHandler = (ast: ConfigNode[]): boolean => {
  return ast.some((node) => startsWithIgnoreCase(node.id, 'event-handler '));
};

/**
 * Get all VRF instances
 * @param ast The full AST array
 * @returns Array of VRF instance nodes
 */
export const getVrfInstances = (ast: ConfigNode[]): ConfigNode[] => {
  return ast.filter((node) =>
    /^vrf\s+instance\s+\S+/i.test(node.id)
  );
};

/**
 * Check if interface is in a VRF
 * @param interfaceNode The interface ConfigNode
 * @returns The VRF name if configured, undefined otherwise
 */
export const getInterfaceVrf = (interfaceNode: ConfigNode): string | undefined => {
  if (!interfaceNode?.children) return undefined;
  const vrfCmd = interfaceNode.children.find((child) =>
    child?.id && /^vrf\s+\S+/i.test(child.id)
  );
  if (!vrfCmd) return undefined;

  const match = vrfCmd.id.match(/vrf\s+(\S+)/i);
  return match ? match[1] : undefined;
};

/**
 * Check if BGP EVPN is configured
 * @param routerBgpNode The router bgp ConfigNode
 * @returns true if EVPN address-family is configured
 */
export const hasEvpnAddressFamily = (routerBgpNode: ConfigNode): boolean => {
  if (!routerBgpNode?.children) return false;
  return routerBgpNode.children.some((child) =>
    child?.id && /^address-family\s+evpn/i.test(child.id)
  );
};

/**
 * Check if interface has IP virtual-router address (VARP)
 * @param interfaceNode The interface ConfigNode
 * @returns true if ip virtual-router address is configured
 */
export const hasVirtualRouterAddress = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^ip\s+virtual-router\s+address/i.test(child.id)
  );
};

/**
 * Check if interface has ip address configured
 * @param interfaceNode The interface ConfigNode
 * @returns true if ip address is configured
 */
export const hasIpAddress = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  return interfaceNode.children.some((child) =>
    child?.id && /^ip\s+address\s+\d+\.\d+\.\d+\.\d+/i.test(child.id)
  );
};

/**
 * Check if interface is shutdown
 * @param interfaceNode The interface ConfigNode
 * @returns true if interface is shutdown
 */
export const isShutdown = (interfaceNode: ConfigNode): boolean => {
  if (!interfaceNode?.children) return false;
  const hasShutdown = interfaceNode.children.some((child) =>
    child?.id && equalsIgnoreCase(child.id, 'shutdown')
  );
  const hasNoShutdown = interfaceNode.children.some((child) =>
    child?.id && equalsIgnoreCase(child.id, 'no shutdown')
  );
  return hasShutdown && !hasNoShutdown;
};

/**
 * Get interface description
 * @param interfaceNode The interface ConfigNode
 * @returns The description if configured, undefined otherwise
 */
export const getInterfaceDescription = (interfaceNode: ConfigNode): string | undefined => {
  if (!interfaceNode?.children) return undefined;
  const descCmd = interfaceNode.children.find((child) =>
    child?.id && startsWithIgnoreCase(child.id, 'description ')
  );
  if (!descCmd) return undefined;

  return descCmd.id.replace(/^description\s+/i, '').trim();
};

/**
 * Check if NTP is configured
 * @param ast The full AST array
 * @returns true if NTP server(s) are configured
 */
export const hasNtpServer = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^ntp\s+server\s+/i.test(node.id)
  );
};

/**
 * Check if syslog/logging is configured
 * @param ast The full AST array
 * @returns true if logging host is configured
 */
export const hasLoggingHost = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^logging\s+host\s+/i.test(node.id)
  );
};

/**
 * Check if SNMP is configured
 * @param ast The full AST array
 * @returns true if SNMP is configured
 */
export const hasSnmpServer = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^snmp-server\s+/i.test(node.id)
  );
};

/**
 * Check if AAA is configured
 * @param ast The full AST array
 * @returns true if AAA is configured
 */
export const hasAaa = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^aaa\s+/i.test(node.id)
  );
};

/**
 * Check if spanning-tree is configured
 * @param ast The full AST array
 * @returns true if spanning-tree is configured
 */
export const hasSpanningTree = (ast: ConfigNode[]): boolean => {
  return ast.some((node) =>
    /^spanning-tree\s+/i.test(node.id)
  );
};

/**
 * Get spanning-tree mode
 * @param ast The full AST array
 * @returns The spanning-tree mode (mstp, rapid-pvst, none, etc.)
 */
export const getSpanningTreeMode = (ast: ConfigNode[]): string | undefined => {
  const stpNode = ast.find((node) =>
    /^spanning-tree\s+mode\s+/i.test(node.id)
  );
  if (!stpNode) return undefined;

  const match = stpNode.id.match(/spanning-tree\s+mode\s+(\S+)/i);
  return match ? match[1] : undefined;
};
