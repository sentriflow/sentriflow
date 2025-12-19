// packages/rule-helpers/src/huawei/helpers.ts
// Huawei VRP-specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

// Re-export common helpers for convenience
export { hasChildCommand, getChildCommand, getChildCommands } from '../common/helpers';

/**
 * Check if interface is shutdown (using Huawei's 'undo shutdown' pattern)
 * In Huawei, interfaces are shutdown by default; 'undo shutdown' enables them
 */
export const isShutdown = (node: ConfigNode): boolean => {
  // Check if there's a 'shutdown' command
  const hasShutdown = node.children.some((child) => {
    const id = child.id.toLowerCase().trim();
    return id === 'shutdown';
  });

  // Check if there's an 'undo shutdown' command
  const hasUndoShutdown = node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo shutdown';
  });

  // Shutdown if explicitly shutdown OR no undo shutdown (Huawei default is shutdown)
  return hasShutdown || !hasUndoShutdown;
};

/**
 * Check if interface is explicitly enabled (has 'undo shutdown')
 */
export const isEnabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo shutdown';
  });
};

/**
 * Check if interface is a physical port (not Vlanif, LoopBack, NULL, Tunnel, etc.)
 */
export const isPhysicalPort = (interfaceName: string): boolean => {
  const name = interfaceName.toLowerCase();
  return (
    !name.includes('vlanif') &&
    !name.includes('loopback') &&
    !name.includes('null') &&
    !name.includes('tunnel') &&
    !name.includes('eth-trunk') &&
    !name.includes('nve') &&
    !name.includes('vbdif')
  );
};

/**
 * Check if interface is a VLAN interface (Vlanif)
 */
export const isVlanInterface = (interfaceName: string): boolean => {
  return interfaceName.toLowerCase().includes('vlanif');
};

/**
 * Check if interface is a loopback interface
 */
export const isLoopbackInterface = (interfaceName: string): boolean => {
  return interfaceName.toLowerCase().includes('loopback');
};

/**
 * Check if interface is an Eth-Trunk (LAG)
 */
export const isEthTrunk = (interfaceName: string): boolean => {
  return interfaceName.toLowerCase().includes('eth-trunk');
};

/**
 * Check if interface is configured as trunk port
 */
export const isTrunkPort = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.includes('port link-type trunk') ?? false;
  });
};

/**
 * Check if interface is configured as access port
 */
export const isAccessPort = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.includes('port link-type access') ?? false;
  });
};

/**
 * Check if interface is configured as hybrid port
 */
export const isHybridPort = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.includes('port link-type hybrid') ?? false;
  });
};

/**
 * Get the default VLAN for an access port
 */
export const getDefaultVlan = (node: ConfigNode): string | undefined => {
  const vlanCmd = node.children.find((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.startsWith('port default vlan') ?? false;
  });

  if (vlanCmd?.rawText) {
    const match = vlanCmd.rawText.match(/port\s+default\s+vlan\s+(\d+)/i);
    const vlan = match?.[1];
    if (vlan) {
      return vlan;
    }
  }
  return undefined;
};

/**
 * Get allowed VLANs for trunk port
 */
export const getTrunkAllowedVlans = (node: ConfigNode): string | undefined => {
  const vlanCmd = node.children.find((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.startsWith('port trunk allow-pass vlan') ?? false;
  });

  if (vlanCmd?.rawText) {
    const match = vlanCmd.rawText.match(/port\s+trunk\s+allow-pass\s+vlan\s+(.+)/i);
    const vlans = match?.[1];
    if (vlans) {
      return vlans.trim();
    }
  }
  return undefined;
};

/**
 * Check if interface has description
 */
export const hasDescription = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'description');
};

/**
 * Get interface description
 */
export const getDescription = (node: ConfigNode): string | undefined => {
  const descCmd = getChildCommand(node, 'description');
  if (descCmd?.rawText) {
    const match = descCmd.rawText.match(/description\s+(.+)/i);
    const description = match?.[1];
    if (description) {
      return description.trim();
    }
  }
  return undefined;
};

/**
 * Check if STP edge port is enabled (stp edged-port enable)
 */
export const hasStpEdgedPort = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.includes('stp edged-port enable') ?? false;
  });
};

/**
 * Check if port security is enabled
 */
export const hasPortSecurity = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText?.includes('port-security enable') ?? false;
  });
};

/**
 * Check if BPDU protection is enabled
 */
export const hasBpduProtection = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    if (!rawText) {
      return false;
    }
    return rawText.includes('stp bpdu-protection') || rawText.includes('bpdu-protection enable');
  });
};

/**
 * Get child command value for 'set <key> <value>' style commands
 */
export const getCommandValue = (node: ConfigNode, command: string): string | undefined => {
  const cmd = node.children.find((child) => {
    const text = child.rawText?.toLowerCase().trim();
    return text?.startsWith(command.toLowerCase()) ?? false;
  });

  if (cmd?.rawText) {
    const rest = cmd.rawText.substring(command.length).trim();
    return rest || undefined;
  }
  return undefined;
};

/**
 * Check if SSH is enabled
 */
export const isSshEnabled = (node: ConfigNode): boolean => {
  if (node.id.toLowerCase().includes('user-interface')) {
    return node.children.some((child) => {
      const rawText = child.rawText?.toLowerCase().trim();
      return rawText?.includes('protocol inbound ssh') || rawText === 'protocol inbound all';
    });
  }
  return false;
};

/**
 * Check if Telnet is enabled (security concern)
 */
export const isTelnetEnabled = (node: ConfigNode): boolean => {
  if (node.id.toLowerCase().includes('user-interface')) {
    return node.children.some((child) => {
      const rawText = child.rawText.toLowerCase().trim();
      return (
        rawText.includes('protocol inbound telnet') ||
        rawText === 'protocol inbound all' ||
        // Default for VTY is often telnet
        (!rawText.includes('protocol inbound'))
      );
    });
  }
  return false;
};

/**
 * Check if authentication mode AAA is configured
 */
export const hasAaaAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText.toLowerCase().trim();
    return rawText.includes('authentication-mode aaa');
  });
};

/**
 * Check if password authentication is configured (less secure)
 */
export const hasPasswordAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText.toLowerCase().trim();
    return rawText.includes('authentication-mode password');
  });
};

/**
 * Check if idle timeout is configured
 */
export const hasIdleTimeout = (node: ConfigNode): boolean => {
  return hasChildCommand(node, 'idle-timeout');
};

/**
 * Get idle timeout value in minutes
 */
export const getIdleTimeout = (node: ConfigNode): number | undefined => {
  const timeoutCmd = getChildCommand(node, 'idle-timeout');
  if (timeoutCmd?.rawText) {
    const match = timeoutCmd.rawText.match(/idle-timeout\s+(\d+)/i);
    const timeout = match?.[1];
    if (timeout) {
      return parseInt(timeout, 10);
    }
  }
  return undefined;
};

/**
 * Check if ACL is applied inbound on user-interface
 */
export const hasAclInbound = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText.toLowerCase().trim();
    return rawText.match(/acl\s+\d+\s+inbound/);
  });
};

/**
 * Find a stanza by name in the configuration tree
 */
export const findStanza = (node: ConfigNode, stanzaName: string): ConfigNode | undefined => {
  if (node.id.toLowerCase().startsWith(stanzaName.toLowerCase())) {
    return node;
  }
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
  if (node.id.toLowerCase().startsWith(stanzaName.toLowerCase())) {
    results.push(node);
  }
  for (const child of node.children) {
    results.push(...findStanzas(child, stanzaName));
  }
  return results;
};

/**
 * Check if local-user has password configured with cipher (encrypted)
 */
export const hasEncryptedPassword = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText.toLowerCase().trim();
    return (
      rawText.includes('password cipher') ||
      rawText.includes('password irreversible-cipher')
    );
  });
};

/**
 * Check if local-user has plaintext password (security concern)
 */
export const hasPlaintextPassword = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText.toLowerCase().trim();
    return rawText.includes('password simple');
  });
};

/**
 * Get privilege level for local-user
 */
export const getPrivilegeLevel = (node: ConfigNode): number | undefined => {
  const privCmd = node.children.find((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('privilege level');
  });

  if (privCmd?.rawText) {
    const match = privCmd.rawText.match(/privilege\s+level\s+(\d+)/i);
    const level = match?.[1];
    if (level) {
      return parseInt(level, 10);
    }
  }
  return undefined;
};

// ============================================================================
// BGP Helper Functions
// ============================================================================

/**
 * Check if BGP peer has password authentication configured
 */
export const hasBgpPeerPassword = (node: ConfigNode, peerIp: string): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes(`peer ${peerIp.toLowerCase()}`) && rawText?.includes('password');
  });
};

/**
 * Check if BGP peer has keychain authentication configured
 */
export const hasBgpPeerKeychain = (node: ConfigNode, peerIp: string): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes(`peer ${peerIp.toLowerCase()}`) && rawText?.includes('keychain');
  });
};

/**
 * Check if BGP peer has GTSM (valid-ttl-hops) configured
 */
export const hasBgpPeerGtsm = (node: ConfigNode, peerIp: string): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes(`peer ${peerIp.toLowerCase()}`) && rawText?.includes('valid-ttl-hops');
  });
};

/**
 * Check if BGP peer has route-limit (maximum prefix) configured
 */
export const hasBgpPeerRouteLimit = (node: ConfigNode, peerIp: string): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes(`peer ${peerIp.toLowerCase()}`) && rawText?.includes('route-limit');
  });
};

/**
 * Check if BGP peer has prefix filtering configured (ip-prefix or route-policy)
 */
export const hasBgpPeerPrefixFilter = (node: ConfigNode, peerIp: string): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return (
      rawText?.includes(`peer ${peerIp.toLowerCase()}`) &&
      (rawText?.includes('ip-prefix') || rawText?.includes('route-policy') || rawText?.includes('filter-policy'))
    );
  });
};

/**
 * Get all BGP peer IP addresses from config
 */
export const getBgpPeers = (node: ConfigNode): string[] => {
  const peers: string[] = [];
  for (const child of node.children) {
    if (child.rawText) {
      const match = child.rawText.match(/peer\s+([\d.]+)\s+as-number/i);
      if (match?.[1]) {
        peers.push(match[1]);
      }
    }
  }
  return peers;
};

/**
 * Check if BGP has graceful-restart enabled
 */
export const hasBgpGracefulRestart = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'graceful-restart' || rawText?.startsWith('graceful-restart ');
  });
};

// ============================================================================
// OSPF/IS-IS Helper Functions
// ============================================================================

/**
 * Check if OSPF area has authentication configured
 */
export const hasOspfAreaAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('authentication-mode');
  });
};

/**
 * Check if interface has OSPF authentication configured
 */
export const hasInterfaceOspfAuth = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('ospf authentication-mode');
  });
};

/**
 * Check if IS-IS has area authentication configured
 */
export const hasIsisAreaAuth = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('area-authentication-mode');
  });
};

/**
 * Check if IS-IS has domain authentication configured
 */
export const hasIsisDomainAuth = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('domain-authentication-mode');
  });
};

/**
 * Check if interface has IS-IS authentication configured
 */
export const hasInterfaceIsisAuth = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('isis authentication-mode');
  });
};

// ============================================================================
// VRRP Helper Functions
// ============================================================================

/**
 * Check if interface has VRRP configured
 */
export const hasVrrp = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('vrrp vrid');
  });
};

/**
 * Check if VRRP has authentication configured
 * In Huawei VRP, authentication can be on a single line: "vrrp vrid 1 authentication-mode md5 <key>"
 */
export const hasVrrpAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    // Check if line contains both vrrp vrid and authentication-mode
    return rawText?.includes('vrrp vrid') && rawText?.includes('authentication-mode');
  });
};

/**
 * Get VRRP VRID from interface
 */
export const getVrrpVrid = (node: ConfigNode): string | undefined => {
  const vrrpCmd = node.children.find((child) => {
    return child.rawText?.toLowerCase().includes('vrrp vrid');
  });

  if (vrrpCmd?.rawText) {
    const match = vrrpCmd.rawText.match(/vrrp\s+vrid\s+(\d+)/i);
    if (match?.[1]) {
      return match[1];
    }
  }
  return undefined;
};

// ============================================================================
// Interface Security Helper Functions
// ============================================================================

/**
 * Check if ICMP redirect is disabled on interface
 */
export const hasIcmpRedirectDisabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo icmp redirect send';
  });
};

/**
 * Check if directed broadcast is disabled on interface
 */
export const hasDirectedBroadcastDisabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo ip directed-broadcast enable' || rawText === 'undo ip directed-broadcast';
  });
};

/**
 * Check if ARP proxy is disabled on interface
 */
export const hasArpProxyDisabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo arp proxy enable' || rawText === 'undo proxy-arp';
  });
};

/**
 * Check if uRPF is enabled on interface
 */
export const hasUrpf = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('urpf strict') || rawText?.includes('urpf loose');
  });
};

/**
 * Get uRPF mode (strict or loose)
 */
export const getUrpfMode = (node: ConfigNode): 'strict' | 'loose' | undefined => {
  const urpfCmd = node.children.find((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('urpf');
  });

  if (urpfCmd?.rawText) {
    const rawText = urpfCmd.rawText.toLowerCase();
    if (rawText.includes('urpf strict')) return 'strict';
    if (rawText.includes('urpf loose')) return 'loose';
  }
  return undefined;
};

/**
 * Check if LLDP is disabled on interface
 */
export const hasLldpDisabled = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'undo lldp enable';
  });
};

// ============================================================================
// NTP Helper Functions
// ============================================================================

/**
 * Check if NTP authentication is enabled
 */
export const hasNtpAuthentication = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'authentication enable';
  });
};

/**
 * Check if NTP has authentication key configured
 */
export const hasNtpAuthKey = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('authentication-keyid');
  });
};

// ============================================================================
// SSH Server Helper Functions
// ============================================================================

/**
 * Check if SSH server has strong ciphers configured
 */
export const hasSshStrongCiphers = (node: ConfigNode): boolean => {
  // Check global config for ssh server cipher settings
  const rawText = node.rawText?.toLowerCase();
  if (rawText?.includes('ssh server cipher')) {
    // Check for strong ciphers (aes256, aes128)
    return rawText.includes('aes256') || rawText.includes('aes128');
  }
  return false;
};

/**
 * Check for weak SSH algorithms
 */
export const hasWeakSshAlgorithms = (node: ConfigNode): boolean => {
  const rawText = node.rawText?.toLowerCase();
  // Check for weak algorithms like 3des, des, arcfour
  return (
    rawText?.includes('3des') ||
    rawText?.includes('arcfour') ||
    (rawText?.includes('des') && !rawText.includes('aes') && !rawText.includes('3des'))
  ) ?? false;
};

/**
 * Check if SSH uses strong HMAC algorithms
 */
export const hasSshStrongHmac = (node: ConfigNode): boolean => {
  const rawText = node.rawText?.toLowerCase();
  if (rawText?.includes('ssh server hmac')) {
    return rawText.includes('sha2-256') || rawText.includes('sha2-512');
  }
  return false;
};

/**
 * Check if SSH uses strong key exchange
 */
export const hasSshStrongKeyExchange = (node: ConfigNode): boolean => {
  const rawText = node.rawText?.toLowerCase();
  if (rawText?.includes('ssh server key-exchange')) {
    return rawText.includes('dh-group14') || rawText.includes('dh-group16') || rawText.includes('dh-group18');
  }
  return false;
};

// ============================================================================
// CPU-Defend Helper Functions
// ============================================================================

/**
 * Check if CPU-defend policy is configured
 */
export const hasCpuDefendPolicy = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('cpu-defend policy');
};

/**
 * Check if CPU-defend policy has auto-defend enabled
 */
export const hasCpuDefendAutoDefend = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase().trim();
    return rawText === 'auto-defend enable';
  });
};

/**
 * Check if CPU-defend policy is applied
 */
export const isCpuDefendPolicyApplied = (rawText: string): boolean => {
  return rawText.toLowerCase().startsWith('cpu-defend-policy');
};

// ============================================================================
// Login Banner Helper Functions
// ============================================================================

/**
 * Check if login banner is configured
 */
export const hasLoginBanner = (node: ConfigNode): boolean => {
  return node.id.toLowerCase().startsWith('header login');
};

// ============================================================================
// Service Status Helper Functions
// ============================================================================

/**
 * Check if FTP server is disabled
 */
export const isFtpDisabled = (rawText: string): boolean => {
  return rawText.toLowerCase().trim() === 'undo ftp server enable';
};

/**
 * Check if HTTP server is disabled
 */
export const isHttpDisabled = (rawText: string): boolean => {
  return rawText.toLowerCase().trim() === 'undo http server enable';
};

/**
 * Check if TFTP server is disabled
 */
export const isTftpDisabled = (rawText: string): boolean => {
  return rawText.toLowerCase().trim() === 'undo tftp-server enable';
};

/**
 * Check if IP source route is disabled
 */
export const isIpSourceRouteDisabled = (rawText: string): boolean => {
  return rawText.toLowerCase().trim() === 'undo ip source-route';
};

// ============================================================================
// HWTACACS Helper Functions
// ============================================================================

/**
 * Check if HWTACACS server template has shared-key configured
 */
export const hasHwtacacsSharedKey = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('shared-key cipher');
  });
};

/**
 * Check if HWTACACS has secondary server configured
 */
export const hasHwtacacsSecondary = (node: ConfigNode): boolean => {
  return node.children.some((child) => {
    const rawText = child.rawText?.toLowerCase();
    return rawText?.includes('secondary');
  });
};
