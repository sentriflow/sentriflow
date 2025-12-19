// packages/rule-helpers/src/paloalto/helpers.ts
// Palo Alto PAN-OS-specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { hasChildCommand, getChildCommand, parseIp } from '../common/helpers';

/**
 * Find a stanza by name within a node's children (case-insensitive)
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
 * Find all stanzas matching a pattern within a node's children
 * @param node The parent ConfigNode
 * @param pattern The regex pattern to match
 * @returns Array of matching child nodes
 */
export const findStanzas = (node: ConfigNode, pattern: RegExp): ConfigNode[] => {
  return node.children.filter((child) => pattern.test(child.id.toLowerCase()));
};

/**
 * Check if a security rule has logging enabled
 * @param ruleNode The security rule ConfigNode
 * @returns Object indicating log-start and log-end status
 */
export const hasLogging = (
  ruleNode: ConfigNode
): { logStart: boolean; logEnd: boolean } => {
  const logStart = hasChildCommand(ruleNode, 'log-start');
  const logEnd = hasChildCommand(ruleNode, 'log-end');
  return { logStart, logEnd };
};

/**
 * Check if a security rule has a security profile attached
 * @param ruleNode The security rule ConfigNode
 * @returns true if any security profile is attached
 */
export const hasSecurityProfile = (ruleNode: ConfigNode): boolean => {
  // Check for profile-setting stanza
  const profileSetting = findStanza(ruleNode, 'profile-setting');
  if (profileSetting && profileSetting.children.length > 0) {
    return true;
  }

  // Check for individual profile commands
  const profileKeywords = [
    'virus',
    'spyware',
    'vulnerability',
    'url-filtering',
    'file-blocking',
    'wildfire-analysis',
    'data-filtering',
  ];

  return profileKeywords.some((keyword) => hasChildCommand(ruleNode, keyword));
};

/**
 * Check if a rule action is "allow" (vs deny/drop/reset)
 * @param ruleNode The rule ConfigNode
 * @returns true if the action is allow
 */
export const isAllowRule = (ruleNode: ConfigNode): boolean => {
  const action = getChildCommand(ruleNode, 'action');
  if (!action) return false;
  return action.id.toLowerCase().includes('allow');
};

/**
 * Check if a rule action is "deny" or "drop" or "reset"
 * @param ruleNode The rule ConfigNode
 * @returns true if the action is deny/drop/reset
 */
export const isDenyRule = (ruleNode: ConfigNode): boolean => {
  const action = getChildCommand(ruleNode, 'action');
  if (!action) return false;
  const actionId = action.id.toLowerCase();
  return (
    actionId.includes('deny') ||
    actionId.includes('drop') ||
    actionId.includes('reset')
  );
};

/**
 * Get the source zones from a rule
 * @param ruleNode The rule ConfigNode
 * @returns Array of source zone names
 */
export const getSourceZones = (ruleNode: ConfigNode): string[] => {
  const from = findStanza(ruleNode, 'from');
  if (!from) return [];
  return from.children.map((child) => child.id.trim());
};

/**
 * Get the destination zones from a rule
 * @param ruleNode The rule ConfigNode
 * @returns Array of destination zone names
 */
export const getDestinationZones = (ruleNode: ConfigNode): string[] => {
  const to = findStanza(ruleNode, 'to');
  if (!to) return [];
  return to.children.map((child) => child.id.trim());
};

/**
 * Get the applications from a rule
 * @param ruleNode The rule ConfigNode
 * @returns Array of application names
 */
export const getApplications = (ruleNode: ConfigNode): string[] => {
  // Check for "application" stanza with children
  const application = findStanza(ruleNode, 'application');
  if (application && application.children.length > 0) {
    return application.children.map((child) => child.id.trim());
  }

  // Also check for inline "application <value>" commands
  const appCommands = ruleNode.children.filter((child) =>
    child.id.toLowerCase().startsWith('application ')
  );
  if (appCommands.length > 0) {
    return appCommands.map((cmd) => {
      const parts = cmd.id.split(/\s+/);
      return parts.slice(1).join(' ').replace(/;$/, '').trim();
    });
  }

  return [];
};

/**
 * Check if a rule uses "any" application (risky)
 * @param ruleNode The rule ConfigNode
 * @returns true if application is "any"
 */
export const hasAnyApplication = (ruleNode: ConfigNode): boolean => {
  const apps = getApplications(ruleNode);
  return apps.some((app) => app.toLowerCase() === 'any');
};

/**
 * Check if a rule uses "any" source (0.0.0.0/0 or "any")
 * @param ruleNode The rule ConfigNode
 * @returns true if source is "any"
 */
export const hasAnySource = (ruleNode: ConfigNode): boolean => {
  // Check for "source" stanza with children
  const source = findStanza(ruleNode, 'source');
  if (source && source.children.length > 0) {
    return source.children.some((child) => {
      const id = child.id.toLowerCase().trim().replace(/;$/, '');
      return id === 'any' || id === '0.0.0.0/0';
    });
  }

  // Also check for inline "source any" or "source <value>" commands
  const sourceCommands = ruleNode.children.filter((child) =>
    child.id.toLowerCase().startsWith('source ')
  );
  if (sourceCommands.length > 0) {
    return sourceCommands.some((cmd) => {
      const value = cmd.id.split(/\s+/).slice(1).join(' ').toLowerCase().replace(/;$/, '').trim();
      return value === 'any' || value === '0.0.0.0/0';
    });
  }

  return false;
};

/**
 * Check if a rule uses "any" destination
 * @param ruleNode The rule ConfigNode
 * @returns true if destination is "any"
 */
export const hasAnyDestination = (ruleNode: ConfigNode): boolean => {
  // Check for "destination" stanza with children
  const destination = findStanza(ruleNode, 'destination');
  if (destination && destination.children.length > 0) {
    return destination.children.some((child) => {
      const id = child.id.toLowerCase().trim().replace(/;$/, '');
      return id === 'any' || id === '0.0.0.0/0';
    });
  }

  // Also check for inline "destination any" or "destination <value>" commands
  const destCommands = ruleNode.children.filter((child) =>
    child.id.toLowerCase().startsWith('destination ')
  );
  if (destCommands.length > 0) {
    return destCommands.some((cmd) => {
      const value = cmd.id.split(/\s+/).slice(1).join(' ').toLowerCase().replace(/;$/, '').trim();
      return value === 'any' || value === '0.0.0.0/0';
    });
  }

  return false;
};

/**
 * Check if a rule uses "any" service (all TCP/UDP ports)
 * @param ruleNode The rule ConfigNode
 * @returns true if service is "any"
 */
export const hasAnyService = (ruleNode: ConfigNode): boolean => {
  // Check for "service" stanza with children
  const service = findStanza(ruleNode, 'service');
  if (service && service.children.length > 0) {
    return service.children.some((child) => {
      const id = child.id.toLowerCase().trim().replace(/;$/, '');
      return id === 'any';
    });
  }

  // Also check for inline "service any" or "service <value>" commands
  const serviceCommands = ruleNode.children.filter((child) =>
    child.id.toLowerCase().startsWith('service ')
  );
  if (serviceCommands.length > 0) {
    return serviceCommands.some((cmd) => {
      const value = cmd.id.split(/\s+/).slice(1).join(' ').toLowerCase().replace(/;$/, '').trim();
      return value === 'any';
    });
  }

  return false;
};

/**
 * Check if a rule is disabled
 * @param ruleNode The rule ConfigNode
 * @returns true if the rule is disabled
 */
export const isRuleDisabled = (ruleNode: ConfigNode): boolean => {
  const disabled = getChildCommand(ruleNode, 'disabled');
  if (!disabled) return false;
  return disabled.id.toLowerCase().includes('yes') || disabled.id.toLowerCase().includes('true');
};

/**
 * Get all security rules from a rulebase
 * @param rulebaseNode The rulebase ConfigNode
 * @returns Array of security rule nodes
 */
export const getSecurityRules = (rulebaseNode: ConfigNode): ConfigNode[] => {
  const security = findStanza(rulebaseNode, 'security');
  if (!security) return [];

  const rules = findStanza(security, 'rules');
  if (!rules) return [];

  return rules.children;
};

/**
 * Get all NAT rules from a rulebase
 * @param rulebaseNode The rulebase ConfigNode
 * @returns Array of NAT rule nodes
 */
export const getNatRules = (rulebaseNode: ConfigNode): ConfigNode[] => {
  const nat = findStanza(rulebaseNode, 'nat');
  if (!nat) return [];

  const rules = findStanza(nat, 'rules');
  if (!rules) return [];

  return rules.children;
};

/**
 * Check if HA (High Availability) is configured
 * @param deviceconfigNode The deviceconfig ConfigNode
 * @returns true if HA is configured
 */
export const isHAConfigured = (deviceconfigNode: ConfigNode): boolean => {
  const ha = findStanza(deviceconfigNode, 'high-availability');
  if (!ha) return false;
  return ha.children.length > 0;
};

/**
 * Check if an interface is a physical Ethernet port
 * @param interfaceName The interface name
 * @returns true if it's a physical ethernet port
 */
export const isPhysicalEthernetPort = (interfaceName: string): boolean => {
  return /^ethernet\d+\/\d+$/i.test(interfaceName);
};

/**
 * Check if an interface is a loopback
 * @param interfaceName The interface name
 * @returns true if it's a loopback interface
 */
export const isLoopbackInterface = (interfaceName: string): boolean => {
  return /^loopback\.\d+$/i.test(interfaceName);
};

/**
 * Check if an interface is a tunnel
 * @param interfaceName The interface name
 * @returns true if it's a tunnel interface
 */
export const isTunnelInterface = (interfaceName: string): boolean => {
  return /^tunnel\.\d+$/i.test(interfaceName);
};

/**
 * Check if an interface is an aggregate (LACP)
 * @param interfaceName The interface name
 * @returns true if it's an aggregate interface
 */
export const isAggregateInterface = (interfaceName: string): boolean => {
  return /^ae\d+$/i.test(interfaceName);
};

/**
 * Extract zone name from a zone configuration node
 * @param zoneNode The zone ConfigNode
 * @returns The zone name
 */
export const getZoneName = (zoneNode: ConfigNode): string => {
  // Zone node ID is typically the zone name itself
  return zoneNode.id.split(/\s+/)[0] || zoneNode.id;
};

/**
 * Check if zone protection profile is applied to a zone
 * @param zoneNode The zone ConfigNode
 * @returns true if zone protection profile is configured
 */
export const hasZoneProtectionProfile = (zoneNode: ConfigNode): boolean => {
  return hasChildCommand(zoneNode, 'zone-protection-profile');
};

/**
 * Check if user identification is enabled on a zone
 * @param zoneNode The zone ConfigNode
 * @returns true if user identification is enabled
 */
export const hasUserIdentification = (zoneNode: ConfigNode): boolean => {
  const network = findStanza(zoneNode, 'network');
  if (!network) return false;
  return hasChildCommand(network, 'enable-user-identification');
};

/**
 * Parse PAN-OS address format (e.g., "10.0.0.1/24" or "10.0.0.1-10.0.0.255")
 * @param address The address string
 * @returns Object with parsed address info, or null if invalid
 */
export const parsePanosAddress = (
  address: string
): { ip: number; prefix?: number; rangeEnd?: number } | null => {
  // CIDR format: 10.0.0.1/24
  if (address.includes('/')) {
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

    return { ip, prefix };
  }

  // Range format: 10.0.0.1-10.0.0.255
  if (address.includes('-')) {
    const parts = address.split('-');
    if (parts.length !== 2) return null;

    const [startStr, endStr] = parts;
    if (!startStr || !endStr) {
      return null;
    }

    const ip = parseIp(startStr);
    const rangeEnd = parseIp(endStr);

    if (ip === null || rangeEnd === null) {
      return null;
    }

    return { ip, rangeEnd };
  }

  // Single IP
  const ip = parseIp(address);
  if (ip === null) return null;

  return { ip };
};

/**
 * Check if WildFire is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if WildFire analysis is configured
 */
export const hasWildfireProfile = (profilesNode: ConfigNode): boolean => {
  const wildfire = findStanza(profilesNode, 'wildfire-analysis');
  return wildfire !== undefined && wildfire.children.length > 0;
};

/**
 * Check if URL Filtering is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if URL filtering is configured
 */
export const hasUrlFilteringProfile = (profilesNode: ConfigNode): boolean => {
  const urlFiltering = findStanza(profilesNode, 'url-filtering');
  return urlFiltering !== undefined && urlFiltering.children.length > 0;
};

/**
 * Check if Anti-Virus profile is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if AV profile is configured
 */
export const hasAntiVirusProfile = (profilesNode: ConfigNode): boolean => {
  const virus = findStanza(profilesNode, 'virus');
  return virus !== undefined && virus.children.length > 0;
};

/**
 * Check if Anti-Spyware profile is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if Anti-Spyware profile is configured
 */
export const hasAntiSpywareProfile = (profilesNode: ConfigNode): boolean => {
  const spyware = findStanza(profilesNode, 'spyware');
  return spyware !== undefined && spyware.children.length > 0;
};

/**
 * Check if Vulnerability Protection profile is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if Vulnerability Protection profile is configured
 */
export const hasVulnerabilityProfile = (profilesNode: ConfigNode): boolean => {
  const vuln = findStanza(profilesNode, 'vulnerability');
  return vuln !== undefined && vuln.children.length > 0;
};

/**
 * Check if File Blocking profile is configured
 * @param profilesNode The profiles ConfigNode
 * @returns true if File Blocking profile is configured
 */
export const hasFileBlockingProfile = (profilesNode: ConfigNode): boolean => {
  const fileBlocking = findStanza(profilesNode, 'file-blocking');
  return fileBlocking !== undefined && fileBlocking.children.length > 0;
};

/**
 * Check if password complexity is configured
 * @param systemNode The system ConfigNode
 * @returns true if password complexity is configured
 */
export const hasPasswordComplexity = (systemNode: ConfigNode): boolean => {
  const passwordComplexity = findStanza(systemNode, 'password-complexity');
  if (!passwordComplexity) return false;
  return hasChildCommand(passwordComplexity, 'enabled');
};

/**
 * Get password complexity settings
 * @param systemNode The system ConfigNode
 * @returns Object with password complexity settings
 */
export const getPasswordComplexitySettings = (
  systemNode: ConfigNode
): {
  enabled: boolean;
  minLength: number | null;
  minUppercase: number | null;
  minLowercase: number | null;
  minNumeric: number | null;
  minSpecial: number | null;
} => {
  const defaults = {
    enabled: false,
    minLength: null as number | null,
    minUppercase: null as number | null,
    minLowercase: null as number | null,
    minNumeric: null as number | null,
    minSpecial: null as number | null,
  };

  const passwordComplexity = findStanza(systemNode, 'password-complexity');
  if (!passwordComplexity) return defaults;

  const enabledCmd = getChildCommand(passwordComplexity, 'enabled');
  const enabled = enabledCmd?.id.toLowerCase().includes('yes') ?? false;

  const getNumericValue = (key: string): number | null => {
    const cmd = getChildCommand(passwordComplexity, key);
    if (!cmd) return null;
    const match = cmd.id.match(/(\d+)/);
    return match?.[1] ? parseInt(match[1], 10) : null;
  };

  return {
    enabled,
    minLength: getNumericValue('minimum-length'),
    minUppercase: getNumericValue('minimum-uppercase-letters'),
    minLowercase: getNumericValue('minimum-lowercase-letters'),
    minNumeric: getNumericValue('minimum-numeric-letters'),
    minSpecial: getNumericValue('minimum-special-characters'),
  };
};

/**
 * Check if SNMP is configured with v3 (secure) or v2c (less secure)
 * @param systemNode The system ConfigNode
 * @returns Object indicating SNMP configuration status
 */
export const getSnmpConfiguration = (
  systemNode: ConfigNode
): { configured: boolean; hasV3: boolean; hasV2c: boolean; hasCommunityPublic: boolean } => {
  const snmpSetting = findStanza(systemNode, 'snmp-setting');
  if (!snmpSetting) {
    return { configured: false, hasV3: false, hasV2c: false, hasCommunityPublic: false };
  }

  const accessSetting = findStanza(snmpSetting, 'access-setting');
  if (!accessSetting) {
    return { configured: false, hasV3: false, hasV2c: false, hasCommunityPublic: false };
  }

  const version = findStanza(accessSetting, 'version');
  if (!version) {
    return { configured: false, hasV3: false, hasV2c: false, hasCommunityPublic: false };
  }

  const hasV3 = findStanza(version, 'v3') !== undefined;
  const v2c = findStanza(version, 'v2c');
  const hasV2c = v2c !== undefined;

  // Check for default/weak community strings
  let hasCommunityPublic = false;
  if (v2c) {
    const communityString = getChildCommand(v2c, 'snmp-community-string');
    if (communityString) {
      const value = communityString.id.toLowerCase();
      hasCommunityPublic =
        value.includes('public') || value.includes('private') || value.includes('community');
    }
  }

  return { configured: true, hasV3, hasV2c, hasCommunityPublic };
};

/**
 * Check if decryption profile has secure TLS settings
 * @param decryptionProfileNode The decryption profile ConfigNode
 * @returns Object with TLS security assessment
 */
export const getDecryptionTlsSettings = (
  decryptionProfileNode: ConfigNode
): { hasMinVersion: boolean; minVersion: string | null; hasWeakCiphers: boolean } => {
  const sslProtocolSettings = findStanza(decryptionProfileNode, 'ssl-protocol-settings');
  if (!sslProtocolSettings) {
    return { hasMinVersion: false, minVersion: null, hasWeakCiphers: false };
  }

  const minVersionCmd = getChildCommand(sslProtocolSettings, 'min-version');
  let minVersion: string | null = null;
  let hasMinVersion = false;

  if (minVersionCmd) {
    hasMinVersion = true;
    const match = minVersionCmd.id.match(/min-version\s+(\S+)/i);
    minVersion = match?.[1]?.replace(/;$/, '') ?? null;
  }

  // Check for weak ciphers
  const encAlgoCmd = getChildCommand(sslProtocolSettings, 'enc-algo');
  let hasWeakCiphers = false;
  if (encAlgoCmd) {
    const value = encAlgoCmd.id.toLowerCase();
    hasWeakCiphers =
      value.includes('rc4') ||
      value.includes('3des') ||
      value.includes('des') ||
      value.includes('null');
  }

  return { hasMinVersion, minVersion, hasWeakCiphers };
};

/**
 * Get IKE crypto profile settings for security assessment
 * @param ikeProfileNode The IKE crypto profile ConfigNode
 * @returns Object with security assessment
 */
export const getIkeCryptoSettings = (
  ikeProfileNode: ConfigNode
): {
  hasWeakDH: boolean;
  hasWeakHash: boolean;
  hasWeakEncryption: boolean;
  dhGroups: string[];
  hashes: string[];
  encryptions: string[];
} => {
  const dhGroups: string[] = [];
  const hashes: string[] = [];
  const encryptions: string[] = [];

  // Extract DH groups
  const dhGroupCmd = getChildCommand(ikeProfileNode, 'dh-group');
  if (dhGroupCmd) {
    const match = dhGroupCmd.id.match(/dh-group\s+\[([^\]]+)\]/i);
    if (match?.[1]) {
      dhGroups.push(...match[1].split(/\s+/).filter((g) => g.length > 0));
    } else {
      const singleMatch = dhGroupCmd.id.match(/dh-group\s+(\S+)/i);
      if (singleMatch?.[1]) {
        dhGroups.push(singleMatch[1].replace(/;$/, ''));
      }
    }
  }

  // Extract hash algorithms
  const hashCmd = getChildCommand(ikeProfileNode, 'hash');
  if (hashCmd) {
    const match = hashCmd.id.match(/hash\s+\[([^\]]+)\]/i);
    if (match?.[1]) {
      hashes.push(...match[1].split(/\s+/).filter((h) => h.length > 0));
    } else {
      const singleMatch = hashCmd.id.match(/hash\s+(\S+)/i);
      if (singleMatch?.[1]) {
        hashes.push(singleMatch[1].replace(/;$/, ''));
      }
    }
  }

  // Extract encryption algorithms
  const encCmd = getChildCommand(ikeProfileNode, 'encryption');
  if (encCmd) {
    const match = encCmd.id.match(/encryption\s+\[([^\]]+)\]/i);
    if (match?.[1]) {
      encryptions.push(...match[1].split(/\s+/).filter((e) => e.length > 0));
    } else {
      const singleMatch = encCmd.id.match(/encryption\s+(\S+)/i);
      if (singleMatch?.[1]) {
        encryptions.push(singleMatch[1].replace(/;$/, ''));
      }
    }
  }

  // Check for weak settings
  const weakDHGroups = ['group1', 'group2', 'group5'];
  const weakHashes = ['md5', 'sha1'];
  const weakEncryptions = ['des', '3des'];

  const hasWeakDH = dhGroups.some((g) => weakDHGroups.includes(g.toLowerCase()));
  const hasWeakHash = hashes.some((h) => weakHashes.includes(h.toLowerCase()));
  const hasWeakEncryption = encryptions.some((e) => weakEncryptions.includes(e.toLowerCase()));

  return { hasWeakDH, hasWeakHash, hasWeakEncryption, dhGroups, hashes, encryptions };
};

/**
 * Check if zone protection profile has flood protection configured
 * @param zppNode The zone protection profile ConfigNode
 * @returns Object indicating flood protection status
 */
export const hasFloodProtection = (
  zppNode: ConfigNode
): { hasSyn: boolean; hasUdp: boolean; hasIcmp: boolean; hasOtherIp: boolean } => {
  const flood = findStanza(zppNode, 'flood');
  if (!flood) {
    return { hasSyn: false, hasUdp: false, hasIcmp: false, hasOtherIp: false };
  }

  const tcpSyn = findStanza(flood, 'tcp-syn');
  const udp = findStanza(flood, 'udp');
  const icmp = findStanza(flood, 'icmp');
  const otherIp = findStanza(flood, 'other-ip');

  const isEnabled = (stanza: ConfigNode | undefined): boolean => {
    if (!stanza) return false;
    const enableCmd = getChildCommand(stanza, 'enable');
    return enableCmd?.id.toLowerCase().includes('yes') ?? false;
  };

  return {
    hasSyn: isEnabled(tcpSyn),
    hasUdp: isEnabled(udp),
    hasIcmp: isEnabled(icmp),
    hasOtherIp: isEnabled(otherIp),
  };
};

/**
 * Check if zone protection profile has reconnaissance protection
 * @param zppNode The zone protection profile ConfigNode
 * @returns true if scan/reconnaissance protection is configured
 */
export const hasReconProtection = (zppNode: ConfigNode): boolean => {
  const scan = findStanza(zppNode, 'scan');
  if (!scan) return false;

  // Check for at least one scan protection type
  const tcpPortScan = findStanza(scan, 'tcp-port-scan');
  const hostSweep = findStanza(scan, 'host-sweep');
  const udpPortScan = findStanza(scan, 'udp-port-scan');

  return tcpPortScan !== undefined || hostSweep !== undefined || udpPortScan !== undefined;
};

/**
 * Check if User-ID is enabled on a zone (for untrust zone check)
 * @param zoneNode The zone ConfigNode
 * @returns true if User-ID is enabled
 */
export const isUserIdEnabled = (zoneNode: ConfigNode): boolean => {
  // Check direct enable-user-identification command
  if (hasChildCommand(zoneNode, 'enable-user-identification')) {
    const cmd = getChildCommand(zoneNode, 'enable-user-identification');
    return cmd?.id.toLowerCase().includes('yes') ?? false;
  }
  return false;
};

/**
 * Check if HA has backup links configured
 * @param haNode The high-availability ConfigNode
 * @returns Object indicating backup link status
 */
export const getHABackupStatus = (
  haNode: ConfigNode
): { hasHa1Backup: boolean; hasHa2Backup: boolean; hasHeartbeatBackup: boolean } => {
  const interfaceStanza = findStanza(haNode, 'interface');
  if (!interfaceStanza) {
    return { hasHa1Backup: false, hasHa2Backup: false, hasHeartbeatBackup: false };
  }

  const hasHa1Backup = findStanza(interfaceStanza, 'ha1-backup') !== undefined;
  const hasHa2Backup = findStanza(interfaceStanza, 'ha2-backup') !== undefined;

  // Check for heartbeat backup in election-option
  const group = findStanza(haNode, 'group');
  let hasHeartbeatBackup = false;
  if (group) {
    const electionOption = findStanza(group, 'election-option');
    if (electionOption) {
      const heartbeatCmd = getChildCommand(electionOption, 'heartbeat-backup');
      hasHeartbeatBackup = heartbeatCmd?.id.toLowerCase().includes('yes') ?? false;
    }
  }

  return { hasHa1Backup, hasHa2Backup, hasHeartbeatBackup };
};

/**
 * Check if HA has link monitoring configured
 * @param haNode The high-availability ConfigNode
 * @returns true if link monitoring is configured
 */
export const hasHALinkMonitoring = (haNode: ConfigNode): boolean => {
  const linkMonitoring = findStanza(haNode, 'link-monitoring');
  if (!linkMonitoring) return false;

  const linkGroup = findStanza(linkMonitoring, 'link-group');
  return linkGroup !== undefined && linkGroup.children.length > 0;
};

/**
 * Check if HA has path monitoring configured
 * @param haNode The high-availability ConfigNode
 * @returns true if path monitoring is configured
 */
export const hasHAPathMonitoring = (haNode: ConfigNode): boolean => {
  const pathMonitoring = findStanza(haNode, 'path-monitoring');
  if (!pathMonitoring) return false;

  const pathGroup = findStanza(pathMonitoring, 'path-group');
  return pathGroup !== undefined && pathGroup.children.length > 0;
};

/**
 * Check if log forwarding is configured
 * @param logSettingsNode The log-settings ConfigNode
 * @returns Object indicating log forwarding status
 */
export const getLogForwardingStatus = (
  logSettingsNode: ConfigNode
): { hasSyslog: boolean; hasPanorama: boolean; hasEmail: boolean } => {
  const profiles = findStanza(logSettingsNode, 'profiles');
  if (!profiles) {
    return { hasSyslog: false, hasPanorama: false, hasEmail: false };
  }

  let hasSyslog = false;
  let hasPanorama = false;
  let hasEmail = false;

  // Check each profile for forwarding destinations
  for (const profile of profiles.children) {
    const matchList = findStanza(profile, 'match-list');
    if (matchList) {
      for (const match of matchList.children) {
        if (findStanza(match, 'send-syslog')) hasSyslog = true;
        if (hasChildCommand(match, 'send-to-panorama')) {
          const cmd = getChildCommand(match, 'send-to-panorama');
          if (cmd?.id.toLowerCase().includes('yes')) hasPanorama = true;
        }
        if (findStanza(match, 'send-email')) hasEmail = true;
      }
    }
  }

  return { hasSyslog, hasPanorama, hasEmail };
};

/**
 * Check if dynamic content updates are scheduled
 * @param systemNode The system ConfigNode
 * @returns Object indicating update schedule status
 */
export const getUpdateScheduleStatus = (
  systemNode: ConfigNode
): {
  hasThreats: boolean;
  hasAntivirus: boolean;
  hasWildfire: boolean;
  wildfireRealtime: boolean;
} => {
  const updateSchedule = findStanza(systemNode, 'update-schedule');
  if (!updateSchedule) {
    return { hasThreats: false, hasAntivirus: false, hasWildfire: false, wildfireRealtime: false };
  }

  const threats = findStanza(updateSchedule, 'threats');
  const antivirus = findStanza(updateSchedule, 'anti-virus');
  const wildfire = findStanza(updateSchedule, 'wildfire');

  let wildfireRealtime = false;
  if (wildfire) {
    const recurring = findStanza(wildfire, 'recurring');
    if (recurring) {
      wildfireRealtime = hasChildCommand(recurring, 'real-time');
    }
  }

  return {
    hasThreats: threats !== undefined && threats.children.length > 0,
    hasAntivirus: antivirus !== undefined && antivirus.children.length > 0,
    hasWildfire: wildfire !== undefined && wildfire.children.length > 0,
    wildfireRealtime,
  };
};

/**
 * Get all decryption rules from a rulebase
 * @param rulebaseNode The rulebase ConfigNode
 * @returns Array of decryption rule nodes
 */
export const getDecryptionRules = (rulebaseNode: ConfigNode): ConfigNode[] => {
  const decryption = findStanza(rulebaseNode, 'decryption');
  if (!decryption) return [];

  const rules = findStanza(decryption, 'rules');
  if (!rules) return [];

  return rules.children;
};

/**
 * Check if a decryption rule uses "decrypt" action
 * @param ruleNode The decryption rule ConfigNode
 * @returns true if the action is decrypt
 */
export const isDecryptRule = (ruleNode: ConfigNode): boolean => {
  const action = getChildCommand(ruleNode, 'action');
  if (!action) return false;
  return action.id.toLowerCase().includes('decrypt');
};

/**
 * Get interface management profile settings
 * @param profileNode The interface-management-profile ConfigNode
 * @returns Object indicating enabled services
 */
export const getInterfaceManagementServices = (
  profileNode: ConfigNode
): {
  https: boolean;
  http: boolean;
  ssh: boolean;
  telnet: boolean;
  ping: boolean;
  snmp: boolean;
} => {
  // Use exact matching with word boundary to avoid "https" matching "http"
  const isServiceEnabled = (serviceName: string): boolean => {
    // Look for exact service name followed by space/end (e.g., "http yes" not "https yes")
    const cmd = profileNode.children.find((child) => {
      const lowerId = child.id.toLowerCase();
      // Match exact service name: "http yes", "http no", etc.
      return lowerId === serviceName || lowerId.startsWith(serviceName + ' ');
    });
    if (!cmd) return false;
    return cmd.id.toLowerCase().includes('yes');
  };

  return {
    https: isServiceEnabled('https'),
    http: isServiceEnabled('http'),
    ssh: isServiceEnabled('ssh'),
    telnet: isServiceEnabled('telnet'),
    ping: isServiceEnabled('ping'),
    snmp: isServiceEnabled('snmp'),
  };
};
