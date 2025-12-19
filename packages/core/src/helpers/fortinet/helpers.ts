// packages/rule-helpers/src/fortinet/helpers.ts
// Fortinet FortiGate (FortiOS) specific helper functions

import type { ConfigNode } from '../../types/ConfigNode';
import { parseIp } from '../common/helpers';

/**
 * Find a config section by name within a node's children.
 * FortiOS uses "config <section>" format.
 * @param node The parent ConfigNode
 * @param sectionName The section name (e.g., "system global", "firewall policy")
 * @returns The matching child node, or undefined
 */
export const findConfigSection = (
  node: ConfigNode,
  sectionName: string
): ConfigNode | undefined => {
  const normalizedName = sectionName.toLowerCase();
  return node.children.find((child) => {
    const childId = child.id.toLowerCase();
    // Match "config <sectionName>" or just "<sectionName>"
    return (
      childId === `config ${normalizedName}` ||
      childId === normalizedName ||
      childId.startsWith(`config ${normalizedName} `) ||
      childId.startsWith(`${normalizedName} `)
    );
  });
};

/**
 * Find all config sections matching a pattern within a node's children
 * @param node The parent ConfigNode
 * @param pattern The regex pattern to match
 * @returns Array of matching child nodes
 */
export const findConfigSections = (node: ConfigNode, pattern: RegExp): ConfigNode[] => {
  return node.children.filter((child) => pattern.test(child.id.toLowerCase()));
};

/**
 * Find an edit entry by name within a config section.
 * FortiOS uses "edit <name>" for entries.
 * @param configSection The config section ConfigNode
 * @param entryName The entry name to find
 * @returns The matching edit entry, or undefined
 */
export const findEditEntry = (
  configSection: ConfigNode,
  entryName: string
): ConfigNode | undefined => {
  const normalizedName = entryName.toLowerCase().replace(/^["']|["']$/g, '');
  return configSection.children.find((child) => {
    const childId = child.id.toLowerCase();
    // Match "edit <name>" with or without quotes
    const editMatch = childId.match(/^edit\s+["']?([^"']+)["']?$/i);
    const editName = editMatch?.[1];
    if (editName) {
      return editName.toLowerCase() === normalizedName;
    }
    return false;
  });
};

/**
 * Get all edit entries within a config section
 * @param configSection The config section ConfigNode
 * @returns Array of edit entry nodes
 */
export const getEditEntries = (configSection: ConfigNode): ConfigNode[] => {
  return configSection.children.filter((child) =>
    child.id.toLowerCase().startsWith('edit ')
  );
};

/**
 * Extract the name from an edit entry.
 * FortiOS uses "edit <name>" format.
 * @param editEntry The edit entry ConfigNode
 * @returns The entry name
 */
export const getEditEntryName = (editEntry: ConfigNode): string => {
  const match = editEntry.id.match(/^edit\s+["']?([^"']+)["']?$/i);
  const entryName = match?.[1];
  return entryName ?? editEntry.id;
};

/**
 * Get a "set" command value from a FortiOS config entry.
 * FortiOS uses "set <param> <value>" format.
 * @param node The ConfigNode
 * @param paramName The parameter name
 * @returns The value, or undefined
 */
export const getSetValue = (node: ConfigNode, paramName: string): string | undefined => {
  const normalizedParam = paramName.toLowerCase();
  for (const child of node.children) {
    const childId = child.id.toLowerCase();
    const match = childId.match(new RegExp(`^set\\s+${normalizedParam}\\s+(.+)$`, 'i'));
    const value = match?.[1];
    if (value) {
      // Remove quotes if present
      return value.replace(/^["']|["']$/g, '').trim();
    }
  }
  return undefined;
};

/**
 * Check if a "set" command exists for a parameter
 * @param node The ConfigNode
 * @param paramName The parameter name
 * @returns true if the set command exists
 */
export const hasSetValue = (node: ConfigNode, paramName: string): boolean => {
  return getSetValue(node, paramName) !== undefined;
};

/**
 * Get all "set" command values for a parameter that may appear multiple times
 * (e.g., set member "obj1", set member "obj2")
 * @param node The ConfigNode
 * @param paramName The parameter name
 * @returns Array of values
 */
export const getSetValues = (node: ConfigNode, paramName: string): string[] => {
  const normalizedParam = paramName.toLowerCase();
  const values: string[] = [];
  for (const child of node.children) {
    const childId = child.id.toLowerCase();
    const match = childId.match(new RegExp(`^set\\s+${normalizedParam}\\s+(.+)$`, 'i'));
    const matchValue = match?.[1];
    if (matchValue) {
      // Handle space-separated values (e.g., set allowaccess ping https ssh)
      const valueStr = matchValue.replace(/^["']|["']$/g, '').trim();
      // Split by space, keeping quoted values together
      const parts = valueStr.match(/["'][^"']+["']|\S+/g) || [];
      values.push(...parts.map((p) => p.replace(/^["']|["']$/g, '')));
    }
  }
  return values;
};

/**
 * Check if a firewall policy action is "accept" (allow)
 * @param policyNode The firewall policy ConfigNode
 * @returns true if the action is accept
 */
export const isPolicyAccept = (policyNode: ConfigNode): boolean => {
  const action = getSetValue(policyNode, 'action');
  return action?.toLowerCase() === 'accept';
};

/**
 * Check if a firewall policy action is "deny" or "drop"
 * @param policyNode The firewall policy ConfigNode
 * @returns true if the action is deny
 */
export const isPolicyDeny = (policyNode: ConfigNode): boolean => {
  const action = getSetValue(policyNode, 'action');
  if (!action) return false;
  const actionLower = action.toLowerCase();
  return actionLower === 'deny' || actionLower === 'drop';
};

/**
 * Check if a firewall policy is disabled (status disable)
 * @param policyNode The firewall policy ConfigNode
 * @returns true if the policy is disabled
 */
export const isPolicyDisabled = (policyNode: ConfigNode): boolean => {
  const status = getSetValue(policyNode, 'status');
  return status?.toLowerCase() === 'disable';
};

/**
 * Check if a firewall policy has logging enabled
 * @param policyNode The firewall policy ConfigNode
 * @returns Object indicating logtraffic status
 */
export const hasLogging = (policyNode: ConfigNode): { logtraffic: string | undefined; logtrafficStart: boolean } => {
  const logtraffic = getSetValue(policyNode, 'logtraffic');
  const logtrafficStart = getSetValue(policyNode, 'logtraffic-start');
  return {
    logtraffic,
    logtrafficStart: logtrafficStart?.toLowerCase() === 'enable',
  };
};

/**
 * Check if a policy uses "all" (any) source address
 * @param policyNode The firewall policy ConfigNode
 * @returns true if srcaddr includes "all"
 */
export const hasAnySrcAddr = (policyNode: ConfigNode): boolean => {
  const srcaddr = getSetValues(policyNode, 'srcaddr');
  return srcaddr.some((addr) => addr.toLowerCase() === 'all');
};

/**
 * Check if a policy uses "all" (any) destination address
 * @param policyNode The firewall policy ConfigNode
 * @returns true if dstaddr includes "all"
 */
export const hasAnyDstAddr = (policyNode: ConfigNode): boolean => {
  const dstaddr = getSetValues(policyNode, 'dstaddr');
  return dstaddr.some((addr) => addr.toLowerCase() === 'all');
};

/**
 * Check if a policy uses "ALL" service (any service)
 * @param policyNode The firewall policy ConfigNode
 * @returns true if service includes "ALL"
 */
export const hasAnyService = (policyNode: ConfigNode): boolean => {
  const service = getSetValues(policyNode, 'service');
  return service.some((svc) => svc.toUpperCase() === 'ALL');
};

/**
 * Check if a policy has UTM/security profiles attached
 * @param policyNode The firewall policy ConfigNode
 * @returns Object with profile statuses
 */
export const getSecurityProfiles = (policyNode: ConfigNode): {
  avProfile: string | undefined;
  webfilterProfile: string | undefined;
  ipsProfile: string | undefined;
  applicationList: string | undefined;
  dnsfilterProfile: string | undefined;
  emailfilterProfile: string | undefined;
  dlpSensor: string | undefined;
  sslSshProfile: string | undefined;
  profileProtocolOptions: string | undefined;
  utmStatus: string | undefined;
  inspectionMode: string | undefined;
} => {
  return {
    avProfile: getSetValue(policyNode, 'av-profile'),
    webfilterProfile: getSetValue(policyNode, 'webfilter-profile'),
    ipsProfile: getSetValue(policyNode, 'ips-sensor'),
    applicationList: getSetValue(policyNode, 'application-list'),
    dnsfilterProfile: getSetValue(policyNode, 'dnsfilter-profile'),
    emailfilterProfile: getSetValue(policyNode, 'emailfilter-profile'),
    dlpSensor: getSetValue(policyNode, 'dlp-sensor'),
    sslSshProfile: getSetValue(policyNode, 'ssl-ssh-profile'),
    profileProtocolOptions: getSetValue(policyNode, 'profile-protocol-options'),
    utmStatus: getSetValue(policyNode, 'utm-status'),
    inspectionMode: getSetValue(policyNode, 'inspection-mode'),
  };
};

/**
 * Check if a policy has any UTM profile attached
 * @param policyNode The firewall policy ConfigNode
 * @returns true if any security profile is configured
 */
export const hasSecurityProfile = (policyNode: ConfigNode): boolean => {
  const profiles = getSecurityProfiles(policyNode);
  return !!(
    profiles.avProfile ||
    profiles.webfilterProfile ||
    profiles.ipsProfile ||
    profiles.applicationList ||
    profiles.dnsfilterProfile ||
    profiles.emailfilterProfile ||
    profiles.dlpSensor
  );
};

/**
 * Get the interface IP address and mask from a system interface entry
 * @param interfaceNode The interface edit entry ConfigNode
 * @returns Object with ip and mask, or undefined
 */
export const getInterfaceIp = (
  interfaceNode: ConfigNode
): { ip: string; mask: string } | undefined => {
  const ipValue = getSetValue(interfaceNode, 'ip');
  if (!ipValue) return undefined;

  // FortiOS format: "set ip 192.168.1.1 255.255.255.0" or "set ip 192.168.1.1/24"
  const parts = ipValue.split(/\s+/);
  if (parts.length >= 2) {
    const [ip, mask] = parts;
    if (!ip || !mask) {
      return undefined;
    }
    return { ip, mask };
  }
  const firstPart = parts[0];
  if (firstPart && firstPart.includes('/')) {
    const [ip, prefix] = firstPart.split('/');
    if (!ip || !prefix) {
      return undefined;
    }
    return { ip, mask: prefix };
  }
  return undefined;
};

/**
 * Get allowed access methods on an interface
 * @param interfaceNode The interface edit entry ConfigNode
 * @returns Array of allowed access methods
 */
export const getInterfaceAllowAccess = (interfaceNode: ConfigNode): string[] => {
  return getSetValues(interfaceNode, 'allowaccess');
};

/**
 * Check if HTTP(S) management is allowed on an interface
 * @param interfaceNode The interface edit entry ConfigNode
 * @returns true if HTTP or HTTPS access is allowed
 */
export const hasHttpManagement = (interfaceNode: ConfigNode): boolean => {
  const access = getInterfaceAllowAccess(interfaceNode);
  return access.some((a) => a.toLowerCase() === 'http' || a.toLowerCase() === 'https');
};

/**
 * Check if SSH is allowed on an interface
 * @param interfaceNode The interface edit entry ConfigNode
 * @returns true if SSH access is allowed
 */
export const hasSshAccess = (interfaceNode: ConfigNode): boolean => {
  const access = getInterfaceAllowAccess(interfaceNode);
  return access.some((a) => a.toLowerCase() === 'ssh');
};

/**
 * Check if Telnet is allowed on an interface (insecure)
 * @param interfaceNode The interface edit entry ConfigNode
 * @returns true if Telnet access is allowed
 */
export const hasTelnetAccess = (interfaceNode: ConfigNode): boolean => {
  const access = getInterfaceAllowAccess(interfaceNode);
  return access.some((a) => a.toLowerCase() === 'telnet');
};

/**
 * Get the schedule for a firewall policy
 * @param policyNode The firewall policy ConfigNode
 * @returns The schedule name
 */
export const getPolicySchedule = (policyNode: ConfigNode): string | undefined => {
  return getSetValue(policyNode, 'schedule');
};

/**
 * Check if the schedule is "always" (always active)
 * @param policyNode The firewall policy ConfigNode
 * @returns true if schedule is "always"
 */
export const isAlwaysSchedule = (policyNode: ConfigNode): boolean => {
  const schedule = getPolicySchedule(policyNode);
  return schedule?.toLowerCase() === 'always';
};

/**
 * Get NAT settings for a policy
 * @param policyNode The firewall policy ConfigNode
 * @returns Object with NAT settings
 */
export const getNatSettings = (policyNode: ConfigNode): {
  nat: boolean;
  ippool: boolean;
  poolname: string[];
} => {
  const nat = getSetValue(policyNode, 'nat');
  const ippool = getSetValue(policyNode, 'ippool');
  const poolname = getSetValues(policyNode, 'poolname');
  return {
    nat: nat?.toLowerCase() === 'enable',
    ippool: ippool?.toLowerCase() === 'enable',
    poolname,
  };
};

/**
 * Check if HA (High Availability) is configured
 * @param systemHaNode The system ha config section
 * @returns true if HA is enabled
 */
export const isHAEnabled = (systemHaNode: ConfigNode): boolean => {
  const mode = getSetValue(systemHaNode, 'mode');
  return mode !== undefined && mode.toLowerCase() !== 'standalone';
};

/**
 * Get the HA mode
 * @param systemHaNode The system ha config section
 * @returns The HA mode (standalone, a-a, a-p, etc.)
 */
export const getHAMode = (systemHaNode: ConfigNode): string | undefined => {
  return getSetValue(systemHaNode, 'mode');
};

/**
 * Check if admin user has strong password policy
 * @param adminNode The admin user edit entry
 * @returns Object with password policy info
 */
export const getAdminPasswordPolicy = (adminNode: ConfigNode): {
  forcePasswordChange: boolean;
  twoFactorAuth: string | undefined;
} => {
  const forcePasswordChange = getSetValue(adminNode, 'force-password-change');
  const twoFactorAuth = getSetValue(adminNode, 'two-factor');
  return {
    forcePasswordChange: forcePasswordChange?.toLowerCase() === 'enable',
    twoFactorAuth,
  };
};

/**
 * Get the admin profile (permission level) for an admin user
 * @param adminNode The admin user edit entry
 * @returns The profile name
 */
export const getAdminProfile = (adminNode: ConfigNode): string | undefined => {
  return getSetValue(adminNode, 'accprofile');
};

/**
 * Check if admin is a super_admin
 * @param adminNode The admin user edit entry
 * @returns true if super_admin profile
 */
export const isSuperAdmin = (adminNode: ConfigNode): boolean => {
  const profile = getAdminProfile(adminNode);
  return profile?.toLowerCase() === 'super_admin';
};

/**
 * Get trusted hosts for admin access restriction
 * @param adminNode The admin user edit entry
 * @returns Array of trusted host entries
 */
export const getAdminTrustedHosts = (adminNode: ConfigNode): string[] => {
  const trustedHosts: string[] = [];
  // FortiOS uses trusthost1, trusthost2, ... trusthost10
  for (let i = 1; i <= 10; i++) {
    const host = getSetValue(adminNode, `trusthost${i}`);
    if (host && host !== '0.0.0.0 0.0.0.0') {
      trustedHosts.push(host);
    }
  }
  return trustedHosts;
};

/**
 * Check if admin has any trusted host restriction
 * @param adminNode The admin user edit entry
 * @returns true if trusted hosts are configured
 */
export const hasAdminTrustedHosts = (adminNode: ConfigNode): boolean => {
  return getAdminTrustedHosts(adminNode).length > 0;
};

/**
 * Parse FortiOS IP address format (e.g., "10.0.0.1 255.255.255.0" or "10.0.0.0/24")
 * @param address The address string
 * @returns Object with parsed address info, or null if invalid
 */
export const parseFortiAddress = (
  address: string
): { ip: number; mask: string } | null => {
  const parts = address.trim().split(/\s+/);

  // IP + netmask format: "10.0.0.1 255.255.255.0"
  if (parts.length === 2) {
    const [ipStr, maskStr] = parts;
    if (!ipStr || !maskStr) {
      return null;
    }
    const ip = parseIp(ipStr);
    if (ip === null) return null;
    return { ip, mask: maskStr };
  }

  // CIDR format: "10.0.0.1/24"
  const singlePart = parts[0];
  if (parts.length === 1 && singlePart && singlePart.includes('/')) {
    const [ipStr, prefix] = singlePart.split('/');
    if (!ipStr || !prefix) {
      return null;
    }
    const ip = parseIp(ipStr);
    if (ip === null) return null;
    return { ip, mask: `/${prefix}` };
  }

  // Single IP
  if (parts.length === 1 && singlePart) {
    const ip = parseIp(singlePart);
    if (ip === null) return null;
    return { ip, mask: '255.255.255.255' };
  }

  return null;
};

// ============================================================================
// System Hardening Helpers (FGT-HARD-*)
// ============================================================================

/**
 * Check if USB auto-install is enabled (security risk)
 * @param globalNode The system global config section
 * @returns true if USB auto-install is enabled
 */
export const isUsbAutoInstallEnabled = (globalNode: ConfigNode): boolean => {
  const usbAutoInstall = getSetValue(globalNode, 'usb-auto-install');
  return usbAutoInstall?.toLowerCase() === 'enable';
};

/**
 * Check if admin-maintainer account is enabled
 * @param globalNode The system global config section
 * @returns true if maintainer account is enabled
 */
export const isAdminMaintainerEnabled = (globalNode: ConfigNode): boolean => {
  const maintainer = getSetValue(globalNode, 'admin-maintainer');
  // Default is enable, so if not explicitly disabled, it's enabled
  return maintainer?.toLowerCase() !== 'disable';
};

/**
 * Check if private data encryption is enabled
 * @param globalNode The system global config section
 * @returns true if private data encryption is enabled
 */
export const isPrivateDataEncryptionEnabled = (globalNode: ConfigNode): boolean => {
  const encryption = getSetValue(globalNode, 'private-data-encryption');
  return encryption?.toLowerCase() === 'enable';
};

/**
 * Get admin lockout threshold
 * @param globalNode The system global config section
 * @returns The lockout threshold number, or undefined
 */
export const getAdminLockoutThreshold = (globalNode: ConfigNode): number | undefined => {
  const threshold = getSetValue(globalNode, 'admin-lockout-threshold');
  return threshold ? parseInt(threshold, 10) : undefined;
};

/**
 * Get admin lockout duration
 * @param globalNode The system global config section
 * @returns The lockout duration in seconds, or undefined
 */
export const getAdminLockoutDuration = (globalNode: ConfigNode): number | undefined => {
  const duration = getSetValue(globalNode, 'admin-lockout-duration');
  return duration ? parseInt(duration, 10) : undefined;
};

// ============================================================================
// Password Policy Helpers (FGT-MGMT-004)
// ============================================================================

/**
 * Get password policy settings
 * @param passwordPolicyNode The system password-policy config section
 * @returns Object with password policy settings
 */
export const getPasswordPolicySettings = (passwordPolicyNode: ConfigNode): {
  status: boolean;
  minimumLength: number | undefined;
  minLowerCase: number | undefined;
  minUpperCase: number | undefined;
  minNonAlphanumeric: number | undefined;
  minNumber: number | undefined;
  expireStatus: boolean;
  expireDays: number | undefined;
  reusePassword: boolean;
} => {
  const status = getSetValue(passwordPolicyNode, 'status');
  const minimumLength = getSetValue(passwordPolicyNode, 'minimum-length');
  const minLowerCase = getSetValue(passwordPolicyNode, 'min-lower-case-letter');
  const minUpperCase = getSetValue(passwordPolicyNode, 'min-upper-case-letter');
  const minNonAlphanumeric = getSetValue(passwordPolicyNode, 'min-non-alphanumeric');
  const minNumber = getSetValue(passwordPolicyNode, 'min-number');
  const expireStatus = getSetValue(passwordPolicyNode, 'expire-status');
  const expireDays = getSetValue(passwordPolicyNode, 'expire-day');
  const reusePassword = getSetValue(passwordPolicyNode, 'reuse-password');

  return {
    status: status?.toLowerCase() === 'enable',
    minimumLength: minimumLength ? parseInt(minimumLength, 10) : undefined,
    minLowerCase: minLowerCase ? parseInt(minLowerCase, 10) : undefined,
    minUpperCase: minUpperCase ? parseInt(minUpperCase, 10) : undefined,
    minNonAlphanumeric: minNonAlphanumeric ? parseInt(minNonAlphanumeric, 10) : undefined,
    minNumber: minNumber ? parseInt(minNumber, 10) : undefined,
    expireStatus: expireStatus?.toLowerCase() === 'enable',
    expireDays: expireDays ? parseInt(expireDays, 10) : undefined,
    reusePassword: reusePassword?.toLowerCase() !== 'disable',
  };
};

// ============================================================================
// SNMP Helpers (FGT-MGMT-009)
// ============================================================================

/**
 * Check if SNMP community has default/weak name
 * @param communityNode The SNMP community edit entry
 * @returns true if the community name is weak/default
 */
export const hasWeakSnmpCommunity = (communityNode: ConfigNode): boolean => {
  const name = getSetValue(communityNode, 'name');
  if (!name) return false;
  const weakNames = ['public', 'private', 'community', 'snmp', 'default'];
  return weakNames.includes(name.toLowerCase());
};

/**
 * Get SNMP user security level
 * @param snmpUserNode The SNMP user edit entry
 * @returns The security level (no-auth-no-priv, auth-no-priv, auth-priv)
 */
export const getSnmpSecurityLevel = (snmpUserNode: ConfigNode): string | undefined => {
  return getSetValue(snmpUserNode, 'security-level');
};

// ============================================================================
// SSL/SSH Profile Helpers (FGT-SSL-*)
// ============================================================================

/**
 * Get SSL inspection profile settings
 * @param sslProfileNode The SSL-SSH profile edit entry
 * @returns Object with SSL settings
 */
export const getSslProfileSettings = (sslProfileNode: ConfigNode): {
  minSslVersion: string | undefined;
  unsupportedSslVersion: string | undefined;
  expiredServerCert: string | undefined;
  revokedServerCert: string | undefined;
  untrustedServerCert: string | undefined;
  certValidationFailure: string | undefined;
} => {
  // Find the ssl config section within the profile
  const sslSection = findConfigSection(sslProfileNode, 'ssl');
  if (!sslSection) {
    return {
      minSslVersion: undefined,
      unsupportedSslVersion: undefined,
      expiredServerCert: undefined,
      revokedServerCert: undefined,
      untrustedServerCert: undefined,
      certValidationFailure: undefined,
    };
  }

  return {
    minSslVersion: getSetValue(sslSection, 'min-allowed-ssl-version'),
    unsupportedSslVersion: getSetValue(sslSection, 'unsupported-ssl-version'),
    expiredServerCert: getSetValue(sslSection, 'expired-server-cert'),
    revokedServerCert: getSetValue(sslSection, 'revoked-server-cert'),
    untrustedServerCert: getSetValue(sslSection, 'untrusted-server-cert'),
    certValidationFailure: getSetValue(sslSection, 'cert-validation-failure'),
  };
};

/**
 * Check if SSL profile uses weak SSL version
 * @param minSslVersion The minimum SSL version string
 * @returns true if the version is considered weak
 */
export const isWeakSslVersion = (minSslVersion: string | undefined): boolean => {
  if (!minSslVersion) return false;
  const weakVersions = ['ssl-3.0', 'tls-1.0', 'tls-1.1'];
  return weakVersions.includes(minSslVersion.toLowerCase());
};

// ============================================================================
// DoS Policy Helpers (FGT-DOS-*)
// ============================================================================

/**
 * Get DoS anomaly settings from a DoS policy
 * @param dosPolicyNode The DoS policy edit entry
 * @returns Array of anomaly configurations
 */
export const getDosAnomalySettings = (dosPolicyNode: ConfigNode): Array<{
  name: string;
  status: boolean;
  action: string | undefined;
  threshold: number | undefined;
  log: boolean;
}> => {
  const anomalySection = findConfigSection(dosPolicyNode, 'anomaly');
  if (!anomalySection) return [];

  const anomalies = getEditEntries(anomalySection);
  return anomalies.map((anomaly) => {
    const name = getEditEntryName(anomaly);
    const status = getSetValue(anomaly, 'status');
    const action = getSetValue(anomaly, 'action');
    const threshold = getSetValue(anomaly, 'threshold');
    const log = getSetValue(anomaly, 'log');

    return {
      name,
      status: status?.toLowerCase() === 'enable',
      action,
      threshold: threshold ? parseInt(threshold, 10) : undefined,
      log: log?.toLowerCase() === 'enable',
    };
  });
};

// ============================================================================
// SD-WAN Helpers (FGT-SDW-*)
// ============================================================================

/**
 * Check if SD-WAN is enabled
 * @param sdwanNode The system sdwan config section
 * @returns true if SD-WAN is enabled
 */
export const isSdwanEnabled = (sdwanNode: ConfigNode): boolean => {
  const status = getSetValue(sdwanNode, 'status');
  return status?.toLowerCase() === 'enable';
};

/**
 * Get SD-WAN health check configurations
 * @param sdwanNode The system sdwan config section
 * @returns Array of health check names
 */
export const getSdwanHealthChecks = (sdwanNode: ConfigNode): ConfigNode[] => {
  const healthCheckSection = findConfigSection(sdwanNode, 'health-check');
  if (!healthCheckSection) return [];
  return getEditEntries(healthCheckSection);
};

/**
 * Get SD-WAN members
 * @param sdwanNode The system sdwan config section
 * @returns Array of member configurations
 */
export const getSdwanMembers = (sdwanNode: ConfigNode): ConfigNode[] => {
  const membersSection = findConfigSection(sdwanNode, 'members');
  if (!membersSection) return [];
  return getEditEntries(membersSection);
};

// ============================================================================
// VPN Helpers (Extended for FGT-VPN-*)
// ============================================================================

/**
 * Get IKE version from IPsec phase1
 * @param phase1Node The IPsec phase1-interface edit entry
 * @returns The IKE version (1 or 2), or undefined
 */
export const getIkeVersion = (phase1Node: ConfigNode): number | undefined => {
  const version = getSetValue(phase1Node, 'ike-version');
  return version ? parseInt(version, 10) : undefined;
};

/**
 * Get DH groups from IPsec configuration
 * @param phaseNode The IPsec phase1 or phase2 edit entry
 * @returns Array of DH group numbers
 */
export const getDhGroups = (phaseNode: ConfigNode): number[] => {
  const dhgrp = getSetValues(phaseNode, 'dhgrp');
  return dhgrp.map((g) => parseInt(g, 10)).filter((n) => !isNaN(n));
};

/**
 * Check if weak DH groups are used
 * @param dhGroups Array of DH group numbers
 * @returns true if any weak DH group is found
 */
export const hasWeakDhGroup = (dhGroups: number[]): boolean => {
  const weakGroups = [1, 2, 5]; // DH groups 1, 2, 5 are considered weak
  return dhGroups.some((g) => weakGroups.includes(g));
};

/**
 * Check if PFS is enabled in phase2
 * @param phase2Node The IPsec phase2-interface edit entry
 * @returns true if PFS is enabled
 */
export const isPfsEnabled = (phase2Node: ConfigNode): boolean => {
  const pfs = getSetValue(phase2Node, 'pfs');
  return pfs?.toLowerCase() === 'enable';
};

/**
 * Get key lifetime from IPsec phase2
 * @param phase2Node The IPsec phase2-interface edit entry
 * @returns Key lifetime in seconds, or undefined
 */
export const getKeyLifetime = (phase2Node: ConfigNode): number | undefined => {
  const lifetime = getSetValue(phase2Node, 'keylifeseconds');
  return lifetime ? parseInt(lifetime, 10) : undefined;
};

// ============================================================================
// SSL VPN Helpers (FGT-VPN-006)
// ============================================================================

/**
 * Get SSL VPN settings
 * @param sslSettingsNode The vpn ssl settings config section
 * @returns Object with SSL VPN settings
 */
export const getSslVpnSettings = (sslSettingsNode: ConfigNode): {
  sslMinProtoVer: string | undefined;
  sslMaxProtoVer: string | undefined;
  idleTimeout: number | undefined;
  authTimeout: number | undefined;
  loginAttemptLimit: number | undefined;
  loginBlockTime: number | undefined;
  reqClientCert: boolean;
  checkReferer: boolean;
} => {
  return {
    sslMinProtoVer: getSetValue(sslSettingsNode, 'ssl-min-proto-ver'),
    sslMaxProtoVer: getSetValue(sslSettingsNode, 'ssl-max-proto-ver'),
    idleTimeout: parseInt(getSetValue(sslSettingsNode, 'idle-timeout') || '0', 10) || undefined,
    authTimeout: parseInt(getSetValue(sslSettingsNode, 'auth-timeout') || '0', 10) || undefined,
    loginAttemptLimit: parseInt(getSetValue(sslSettingsNode, 'login-attempt-limit') || '0', 10) || undefined,
    loginBlockTime: parseInt(getSetValue(sslSettingsNode, 'login-block-time') || '0', 10) || undefined,
    reqClientCert: getSetValue(sslSettingsNode, 'reqclientcert')?.toLowerCase() === 'enable',
    checkReferer: getSetValue(sslSettingsNode, 'check-referer')?.toLowerCase() === 'enable',
  };
};

// ============================================================================
// Admin 2FA Helpers (FGT-MGMT-006)
// ============================================================================

/**
 * Check if admin has two-factor authentication enabled
 * @param adminNode The admin user edit entry
 * @returns true if 2FA is enabled
 */
export const hasAdmin2FA = (adminNode: ConfigNode): boolean => {
  const twoFactor = getSetValue(adminNode, 'two-factor');
  return twoFactor !== undefined && twoFactor.toLowerCase() !== 'disable';
};

/**
 * Get admin two-factor authentication type
 * @param adminNode The admin user edit entry
 * @returns The 2FA type (fortitoken, email, sms, etc.) or undefined
 */
export const getAdmin2FAType = (adminNode: ConfigNode): string | undefined => {
  return getSetValue(adminNode, 'two-factor');
};

// ============================================================================
// Interface Role Helpers (FGT-NET-003)
// ============================================================================

/**
 * Get interface role
 * @param interfaceNode The interface edit entry
 * @returns The interface role (wan, lan, dmz, undefined)
 */
export const getInterfaceRole = (interfaceNode: ConfigNode): string | undefined => {
  return getSetValue(interfaceNode, 'role');
};

/**
 * Check if interface is WAN-facing
 * @param interfaceNode The interface edit entry
 * @returns true if interface has WAN role
 */
export const isWanInterface = (interfaceNode: ConfigNode): boolean => {
  const role = getInterfaceRole(interfaceNode);
  return role?.toLowerCase() === 'wan';
};

/**
 * Check if interface has management access on WAN
 * @param interfaceNode The interface edit entry
 * @returns true if WAN interface has management protocols enabled
 */
export const hasWanManagementAccess = (interfaceNode: ConfigNode): boolean => {
  if (!isWanInterface(interfaceNode)) return false;
  const access = getInterfaceAllowAccess(interfaceNode);
  const mgmtProtocols = ['https', 'http', 'ssh', 'telnet', 'snmp'];
  return access.some((a) => mgmtProtocols.includes(a.toLowerCase()));
};
