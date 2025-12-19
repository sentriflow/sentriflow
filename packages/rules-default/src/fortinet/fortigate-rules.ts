// packages/rules-default/src/fortinet/fortigate-rules.ts
// Fortinet FortiGate (FortiOS) specific rules

import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import {
  equalsIgnoreCase,
  isFeatureEnabled,
  isFeatureDisabled,
  parseInteger,
} from '@sentriflow/core';
import {
  findConfigSection,
  getEditEntries,
  getEditEntryName,
  getSetValue,
  hasSetValue,
  getSetValues,
  isPolicyAccept,
  isPolicyDisabled,
  hasLogging,
  hasAnySrcAddr,
  hasAnyDstAddr,
  hasAnyService,
  hasSecurityProfile,
  getInterfaceAllowAccess,
  hasTelnetAccess,
  hasHttpManagement,
  isHAEnabled,
  getHAMode,
  hasAdminTrustedHosts,
  isSuperAdmin,
  getAdminTrustedHosts,
} from '@sentriflow/core/helpers/fortinet';

// ============================================================================
// System Security Rules
// ============================================================================

/**
 * FGT-SYS-001: Hostname must be configured
 */
export const HostnameRequired: IRule = {
  id: 'FGT-SYS-001',
  selector: 'config system global',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure hostname under "config system global" using "set hostname <name>".',
  },
  check: (node: ConfigNode): RuleResult => {
    const hostname = getSetValue(node, 'hostname');
    if (!hostname) {
      return {
        passed: false,
        message: 'System hostname is not configured.',
        ruleId: 'FGT-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Hostname is configured.',
      ruleId: 'FGT-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-SYS-002: NTP must be configured for time synchronization
 */
export const NtpRequired: IRule = {
  id: 'FGT-SYS-002',
  selector: 'config system ntp',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP servers under "config system ntp" using "set ntpsync enable" and adding NTP servers.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ntpsync = getSetValue(node, 'ntpsync');
    if (!isFeatureEnabled(ntpsync)) {
      return {
        passed: false,
        message: 'NTP synchronization is not enabled. Time synchronization is critical for logging and certificate validation.',
        ruleId: 'FGT-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check for NTP servers
    const ntpservers = getEditEntries(node);
    if (ntpservers.length === 0) {
      return {
        passed: false,
        message: 'NTP is enabled but no NTP servers are configured.',
        ruleId: 'FGT-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP servers are configured.',
      ruleId: 'FGT-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-SYS-003: DNS servers must be configured
 */
export const DnsRequired: IRule = {
  id: 'FGT-SYS-003',
  selector: 'config system dns',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure DNS servers under "config system dns" using "set primary" and "set secondary".',
  },
  check: (node: ConfigNode): RuleResult => {
    const primary = getSetValue(node, 'primary');
    if (!primary || primary === '0.0.0.0') {
      return {
        passed: false,
        message: 'Primary DNS server is not configured.',
        ruleId: 'FGT-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'DNS servers are configured.',
      ruleId: 'FGT-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-SYS-004: Admin timeout should be configured
 */
export const AdminTimeoutRequired: IRule = {
  id: 'FGT-SYS-004',
  selector: 'config system global',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure admin session timeout under "config system global" using "set admintimeout <minutes>".',
  },
  check: (node: ConfigNode): RuleResult => {
    const timeout = getSetValue(node, 'admintimeout');
    if (!timeout) {
      return {
        passed: false,
        message: 'Admin session timeout is not configured. Default may be too long for security requirements.',
        ruleId: 'FGT-SYS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const timeoutMinutes = parseInteger(timeout);
    if (timeoutMinutes === null || timeoutMinutes > 30) {
      return {
        passed: false,
        message: `Admin timeout is set to ${timeoutMinutes} minutes. Consider reducing to 30 minutes or less.`,
        ruleId: 'FGT-SYS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Admin timeout is configured (${timeoutMinutes} minutes).`,
      ruleId: 'FGT-SYS-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-SYS-005: Strong admin password policy should be enabled
 */
export const PasswordPolicyRequired: IRule = {
  id: 'FGT-SYS-005',
  selector: 'config system global',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable strong password policy under "config system global" using "set admin-lockout-threshold", "set strong-crypto enable".',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];

    const lockoutThreshold = getSetValue(node, 'admin-lockout-threshold');
    const lockoutValue = lockoutThreshold ? parseInteger(lockoutThreshold) : null;
    if (lockoutValue === null || lockoutValue > 5) {
      issues.push('Admin lockout threshold should be 5 or less failed attempts.');
    }

    const strongCrypto = getSetValue(node, 'strong-crypto');
    if (!isFeatureEnabled(strongCrypto)) {
      issues.push('Strong crypto should be enabled for secure communications.');
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-SYS-005',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Password policy settings are properly configured.',
      ruleId: 'FGT-SYS-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-SYS-006: Pre-login banner should be configured
 */
export const PreLoginBannerRequired: IRule = {
  id: 'FGT-SYS-006',
  selector: 'config system global',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure pre-login banner under "config system global" using "set pre-login-banner enable".',
  },
  check: (node: ConfigNode): RuleResult => {
    const banner = getSetValue(node, 'pre-login-banner');
    if (!isFeatureEnabled(banner)) {
      return {
        passed: false,
        message: 'Pre-login banner is not enabled. Consider adding a legal warning banner.',
        ruleId: 'FGT-SYS-006',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Pre-login banner is enabled.',
      ruleId: 'FGT-SYS-006',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Admin User Rules
// ============================================================================

/**
 * FGT-ADMIN-001: Admin users should have trusted host restrictions
 */
export const AdminTrustedHostRequired: IRule = {
  id: 'FGT-ADMIN-001',
  selector: 'config system admin',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure trusted hosts for each admin user using "set trusthost1", "set trusthost2", etc.',
  },
  check: (node: ConfigNode): RuleResult => {
    const admins = getEditEntries(node);
    if (admins.length === 0) {
      return {
        passed: true,
        message: 'No admin users configured.',
        ruleId: 'FGT-ADMIN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const admin of admins) {
      const adminName = getEditEntryName(admin);

      // Skip if admin has trusted hosts configured
      if (hasAdminTrustedHosts(admin)) {
        continue;
      }

      // Super_admin without trusted hosts is a security risk
      if (isSuperAdmin(admin)) {
        issues.push(`Super admin "${adminName}" has no trusted host restrictions. This is a critical security issue.`);
      } else {
        issues.push(`Admin "${adminName}" has no trusted host restrictions.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-ADMIN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All admin users have trusted host restrictions configured.',
      ruleId: 'FGT-ADMIN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-ADMIN-002: Super admin count should be limited
 */
export const LimitSuperAdmins: IRule = {
  id: 'FGT-ADMIN-002',
  selector: 'config system admin',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Limit the number of super_admin accounts. Use role-based access profiles for regular administration.',
  },
  check: (node: ConfigNode): RuleResult => {
    const admins = getEditEntries(node);
    const superAdmins = admins.filter((admin) => isSuperAdmin(admin));

    if (superAdmins.length > 3) {
      const names = superAdmins.map((a) => getEditEntryName(a)).join(', ');
      return {
        passed: false,
        message: `Found ${superAdmins.length} super_admin accounts (${names}). Consider reducing to limit privilege exposure.`,
        ruleId: 'FGT-ADMIN-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Super admin count is acceptable (${superAdmins.length}).`,
      ruleId: 'FGT-ADMIN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Interface Security Rules
// ============================================================================

/**
 * FGT-IF-001: Telnet should not be allowed on interfaces
 */
export const NoTelnetAccess: IRule = {
  id: 'FGT-IF-001',
  selector: 'config system interface',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Remove "telnet" from allowaccess on all interfaces. Use SSH instead.',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaces = getEditEntries(node);
    const issues: string[] = [];

    for (const iface of interfaces) {
      if (hasTelnetAccess(iface)) {
        const ifName = getEditEntryName(iface);
        issues.push(`Interface "${ifName}" allows Telnet access. Telnet is insecure and should be disabled.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-IF-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No interfaces have Telnet access enabled.',
      ruleId: 'FGT-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-IF-002: HTTP management should be avoided (use HTTPS)
 */
export const NoHttpManagement: IRule = {
  id: 'FGT-IF-002',
  selector: 'config system interface',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Remove "http" from allowaccess on all interfaces. Use HTTPS for web management.',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaces = getEditEntries(node);
    const issues: string[] = [];

    for (const iface of interfaces) {
      const access = getInterfaceAllowAccess(iface);
      if (access.some((a) => equalsIgnoreCase(a, 'http'))) {
        const ifName = getEditEntryName(iface);
        issues.push(`Interface "${ifName}" allows HTTP access. Use HTTPS instead for secure management.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-IF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No interfaces have HTTP access enabled.',
      ruleId: 'FGT-IF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-IF-003: Interfaces should have descriptions
 */
export const InterfaceDescriptionRequired: IRule = {
  id: 'FGT-IF-003',
  selector: 'config system interface',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to all interfaces using "set description".',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaces = getEditEntries(node);
    const issues: string[] = [];

    for (const iface of interfaces) {
      const description = getSetValue(iface, 'description');
      const alias = getSetValue(iface, 'alias');
      if (!description && !alias) {
        const ifName = getEditEntryName(iface);
        // Skip system interfaces like modem, ssl.root, etc.
        if (!/^(modem|ssl\.|npu\d|internal\d)/.test(ifName)) {
          issues.push(`Interface "${ifName}" has no description or alias.`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-IF-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All interfaces have descriptions.',
      ruleId: 'FGT-IF-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Firewall Policy Rules
// ============================================================================

/**
 * FGT-POL-001: Firewall policies should have logging enabled
 */
export const PolicyLoggingRequired: IRule = {
  id: 'FGT-POL-001',
  selector: 'config firewall policy',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable logging on all firewall policies using "set logtraffic all" or "set logtraffic utm".',
  },
  check: (node: ConfigNode): RuleResult => {
    const policies = getEditEntries(node);
    if (policies.length === 0) {
      return {
        passed: true,
        message: 'No firewall policies configured.',
        ruleId: 'FGT-POL-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const policy of policies) {
      if (isPolicyDisabled(policy)) continue;

      const logging = hasLogging(policy);
      if (!logging.logtraffic || isFeatureDisabled(logging.logtraffic)) {
        const policyId = getEditEntryName(policy);
        issues.push(`Policy ${policyId} does not have logging enabled.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-POL-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All firewall policies have logging enabled.',
      ruleId: 'FGT-POL-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-POL-002: Accept policies should have UTM/security profiles attached
 */
export const PolicySecurityProfileRequired: IRule = {
  id: 'FGT-POL-002',
  selector: 'config firewall policy',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Attach UTM profiles (AV, IPS, Web Filter, Application Control) to all accept policies.',
  },
  check: (node: ConfigNode): RuleResult => {
    const policies = getEditEntries(node);
    if (policies.length === 0) {
      return {
        passed: true,
        message: 'No firewall policies configured.',
        ruleId: 'FGT-POL-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const policy of policies) {
      if (isPolicyDisabled(policy)) continue;
      if (!isPolicyAccept(policy)) continue;

      if (!hasSecurityProfile(policy)) {
        const policyId = getEditEntryName(policy);
        issues.push(`Accept policy ${policyId} does not have UTM/security profiles attached.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-POL-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All accept policies have security profiles attached.',
      ruleId: 'FGT-POL-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-POL-003: Avoid using "all" for source and destination addresses
 */
export const NoOverlyPermissivePolicies: IRule = {
  id: 'FGT-POL-003',
  selector: 'config firewall policy',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Avoid policies with srcaddr "all" AND dstaddr "all". Use specific address objects.',
  },
  check: (node: ConfigNode): RuleResult => {
    const policies = getEditEntries(node);
    if (policies.length === 0) {
      return {
        passed: true,
        message: 'No firewall policies configured.',
        ruleId: 'FGT-POL-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const policy of policies) {
      if (isPolicyDisabled(policy)) continue;
      if (!isPolicyAccept(policy)) continue;

      const anySource = hasAnySrcAddr(policy);
      const anyDest = hasAnyDstAddr(policy);
      const anyService = hasAnyService(policy);

      if (anySource && anyDest && anyService) {
        const policyId = getEditEntryName(policy);
        issues.push(`Policy ${policyId} is overly permissive: all sources, all destinations, all services.`);
      } else if (anySource && anyDest) {
        const policyId = getEditEntryName(policy);
        issues.push(`Policy ${policyId} allows all sources to all destinations. Consider restricting.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-POL-003',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No overly permissive policies found.',
      ruleId: 'FGT-POL-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-POL-004: Firewall policies should have comments/names
 */
export const PolicyCommentRequired: IRule = {
  id: 'FGT-POL-004',
  selector: 'config firewall policy',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add comments to all firewall policies using "set comments" or "set name".',
  },
  check: (node: ConfigNode): RuleResult => {
    const policies = getEditEntries(node);
    if (policies.length === 0) {
      return {
        passed: true,
        message: 'No firewall policies configured.',
        ruleId: 'FGT-POL-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const policy of policies) {
      if (isPolicyDisabled(policy)) continue;

      const name = getSetValue(policy, 'name');
      const comments = getSetValue(policy, 'comments');
      if (!name && !comments) {
        const policyId = getEditEntryName(policy);
        issues.push(`Policy ${policyId} does not have a name or comment.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-POL-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All firewall policies have comments or names.',
      ruleId: 'FGT-POL-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-POL-005: Policies using "ALL" service should be reviewed
 */
export const NoAnyServicePolicy: IRule = {
  id: 'FGT-POL-005',
  selector: 'config firewall policy',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Replace "ALL" service with specific services or service groups for better control.',
  },
  check: (node: ConfigNode): RuleResult => {
    const policies = getEditEntries(node);
    if (policies.length === 0) {
      return {
        passed: true,
        message: 'No firewall policies configured.',
        ruleId: 'FGT-POL-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const policy of policies) {
      if (isPolicyDisabled(policy)) continue;
      if (!isPolicyAccept(policy)) continue;

      if (hasAnyService(policy)) {
        const policyId = getEditEntryName(policy);
        issues.push(`Policy ${policyId} uses "ALL" service. Consider specifying exact services.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-POL-005',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No policies use "ALL" service.',
      ruleId: 'FGT-POL-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// High Availability Rules
// ============================================================================

/**
 * FGT-HA-001: HA should be configured for production firewalls
 */
export const HARecommended: IRule = {
  id: 'FGT-HA-001',
  selector: 'config system ha',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Consider configuring HA (Active-Passive or Active-Active) for production environments.',
  },
  check: (node: ConfigNode): RuleResult => {
    const mode = getHAMode(node);
    if (!mode || equalsIgnoreCase(mode, 'standalone')) {
      return {
        passed: false,
        message: 'High Availability is not configured. Consider HA for production deployments.',
        ruleId: 'FGT-HA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `High Availability is configured (mode: ${mode}).`,
      ruleId: 'FGT-HA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-HA-002: HA encryption should be enabled
 */
export const HAEncryptionRequired: IRule = {
  id: 'FGT-HA-002',
  selector: 'config system ha',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable HA heartbeat encryption using "set hbdev-vlan-id", "set session-sync-dev" with encryption.',
  },
  check: (node: ConfigNode): RuleResult => {
    const mode = getHAMode(node);
    if (!mode || equalsIgnoreCase(mode, 'standalone')) {
      return {
        passed: true,
        message: 'HA not configured, encryption check not applicable.',
        ruleId: 'FGT-HA-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const encryption = getSetValue(node, 'encryption');
    if (!isFeatureEnabled(encryption)) {
      return {
        passed: false,
        message: 'HA heartbeat encryption is not enabled. Enable to protect HA communications.',
        ruleId: 'FGT-HA-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'HA encryption is enabled.',
      ruleId: 'FGT-HA-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VPN Rules
// ============================================================================

/**
 * FGT-VPN-001: IPsec VPN should use strong encryption
 */
export const VpnStrongEncryption: IRule = {
  id: 'FGT-VPN-001',
  selector: 'config vpn ipsec phase1-interface',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use AES256 or AES128 for IPsec encryption. Avoid DES, 3DES, and weak algorithms.',
  },
  check: (node: ConfigNode): RuleResult => {
    const tunnels = getEditEntries(node);
    if (tunnels.length === 0) {
      return {
        passed: true,
        message: 'No IPsec tunnels configured.',
        ruleId: 'FGT-VPN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    const weakAlgorithms = ['des', '3des', 'null'];

    for (const tunnel of tunnels) {
      const tunnelName = getEditEntryName(tunnel);
      const proposal = getSetValues(tunnel, 'proposal');

      for (const prop of proposal) {
        const propLower = prop.toLowerCase();
        if (weakAlgorithms.some((weak) => propLower.includes(weak))) {
          issues.push(`IPsec tunnel "${tunnelName}" uses weak encryption algorithm: ${prop}`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-VPN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All IPsec tunnels use strong encryption.',
      ruleId: 'FGT-VPN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-VPN-002: IPsec VPN should have DPD (Dead Peer Detection) enabled
 */
export const VpnDpdEnabled: IRule = {
  id: 'FGT-VPN-002',
  selector: 'config vpn ipsec phase1-interface',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable DPD for IPsec tunnels using "set dpd on-demand" or "set dpd on-idle".',
  },
  check: (node: ConfigNode): RuleResult => {
    const tunnels = getEditEntries(node);
    if (tunnels.length === 0) {
      return {
        passed: true,
        message: 'No IPsec tunnels configured.',
        ruleId: 'FGT-VPN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const tunnel of tunnels) {
      const tunnelName = getEditEntryName(tunnel);
      const dpd = getSetValue(tunnel, 'dpd');
      if (!dpd || isFeatureDisabled(dpd)) {
        issues.push(`IPsec tunnel "${tunnelName}" does not have DPD enabled.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'FGT-VPN-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All IPsec tunnels have DPD enabled.',
      ruleId: 'FGT-VPN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Logging Rules
// ============================================================================

/**
 * FGT-LOG-001: Syslog should be configured for centralized logging
 */
export const SyslogRequired: IRule = {
  id: 'FGT-LOG-001',
  selector: 'config log syslogd setting',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure syslog server for centralized logging under "config log syslogd setting".',
  },
  check: (node: ConfigNode): RuleResult => {
    const status = getSetValue(node, 'status');
    if (!isFeatureEnabled(status)) {
      return {
        passed: false,
        message: 'Syslog is not enabled. Configure centralized logging for security monitoring.',
        ruleId: 'FGT-LOG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const server = getSetValue(node, 'server');
    if (!server || server === '0.0.0.0') {
      return {
        passed: false,
        message: 'Syslog is enabled but no server is configured.',
        ruleId: 'FGT-LOG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Syslog is configured for centralized logging.',
      ruleId: 'FGT-LOG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Security Profile Rules
// ============================================================================

/**
 * FGT-PROF-001: Antivirus profile should be configured
 */
export const AntivirusProfileRequired: IRule = {
  id: 'FGT-PROF-001',
  selector: 'config antivirus profile',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one antivirus profile for malware protection.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profiles = getEditEntries(node);
    if (profiles.length === 0) {
      return {
        passed: false,
        message: 'No antivirus profiles are configured.',
        ruleId: 'FGT-PROF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `${profiles.length} antivirus profile(s) configured.`,
      ruleId: 'FGT-PROF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-PROF-002: IPS sensor should be configured
 */
export const IpsSensorRequired: IRule = {
  id: 'FGT-PROF-002',
  selector: 'config ips sensor',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one IPS sensor for intrusion prevention.',
  },
  check: (node: ConfigNode): RuleResult => {
    const sensors = getEditEntries(node);
    if (sensors.length === 0) {
      return {
        passed: false,
        message: 'No IPS sensors are configured.',
        ruleId: 'FGT-PROF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `${sensors.length} IPS sensor(s) configured.`,
      ruleId: 'FGT-PROF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-PROF-003: Web filter profile should be configured
 */
export const WebFilterProfileRequired: IRule = {
  id: 'FGT-PROF-003',
  selector: 'config webfilter profile',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one web filter profile for URL filtering.',
  },
  check: (node: ConfigNode): RuleResult => {
    const profiles = getEditEntries(node);
    if (profiles.length === 0) {
      return {
        passed: false,
        message: 'No web filter profiles are configured.',
        ruleId: 'FGT-PROF-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `${profiles.length} web filter profile(s) configured.`,
      ruleId: 'FGT-PROF-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * FGT-PROF-004: Application control list should be configured
 */
export const ApplicationListRequired: IRule = {
  id: 'FGT-PROF-004',
  selector: 'config application list',
  vendor: 'fortinet-fortigate',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one application control list for application visibility and control.',
  },
  check: (node: ConfigNode): RuleResult => {
    const lists = getEditEntries(node);
    if (lists.length === 0) {
      return {
        passed: false,
        message: 'No application control lists are configured.',
        ruleId: 'FGT-PROF-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `${lists.length} application control list(s) configured.`,
      ruleId: 'FGT-PROF-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all FortiGate rules - proof-of-concept subset
// NOTE: Additional rules available in basic-netsec-pack
// ============================================================================

export const allFortinetRules: IRule[] = [
  // System rules
  HostnameRequired,
  // Firewall policy rules
  PolicyLoggingRequired,
  // Admin rules
  AdminTrustedHostRequired,
];
