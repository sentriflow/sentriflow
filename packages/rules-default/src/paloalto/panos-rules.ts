// packages/rules-default/src/paloalto/panos-rules.ts
// Palo Alto PAN-OS specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  hasChildCommand,
  findStanza,
  findStanzas,
  getSecurityRules,
  getNatRules,
  hasLogging,
  hasSecurityProfile,
  isAllowRule,
  hasAnyApplication,
  hasAnySource,
  hasAnyDestination,
  hasAnyService,
  isRuleDisabled,
  hasZoneProtectionProfile,
  hasWildfireProfile,
  hasUrlFilteringProfile,
  hasAntiVirusProfile,
  hasAntiSpywareProfile,
  hasVulnerabilityProfile,
} from '@sentriflow/core/helpers/paloalto';

// ============================================================================
// System Security Rules
// ============================================================================

/**
 * PAN-SYS-001: Hostname must be configured
 */
export const HostnameRequired: IRule = {
  id: 'PAN-SYS-001',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure hostname under deviceconfig > system.',
  },
  check: (node: ConfigNode): RuleResult => {
    const system = findStanza(node, 'system');
    if (!system) {
      return {
        passed: false,
        message: 'Device configuration missing system stanza.',
        ruleId: 'PAN-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const hasHostname = hasChildCommand(system, 'hostname');
    if (!hasHostname) {
      return {
        passed: false,
        message: 'System hostname is not configured.',
        ruleId: 'PAN-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Hostname is configured.',
      ruleId: 'PAN-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SYS-002: NTP must be configured for time synchronization
 */
export const NtpRequired: IRule = {
  id: 'PAN-SYS-002',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP servers under deviceconfig > system > ntp-servers.',
  },
  check: (node: ConfigNode): RuleResult => {
    const system = findStanza(node, 'system');
    if (!system) {
      return {
        passed: false,
        message: 'Device configuration missing system stanza.',
        ruleId: 'PAN-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const ntp = findStanza(system, 'ntp-servers');
    if (!ntp || ntp.children.length === 0) {
      return {
        passed: false,
        message: 'NTP servers are not configured. Time synchronization is critical for logging and certificate validation.',
        ruleId: 'PAN-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP servers are configured.',
      ruleId: 'PAN-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SYS-003: DNS servers must be configured
 */
export const DnsRequired: IRule = {
  id: 'PAN-SYS-003',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure DNS servers under deviceconfig > system > dns-setting.',
  },
  check: (node: ConfigNode): RuleResult => {
    const system = findStanza(node, 'system');
    if (!system) {
      return {
        passed: false,
        message: 'Device configuration missing system stanza.',
        ruleId: 'PAN-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const dns = findStanza(system, 'dns-setting');
    if (!dns) {
      return {
        passed: false,
        message: 'DNS settings are not configured.',
        ruleId: 'PAN-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const servers = findStanza(dns, 'servers');
    if (!servers || servers.children.length === 0) {
      return {
        passed: false,
        message: 'No DNS servers configured.',
        ruleId: 'PAN-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'DNS servers are configured.',
      ruleId: 'PAN-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SYS-004: Management interface access should be restricted
 */
export const ManagementAccessRestricted: IRule = {
  id: 'PAN-SYS-004',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure permitted-ip under deviceconfig > system > permitted-ip to restrict management access.',
  },
  check: (node: ConfigNode): RuleResult => {
    const system = findStanza(node, 'system');
    if (!system) {
      return {
        passed: true,
        message: 'System configuration not present.',
        ruleId: 'PAN-SYS-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const permittedIp = findStanza(system, 'permitted-ip');
    if (!permittedIp || permittedIp.children.length === 0) {
      return {
        passed: false,
        message: 'Management access is not restricted. Configure permitted-ip to limit access to trusted networks.',
        ruleId: 'PAN-SYS-004',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Management access is restricted via permitted-ip.',
      ruleId: 'PAN-SYS-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SYS-005: Login banner should be configured
 */
export const LoginBannerRequired: IRule = {
  id: 'PAN-SYS-005',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure login-banner under deviceconfig > system.',
  },
  check: (node: ConfigNode): RuleResult => {
    const system = findStanza(node, 'system');
    if (!system) {
      return {
        passed: true,
        message: 'System configuration not present.',
        ruleId: 'PAN-SYS-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasBanner = hasChildCommand(system, 'login-banner');
    if (!hasBanner) {
      return {
        passed: false,
        message: 'Login banner is not configured. Consider adding a legal warning banner.',
        ruleId: 'PAN-SYS-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Login banner is configured.',
      ruleId: 'PAN-SYS-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Security Policy Rules
// ============================================================================

/**
 * PAN-SEC-001: Security rules should have logging enabled
 */
export const SecurityRuleLogging: IRule = {
  id: 'PAN-SEC-001',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable log-end (and optionally log-start) on all security rules.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getSecurityRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No security rules configured.',
        ruleId: 'PAN-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (isRuleDisabled(rule)) continue;

      const logging = hasLogging(rule);
      if (!logging.logEnd) {
        issues.push(`Rule "${rule.id}" does not have log-end enabled.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-SEC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All security rules have logging enabled.',
      ruleId: 'PAN-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SEC-002: Allow rules should have security profiles attached
 */
export const SecurityProfileRequired: IRule = {
  id: 'PAN-SEC-002',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Attach security profile group (AV, Anti-Spyware, Vulnerability, URL Filtering, WildFire) to all allow rules.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getSecurityRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No security rules configured.',
        ruleId: 'PAN-SEC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (isRuleDisabled(rule)) continue;
      if (!isAllowRule(rule)) continue;

      if (!hasSecurityProfile(rule)) {
        issues.push(`Allow rule "${rule.id}" does not have security profiles attached.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-SEC-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All allow rules have security profiles attached.',
      ruleId: 'PAN-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SEC-003: Avoid using "any" application in allow rules
 */
export const NoAnyApplication: IRule = {
  id: 'PAN-SEC-003',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Replace "any" application with specific applications or application groups for better visibility and control.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getSecurityRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No security rules configured.',
        ruleId: 'PAN-SEC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (isRuleDisabled(rule)) continue;
      if (!isAllowRule(rule)) continue;

      if (hasAnyApplication(rule)) {
        issues.push(`Allow rule "${rule.id}" uses "any" application. Consider specifying applications for better security posture.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-SEC-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No rules use "any" application.',
      ruleId: 'PAN-SEC-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SEC-004: Overly permissive rules (any source, any destination, any service)
 */
export const NoOverlyPermissiveRules: IRule = {
  id: 'PAN-SEC-004',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Avoid rules with "any" source AND "any" destination AND "any" service. Use specific objects.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getSecurityRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No security rules configured.',
        ruleId: 'PAN-SEC-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (isRuleDisabled(rule)) continue;
      if (!isAllowRule(rule)) continue;

      const anySource = hasAnySource(rule);
      const anyDest = hasAnyDestination(rule);
      const anyService = hasAnyService(rule);

      if (anySource && anyDest && anyService) {
        issues.push(`Rule "${rule.id}" is overly permissive: any source, any destination, any service.`);
      } else if (anySource && anyDest) {
        issues.push(`Rule "${rule.id}" allows any source to any destination. Consider restricting.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-SEC-004',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'No overly permissive rules found.',
      ruleId: 'PAN-SEC-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-SEC-005: Security rules should have descriptions
 */
export const SecurityRuleDescription: IRule = {
  id: 'PAN-SEC-005',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a description to each security rule explaining its purpose.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getSecurityRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No security rules configured.',
        ruleId: 'PAN-SEC-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (isRuleDisabled(rule)) continue;

      if (!hasChildCommand(rule, 'description')) {
        issues.push(`Rule "${rule.id}" does not have a description.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-SEC-005',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All security rules have descriptions.',
      ruleId: 'PAN-SEC-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Zone Rules
// ============================================================================

/**
 * PAN-ZONE-001: Zones should have zone protection profiles
 */
export const ZoneProtectionRequired: IRule = {
  id: 'PAN-ZONE-001',
  selector: 'zone',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Apply a Zone Protection Profile to each zone to protect against flood attacks and reconnaissance.',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];

    // Iterate through all zone definitions
    for (const zone of node.children) {
      if (!hasZoneProtectionProfile(zone)) {
        issues.push(`Zone "${zone.id}" does not have a Zone Protection Profile applied.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-ZONE-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (node.children.length === 0) {
      return {
        passed: true,
        message: 'No zones configured.',
        ruleId: 'PAN-ZONE-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All zones have Zone Protection Profiles applied.',
      ruleId: 'PAN-ZONE-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Profile Rules
// ============================================================================

/**
 * PAN-PROF-001: WildFire analysis profile should be configured
 */
export const WildfireRequired: IRule = {
  id: 'PAN-PROF-001',
  selector: 'profiles',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one WildFire Analysis profile for advanced malware detection.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasWildfireProfile(node)) {
      return {
        passed: false,
        message: 'No WildFire Analysis profile is configured. WildFire provides cloud-based malware analysis.',
        ruleId: 'PAN-PROF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'WildFire Analysis profile is configured.',
      ruleId: 'PAN-PROF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-PROF-002: URL Filtering profile should be configured
 */
export const UrlFilteringRequired: IRule = {
  id: 'PAN-PROF-002',
  selector: 'profiles',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one URL Filtering profile for web security.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasUrlFilteringProfile(node)) {
      return {
        passed: false,
        message: 'No URL Filtering profile is configured.',
        ruleId: 'PAN-PROF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'URL Filtering profile is configured.',
      ruleId: 'PAN-PROF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-PROF-003: Anti-Virus profile should be configured
 */
export const AntiVirusRequired: IRule = {
  id: 'PAN-PROF-003',
  selector: 'profiles',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one Anti-Virus profile.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasAntiVirusProfile(node)) {
      return {
        passed: false,
        message: 'No Anti-Virus profile is configured.',
        ruleId: 'PAN-PROF-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Anti-Virus profile is configured.',
      ruleId: 'PAN-PROF-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-PROF-004: Anti-Spyware profile should be configured
 */
export const AntiSpywareRequired: IRule = {
  id: 'PAN-PROF-004',
  selector: 'profiles',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one Anti-Spyware profile for C2 and spyware detection.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasAntiSpywareProfile(node)) {
      return {
        passed: false,
        message: 'No Anti-Spyware profile is configured.',
        ruleId: 'PAN-PROF-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Anti-Spyware profile is configured.',
      ruleId: 'PAN-PROF-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * PAN-PROF-005: Vulnerability Protection profile should be configured
 */
export const VulnerabilityProtectionRequired: IRule = {
  id: 'PAN-PROF-005',
  selector: 'profiles',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure at least one Vulnerability Protection profile for IPS functionality.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasVulnerabilityProfile(node)) {
      return {
        passed: false,
        message: 'No Vulnerability Protection profile is configured.',
        ruleId: 'PAN-PROF-005',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Vulnerability Protection profile is configured.',
      ruleId: 'PAN-PROF-005',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// NAT Rules
// ============================================================================

/**
 * PAN-NAT-001: NAT rules should have descriptions
 */
export const NatRuleDescription: IRule = {
  id: 'PAN-NAT-001',
  selector: 'rulebase',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a description to each NAT rule explaining its purpose.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rules = getNatRules(node);
    if (rules.length === 0) {
      return {
        passed: true,
        message: 'No NAT rules configured.',
        ruleId: 'PAN-NAT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const rule of rules) {
      if (!hasChildCommand(rule, 'description')) {
        issues.push(`NAT rule "${rule.id}" does not have a description.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-NAT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All NAT rules have descriptions.',
      ruleId: 'PAN-NAT-001',
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
 * PAN-HA-001: HA should be configured for production firewalls
 */
export const HARecommended: IRule = {
  id: 'PAN-HA-001',
  selector: 'deviceconfig',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Consider configuring High Availability (Active/Passive or Active/Active) for production environments.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ha = findStanza(node, 'high-availability');
    if (!ha || ha.children.length === 0) {
      return {
        passed: false,
        message: 'High Availability is not configured. Consider HA for production deployments.',
        ruleId: 'PAN-HA-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'High Availability is configured.',
      ruleId: 'PAN-HA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Network Rules
// ============================================================================

/**
 * PAN-NET-001: Virtual routers should have a default route
 */
export const VirtualRouterDefaultRoute: IRule = {
  id: 'PAN-NET-001',
  selector: 'network',
  vendor: 'paloalto-panos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure a default route (0.0.0.0/0) in each virtual router.',
  },
  check: (node: ConfigNode): RuleResult => {
    const virtualRouter = findStanza(node, 'virtual-router');
    if (!virtualRouter) {
      return {
        passed: true,
        message: 'No virtual routers configured.',
        ruleId: 'PAN-NET-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const vr of virtualRouter.children) {
      const routingTable = findStanza(vr, 'routing-table');
      if (!routingTable) {
        issues.push(`Virtual router "${vr.id}" has no routing table configured.`);
        continue;
      }

      // Check for static routes with default
      const staticRoutes = findStanza(routingTable, 'ip');
      if (staticRoutes) {
        const staticRoute = findStanza(staticRoutes, 'static-route');
        if (staticRoute) {
          const hasDefault = staticRoute.children.some(
            (route) => route.id.includes('0.0.0.0/0') || route.id.toLowerCase().includes('default')
          );
          if (hasDefault) {
            continue; // Has default route
          }
        }
      }

      // Check for dynamic routing protocols (which may provide default)
      const protocol = findStanza(vr, 'protocol');
      if (protocol) {
        const hasBgp = findStanza(protocol, 'bgp');
        const hasOspf = findStanza(protocol, 'ospf');
        if (hasBgp || hasOspf) {
          continue; // May receive default via dynamic routing
        }
      }

      issues.push(`Virtual router "${vr.id}" may not have a default route configured.`);
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'PAN-NET-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Virtual routers have default routes configured.',
      ruleId: 'PAN-NET-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all Palo Alto PAN-OS rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allPaloAltoRules: IRule[] = [
  // System rules
  HostnameRequired,
  // Security policy rules
  SecurityRuleLogging,
  // Zone rules
  ZoneProtectionRequired,
];
