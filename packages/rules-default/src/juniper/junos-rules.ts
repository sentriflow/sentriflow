// packages/rules-default/src/juniper/junos-rules.ts
// Juniper JunOS specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { equalsIgnoreCase, startsWithIgnoreCase, includesIgnoreCase } from '@sentriflow/core';
import {
  hasChildCommand,
  findStanza,
  findStanzas,
  getInterfaceUnits,
  isDisabled,
  isPhysicalJunosPort,
  isLoopback,
  parseJunosAddress,
  getTermAction,
  isFilterTermDrop,
} from '@sentriflow/core/helpers/juniper';

// ============================================================================
// System Security Rules
// ============================================================================

/**
 * JUN-SYS-001: Root authentication must be configured
 */
export const RootAuthRequired: IRule = {
  id: 'JUN-SYS-001',
  selector: 'system',
  vendor: 'juniper-junos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "root-authentication" under system stanza with encrypted-password or ssh-rsa.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rootAuth = findStanza(node, 'root-authentication');
    if (!rootAuth) {
      return {
        passed: false,
        message: 'System missing root-authentication configuration.',
        ruleId: 'JUN-SYS-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    // Check for encrypted-password or ssh-rsa
    const hasPassword = hasChildCommand(rootAuth, 'encrypted-password');
    const hasSshKey = hasChildCommand(rootAuth, 'ssh-rsa') || hasChildCommand(rootAuth, 'ssh-ecdsa');

    if (!hasPassword && !hasSshKey) {
      return {
        passed: false,
        message: 'Root authentication has no password or SSH key configured.',
        ruleId: 'JUN-SYS-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Root authentication is properly configured.',
      ruleId: 'JUN-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * JUN-SYS-002: SSH service must be enabled under system services
 */
export const SshServiceRequired: IRule = {
  id: 'JUN-SYS-002',
  selector: 'system',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "services { ssh; }" under system stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const services = findStanza(node, 'services');
    if (!services) {
      return {
        passed: false,
        message: 'System missing services configuration.',
        ruleId: 'JUN-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const hasSsh = hasChildCommand(services, 'ssh');
    if (!hasSsh) {
      return {
        passed: false,
        message: 'SSH service is not enabled. Configure "ssh" under services.',
        ruleId: 'JUN-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH service is enabled.',
      ruleId: 'JUN-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * JUN-SYS-003: Syslog must be configured
 */
export const SyslogRequired: IRule = {
  id: 'JUN-SYS-003',
  selector: 'system',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "syslog" under system stanza with appropriate log destinations.',
  },
  check: (node: ConfigNode): RuleResult => {
    const syslog = findStanza(node, 'syslog');
    if (!syslog) {
      return {
        passed: false,
        message: 'System missing syslog configuration.',
        ruleId: 'JUN-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check for at least one log destination (file or host)
    const hasFile = hasChildCommand(syslog, 'file');
    const hasHost = hasChildCommand(syslog, 'host');

    if (!hasFile && !hasHost) {
      return {
        passed: false,
        message: 'Syslog configured but no log destinations (file or host) defined.',
        ruleId: 'JUN-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Syslog is properly configured.',
      ruleId: 'JUN-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * JUN-SYS-004: NTP must be configured
 */
export const NtpRequired: IRule = {
  id: 'JUN-SYS-004',
  selector: 'system',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "ntp" under system stanza with at least one NTP server.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ntp = findStanza(node, 'ntp');
    if (!ntp) {
      return {
        passed: false,
        message: 'System missing NTP configuration.',
        ruleId: 'JUN-SYS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check for at least one server
    const hasServer = hasChildCommand(ntp, 'server');
    if (!hasServer) {
      return {
        passed: false,
        message: 'NTP configured but no servers defined.',
        ruleId: 'JUN-SYS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP is properly configured.',
      ruleId: 'JUN-SYS-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Interface Rules
// ============================================================================

/**
 * JUN-IF-001: Physical interfaces should have descriptions
 */
export const JunosInterfaceDescription: IRule = {
  id: 'JUN-IF-001',
  selector: 'interfaces',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "description" to each physical interface.',
  },
  check: (node: ConfigNode): RuleResult => {
    const issues: string[] = [];

    for (const child of node.children) {
      const ifaceName = child.id;

      // Only check physical interfaces
      if (!isPhysicalJunosPort(ifaceName)) {
        continue;
      }

      // Skip disabled interfaces
      if (isDisabled(child)) {
        continue;
      }

      const hasDesc = hasChildCommand(child, 'description');
      if (!hasDesc) {
        issues.push(`Interface "${ifaceName}" missing description.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'JUN-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All physical interfaces have descriptions.',
      ruleId: 'JUN-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Routing Protocol Rules
// ============================================================================

/**
 * JUN-BGP-001: BGP must have router-id configured in routing-options
 */
export const JunosBgpRouterId: IRule = {
  id: 'JUN-BGP-001',
  selector: 'routing-options',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "router-id" under routing-options stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasRouterId = hasChildCommand(node, 'router-id');
    if (!hasRouterId) {
      return {
        passed: false,
        message: 'Routing-options missing explicit router-id.',
        ruleId: 'JUN-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Router-id is configured.',
      ruleId: 'JUN-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * JUN-BGP-002: BGP must have autonomous-system configured
 */
export const JunosBgpAsNumber: IRule = {
  id: 'JUN-BGP-002',
  selector: 'routing-options',
  vendor: 'juniper-junos',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "autonomous-system" under routing-options stanza.',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Only check if BGP is configured
    const ast = context.getAst?.();
    if (!ast) {
      return { passed: true, message: 'Cannot check without AST context.', ruleId: 'JUN-BGP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Look for protocols { bgp { ... } }
    let hasBgp = false;
    const findBgp = (nodes: ConfigNode[]) => {
      for (const n of nodes) {
        if (equalsIgnoreCase(n.id, 'protocols')) {
          if (hasChildCommand(n, 'bgp')) {
            hasBgp = true;
            return;
          }
        }
        if (n.children.length > 0) {
          findBgp(n.children);
        }
      }
    };
    findBgp(ast);

    if (!hasBgp) {
      return { passed: true, message: 'BGP not configured.', ruleId: 'JUN-BGP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const hasAs = hasChildCommand(node, 'autonomous-system');
    if (!hasAs) {
      return {
        passed: false,
        message: 'BGP configured but autonomous-system not defined in routing-options.',
        ruleId: 'JUN-BGP-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Autonomous-system is configured.',
      ruleId: 'JUN-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * JUN-OSPF-001: OSPF areas should have interfaces assigned
 */
export const JunosOspfAreaInterfaces: IRule = {
  id: 'JUN-OSPF-001',
  selector: 'protocols',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure interfaces under each OSPF area.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ospf = findStanza(node, 'ospf');
    if (!ospf) {
      return { passed: true, message: 'OSPF not configured.', ruleId: 'JUN-OSPF-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const areas = findStanzas(ospf, /^area/i);
    if (areas.length === 0) {
      return {
        passed: false,
        message: 'OSPF configured but no areas defined.',
        ruleId: 'JUN-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const issues: string[] = [];
    for (const area of areas) {
      const hasInterface = hasChildCommand(area, 'interface');
      if (!hasInterface) {
        issues.push(`OSPF area "${area.id}" has no interfaces configured.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'JUN-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All OSPF areas have interfaces configured.',
      ruleId: 'JUN-OSPF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Policy Rules
// ============================================================================

/**
 * JUN-POL-001: Policy statements should have explicit accept/reject actions
 */
export const JunosPolicyAction: IRule = {
  id: 'JUN-POL-001',
  selector: 'policy-options',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Ensure all policy-statement terms have explicit "then accept" or "then reject" actions.',
  },
  check: (node: ConfigNode): RuleResult => {
    const policyStatements = findStanzas(node, /^policy-statement/i);
    if (policyStatements.length === 0) {
      return { passed: true, message: 'No policy statements configured.', ruleId: 'JUN-POL-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const issues: string[] = [];

    for (const policy of policyStatements) {
      const terms = findStanzas(policy, /^term/i);

      // Check if policy has any terms
      if (terms.length === 0) {
        // Policy without terms - check for direct then action
        const thenStanza = findStanza(policy, 'then');
        if (!thenStanza) {
          issues.push(`Policy "${policy.id}" has no terms and no default action.`);
        }
        continue;
      }

      // Check each term for action
      for (const term of terms) {
        const action = getTermAction(term);
        if (!action) {
          issues.push(`Policy "${policy.id}" term "${term.id}" has no explicit action.`);
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'JUN-POL-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All policy statements have explicit actions.',
      ruleId: 'JUN-POL-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Firewall Rules
// ============================================================================

/**
 * JUN-FW-001: Firewall filters should have a default deny term
 */
export const JunosFirewallDefaultDeny: IRule = {
  id: 'JUN-FW-001',
  selector: 'firewall',
  vendor: 'juniper-junos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Add a final term with "then discard" or "then reject" to explicitly deny unmatched traffic.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Find all filters (could be under family inet, family inet6, or directly)
    const findFilters = (n: ConfigNode): ConfigNode[] => {
      const filters: ConfigNode[] = [];
      for (const child of n.children) {
        if (startsWithIgnoreCase(child.id, 'filter')) {
          filters.push(child);
        }
        if (startsWithIgnoreCase(child.id, 'family')) {
          filters.push(...findFilters(child));
        }
      }
      return filters;
    };

    const filters = findFilters(node);
    if (filters.length === 0) {
      return { passed: true, message: 'No firewall filters configured.', ruleId: 'JUN-FW-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const issues: string[] = [];

    for (const filter of filters) {
      const terms = findStanzas(filter, /^term/i);
      if (terms.length === 0) {
        continue;
      }

      // Check if last term is a deny
      const lastTerm = terms[terms.length - 1];
      if (!lastTerm) {
        continue;
      }
      if (!isFilterTermDrop(lastTerm)) {
        issues.push(`Filter "${filter.id}" does not end with a deny term.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'JUN-FW-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'All firewall filters have default deny.',
      ruleId: 'JUN-FW-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// SNMP Rules
// ============================================================================

/**
 * JUN-SNMP-001: SNMP community should not be public/private
 */
export const JunosSnmpNoCommunity: IRule = {
  id: 'JUN-SNMP-001',
  selector: 'snmp',
  vendor: 'juniper-junos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use complex community strings or migrate to SNMPv3.',
  },
  check: (node: ConfigNode): RuleResult => {
    const communities = findStanzas(node, /^community/i);
    if (communities.length === 0) {
      return { passed: true, message: 'No SNMP communities configured.', ruleId: 'JUN-SNMP-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const issues: string[] = [];

    for (const comm of communities) {
      // Extract community name from "community <name>"
      const name = comm.id.split(/\s+/)[1]?.toLowerCase();
      if (name === 'public' || name === 'private') {
        issues.push(`Default SNMP community "${name}" detected.`);
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: issues.join('\n'),
        ruleId: 'JUN-SNMP-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SNMP communities are not default values.',
      ruleId: 'JUN-SNMP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Protocol Security Rules
// ============================================================================

/**
 * JUN-SEC-001: LLDP should be disabled on external interfaces
 */
export const JunosLldpExternal: IRule = {
  id: 'JUN-SEC-001',
  selector: 'protocols',
  vendor: 'juniper-junos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable LLDP on external-facing interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    const lldp = findStanza(node, 'lldp');
    if (!lldp) {
      return { passed: true, message: 'LLDP not configured.', ruleId: 'JUN-SEC-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if "interface all" is configured without any disable statements
    const hasInterfaceAll = lldp.children.some(
      (child) => equalsIgnoreCase(child.id.trim(), 'interface all')
    );

    if (hasInterfaceAll) {
      return {
        passed: true,
        message: 'LLDP enabled on all interfaces. Consider disabling on external-facing interfaces.',
        ruleId: 'JUN-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'LLDP configuration reviewed.',
      ruleId: 'JUN-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all Juniper JunOS rules - proof-of-concept subset
// NOTE: Additional rules available in basic-netsec-pack
// ============================================================================

export const allJuniperRules: IRule[] = [
  // System
  RootAuthRequired,
  // Routing
  JunosBgpRouterId,
  // Firewall
  JunosFirewallDefaultDeny,
];
