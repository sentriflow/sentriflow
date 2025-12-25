// packages/rules-default/src/nokia/sros-rules.ts
// Nokia SR OS specific rules

import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import { startsWithIgnoreCase, includesIgnoreCase } from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  isAdminStateEnabled,
  isAdminStateDisabled,
  isEnabled,
  isPhysicalPort,
  isLagPort,
  isSystemInterface,
  hasDescription,
  getDescription,
  getSystemName,
  hasIpAddress,
  getIpAddress,
  hasBgpRouterId,
  getBgpRouterId,
  hasSap,
  isSnmpEnabled,
  hasNtpServer,
  isSshEnabled,
  isTelnetEnabled,
  hasAuthentication,
  getInterfaceName,
  getRouterName,
  hasPeerDescription,
  getServiceType,
  getServiceId,
  hasCustomer,
} from '@sentriflow/core/helpers/nokia';

// ============================================================================
// System Configuration Rules
// ============================================================================

/**
 * NOKIA-SYS-001: System name must be configured
 */
export const SystemNameRequired: IRule = {
  id: 'NOKIA-SYS-001',
  selector: 'system',
  vendor: 'nokia-sros',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure system name using: system > name "<hostname>"',
  },
  check: (node: ConfigNode): RuleResult => {
    const name = getSystemName(node);
    if (!name || name.length === 0) {
      return {
        passed: false,
        message: 'System name is not configured.',
        ruleId: 'NOKIA-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `System name is configured: ${name}`,
      ruleId: 'NOKIA-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SYS-002: SNMP should be enabled with proper configuration
 */
export const SnmpConfigured: IRule = {
  id: 'NOKIA-SYS-002',
  selector: 'snmp',
  vendor: 'nokia-sros',
  category: 'Protocol-Security',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure SNMP with admin-state enable for network monitoring.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isAdminStateEnabled(node)) {
      return {
        passed: false,
        message: 'SNMP is not enabled. Enable for network monitoring.',
        ruleId: 'NOKIA-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SNMP is enabled.',
      ruleId: 'NOKIA-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SYS-003: NTP should be configured for time synchronization
 */
export const NtpRequired: IRule = {
  id: 'NOKIA-SYS-003',
  selector: 'time',
  vendor: 'nokia-sros',
  category: 'Time-Synchronization',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP server for accurate time synchronization: time > ntp > server <ip-address>',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check for NTP configuration
    const hasNtp = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return rawText === 'ntp' || startsWithIgnoreCase(rawText, 'ntp');
    });

    if (!hasNtp) {
      return {
        passed: false,
        message: 'NTP is not configured. Time synchronization is critical for logging and security.',
        ruleId: 'NOKIA-SYS-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP is configured.',
      ruleId: 'NOKIA-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Port Configuration Rules
// ============================================================================

/**
 * NOKIA-PORT-001: Physical ports should have descriptions
 */
export const PortDescriptionRequired: IRule = {
  id: 'NOKIA-PORT-001',
  selector: 'port',
  vendor: 'nokia-sros',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to port: port X/Y/Z > description "<description>"',
  },
  check: (node: ConfigNode): RuleResult => {
    const portName = node.id.replace(/^port\s+/i, '').trim();

    // Only check physical ports
    if (!isPhysicalPort(portName)) {
      return {
        passed: true,
        message: 'Not a physical port, description optional.',
        ruleId: 'NOKIA-PORT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip disabled ports
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'Port is disabled, description optional.',
        ruleId: 'NOKIA-PORT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `Port ${portName} is enabled but has no description.`,
        ruleId: 'NOKIA-PORT-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Port ${portName} has description: ${getDescription(node)}`,
      ruleId: 'NOKIA-PORT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-PORT-002: Physical ports should have admin-state explicitly configured
 */
export const PortAdminStateRequired: IRule = {
  id: 'NOKIA-PORT-002',
  selector: 'port',
  vendor: 'nokia-sros',
  category: 'Documentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure admin-state for port: port X/Y/Z > admin-state enable',
  },
  check: (node: ConfigNode): RuleResult => {
    const portName = node.id.replace(/^port\s+/i, '').trim();

    // Only check physical ports
    if (!isPhysicalPort(portName)) {
      return {
        passed: true,
        message: 'Not a physical port.',
        ruleId: 'NOKIA-PORT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasAdminState = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return startsWithIgnoreCase(rawText, 'admin-state');
    });

    if (!hasAdminState) {
      return {
        passed: false,
        message: `Port ${portName} does not have explicit admin-state configuration.`,
        ruleId: 'NOKIA-PORT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Port ${portName} has admin-state configured.`,
      ruleId: 'NOKIA-PORT-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Router Interface Rules
// ============================================================================

/**
 * NOKIA-IF-001: Router interfaces should have descriptions
 */
export const InterfaceDescriptionRequired: IRule = {
  id: 'NOKIA-IF-001',
  selector: 'interface',
  vendor: 'nokia-sros',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to interface: interface "<name>" > description "<description>"',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = getInterfaceName(node);

    // Skip system interfaces
    if (isSystemInterface(interfaceName)) {
      return {
        passed: true,
        message: 'System interface, description optional.',
        ruleId: 'NOKIA-IF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip disabled interfaces
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'Interface is disabled, description optional.',
        ruleId: 'NOKIA-IF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `Interface "${interfaceName}" has no description.`,
        ruleId: 'NOKIA-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Interface "${interfaceName}" has description.`,
      ruleId: 'NOKIA-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-IF-002: Router interfaces should have IP addresses configured
 */
export const InterfaceAddressRequired: IRule = {
  id: 'NOKIA-IF-002',
  selector: 'interface',
  vendor: 'nokia-sros',
  category: 'IP-Addressing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure IP address: interface "<name>" > address <ip-prefix>',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = getInterfaceName(node);

    // Skip disabled interfaces
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'Interface is disabled, address configuration optional.',
        ruleId: 'NOKIA-IF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasIpAddress(node)) {
      return {
        passed: false,
        message: `Interface "${interfaceName}" has no IP address configured.`,
        ruleId: 'NOKIA-IF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Interface "${interfaceName}" has IP address: ${getIpAddress(node)}`,
      ruleId: 'NOKIA-IF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// BGP Configuration Rules
// ============================================================================

/**
 * NOKIA-BGP-001: BGP should have router-id configured
 */
export const BgpRouterIdRequired: IRule = {
  id: 'NOKIA-BGP-001',
  selector: 'bgp',
  vendor: 'nokia-sros',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure BGP router-id: bgp > router-id <ip-address>',
  },
  check: (node: ConfigNode): RuleResult => {
    // Skip if BGP is disabled
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'BGP is disabled.',
        ruleId: 'NOKIA-BGP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasBgpRouterId(node)) {
      return {
        passed: false,
        message: 'BGP router-id is not configured. Configure a stable router-id.',
        ruleId: 'NOKIA-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `BGP router-id is configured: ${getBgpRouterId(node)}`,
      ruleId: 'NOKIA-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-BGP-002: BGP should be explicitly enabled
 */
export const BgpAdminStateRequired: IRule = {
  id: 'NOKIA-BGP-002',
  selector: 'bgp',
  vendor: 'nokia-sros',
  category: 'Routing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable BGP: bgp > admin-state enable',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isAdminStateEnabled(node)) {
      return {
        passed: false,
        message: 'BGP admin-state is not enabled.',
        ruleId: 'NOKIA-BGP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP is enabled.',
      ruleId: 'NOKIA-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-BGP-003: BGP groups should have descriptions
 */
export const BgpGroupDescriptionRequired: IRule = {
  id: 'NOKIA-BGP-003',
  selector: 'group',
  vendor: 'nokia-sros',
  category: 'Routing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to BGP group: group "<name>" > description "<description>"',
  },
  check: (node: ConfigNode): RuleResult => {
    // Only check BGP groups (contains "group")
    if (!includesIgnoreCase(node.id, 'group')) {
      return {
        passed: true,
        message: 'Not a BGP group.',
        ruleId: 'NOKIA-BGP-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      const groupName = node.id.replace(/^group\s+/i, '').trim();
      return {
        passed: false,
        message: `BGP group ${groupName} has no description.`,
        ruleId: 'NOKIA-BGP-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP group has description.',
      ruleId: 'NOKIA-BGP-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-BGP-004: BGP peers should have authentication configured
 */
export const BgpPeerAuthenticationRecommended: IRule = {
  id: 'NOKIA-BGP-004',
  selector: 'neighbor',
  vendor: 'nokia-sros',
  category: 'Authentication',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure BGP authentication: neighbor <ip> > auth-keychain "<name>" or > authentication-key <key>',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check for authentication
    if (!hasAuthentication(node)) {
      const neighborIp = node.id.replace(/^neighbor\s+/i, '').trim();
      return {
        passed: true, // Just informational
        message: `BGP neighbor ${neighborIp} does not have authentication configured. Consider enabling authentication.`,
        ruleId: 'NOKIA-BGP-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP neighbor has authentication configured.',
      ruleId: 'NOKIA-BGP-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// OSPF Configuration Rules
// ============================================================================

/**
 * NOKIA-OSPF-001: OSPF should be explicitly enabled
 */
export const OspfAdminStateRequired: IRule = {
  id: 'NOKIA-OSPF-001',
  selector: 'ospf',
  vendor: 'nokia-sros',
  category: 'Routing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable OSPF: ospf > admin-state enable',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isAdminStateEnabled(node)) {
      return {
        passed: false,
        message: 'OSPF admin-state is not enabled.',
        ruleId: 'NOKIA-OSPF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF is enabled.',
      ruleId: 'NOKIA-OSPF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-OSPF-002: OSPF areas should have at least one interface
 */
export const OspfAreaInterfaceRequired: IRule = {
  id: 'NOKIA-OSPF-002',
  selector: 'area',
  vendor: 'nokia-sros',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add interface to OSPF area: area X.X.X.X > interface "<name>"',
  },
  check: (node: ConfigNode): RuleResult => {
    const areaId = node.id.replace(/^area\s+/i, '').trim();

    const hasInterface = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return startsWithIgnoreCase(rawText, 'interface');
    });

    if (!hasInterface) {
      return {
        passed: false,
        message: `OSPF area ${areaId} has no interfaces configured.`,
        ruleId: 'NOKIA-OSPF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `OSPF area ${areaId} has interfaces configured.`,
      ruleId: 'NOKIA-OSPF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Service Configuration Rules
// ============================================================================

/**
 * NOKIA-SVC-001: Services should have customer ID configured
 */
export const ServiceCustomerRequired: IRule = {
  id: 'NOKIA-SVC-001',
  selector: 'vpls',
  vendor: 'nokia-sros',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Assign customer to service: vpls <id> > customer <customer-id>',
  },
  check: (node: ConfigNode): RuleResult => {
    const serviceId = getServiceId(node);

    if (!hasCustomer(node)) {
      return {
        passed: false,
        message: `VPLS ${serviceId} does not have a customer assigned.`,
        ruleId: 'NOKIA-SVC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VPLS ${serviceId} has customer assigned.`,
      ruleId: 'NOKIA-SVC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SVC-002: VPRN services should have customer ID configured
 */
export const VprnCustomerRequired: IRule = {
  id: 'NOKIA-SVC-002',
  selector: 'vprn',
  vendor: 'nokia-sros',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Assign customer to service: vprn <id> > customer <customer-id>',
  },
  check: (node: ConfigNode): RuleResult => {
    const serviceId = getServiceId(node);

    if (!hasCustomer(node)) {
      return {
        passed: false,
        message: `VPRN ${serviceId} does not have a customer assigned.`,
        ruleId: 'NOKIA-SVC-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VPRN ${serviceId} has customer assigned.`,
      ruleId: 'NOKIA-SVC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SVC-003: Services should have admin-state enabled
 */
export const ServiceAdminStateRequired: IRule = {
  id: 'NOKIA-SVC-003',
  selector: 'vpls',
  vendor: 'nokia-sros',
  category: 'Network-Segmentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable service: <service-type> <id> > admin-state enable',
  },
  check: (node: ConfigNode): RuleResult => {
    const serviceId = getServiceId(node);
    const serviceType = getServiceType(node);

    if (!isAdminStateEnabled(node)) {
      return {
        passed: false,
        message: `${serviceType?.toUpperCase() || 'Service'} ${serviceId} is not enabled.`,
        ruleId: 'NOKIA-SVC-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `${serviceType?.toUpperCase() || 'Service'} ${serviceId} is enabled.`,
      ruleId: 'NOKIA-SVC-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SVC-004: Services should have at least one SAP configured
 */
export const ServiceSapRequired: IRule = {
  id: 'NOKIA-SVC-004',
  selector: 'vpls',
  vendor: 'nokia-sros',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add SAP to service: vpls <id> > sap <port>:<vlan>',
  },
  check: (node: ConfigNode): RuleResult => {
    const serviceId = getServiceId(node);

    // Skip disabled services
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'Service is disabled.',
        ruleId: 'NOKIA-SVC-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasSap(node)) {
      return {
        passed: false,
        message: `VPLS ${serviceId} has no SAPs configured.`,
        ruleId: 'NOKIA-SVC-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VPLS ${serviceId} has SAPs configured.`,
      ruleId: 'NOKIA-SVC-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Security Configuration Rules
// ============================================================================

/**
 * NOKIA-SEC-001: SSH should be enabled for secure management
 */
export const SshEnabled: IRule = {
  id: 'NOKIA-SEC-001',
  selector: 'security',
  vendor: 'nokia-sros',
  category: 'Session-Management',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH for secure management access.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isSshEnabled(node)) {
      return {
        passed: false,
        message: 'SSH does not appear to be enabled. Enable SSH for secure management.',
        ruleId: 'NOKIA-SEC-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SSH is enabled.',
      ruleId: 'NOKIA-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-SEC-002: Telnet should be disabled
 */
export const TelnetDisabled: IRule = {
  id: 'NOKIA-SEC-002',
  selector: 'security',
  vendor: 'nokia-sros',
  category: 'Service-Hardening',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable Telnet for security. Use SSH instead.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (isTelnetEnabled(node)) {
      return {
        passed: false,
        message: 'Telnet appears to be enabled. Disable Telnet and use SSH for security.',
        ruleId: 'NOKIA-SEC-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Telnet is not enabled.',
      ruleId: 'NOKIA-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// LAG Configuration Rules
// ============================================================================

/**
 * NOKIA-LAG-001: LAGs should have descriptions
 */
export const LagDescriptionRequired: IRule = {
  id: 'NOKIA-LAG-001',
  selector: 'lag',
  vendor: 'nokia-sros',
  category: 'Link-Aggregation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to LAG: lag <id> > description "<description>"',
  },
  check: (node: ConfigNode): RuleResult => {
    const lagId = node.id.replace(/^lag\s+/i, '').trim();

    // Skip disabled LAGs
    if (isAdminStateDisabled(node)) {
      return {
        passed: true,
        message: 'LAG is disabled, description optional.',
        ruleId: 'NOKIA-LAG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `LAG ${lagId} has no description.`,
        ruleId: 'NOKIA-LAG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `LAG ${lagId} has description.`,
      ruleId: 'NOKIA-LAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * NOKIA-LAG-002: LAGs should have admin-state enabled
 */
export const LagAdminStateRequired: IRule = {
  id: 'NOKIA-LAG-002',
  selector: 'lag',
  vendor: 'nokia-sros',
  category: 'Link-Aggregation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable LAG: lag <id> > admin-state enable',
  },
  check: (node: ConfigNode): RuleResult => {
    const lagId = node.id.replace(/^lag\s+/i, '').trim();

    if (!isAdminStateEnabled(node)) {
      return {
        passed: false,
        message: `LAG ${lagId} is not enabled.`,
        ruleId: 'NOKIA-LAG-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `LAG ${lagId} is enabled.`,
      ruleId: 'NOKIA-LAG-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Logging Configuration Rules
// ============================================================================

/**
 * NOKIA-LOG-001: Log destinations should be configured
 */
export const LogConfigured: IRule = {
  id: 'NOKIA-LOG-001',
  selector: 'log',
  vendor: 'nokia-sros',
  category: 'Logging',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure logging destinations: log > log-id <id>, syslog <id>, or snmp-trap-group <id>',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasLogDestination = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return (
        startsWithIgnoreCase(rawText, 'log-id') ||
        startsWithIgnoreCase(rawText, 'syslog') ||
        startsWithIgnoreCase(rawText, 'snmp-trap-group') ||
        startsWithIgnoreCase(rawText, 'file-id')
      );
    });

    if (!hasLogDestination) {
      return {
        passed: false,
        message: 'No logging destinations configured. Configure logging for security and troubleshooting.',
        ruleId: 'NOKIA-LOG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Logging destinations are configured.',
      ruleId: 'NOKIA-LOG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allNokiaRules: IRule[] = [
  // System
  SystemNameRequired,
  // Ports
  PortDescriptionRequired,
  // BGP
  BgpRouterIdRequired,
];
