// packages/rules-default/src/huawei/vrp-rules.ts
// Huawei VRP specific rules

import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import {
  equalsIgnoreCase,
  includesIgnoreCase,
  startsWithIgnoreCase,
} from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  isEnabled,
  isPhysicalPort,
  isTrunkPort,
  isAccessPort,
  hasDescription,
  hasStpEdgedPort,
  hasPortSecurity,
  isSshEnabled,
  isTelnetEnabled,
  hasAaaAuthentication,
  hasPasswordAuthentication,
  hasIdleTimeout,
  getIdleTimeout,
  hasAclInbound,
  hasEncryptedPassword,
  hasPlaintextPassword,
  getPrivilegeLevel,
  getTrunkAllowedVlans,
  isVlanInterface,
  isLoopbackInterface,
} from '@sentriflow/core/helpers/huawei';

// ============================================================================
// System Security Rules
// ============================================================================

/**
 * HUAWEI-SYS-001: System name must be configured
 */
export const SysnameRequired: IRule = {
  id: 'HUAWEI-SYS-001',
  selector: 'sysname',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure system name using "sysname <hostname>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    // If we found a sysname node, it's configured
    const name = node.rawText.replace(/^sysname\s+/i, '').trim();
    if (!name || name.length === 0) {
      return {
        passed: false,
        message: 'System name is empty.',
        ruleId: 'HUAWEI-SYS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `System name is configured: ${name}`,
      ruleId: 'HUAWEI-SYS-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-SYS-002: NTP must be configured
 */
export const NtpRequired: IRule = {
  id: 'HUAWEI-SYS-002',
  selector: 'ntp-service',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP using "ntp-service unicast-server <ip-address>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasNtpServer = node.children.some((child) => {
      return includesIgnoreCase(child.rawText, 'unicast-server');
    });

    if (!hasNtpServer) {
      return {
        passed: false,
        message: 'NTP server is not configured. Time synchronization is critical for logging.',
        ruleId: 'HUAWEI-SYS-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'NTP server is configured.',
      ruleId: 'HUAWEI-SYS-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-SYS-003: SNMP community strings should not use defaults
 */
export const SnmpCommunityNotDefault: IRule = {
  id: 'HUAWEI-SYS-003',
  selector: 'snmp-agent',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Change SNMP community strings from default values like "public" or "private".',
  },
  check: (node: ConfigNode): RuleResult => {
    const defaultCommunities = ['public', 'private', 'community'];
    const communityCommands = node.children.filter((child) =>
      includesIgnoreCase(child.rawText, 'community')
    );

    for (const cmd of communityCommands) {
      const rawText = cmd.rawText;
      for (const defaultComm of defaultCommunities) {
        if (includesIgnoreCase(rawText, defaultComm)) {
          return {
            passed: false,
            message: `SNMP using default community string "${defaultComm}". Use a strong, unique community string.`,
            ruleId: 'HUAWEI-SYS-003',
            nodeId: node.id,
            level: 'error',
            loc: cmd.loc,
          };
        }
      }
    }

    return {
      passed: true,
      message: 'SNMP community strings are not using default values.',
      ruleId: 'HUAWEI-SYS-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-SYS-004: SNMPv3 should be preferred over v1/v2c
 */
export const SnmpV3Recommended: IRule = {
  id: 'HUAWEI-SYS-004',
  selector: 'snmp-agent',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use SNMPv3 with authentication and encryption instead of v1/v2c.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check for v3 configuration
    const hasV3 = node.children.some((child) => {
      const rawText = child.rawText;
      return includesIgnoreCase(rawText, 'usm-user') || includesIgnoreCase(rawText, 'version v3');
    });

    // Check for v1/v2c community strings
    const hasV1V2c = node.children.some((child) => {
      const rawText = child.rawText;
      return includesIgnoreCase(rawText, 'community');
    });

    if (hasV1V2c && !hasV3) {
      return {
        passed: false,
        message: 'SNMP v1/v2c is configured without v3. Consider using SNMPv3 for security.',
        ruleId: 'HUAWEI-SYS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'SNMP configuration is acceptable.',
      ruleId: 'HUAWEI-SYS-004',
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
 * HUAWEI-IF-001: Physical interfaces must have descriptions
 */
export const InterfaceDescriptionRequired: IRule = {
  id: 'HUAWEI-IF-001',
  selector: 'interface',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a description to the interface using "description <text>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = node.id.replace(/^interface\s+/i, '').trim();

    // Skip non-physical interfaces
    if (!isPhysicalPort(interfaceName)) {
      return {
        passed: true,
        message: 'Non-physical interface, description optional.',
        ruleId: 'HUAWEI-IF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip shutdown interfaces
    if (!isEnabled(node)) {
      return {
        passed: true,
        message: 'Interface is shutdown, description optional.',
        ruleId: 'HUAWEI-IF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `Interface ${interfaceName} is enabled but has no description.`,
        ruleId: 'HUAWEI-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Interface has a description.',
      ruleId: 'HUAWEI-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-IF-002: Access ports should have STP edge-port enabled
 */
export const AccessPortStpEdgeRequired: IRule = {
  id: 'HUAWEI-IF-002',
  selector: 'interface',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable STP edge-port on access ports using "stp edged-port enable".',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = node.id.replace(/^interface\s+/i, '').trim();

    // Only check physical access ports
    if (!isPhysicalPort(interfaceName) || !isAccessPort(node) || !isEnabled(node)) {
      return {
        passed: true,
        message: 'Not an active access port.',
        ruleId: 'HUAWEI-IF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasStpEdgedPort(node)) {
      return {
        passed: false,
        message: `Access port ${interfaceName} should have "stp edged-port enable" for faster convergence.`,
        ruleId: 'HUAWEI-IF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'STP edge-port is enabled on access port.',
      ruleId: 'HUAWEI-IF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-IF-003: Trunk ports should not allow all VLANs
 */
export const TrunkVlanRestriction: IRule = {
  id: 'HUAWEI-IF-003',
  selector: 'interface',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Restrict allowed VLANs on trunk ports to only required VLANs.',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = node.id.replace(/^interface\s+/i, '').trim();

    // Only check trunk ports
    if (!isTrunkPort(node) || !isEnabled(node)) {
      return {
        passed: true,
        message: 'Not an active trunk port.',
        ruleId: 'HUAWEI-IF-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const allowedVlans = getTrunkAllowedVlans(node);
    if (allowedVlans && (equalsIgnoreCase(allowedVlans, 'all') || allowedVlans.includes('1 to 4094'))) {
      return {
        passed: false,
        message: `Trunk port ${interfaceName} allows all VLANs. Restrict to only required VLANs.`,
        ruleId: 'HUAWEI-IF-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Trunk port has VLAN restrictions.',
      ruleId: 'HUAWEI-IF-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-IF-004: User-facing ports should have port security enabled
 */
export const PortSecurityRequired: IRule = {
  id: 'HUAWEI-IF-004',
  selector: 'interface',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable port security on user-facing ports using "port-security enable".',
  },
  check: (node: ConfigNode): RuleResult => {
    const interfaceName = node.id.replace(/^interface\s+/i, '').trim();

    // Only check physical access ports that are enabled
    if (!isPhysicalPort(interfaceName) || !isAccessPort(node) || !isEnabled(node)) {
      return {
        passed: true,
        message: 'Not an active access port.',
        ruleId: 'HUAWEI-IF-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasPortSecurity(node)) {
      return {
        passed: false,
        message: `Access port ${interfaceName} does not have port security enabled.`,
        ruleId: 'HUAWEI-IF-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Port security is enabled.',
      ruleId: 'HUAWEI-IF-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// User Interface / Management Rules
// ============================================================================

/**
 * HUAWEI-VTY-001: VTY lines should use AAA authentication
 */
export const VtyAaaRequired: IRule = {
  id: 'HUAWEI-VTY-001',
  selector: 'user-interface vty',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure AAA authentication on VTY lines using "authentication-mode aaa".',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasAaaAuthentication(node)) {
      if (hasPasswordAuthentication(node)) {
        return {
          passed: false,
          message: 'VTY using password authentication. Use AAA authentication instead.',
          ruleId: 'HUAWEI-VTY-001',
          nodeId: node.id,
          level: 'error',
          loc: node.loc,
        };
      }
      return {
        passed: false,
        message: 'VTY lines do not have AAA authentication configured.',
        ruleId: 'HUAWEI-VTY-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VTY lines have AAA authentication configured.',
      ruleId: 'HUAWEI-VTY-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-VTY-002: VTY lines should use SSH instead of Telnet
 */
export const VtySshRequired: IRule = {
  id: 'HUAWEI-VTY-002',
  selector: 'user-interface vty',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure SSH-only access on VTY lines using "protocol inbound ssh".',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check for explicit SSH configuration
    const hasSsh = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return equalsIgnoreCase(rawText, 'protocol inbound ssh');
    });

    // Check for Telnet (either explicit or protocol inbound all)
    const hasTelnet = node.children.some((child) => {
      const rawText = child.rawText.trim();
      return includesIgnoreCase(rawText, 'protocol inbound telnet') || equalsIgnoreCase(rawText, 'protocol inbound all');
    });

    if (hasTelnet) {
      return {
        passed: false,
        message: 'Telnet is allowed on VTY lines. Use SSH only for secure management.',
        ruleId: 'HUAWEI-VTY-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (!hasSsh) {
      return {
        passed: false,
        message: 'VTY lines do not have explicit SSH protocol configured.',
        ruleId: 'HUAWEI-VTY-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VTY lines are configured for SSH-only access.',
      ruleId: 'HUAWEI-VTY-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-VTY-003: VTY lines should have idle timeout configured
 */
export const VtyIdleTimeoutRequired: IRule = {
  id: 'HUAWEI-VTY-003',
  selector: 'user-interface',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure idle timeout on user-interface using "idle-timeout <minutes> <seconds>".',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasIdleTimeout(node)) {
      return {
        passed: false,
        message: 'User-interface does not have idle timeout configured.',
        ruleId: 'HUAWEI-VTY-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const timeout = getIdleTimeout(node);
    if (timeout && timeout > 30) {
      return {
        passed: false,
        message: `Idle timeout is ${timeout} minutes. Consider reducing to 30 minutes or less.`,
        ruleId: 'HUAWEI-VTY-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Idle timeout is configured.',
      ruleId: 'HUAWEI-VTY-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-VTY-004: VTY lines should have ACL applied
 */
export const VtyAclRequired: IRule = {
  id: 'HUAWEI-VTY-004',
  selector: 'user-interface vty',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Apply ACL to VTY lines using "acl <number> inbound" to restrict management access.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasAclInbound(node)) {
      return {
        passed: false,
        message: 'VTY lines do not have an ACL applied to restrict access.',
        ruleId: 'HUAWEI-VTY-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VTY lines have ACL applied.',
      ruleId: 'HUAWEI-VTY-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// AAA / Local User Rules
// ============================================================================

/**
 * HUAWEI-AAA-001: Local users should use encrypted passwords
 */
export const LocalUserEncryptedPassword: IRule = {
  id: 'HUAWEI-AAA-001',
  selector: 'local-user',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use encrypted passwords with "password irreversible-cipher" or "password cipher".',
  },
  check: (node: ConfigNode): RuleResult => {
    if (hasPlaintextPassword(node)) {
      return {
        passed: false,
        message: 'Local user has plaintext password. Use encrypted password (cipher or irreversible-cipher).',
        ruleId: 'HUAWEI-AAA-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (!hasEncryptedPassword(node)) {
      return {
        passed: false,
        message: 'Local user does not have a password configured.',
        ruleId: 'HUAWEI-AAA-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Local user has encrypted password.',
      ruleId: 'HUAWEI-AAA-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-AAA-002: High privilege users should be minimized
 */
export const HighPrivilegeUserWarning: IRule = {
  id: 'HUAWEI-AAA-002',
  selector: 'local-user',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Limit privilege level 15 users. Use lower privilege levels where possible.',
  },
  check: (node: ConfigNode): RuleResult => {
    const privLevel = getPrivilegeLevel(node);

    if (privLevel === 15) {
      const userName = node.id.replace(/^local-user\s+/i, '').trim();
      return {
        passed: true, // Just informational
        message: `User "${userName}" has privilege level 15 (full access). Ensure this is intended.`,
        ruleId: 'HUAWEI-AAA-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'User privilege level is acceptable.',
      ruleId: 'HUAWEI-AAA-002',
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
 * HUAWEI-BGP-001: BGP should have router-id configured
 */
export const BgpRouterIdRequired: IRule = {
  id: 'HUAWEI-BGP-001',
  selector: 'bgp',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure BGP router-id using "router-id <ip-address>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasRouterId = hasChildCommand(node, 'router-id');

    if (!hasRouterId) {
      return {
        passed: false,
        message: 'BGP does not have explicit router-id configured. Configure a stable router-id.',
        ruleId: 'HUAWEI-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP router-id is configured.',
      ruleId: 'HUAWEI-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-BGP-002: BGP peers should have description
 */
export const BgpPeerDescriptionRequired: IRule = {
  id: 'HUAWEI-BGP-002',
  selector: 'bgp',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to BGP peers using "peer <ip> description <text>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Find peer commands without descriptions
    const peers = node.children.filter((child) =>
      startsWithIgnoreCase(child.rawText.trim(), 'peer') &&
      includesIgnoreCase(child.rawText, 'as-number')
    );

    for (const peer of peers) {
      // Check if there's a corresponding description command
      const peerIp = peer.rawText.match(/peer\s+([\d.]+)/)?.[1];
      if (peerIp) {
        const hasDesc = node.children.some((child) =>
          includesIgnoreCase(child.rawText, `peer ${peerIp}`) &&
          includesIgnoreCase(child.rawText, 'description')
        );

        if (!hasDesc) {
          return {
            passed: false,
            message: `BGP peer ${peerIp} does not have a description.`,
            ruleId: 'HUAWEI-BGP-002',
            nodeId: node.id,
            level: 'info',
            loc: peer.loc,
          };
        }
      }
    }

    return {
      passed: true,
      message: 'BGP peers have descriptions.',
      ruleId: 'HUAWEI-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-OSPF-001: OSPF should have router-id configured
 */
export const OspfRouterIdRequired: IRule = {
  id: 'HUAWEI-OSPF-001',
  selector: 'ospf',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure OSPF router-id in the process definition: "ospf <process-id> router-id <ip>".',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check if router-id is in the ospf command line itself
    const hasRouterId = node.rawText.toLowerCase().includes('router-id');

    if (!hasRouterId) {
      return {
        passed: false,
        message: 'OSPF does not have explicit router-id configured. Configure a stable router-id.',
        ruleId: 'HUAWEI-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF router-id is configured.',
      ruleId: 'HUAWEI-OSPF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-OSPF-002: OSPF authentication should be enabled on area
 */
export const OspfAuthenticationRecommended: IRule = {
  id: 'HUAWEI-OSPF-002',
  selector: 'area',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable OSPF authentication on area using "authentication-mode md5" or on interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    // Check if area has authentication configured
    const hasAuth = node.children.some((child) =>
      includesIgnoreCase(child.rawText, 'authentication-mode')
    );

    if (!hasAuth) {
      const areaId = node.id.replace(/^area\s+/i, '').trim();
      return {
        passed: true, // Informational
        message: `OSPF area ${areaId} does not have authentication configured.`,
        ruleId: 'HUAWEI-OSPF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF area has authentication configured.',
      ruleId: 'HUAWEI-OSPF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Logging and Monitoring Rules
// ============================================================================

/**
 * HUAWEI-LOG-001: Info-center (logging) should be enabled
 */
export const InfoCenterEnabled: IRule = {
  id: 'HUAWEI-LOG-001',
  selector: 'info-center enable',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable info-center using "info-center enable" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    // If we found this node, info-center is enabled
    return {
      passed: true,
      message: 'Info-center (logging) is enabled.',
      ruleId: 'HUAWEI-LOG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-LOG-002: Remote syslog server should be configured
 */
export const SyslogServerRequired: IRule = {
  id: 'HUAWEI-LOG-002',
  selector: 'info-center loghost',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure remote syslog server using "info-center loghost <ip-address>" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    // If we found this node, syslog is configured
    const loghost = node.rawText.replace(/^info-center\s+loghost\s+/i, '').trim();
    return {
      passed: true,
      message: `Remote syslog server configured: ${loghost}`,
      ruleId: 'HUAWEI-LOG-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// SSH Server Rules
// ============================================================================

/**
 * HUAWEI-SSH-001: SSH server should be enabled
 */
export const SshServerEnabled: IRule = {
  id: 'HUAWEI-SSH-001',
  selector: 'ssh server enable',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH server using "ssh server enable" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    return {
      passed: true,
      message: 'SSH server is enabled.',
      ruleId: 'HUAWEI-SSH-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * HUAWEI-SSH-002: Telnet should be disabled
 */
export const TelnetDisabled: IRule = {
  id: 'HUAWEI-SSH-002',
  selector: 'undo telnet server enable',
  vendor: 'huawei-vrp',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Disable Telnet server using "undo telnet server enable" command.',
  },
  check: (node: ConfigNode): RuleResult => {
    return {
      passed: true,
      message: 'Telnet server is disabled (good security practice).',
      ruleId: 'HUAWEI-SSH-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all rules - proof-of-concept subset
// NOTE: Additional rules available in basic-netsec-pack
// ============================================================================

export const allHuaweiRules: IRule[] = [
  // System
  SysnameRequired,
  // Interface
  InterfaceDescriptionRequired,
  // VTY / User Interface
  VtySshRequired,
];
