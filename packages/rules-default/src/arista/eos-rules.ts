// packages/rules-default/src/arista/eos-rules.ts
// Arista EOS specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  equalsIgnoreCase,
  startsWithIgnoreCase,
  includesIgnoreCase,
  parseInteger,
} from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  hasMlagConfiguration,
  getMlagConfiguration,
  checkMlagRequirements,
  hasManagementApi,
  getManagementApiNodes,
  hasHttpsTransport,
  isVxlanInterface,
  hasVxlanSourceInterface,
  getVxlanVniMappings,
  isPortChannel,
  getMlagId,
  hasVirtualRouterAddress,
  hasIpAddress,
  isShutdown,
  getInterfaceDescription,
  hasNtpServer,
  hasLoggingHost,
  hasAaa,
  hasSpanningTree,
  getSpanningTreeMode,
  isLoopback,
  isSvi,
  getInterfaceVrf,
  hasEvpnAddressFamily,
} from '@sentriflow/core/helpers/arista';

// ============================================================================
// System Configuration Rules
// ============================================================================

/**
 * ARI-SYS-001: Hostname must be configured
 */
export const HostnameRequired: IRule = {
  id: 'ARI-SYS-001',
  selector: 'hostname',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure hostname using: hostname <device-name>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // If hostname command exists, it passes
    if (startsWithIgnoreCase(node.id, 'hostname ')) {
      const hostname = node.id.replace(/^hostname\s+/i, '').trim();
      if (hostname.length > 0) {
        return {
          passed: true,
          message: `Hostname is configured: ${hostname}`,
          ruleId: 'ARI-SYS-001',
          nodeId: node.id,
          level: 'info',
          loc: node.loc,
        };
      }
    }

    return {
      passed: false,
      message: 'Hostname is not properly configured.',
      ruleId: 'ARI-SYS-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * ARI-SYS-002: NTP must be configured for time synchronization
 */
export const NtpRequired: IRule = {
  id: 'ARI-SYS-002',
  selector: 'ntp',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure NTP server: ntp server <ip-address>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (startsWithIgnoreCase(node.id, 'ntp server ')) {
      return {
        passed: true,
        message: 'NTP server is configured.',
        ruleId: 'ARI-SYS-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'NTP server is not configured. Time synchronization is critical for logging and certificates.',
      ruleId: 'ARI-SYS-002',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * ARI-SYS-003: Logging server should be configured
 */
export const LoggingRequired: IRule = {
  id: 'ARI-SYS-003',
  selector: 'logging',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure logging host: logging host <ip-address>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (startsWithIgnoreCase(node.id, 'logging host ')) {
      return {
        passed: true,
        message: 'Logging host is configured.',
        ruleId: 'ARI-SYS-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'Remote logging host is not configured. Centralized logging is recommended.',
      ruleId: 'ARI-SYS-003',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * ARI-SYS-004: Login banner should be configured
 */
export const BannerRequired: IRule = {
  id: 'ARI-SYS-004',
  selector: 'banner',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure login banner: banner login / banner motd',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (/^banner\s+(login|motd)/i.test(node.id)) {
      return {
        passed: true,
        message: 'Banner is configured.',
        ruleId: 'ARI-SYS-004',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'Login/MOTD banner is not configured. Consider adding a legal warning banner.',
      ruleId: 'ARI-SYS-004',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// MLAG Rules
// ============================================================================

/**
 * ARI-MLAG-001: MLAG configuration completeness
 */
export const MlagConfigComplete: IRule = {
  id: 'ARI-MLAG-001',
  selector: 'mlag configuration',
  vendor: 'arista-eos',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'MLAG configuration requires: domain-id, peer-link, peer-address, and local-interface.',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const requirements = checkMlagRequirements(node);
    const issues: string[] = [];

    if (!requirements.hasDomainId) {
      issues.push('domain-id');
    }
    if (!requirements.hasPeerLink) {
      issues.push('peer-link');
    }
    if (!requirements.hasPeerAddress) {
      issues.push('peer-address');
    }
    if (!requirements.hasLocalInterface) {
      issues.push('local-interface');
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: `MLAG configuration is incomplete. Missing: ${issues.join(', ')}`,
        ruleId: 'ARI-MLAG-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'MLAG configuration is complete.',
      ruleId: 'ARI-MLAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARI-MLAG-002: Port-Channel with MLAG should have description
 */
export const MlagPortChannelDescription: IRule = {
  id: 'ARI-MLAG-002',
  selector: 'interface Port-Channel',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to Port-Channel interfaces with MLAG.',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Check if this Port-Channel has MLAG configured
    const mlagId = getMlagId(node);
    if (!mlagId) {
      // Not an MLAG Port-Channel, skip
      return {
        passed: true,
        message: 'Not an MLAG Port-Channel.',
        ruleId: 'ARI-MLAG-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const description = getInterfaceDescription(node);
    if (!description) {
      return {
        passed: false,
        message: `MLAG Port-Channel (mlag ${mlagId}) is missing description.`,
        ruleId: 'ARI-MLAG-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `MLAG Port-Channel has description: ${description}`,
      ruleId: 'ARI-MLAG-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VXLAN Rules
// ============================================================================

/**
 * ARI-VXLAN-001: VXLAN interface should have source-interface configured
 */
export const VxlanSourceInterface: IRule = {
  id: 'ARI-VXLAN-001',
  selector: 'interface Vxlan',
  vendor: 'arista-eos',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure VXLAN source-interface: vxlan source-interface Loopback<N>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVxlanInterface(node)) {
      return {
        passed: true,
        message: 'Not a VXLAN interface.',
        ruleId: 'ARI-VXLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasVxlanSourceInterface(node)) {
      return {
        passed: false,
        message: 'VXLAN interface missing source-interface configuration. This is required for VTEP operation.',
        ruleId: 'ARI-VXLAN-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VXLAN source-interface is configured.',
      ruleId: 'ARI-VXLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARI-VXLAN-002: VXLAN interface should have VNI mappings
 */
export const VxlanVniMappings: IRule = {
  id: 'ARI-VXLAN-002',
  selector: 'interface Vxlan',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure VNI to VLAN mappings: vxlan vni <vni> vlan <vlan>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!isVxlanInterface(node)) {
      return {
        passed: true,
        message: 'Not a VXLAN interface.',
        ruleId: 'ARI-VXLAN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const mappings = getVxlanVniMappings(node);
    if (mappings.length === 0) {
      return {
        passed: false,
        message: 'VXLAN interface has no VNI mappings configured.',
        ruleId: 'ARI-VXLAN-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VXLAN has ${mappings.length} VNI mapping(s) configured.`,
      ruleId: 'ARI-VXLAN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Management API Rules
// ============================================================================

/**
 * ARI-API-001: Management API should use HTTPS
 */
export const ManagementApiHttps: IRule = {
  id: 'ARI-API-001',
  selector: 'management api',
  vendor: 'arista-eos',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable HTTPS for management API: protocol https',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Only check http-commands API
    if (!includesIgnoreCase(node.id, 'http-commands')) {
      return {
        passed: true,
        message: 'Not HTTP API configuration.',
        ruleId: 'ARI-API-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if HTTP (insecure) protocol is enabled without HTTPS
    const hasHttp = node.children.some((child) =>
      /protocol\s+http(?!s)/i.test(child.id)
    );
    const hasHttps = hasHttpsTransport(node);

    if (hasHttp && !hasHttps) {
      return {
        passed: false,
        message: 'Management API is using HTTP without HTTPS. Enable HTTPS for secure management.',
        ruleId: 'ARI-API-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (!hasHttp && !hasHttps) {
      return {
        passed: false,
        message: 'Management API has no transport protocol configured.',
        ruleId: 'ARI-API-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Management API is using HTTPS.',
      ruleId: 'ARI-API-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARI-API-002: Management API should not be disabled
 */
export const ManagementApiEnabled: IRule = {
  id: 'ARI-API-002',
  selector: 'management api',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable management API with: no shutdown',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (!includesIgnoreCase(node.id, 'http-commands')) {
      return {
        passed: true,
        message: 'Not HTTP API configuration.',
        ruleId: 'ARI-API-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const isApiShutdown = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'shutdown')
    );
    const hasNoShutdown = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'no shutdown')
    );

    if (isApiShutdown && !hasNoShutdown) {
      return {
        passed: false,
        message: 'Management API (eAPI) is shutdown. Enable if automation is needed.',
        ruleId: 'ARI-API-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Management API is enabled.',
      ruleId: 'ARI-API-002',
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
 * ARI-INT-001: Physical interfaces should have descriptions
 */
export const InterfaceDescription: IRule = {
  id: 'ARI-INT-001',
  selector: 'interface Ethernet',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to interface: description <text>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Skip shutdown interfaces
    if (isShutdown(node)) {
      return {
        passed: true,
        message: 'Interface is shutdown, description not required.',
        ruleId: 'ARI-INT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const description = getInterfaceDescription(node);
    if (!description) {
      return {
        passed: false,
        message: 'Active interface is missing description.',
        ruleId: 'ARI-INT-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Interface has description: ${description}`,
      ruleId: 'ARI-INT-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARI-INT-002: L3 interfaces should have IP address
 */
export const L3InterfaceIpAddress: IRule = {
  id: 'ARI-INT-002',
  selector: 'interface',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure IP address on L3 interface: ip address <ip>/<mask>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Only check Loopback and SVI interfaces (always L3)
    if (!isLoopback(node) && !isSvi(node)) {
      return {
        passed: true,
        message: 'Not an SVI or Loopback interface.',
        ruleId: 'ARI-INT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip shutdown interfaces
    if (isShutdown(node)) {
      return {
        passed: true,
        message: 'Interface is shutdown.',
        ruleId: 'ARI-INT-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for IP address or virtual-router address
    const hasIp = hasIpAddress(node);
    const hasVarp = hasVirtualRouterAddress(node);

    if (!hasIp && !hasVarp) {
      return {
        passed: false,
        message: 'L3 interface has no IP address configured.',
        ruleId: 'ARI-INT-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'L3 interface has IP address configured.',
      ruleId: 'ARI-INT-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// BGP / EVPN Rules
// ============================================================================

/**
 * ARI-BGP-001: BGP should have router-id configured
 */
export const BgpRouterId: IRule = {
  id: 'ARI-BGP-001',
  selector: 'router bgp',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure BGP router-id: router-id <ip-address>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const hasRouterId = hasChildCommand(node, 'router-id');

    if (!hasRouterId) {
      return {
        passed: false,
        message: 'BGP router-id is not explicitly configured. Recommend setting it explicitly.',
        ruleId: 'ARI-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP router-id is configured.',
      ruleId: 'ARI-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * ARI-BGP-002: EVPN should be configured for VXLAN environments
 */
export const EvpnConfigured: IRule = {
  id: 'ARI-BGP-002',
  selector: 'router bgp',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure EVPN address-family for VXLAN control-plane: address-family evpn',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Check if EVPN address-family is configured
    const hasEvpn = hasEvpnAddressFamily(node);

    if (!hasEvpn) {
      return {
        passed: false,
        message: 'BGP EVPN address-family is not configured. Required for VXLAN control-plane.',
        ruleId: 'ARI-BGP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP EVPN address-family is configured.',
      ruleId: 'ARI-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Spanning Tree Rules
// ============================================================================

/**
 * ARI-STP-001: Spanning-tree mode should be configured
 */
export const SpanningTreeMode: IRule = {
  id: 'ARI-STP-001',
  selector: 'spanning-tree',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure spanning-tree mode: spanning-tree mode <mstp|rapid-pvst|none>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (startsWithIgnoreCase(node.id, 'spanning-tree mode ')) {
      const mode = node.id.replace(/^spanning-tree\s+mode\s+/i, '').trim();
      return {
        passed: true,
        message: `Spanning-tree mode is set to: ${mode}`,
        ruleId: 'ARI-STP-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'Spanning-tree mode is not explicitly configured.',
      ruleId: 'ARI-STP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Security Rules
// ============================================================================

/**
 * ARI-SEC-001: AAA should be configured
 */
export const AaaConfigured: IRule = {
  id: 'ARI-SEC-001',
  selector: 'aaa',
  vendor: 'arista-eos',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure AAA authentication: aaa authentication login default ...',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    if (startsWithIgnoreCase(node.id, 'aaa ')) {
      return {
        passed: true,
        message: 'AAA is configured.',
        ruleId: 'ARI-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: false,
      message: 'AAA configuration not found.',
      ruleId: 'ARI-SEC-001',
      nodeId: node.id,
      level: 'warning',
      loc: node.loc,
    };
  },
};

/**
 * ARI-SEC-002: Management SSH should be enabled
 */
export const ManagementSshEnabled: IRule = {
  id: 'ARI-SEC-002',
  selector: 'management ssh',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Enable SSH management: management ssh / no shutdown',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Check if SSH is shutdown
    const isApiShutdown = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'shutdown')
    );
    const hasNoShutdown = node.children.some((child) =>
      equalsIgnoreCase(child.id, 'no shutdown')
    );

    if (isApiShutdown && !hasNoShutdown) {
      return {
        passed: false,
        message: 'Management SSH is shutdown.',
        ruleId: 'ARI-SEC-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Management SSH is enabled.',
      ruleId: 'ARI-SEC-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VRF Rules
// ============================================================================

/**
 * ARI-VRF-001: VRF instance should have description
 */
export const VrfDescription: IRule = {
  id: 'ARI-VRF-001',
  selector: 'vrf instance',
  vendor: 'arista-eos',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add description to VRF: description <text>',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    // Extract VRF name
    const vrfMatch = node.id.match(/vrf\s+instance\s+(\S+)/i);
    const vrfName = vrfMatch?.[1]?.trim() ?? 'unknown';

    // Skip default/management VRFs
    if (equalsIgnoreCase(vrfName, 'default') || equalsIgnoreCase(vrfName, 'management')) {
      return {
        passed: true,
        message: `System VRF ${vrfName} does not require description.`,
        ruleId: 'ARI-VRF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasDescription = hasChildCommand(node, 'description');
    if (!hasDescription) {
      return {
        passed: false,
        message: `VRF instance ${vrfName} is missing description.`,
        ruleId: 'ARI-VRF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VRF instance ${vrfName} has description.`,
      ruleId: 'ARI-VRF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all Arista EOS rules - proof-of-concept subset
// NOTE: Additional rules available in basic-netsec-pack
// ============================================================================

export const allAristaRules: IRule[] = [
  // System rules
  HostnameRequired,
  // Interface rules
  InterfaceDescription,
  // MLAG rules
  MlagConfigComplete,
];
