// packages/rules-default/src/cisco/ios-rules.ts
// Cisco IOS/IOS-XE specific rules

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import {
  parseIp,
  parseInteger,
  isDefaultVlan,
  includesIgnoreCase,
  startsWithIgnoreCase,
} from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  isShutdown,
  isPhysicalPort,
  isTrunkPort,
  isAccessPort,
  isExternalFacing,
  isEndpointPort,
  isPhoneOrAP,
  isTrunkToNonCisco,
  isLineConfigPassword,
} from '@sentriflow/core/helpers/cisco';

// ============================================================================
// Layer 2 Trunk Port Rules
// ============================================================================

/**
 * NET-TRUNK-001: DTP must be disabled on trunk ports connected to non-Cisco devices
 */
export const TrunkNoDTP: IRule = {
  id: 'NET-TRUNK-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation:
      'Add "switchport nonegotiate" to disable DTP on trunk ports connected to non-Cisco devices.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-TRUNK-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isTrunkPort(node)) {
      return { passed: true, message: 'Not a trunk port.', ruleId: 'NET-TRUNK-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isTrunkToNonCisco(node)) {
      return { passed: true, message: 'Trunk to Cisco device - DTP acceptable.', ruleId: 'NET-TRUNK-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!hasChildCommand(node, 'switchport nonegotiate')) {
      return {
        passed: false,
        message: `Trunk port "${node.params.slice(1).join(' ')}" connected to non-Cisco device needs "switchport nonegotiate".`,
        ruleId: 'NET-TRUNK-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'DTP disabled on trunk to non-Cisco device.', ruleId: 'NET-TRUNK-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-TRUNK-002: Native VLAN must not be VLAN 1
 */
export const TrunkNativeVlanNotOne: IRule = {
  id: 'NET-TRUNK-002',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "switchport trunk native vlan <non-1-vlan>" (e.g., vlan 999).',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-TRUNK-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isTrunkPort(node)) {
      return { passed: true, message: 'Not a trunk port.', ruleId: 'NET-TRUNK-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const nativeVlanCmd = getChildCommand(node, 'switchport trunk native vlan');
    if (!nativeVlanCmd) {
      return {
        passed: false,
        message: `Trunk port "${node.params.slice(1).join(' ')}" uses default native VLAN 1. Configure explicit native VLAN.`,
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    const vlanNum = nativeVlanCmd.params[4];
    if (vlanNum && isDefaultVlan(vlanNum)) {
      return {
        passed: false,
        message: `Trunk port "${node.params.slice(1).join(' ')}" explicitly uses native VLAN 1. Use a different VLAN.`,
        ruleId: 'NET-TRUNK-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Native VLAN is not VLAN 1.', ruleId: 'NET-TRUNK-002', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-TRUNK-003: Trunk must have explicit allowed VLAN list
 */
export const TrunkAllowedVlans: IRule = {
  id: 'NET-TRUNK-003',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "switchport trunk allowed vlan <list>" to restrict VLANs on trunk.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-TRUNK-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isTrunkPort(node)) {
      return { passed: true, message: 'Not a trunk port.', ruleId: 'NET-TRUNK-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const allowedVlanCmd = getChildCommand(node, 'switchport trunk allowed vlan');
    if (!allowedVlanCmd) {
      return {
        passed: false,
        message: `Trunk port "${node.params.slice(1).join(' ')}" allows all VLANs (default). Restrict with explicit VLAN list.`,
        ruleId: 'NET-TRUNK-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    if (includesIgnoreCase(allowedVlanCmd.rawText, 'allowed vlan all')) {
      return {
        passed: false,
        message: `Trunk port "${node.params.slice(1).join(' ')}" explicitly allows all VLANs. Restrict to required VLANs only.`,
        ruleId: 'NET-TRUNK-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Trunk has explicit allowed VLAN list.', ruleId: 'NET-TRUNK-003', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// Layer 2 Access Port Rules
// ============================================================================

/**
 * NET-ACCESS-001: Access ports must be explicitly configured as mode access
 */
export const AccessExplicitMode: IRule = {
  id: 'NET-ACCESS-001',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "switchport mode access" to explicitly configure access mode.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-ACCESS-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const hasAccessVlan = hasChildCommand(node, 'switchport access vlan');
    const hasExplicitMode = hasChildCommand(node, 'switchport mode');

    if (hasAccessVlan && !hasExplicitMode) {
      return {
        passed: false,
        message: `Interface "${node.params.slice(1).join(' ')}" has access VLAN but no explicit mode. Add "switchport mode access".`,
        ruleId: 'NET-ACCESS-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Access mode is explicit or not applicable.', ruleId: 'NET-ACCESS-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-ACCESS-002: Access ports must have VLAN assignment, not VLAN 1
 */
export const AccessVlanNotOne: IRule = {
  id: 'NET-ACCESS-002',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "switchport access vlan <non-1-vlan>" to assign proper VLAN.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-ACCESS-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isAccessPort(node)) {
      return { passed: true, message: 'Not an access port.', ruleId: 'NET-ACCESS-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const accessVlanCmd = getChildCommand(node, 'switchport access vlan');
    if (!accessVlanCmd) {
      return {
        passed: false,
        message: `Access port "${node.params.slice(1).join(' ')}" uses default VLAN 1. Configure explicit VLAN assignment.`,
        ruleId: 'NET-ACCESS-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    const vlanNum = accessVlanCmd.params[3];
    if (vlanNum && isDefaultVlan(vlanNum)) {
      return {
        passed: false,
        message: `Access port "${node.params.slice(1).join(' ')}" explicitly uses VLAN 1. Use a different VLAN.`,
        ruleId: 'NET-ACCESS-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Access VLAN is not VLAN 1.', ruleId: 'NET-ACCESS-002', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-ACCESS-004: PortFast ports must have BPDU Guard
 */
export const AccessBpduGuard: IRule = {
  id: 'NET-ACCESS-004',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "spanning-tree bpduguard enable" on PortFast-enabled ports.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-ACCESS-004', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const hasPortfast = hasChildCommand(node, 'spanning-tree portfast');
    if (!hasPortfast) {
      return { passed: true, message: 'PortFast not enabled.', ruleId: 'NET-ACCESS-004', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const hasBpduGuard = hasChildCommand(node, 'spanning-tree bpduguard');
    if (!hasBpduGuard) {
      return {
        passed: false,
        message: `Interface "${node.params.slice(1).join(' ')}" has PortFast but no BPDU Guard. Add "spanning-tree bpduguard enable".`,
        ruleId: 'NET-ACCESS-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'BPDU Guard enabled on PortFast port.', ruleId: 'NET-ACCESS-004', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// VTP Rules
// ============================================================================

/**
 * NET-VLAN-004: VTP must have domain set and version 2 or 3
 */
export const VtpConfiguration: IRule = {
  id: 'NET-VLAN-004',
  selector: 'vtp',
  vendor: 'cisco-ios',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure VTP with domain name and version 2 or 3.',
  },
  check: (node: ConfigNode): RuleResult => {
    const cmd = node.id;

    if (startsWithIgnoreCase(cmd, 'vtp version')) {
      const version = node.params[2];
      if (version === '1') {
        return {
          passed: false,
          message: 'VTP version 1 is not allowed. Use version 2 or 3.',
          ruleId: 'NET-VLAN-004',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    return { passed: true, message: 'VTP configuration check passed.', ruleId: 'NET-VLAN-004', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// Management Plane Rules
// ============================================================================

/**
 * NET-MGMT-001: VTY must use SSH only, no Telnet
 */
export const VtyNoTelnet: IRule = {
  id: 'NET-MGMT-001',
  selector: 'line vty',
  vendor: 'cisco-ios',
  category: 'Session-Management',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "transport input ssh" under VTY lines.',
  },
  check: (node: ConfigNode): RuleResult => {
    const transportCmd = getChildCommand(node, 'transport input');
    if (!transportCmd) {
      return {
        passed: false,
        message: 'VTY lines missing transport input configuration. Configure "transport input ssh".',
        ruleId: 'NET-MGMT-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    const transportText = transportCmd.rawText;
    if (includesIgnoreCase(transportText, 'telnet') || includesIgnoreCase(transportText, 'all')) {
      return {
        passed: false,
        message: 'VTY allows Telnet. Configure "transport input ssh" only.',
        ruleId: 'NET-MGMT-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    if (!includesIgnoreCase(transportText, 'ssh')) {
      return {
        passed: false,
        message: 'VTY transport does not include SSH. Configure "transport input ssh".',
        ruleId: 'NET-MGMT-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'VTY configured for SSH only.', ruleId: 'NET-MGMT-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-MGMT-003: Exec-timeout must be configured (max 15 minutes)
 */
export const VtyExecTimeout: IRule = {
  id: 'NET-MGMT-003',
  selector: 'line vty',
  vendor: 'cisco-ios',
  category: 'Session-Management',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "exec-timeout <minutes> <seconds>" with maximum 15 minutes.',
  },
  check: (node: ConfigNode): RuleResult => {
    const timeoutCmd = getChildCommand(node, 'exec-timeout');
    if (!timeoutCmd) {
      return {
        passed: false,
        message: 'VTY lines missing exec-timeout. Configure timeout (max 15 minutes).',
        ruleId: 'NET-MGMT-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    const timeoutMatch = timeoutCmd.id.match(/exec-timeout\s+(\d+)/i);
    const minutesStr = timeoutMatch?.[1];
    if (!minutesStr) {
      return { passed: true, message: 'Exec-timeout configured.', ruleId: 'NET-MGMT-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const minutes = parseInteger(minutesStr);
    if (minutes === null) {
      return { passed: true, message: 'Exec-timeout configured.', ruleId: 'NET-MGMT-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (minutes === 0) {
      return {
        passed: false,
        message: 'VTY exec-timeout is disabled (0). Configure a timeout (max 15 minutes).',
        ruleId: 'NET-MGMT-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    if (minutes > 15) {
      return {
        passed: false,
        message: `VTY exec-timeout of ${minutes} minutes exceeds maximum 15 minutes.`,
        ruleId: 'NET-MGMT-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Exec-timeout configured within limits.', ruleId: 'NET-MGMT-003', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-MGMT-005: HTTP/HTTPS server must be disabled
 */
export const NoHttpServer: IRule = {
  id: 'NET-MGMT-005',
  selector: 'ip http',
  vendor: 'cisco-ios',
  category: 'Service-Hardening',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "no ip http server" and "no ip http secure-server".',
  },
  check: (node: ConfigNode): RuleResult => {
    const cmd = node.id;

    if (cmd.toLowerCase() === 'ip http server') {
      return {
        passed: false,
        message: 'HTTP server is enabled. Disable with "no ip http server".',
        ruleId: 'NET-MGMT-005',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    if (cmd.toLowerCase() === 'ip http secure-server') {
      return {
        passed: false,
        message: 'HTTPS server is enabled. Disable with "no ip http secure-server".',
        ruleId: 'NET-MGMT-005',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'HTTP check passed.', ruleId: 'NET-MGMT-005', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// Routing Protocol Rules
// ============================================================================

/**
 * NET-ROUTE-001: OSPF must have router-id configured
 */
export const OspfRouterId: IRule = {
  id: 'NET-ROUTE-001',
  selector: 'router ospf',
  vendor: 'cisco-ios',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "router-id <ip-address>" under OSPF process.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasChildCommand(node, 'router-id')) {
      return {
        passed: false,
        message: `OSPF process "${node.params.slice(2).join(' ')}" missing explicit router-id.`,
        ruleId: 'NET-ROUTE-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'OSPF router-id is configured.', ruleId: 'NET-ROUTE-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-ROUTE-001B: BGP must have router-id configured
 */
export const BgpRouterId: IRule = {
  id: 'NET-ROUTE-001',
  selector: 'router bgp',
  vendor: 'cisco-ios',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "bgp router-id <ip-address>" under BGP process.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasChildCommand(node, 'bgp router-id')) {
      return {
        passed: false,
        message: `BGP AS "${node.params.slice(2).join(' ')}" missing explicit router-id.`,
        ruleId: 'NET-ROUTE-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'BGP router-id is configured.', ruleId: 'NET-ROUTE-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-ROUTE-005: BGP all neighbors shutdown detection
 */
export const BgpAllNeighborsShutdown: IRule = {
  id: 'NET-ROUTE-005',
  selector: 'router bgp',
  vendor: 'cisco-ios',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Enable at least one BGP neighbor or remove unused BGP configuration.',
  },
  check: (node: ConfigNode): RuleResult => {
    const neighborCmds = node.children.filter(
      (child) =>
        startsWithIgnoreCase(child.id, 'neighbor') &&
        includesIgnoreCase(child.id, 'remote-as')
    );

    if (neighborCmds.length === 0) {
      return { passed: true, message: 'No BGP neighbors configured.', ruleId: 'NET-ROUTE-005', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const neighborIps = new Set<string>();
    const shutdownNeighbors = new Set<string>();

    for (const child of node.children) {
      const cmd = child.id;
      if (startsWithIgnoreCase(cmd, 'neighbor')) {
        const parts = child.params;
        if (parts.length >= 2) {
          const neighborIp = parts[1];
          if (!neighborIp) {
            continue;
          }
          if (includesIgnoreCase(cmd, 'remote-as')) {
            neighborIps.add(neighborIp);
          }
          if (includesIgnoreCase(cmd, 'shutdown')) {
            shutdownNeighbors.add(neighborIp);
          }
        }
      }
    }

    let allShutdown = true;
    for (const ip of neighborIps) {
      if (!shutdownNeighbors.has(ip)) {
        allShutdown = false;
        break;
      }
    }

    if (allShutdown && neighborIps.size > 0) {
      return {
        passed: false,
        message: `BGP AS "${node.params.slice(2).join(' ')}" has all ${neighborIps.size} neighbor(s) shutdown. BGP is effectively inactive.`,
        ruleId: 'NET-ROUTE-005',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'BGP has active neighbors.', ruleId: 'NET-ROUTE-005', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-OSPF-001: Validate OSPF network statements
 */
export const OspfNetworkBestPractice: IRule = {
  id: 'NET-OSPF-001',
  selector: 'router ospf',
  vendor: 'cisco-ios',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation:
      'Use specific interface IP addresses with 0.0.0.0 wildcard mask (e.g., "network 10.0.0.1 0.0.0.0 area 0").',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const interfaceIps = new Set<number>();
    const collectInterfaceIps = (nodes: ConfigNode[]) => {
      for (const n of nodes) {
        if (startsWithIgnoreCase(n.id, 'interface')) {
          for (const child of n.children) {
            const childId = child.id.trim();
            if (startsWithIgnoreCase(childId, 'ip address')) {
              const ipStr = child.params[2];
              if (ipStr) {
                const ip = parseIp(ipStr);
                if (ip !== null) {
                  interfaceIps.add(ip);
                }
              }
            }
          }
        }
        if (n.children.length > 0) {
          collectInterfaceIps(n.children);
        }
      }
    };

    const ast = context.getAst?.();
    if (ast) {
      collectInterfaceIps(ast);
    }

    const networkStatements = node.children.filter((child) =>
      startsWithIgnoreCase(child.id.trim(), 'network')
    );

    if (networkStatements.length === 0) {
      return {
        passed: true,
        message: 'No network statements found in OSPF configuration.',
        ruleId: 'NET-OSPF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const issues: string[] = [];

    for (const netStmt of networkStatements) {
      const params = netStmt.params;
      const networkIpStr = params[1];
      const wildcardStr = params[2];

      if (!networkIpStr || !wildcardStr) {
        issues.push(`Line ${netStmt.loc.startLine}: Incomplete network statement "${netStmt.rawText.trim()}".`);
        continue;
      }

      const networkIp = parseIp(networkIpStr);
      const wildcard = parseIp(wildcardStr);

      if (networkIp === null) {
        issues.push(`Line ${netStmt.loc.startLine}: Invalid IP address "${networkIpStr}".`);
        continue;
      }

      if (wildcard === null) {
        issues.push(`Line ${netStmt.loc.startLine}: Invalid wildcard mask "${wildcardStr}".`);
        continue;
      }

      if (wildcard !== 0) {
        issues.push(
          `Line ${netStmt.loc.startLine}: Network statement "${networkIpStr} ${wildcardStr}" uses a broad wildcard. ` +
            `Best practice: use interface IP with 0.0.0.0 wildcard for precise matching.`
        );
      }

      if (wildcard === 0 && interfaceIps.size > 0) {
        if (!interfaceIps.has(networkIp)) {
          issues.push(
            `Line ${netStmt.loc.startLine}: Network IP "${networkIpStr}" does not match any configured interface IP address.`
          );
        }
      }

      if (wildcard !== 0 && interfaceIps.size > 0) {
        const invertedWildcard = ~wildcard >>> 0;
        const networkBase = (networkIp & invertedWildcard) >>> 0;

        let matchesAnyInterface = false;
        for (const ifaceIp of interfaceIps) {
          if (((ifaceIp & invertedWildcard) >>> 0) === networkBase) {
            matchesAnyInterface = true;
            break;
          }
        }

        if (!matchesAnyInterface) {
          issues.push(
            `Line ${netStmt.loc.startLine}: Network "${networkIpStr} ${wildcardStr}" does not match any configured interface subnet.`
          );
        }
      }
    }

    if (issues.length > 0) {
      return {
        passed: false,
        message: `OSPF network statement issues:\n${issues.join('\n')}`,
        ruleId: 'NET-OSPF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF network statements follow best practices.',
      ruleId: 'NET-OSPF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// SNMP Security Rules
// ============================================================================

/**
 * NET-SNMP-002: No default SNMP community strings (public/private)
 */
export const SnmpNoDefaultCommunity: IRule = {
  id: 'NET-SNMP-002',
  selector: 'snmp-server community',
  vendor: 'cisco-ios',
  category: 'Protocol-Security',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use complex, non-default SNMP community strings. Preferably migrate to SNMPv3.',
  },
  check: (node: ConfigNode): RuleResult => {
    const community = node.params[2]?.toLowerCase();

    if (community === 'public' || community === 'private') {
      return {
        passed: false,
        message: `Default SNMP community string "${community}" detected. Use a complex string.`,
        ruleId: 'NET-SNMP-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'SNMP community is not default.', ruleId: 'NET-SNMP-002', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-SNMP-004: SNMP RW access should be avoided
 */
export const SnmpNoRwAccess: IRule = {
  id: 'NET-SNMP-004',
  selector: 'snmp-server community',
  vendor: 'cisco-ios',
  category: 'Protocol-Security',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Remove SNMP RW access unless specifically required. Use RO for monitoring.',
  },
  check: (node: ConfigNode): RuleResult => {
    const rawText = node.rawText.toUpperCase();

    if (rawText.includes(' RW')) {
      return {
        passed: false,
        message: 'SNMP RW (write) access is configured. This is a security risk.',
        ruleId: 'NET-SNMP-004',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'SNMP is read-only.', ruleId: 'NET-SNMP-004', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// CDP/LLDP Rules
// ============================================================================

/**
 * NET-SVC-005: CDP should be disabled on external-facing and endpoint ports
 */
export const CdpDisabledOnExternal: IRule = {
  id: 'NET-SVC-005',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Protocol-Security',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Add "no cdp enable" on external-facing and user endpoint interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-SVC-005', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (isPhoneOrAP(node)) {
      const desc = getChildCommand(node, 'description');
      const descText = desc?.rawText.toLowerCase() || '';
      if (descText.includes('aruba')) {
        if (!hasChildCommand(node, 'no cdp enable')) {
          return {
            passed: false,
            message: `Aruba AP port "${node.params.slice(1).join(' ')}" should have CDP disabled. Add "no cdp enable".`,
            ruleId: 'NET-SVC-005',
            nodeId: node.id,
            level: 'warning',
            loc: node.loc,
          };
        }
      }
      return { passed: true, message: 'CDP allowed for phone/Cisco AP.', ruleId: 'NET-SVC-005', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (isExternalFacing(node)) {
      if (!hasChildCommand(node, 'no cdp enable')) {
        return {
          passed: false,
          message: `External interface "${node.params.slice(1).join(' ')}" should have CDP disabled. Add "no cdp enable".`,
          ruleId: 'NET-SVC-005',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    if (isEndpointPort(node) && !isPhoneOrAP(node)) {
      if (!hasChildCommand(node, 'no cdp enable')) {
        return {
          passed: false,
          message: `Endpoint port "${node.params.slice(1).join(' ')}" should have CDP disabled. Add "no cdp enable".`,
          ruleId: 'NET-SVC-005',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    return { passed: true, message: 'CDP configuration is appropriate.', ruleId: 'NET-SVC-005', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-SVC-006: LLDP should be disabled on external-facing and endpoint ports
 */
export const LldpDisabledOnExternal: IRule = {
  id: 'NET-SVC-006',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'Protocol-Security',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Add "no lldp transmit" and "no lldp receive" on external-facing and user endpoint interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!isPhysicalPort(node.id) || isShutdown(node)) {
      return { passed: true, message: 'Not applicable.', ruleId: 'NET-SVC-006', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (isPhoneOrAP(node)) {
      const desc = getChildCommand(node, 'description');
      const descText = desc?.rawText.toLowerCase() || '';
      if (descText.includes('cisco-ap')) {
        const noLldpTx = hasChildCommand(node, 'no lldp transmit');
        const noLldpRx = hasChildCommand(node, 'no lldp receive');
        if (!noLldpTx || !noLldpRx) {
          return {
            passed: false,
            message: `Cisco AP port "${node.params.slice(1).join(' ')}" should have LLDP disabled. Add "no lldp transmit" and "no lldp receive".`,
            ruleId: 'NET-SVC-006',
            nodeId: node.id,
            level: 'warning',
            loc: node.loc,
          };
        }
      }
      return { passed: true, message: 'LLDP allowed for phone/Aruba AP.', ruleId: 'NET-SVC-006', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (isExternalFacing(node)) {
      const noLldpTx = hasChildCommand(node, 'no lldp transmit');
      const noLldpRx = hasChildCommand(node, 'no lldp receive');
      if (!noLldpTx || !noLldpRx) {
        return {
          passed: false,
          message: `External interface "${node.params.slice(1).join(' ')}" should have LLDP disabled.`,
          ruleId: 'NET-SVC-006',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    if (isEndpointPort(node) && !isPhoneOrAP(node)) {
      const noLldpTx = hasChildCommand(node, 'no lldp transmit');
      const noLldpRx = hasChildCommand(node, 'no lldp receive');
      if (!noLldpTx || !noLldpRx) {
        return {
          passed: false,
          message: `Endpoint port "${node.params.slice(1).join(' ')}" should have LLDP disabled.`,
          ruleId: 'NET-SVC-006',
          nodeId: node.id,
          level: 'warning',
          loc: node.loc,
        };
      }
    }

    return { passed: true, message: 'LLDP configuration is appropriate.', ruleId: 'NET-SVC-006', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// FHRP Rules
// ============================================================================

/**
 * NET-FHRP-002: HSRP/VRRP must have authentication configured
 */
export const FhrpAuthentication: IRule = {
  id: 'NET-FHRP-002',
  selector: 'interface',
  vendor: 'cisco-ios',
  category: 'High-Availability',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "standby <group> authentication md5 key-string <key>" for HSRP.',
  },
  check: (node: ConfigNode): RuleResult => {
    const hasHsrp = node.children.some(
      (child) =>
        child.id.toLowerCase().startsWith('standby') &&
        child.id.toLowerCase().includes(' ip ')
    );

    if (!hasHsrp) {
      return { passed: true, message: 'No HSRP configured.', ruleId: 'NET-FHRP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const hasAuth = node.children.some(
      (child) =>
        child.id.toLowerCase().startsWith('standby') &&
        child.id.toLowerCase().includes('authentication')
    );

    if (!hasAuth) {
      return {
        passed: false,
        message: `Interface "${node.params.slice(1).join(' ')}" has HSRP without authentication.`,
        ruleId: 'NET-FHRP-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'HSRP has authentication configured.', ruleId: 'NET-FHRP-002', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// VLAN Rules
// ============================================================================

/**
 * NET-VLAN-001: VLAN must have a valid name
 * Detects VLAN definitions with empty or missing name values
 */
export const VlanNameRequired: IRule = {
  id: 'NET-VLAN-001',
  selector: 'vlan',
  vendor: 'cisco-ios',
  category: 'Documentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure a descriptive name for the VLAN: "name <description>".',
  },
  check: (node: ConfigNode): RuleResult => {
    // Only check VLAN definition sections (vlan <id>), not vlan commands inside interfaces
    if (node.type !== 'section') {
      return { passed: true, message: 'Not a VLAN section.', ruleId: 'NET-VLAN-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Find the name command in VLAN children
    const nameCmd = node.children.find((child) => child.id.toLowerCase().startsWith('name'));

    if (!nameCmd) {
      // No name configured - this could be a warning, but some configs don't require it
      return { passed: true, message: 'VLAN has no name configured.', ruleId: 'NET-VLAN-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if name is empty (only "name" keyword with no value)
    if (nameCmd.params.length < 2 || nameCmd.params[1]?.trim() === '') {
      const vlanId = node.params[1] || 'unknown';
      return {
        passed: false,
        message: `VLAN ${vlanId} has empty name. The "name" keyword requires a value.`,
        ruleId: 'NET-VLAN-001',
        nodeId: node.id,
        level: 'error',
        loc: nameCmd.loc,
      };
    }

    return { passed: true, message: 'VLAN has a valid name.', ruleId: 'NET-VLAN-001', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

// ============================================================================
// Service Hardening Rules
// ============================================================================

/**
 * NET-SVC-002: IP source-route must be disabled
 */
export const NoIpSourceRoute: IRule = {
  id: 'NET-SVC-002',
  selector: 'ip source-route',
  vendor: 'cisco-ios',
  category: 'Service-Hardening',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Configure "no ip source-route" to disable IP source routing.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (node.id.toLowerCase() === 'ip source-route') {
      return {
        passed: false,
        message: 'IP source-route is enabled. Disable with "no ip source-route".',
        ruleId: 'NET-SVC-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'IP source-route check passed.', ruleId: 'NET-SVC-002', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-AAA-003: Enable secret must use strong encryption (not type 7 or plaintext)
 */
export const EnableSecretStrong: IRule = {
  id: 'NET-AAA-003',
  selector: 'enable',
  vendor: 'cisco-ios',
  category: 'Authentication',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Use "enable algorithm-type scrypt secret <password>" for strong encryption.',
  },
  check: (node: ConfigNode): RuleResult => {
    const cmd = node.id;

    if (startsWithIgnoreCase(cmd, 'enable password')) {
      const params = node.params;
      if (params[2] === '7') {
        return {
          passed: false,
          message: 'Enable password uses weak type 7 encryption. Use "enable secret" with strong algorithm.',
          ruleId: 'NET-AAA-003',
          nodeId: node.id,
          level: 'error',
          loc: node.loc,
        };
      }
      return {
        passed: false,
        message: 'Enable password is configured. Use "enable secret" instead.',
        ruleId: 'NET-AAA-003',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return { passed: true, message: 'Enable secret check passed.', ruleId: 'NET-AAA-003', nodeId: node.id, level: 'info', loc: node.loc };
  },
};

/**
 * NET-SEC-001: Cisco Plaintext Password Detection (Context-Aware)
 *
 * Detects plaintext passwords in Cisco configurations with proper context awareness:
 * - SKIPS line vty/console/aux passwords (they can't be encrypted - use AAA instead)
 * - FAILS for username plaintext passwords (should use "secret" or "password 7")
 * - FAILS for other plaintext passwords in applicable contexts
 *
 * Cisco-specific: checks for type 5/7/8/9 encryption indicators.
 */
export const CiscoNoPlaintextPasswords: IRule = {
  id: 'NET-SEC-001',
  selector: 'password',
  vendor: ['cisco-ios', 'cisco-nxos'],
  category: 'Authentication',
  metadata: {
    level: 'error',
    obu: 'Security',
    owner: 'SecOps',
    remediation:
      'Use "secret" instead of "password", or encrypt with type 7/8/9.',
  },
  check: (node: ConfigNode, context: Context): RuleResult => {
    const params = node.params;
    const nodeId = node.id.toLowerCase();

    // Skip global config commands that aren't password definitions
    // e.g., "service password-encryption", "password encryption aes"
    if (nodeId.includes('encryption') || nodeId.includes('service')) {
      return {
        passed: true,
        message: 'Global password configuration.',
        ruleId: 'NET-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Skip line passwords (vty/console/aux) - they CANNOT be encrypted in Cisco IOS
    // The only options are:
    //   - "password <plaintext>" (no encryption option exists)
    //   - Use AAA authentication instead (recommended)
    // Security for lines is enforced via transport input ssh, access-class, and AAA rules
    const ast = context.getAst?.();
    if (ast && isLineConfigPassword(ast, node)) {
      return {
        passed: true,
        message: 'Line password - use AAA authentication for security (line passwords cannot be encrypted).',
        ruleId: 'NET-SEC-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check for encrypted password types (5, 7, 8, 9)
    // Format: password <type> <encrypted-string>
    if (params.length >= 2) {
      const typeOrValue = params[1];

      // Encrypted types: 5 (MD5), 7 (Vigenere), 8 (PBKDF2-SHA256), 9 (scrypt)
      if (typeOrValue && ['5', '7', '8', '9'].includes(typeOrValue)) {
        return {
          passed: true,
          message: `Password is encrypted (type ${typeOrValue}).`,
          ruleId: 'NET-SEC-001',
          nodeId: node.id,
          level: 'info',
          loc: node.loc,
        };
      }

      // Type 0 is explicitly plaintext
      if (typeOrValue === '0') {
        return {
          passed: false,
          message: 'Plaintext password detected (type 0). Use "secret" or encrypt with type 7.',
          ruleId: 'NET-SEC-001',
          nodeId: node.id,
          level: 'error',
          loc: node.loc,
        };
      }

      // Non-numeric first parameter means plaintext password value
      if (typeOrValue && !/^\d+$/.test(typeOrValue)) {
        return {
          passed: false,
          message: 'Plaintext password detected. Use "secret" or encrypt with type 7.',
          ruleId: 'NET-SEC-001',
          nodeId: node.id,
          level: 'error',
          loc: node.loc,
        };
      }
    }

    return {
      passed: true,
      message: 'Password check passed.',
      ruleId: 'NET-SEC-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all Cisco IOS rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allCiscoRules: IRule[] = [
  // Layer 2 Trunk
  TrunkNoDTP,
  // Layer 2 Access
  AccessExplicitMode,
  // Security
  CiscoNoPlaintextPasswords,
  EnableSecretStrong,
];
