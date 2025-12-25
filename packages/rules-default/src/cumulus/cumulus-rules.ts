// packages/rules-default/src/cumulus/cumulus-rules.ts
// NVIDIA Cumulus Linux specific rules

import type { IRule, ConfigNode, RuleResult } from '@sentriflow/core';
import {
  startsWithIgnoreCase,
  parseInteger,
} from '@sentriflow/core';
import {
  hasChildCommand,
  isIfaceStanza,
  isSwitchPort,
  isBondInterface,
  isBridgeInterface,
  isVlanInterface,
  isLoopback,
  isPeerlink,
  isVlanAwareBridge,
  getInterfaceName,
  hasAddress,
  hasDescription,
  hasBridgePorts,
  hasBridgeVids,
  hasMtu,
  hasBondSlaves,
  hasClagId,
  hasBpduGuard,
  hasPortAdminEdge,
  findStanza,
  findStanzasByPrefix,
  hasBgpRouterId,
  hasBgpNeighbors,
  getBgpNeighborAddress,
} from '@sentriflow/core/helpers/cumulus';

// ============================================================================
// Interface Configuration Rules
// ============================================================================

/**
 * CUM-IF-001: Switch port interfaces should have descriptions
 */
export const CumulusInterfaceDescription: IRule = {
  id: 'CUM-IF-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Documentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "alias <description>" under the interface stanza.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    // Only check switch ports
    if (!isSwitchPort(ifaceName)) {
      return {
        passed: true,
        message: 'Not a switch port interface.',
        ruleId: 'CUM-IF-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `Switch port "${ifaceName}" missing description (alias).`,
        ruleId: 'CUM-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Switch port "${ifaceName}" has description.`,
      ruleId: 'CUM-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-IF-002: Access ports should have BPDU guard enabled
 */
export const CumulusBpduGuard: IRule = {
  id: 'CUM-IF-002',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "mstpctl-bpduguard yes" for access/edge ports.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    // Only check switch ports that have bridge-access (access ports)
    if (!isSwitchPort(ifaceName)) {
      return {
        passed: true,
        message: 'Not a switch port interface.',
        ruleId: 'CUM-IF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if this is an access port
    const isAccessPort = node.children.some((child) =>
      startsWithIgnoreCase(child.id, 'bridge-access ')
    );

    if (!isAccessPort) {
      return {
        passed: true,
        message: 'Not an access port.',
        ruleId: 'CUM-IF-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasBpduGuard(node)) {
      return {
        passed: false,
        message: `Access port "${ifaceName}" should have BPDU guard enabled.`,
        ruleId: 'CUM-IF-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Access port "${ifaceName}" has BPDU guard enabled.`,
      ruleId: 'CUM-IF-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-IF-003: Access ports should have portadminedge (portfast) enabled
 */
export const CumulusPortAdminEdge: IRule = {
  id: 'CUM-IF-003',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Network-Segmentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "mstpctl-portadminedge yes" for access/edge ports.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isSwitchPort(ifaceName)) {
      return {
        passed: true,
        message: 'Not a switch port interface.',
        ruleId: 'CUM-IF-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if this is an access port
    const isAccessPort = node.children.some((child) =>
      startsWithIgnoreCase(child.id, 'bridge-access ')
    );

    if (!isAccessPort) {
      return {
        passed: true,
        message: 'Not an access port.',
        ruleId: 'CUM-IF-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasPortAdminEdge(node)) {
      return {
        passed: false,
        message: `Access port "${ifaceName}" should have portadminedge enabled for faster convergence.`,
        ruleId: 'CUM-IF-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Access port "${ifaceName}" has portadminedge enabled.`,
      ruleId: 'CUM-IF-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Bridge Configuration Rules
// ============================================================================

/**
 * CUM-BR-001: VLAN-aware bridge should have VLANs configured
 */
export const CumulusBridgeVlans: IRule = {
  id: 'CUM-BR-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "bridge-vids <vlan-ids>" to define allowed VLANs on the bridge.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isBridgeInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a bridge interface.',
        ruleId: 'CUM-BR-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!isVlanAwareBridge(node)) {
      return {
        passed: true,
        message: 'Not a VLAN-aware bridge.',
        ruleId: 'CUM-BR-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasBridgeVids(node)) {
      return {
        passed: false,
        message: `VLAN-aware bridge "${ifaceName}" has no VLANs (bridge-vids) configured.`,
        ruleId: 'CUM-BR-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Bridge "${ifaceName}" has VLANs configured.`,
      ruleId: 'CUM-BR-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-BR-002: Bridge should have member ports configured
 */
export const CumulusBridgePorts: IRule = {
  id: 'CUM-BR-002',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Network-Segmentation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "bridge-ports <interfaces>" to define bridge members.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isBridgeInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a bridge interface.',
        ruleId: 'CUM-BR-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasBridgePorts(node)) {
      return {
        passed: false,
        message: `Bridge "${ifaceName}" has no member ports (bridge-ports) configured.`,
        ruleId: 'CUM-BR-002',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Bridge "${ifaceName}" has member ports configured.`,
      ruleId: 'CUM-BR-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Bond/LAG Configuration Rules
// ============================================================================

/**
 * CUM-BOND-001: Bond interfaces should have slave members
 */
export const CumulusBondSlaves: IRule = {
  id: 'CUM-BOND-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Link-Aggregation',
  metadata: {
    level: 'error',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "bond-slaves <interfaces>" to define bond members.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isBondInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a bond interface.',
        ruleId: 'CUM-BOND-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasBondSlaves(node)) {
      return {
        passed: false,
        message: `Bond "${ifaceName}" has no slave members (bond-slaves) configured.`,
        ruleId: 'CUM-BOND-001',
        nodeId: node.id,
        level: 'error',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Bond "${ifaceName}" has slave members configured.`,
      ruleId: 'CUM-BOND-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-BOND-002: MLAG bonds should have clag-id configured
 */
export const CumulusBondClagId: IRule = {
  id: 'CUM-BOND-002',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'High-Availability',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "clag-id <id>" for MLAG bonds to enable dual-homing.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isBondInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a bond interface.',
        ruleId: 'CUM-BOND-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if this appears to be in an MLAG environment
    // (has peerlink or clagd configuration elsewhere)
    // For now, just check if it has clag-id when bond-slaves is present
    if (hasBondSlaves(node) && !hasClagId(node)) {
      return {
        passed: false,
        message: `Bond "${ifaceName}" may need clag-id for MLAG dual-homing.`,
        ruleId: 'CUM-BOND-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Bond "${ifaceName}" MLAG configuration is acceptable.`,
      ruleId: 'CUM-BOND-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// VLAN/SVI Configuration Rules
// ============================================================================

/**
 * CUM-VLAN-001: VLAN SVIs should have IP addresses
 */
export const CumulusVlanAddress: IRule = {
  id: 'CUM-VLAN-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'IP-Addressing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "address <ip/prefix>" for Layer 3 VLAN interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isVlanInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a VLAN interface.',
        ruleId: 'CUM-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasAddress(node)) {
      return {
        passed: false,
        message: `VLAN interface "${ifaceName}" has no IP address configured.`,
        ruleId: 'CUM-VLAN-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN interface "${ifaceName}" has IP address configured.`,
      ruleId: 'CUM-VLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-VLAN-002: VLAN SVIs should have vlan-raw-device specified
 */
export const CumulusVlanRawDevice: IRule = {
  id: 'CUM-VLAN-002',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'Network-Segmentation',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "vlan-raw-device <bridge>" to associate VLAN with bridge.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isVlanInterface(ifaceName)) {
      return {
        passed: true,
        message: 'Not a VLAN interface.',
        ruleId: 'CUM-VLAN-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    const hasVlanRawDevice = node.children.some((child) =>
      startsWithIgnoreCase(child.id, 'vlan-raw-device ')
    );

    if (!hasVlanRawDevice) {
      return {
        passed: false,
        message: `VLAN interface "${ifaceName}" missing vlan-raw-device association.`,
        ruleId: 'CUM-VLAN-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `VLAN interface "${ifaceName}" has vlan-raw-device configured.`,
      ruleId: 'CUM-VLAN-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// BGP Configuration Rules (FRR)
// ============================================================================

/**
 * CUM-BGP-001: BGP should have router-id configured
 */
export const CumulusBgpRouterId: IRule = {
  id: 'CUM-BGP-001',
  selector: 'router bgp',
  vendor: 'cumulus-linux',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "bgp router-id <ip>" to explicitly set router ID.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasBgpRouterId(node)) {
      return {
        passed: false,
        message: 'BGP missing explicit router-id configuration.',
        ruleId: 'CUM-BGP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP router-id is configured.',
      ruleId: 'CUM-BGP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-BGP-002: BGP should have neighbors configured
 */
export const CumulusBgpNeighbors: IRule = {
  id: 'CUM-BGP-002',
  selector: 'router bgp',
  vendor: 'cumulus-linux',
  category: 'Routing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add BGP neighbors using "neighbor <addr|interface> remote-as <asn>".',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasBgpNeighbors(node)) {
      return {
        passed: false,
        message: 'BGP has no neighbors configured.',
        ruleId: 'CUM-BGP-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP has neighbors configured.',
      ruleId: 'CUM-BGP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-BGP-003: BGP unnumbered should use interface names
 */
export const CumulusBgpUnnumbered: IRule = {
  id: 'CUM-BGP-003',
  selector: 'router bgp',
  vendor: 'cumulus-linux',
  category: 'Routing',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Consider using BGP unnumbered with interface names (e.g., "neighbor swp51 interface remote-as external").',
  },
  check: (node: ConfigNode): RuleResult => {
    const neighbors = node.children.filter((child) =>
      startsWithIgnoreCase(child.id, 'neighbor ')
    );

    if (neighbors.length === 0) {
      return {
        passed: true,
        message: 'No BGP neighbors configured.',
        ruleId: 'CUM-BGP-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    // Check if any neighbors use interface names (unnumbered)
    const hasUnnumbered = neighbors.some((n) => {
      const addr = getBgpNeighborAddress(n.id);
      return isSwitchPort(addr) || addr.includes('interface');
    });

    if (!hasUnnumbered) {
      return {
        passed: false,
        message: 'Consider using BGP unnumbered for simplified peering.',
        ruleId: 'CUM-BGP-003',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP unnumbered is in use.',
      ruleId: 'CUM-BGP-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// MLAG (CLAG) Configuration Rules
// ============================================================================

/**
 * CUM-MLAG-001: Peerlink should have appropriate MTU
 */
export const CumulusPeerlinkMtu: IRule = {
  id: 'CUM-MLAG-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'High-Availability',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Set MTU 9216 on peerlink for MLAG traffic.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isPeerlink(ifaceName)) {
      return {
        passed: true,
        message: 'Not a peerlink interface.',
        ruleId: 'CUM-MLAG-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasMtu(node)) {
      return {
        passed: false,
        message: `Peerlink "${ifaceName}" should have MTU configured (recommended: 9216).`,
        ruleId: 'CUM-MLAG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    // Check if MTU is at least 9000
    const mtuCmd = node.children.find((child) =>
      startsWithIgnoreCase(child.id, 'mtu ')
    );
    if (mtuCmd) {
      const mtuMatch = mtuCmd.id.match(/mtu\s+(\d+)/i);
      const mtuValue = mtuMatch?.[1];
      if (mtuValue) {
        const mtu = parseInteger(mtuValue);
        if (mtu !== null && mtu < 9000) {
          return {
            passed: false,
            message: `Peerlink "${ifaceName}" MTU ${mtu} is below recommended 9216.`,
            ruleId: 'CUM-MLAG-001',
            nodeId: node.id,
            level: 'warning',
            loc: node.loc,
          };
        }
      }
    }

    return {
      passed: true,
      message: `Peerlink "${ifaceName}" has appropriate MTU.`,
      ruleId: 'CUM-MLAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// NCLU/NVUE Command Rules
// ============================================================================

/**
 * CUM-CMD-001: NCLU commands should be committed
 */
export const CumulusNcluCommit: IRule = {
  id: 'CUM-CMD-001',
  selector: 'net',
  vendor: 'cumulus-linux',
  category: 'Documentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Run "net commit" to apply NCLU configuration changes.',
  },
  check: (node: ConfigNode, context): RuleResult => {
    // This rule checks if there are net add/del commands without a net commit
    // Since we're checking individual nodes, we'll just flag NCLU commands
    const id = node.id.toLowerCase();

    if (id.startsWith('net add') || id.startsWith('net del')) {
      return {
        passed: true,
        message: 'NCLU command detected. Remember to run "net commit" to apply changes.',
        ruleId: 'CUM-CMD-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Not an NCLU staging command.',
      ruleId: 'CUM-CMD-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * CUM-CMD-002: NVUE commands should be applied
 */
export const CumulusNvueApply: IRule = {
  id: 'CUM-CMD-002',
  selector: 'nv',
  vendor: 'cumulus-linux',
  category: 'Documentation',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Run "nv config apply" to apply NVUE configuration changes.',
  },
  check: (node: ConfigNode): RuleResult => {
    const id = node.id.toLowerCase();

    if (id.startsWith('nv set') || id.startsWith('nv unset')) {
      return {
        passed: true,
        message: 'NVUE command detected. Remember to run "nv config apply" to apply changes.',
        ruleId: 'CUM-CMD-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Not an NVUE staging command.',
      ruleId: 'CUM-CMD-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Loopback Configuration Rules
// ============================================================================

/**
 * CUM-LO-001: Loopback should have IP address for router-id
 */
export const CumulusLoopbackAddress: IRule = {
  id: 'CUM-LO-001',
  selector: 'iface',
  vendor: 'cumulus-linux',
  category: 'IP-Addressing',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add "address <ip/32>" to loopback for use as router-id.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifaceName = getInterfaceName(node);

    if (!isLoopback(ifaceName)) {
      return {
        passed: true,
        message: 'Not a loopback interface.',
        ruleId: 'CUM-LO-001',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    if (!hasAddress(node)) {
      return {
        passed: false,
        message: 'Loopback missing IP address. Required for BGP/OSPF router-id.',
        ruleId: 'CUM-LO-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Loopback has IP address configured.',
      ruleId: 'CUM-LO-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// ============================================================================
// Export all Cumulus rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// ============================================================================

export const allCumulusRules: IRule[] = [
  // Interface rules
  CumulusInterfaceDescription,
  // Bridge rules
  CumulusBridgeVlans,
  // BGP rules
  CumulusBgpRouterId,
];
