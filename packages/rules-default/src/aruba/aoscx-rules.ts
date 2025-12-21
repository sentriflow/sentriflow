// packages/rules-default/src/aruba/aoscx-rules.ts
// Aruba AOS-CX specific rules for CX series switches

import type { IRule, ConfigNode, RuleResult, Context } from '@sentriflow/core';
import { parseInteger, isDefaultVlan } from '@sentriflow/core';
import {
  hasChildCommand,
  getChildCommand,
  getInterfaceName,
  isAosCxPhysicalPort,
  isAosCxTrunk,
  isAosCxAccess,
  getAosCxVlanAccess,
  getAosCxTrunkAllowed,
  getAosCxTrunkNative,
  hasAosCxBpduGuard,
  isAosCxEdgePort,
  isAosCxLag,
  isAosCxVlanInterface,
  hasDescription,
  isShutdown,
} from '@sentriflow/core/helpers/aruba';

// =============================================================================
// Interface Rules
// =============================================================================

/**
 * AOSCX-IF-001: Physical interfaces should have descriptions.
 */
export const AosCxInterfaceDescription: IRule = {
  id: 'AOSCX-IF-001',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a description to physical interfaces for documentation.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-IF-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports and LAGs
    if (!isAosCxPhysicalPort(ifName) && !isAosCxLag(ifName)) {
      return { passed: true, message: 'Not a physical interface.', ruleId: 'AOSCX-IF-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Skip shutdown interfaces
    if (isShutdown(node)) {
      return { passed: true, message: 'Interface is shutdown.', ruleId: 'AOSCX-IF-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!hasDescription(node)) {
      return {
        passed: false,
        message: `Interface ${ifName} missing description.`,
        ruleId: 'AOSCX-IF-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Interface has description.',
      ruleId: 'AOSCX-IF-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Layer 2 Rules
// =============================================================================

/**
 * AOSCX-L2-001: Trunk ports must have allowed VLANs explicitly configured.
 */
export const AosCxTrunkAllowedVlans: IRule = {
  id: 'AOSCX-L2-001',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "vlan trunk allowed <vlans>" on trunk interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-L2-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports and LAGs
    if (!isAosCxPhysicalPort(ifName) && !isAosCxLag(ifName)) {
      return { passed: true, message: 'Not a switchport interface.', ruleId: 'AOSCX-L2-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if it's a trunk
    if (!isAosCxTrunk(node)) {
      return { passed: true, message: 'Not a trunk port.', ruleId: 'AOSCX-L2-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const allowedVlans = getAosCxTrunkAllowed(node);
    if (allowedVlans.length === 0) {
      return {
        passed: false,
        message: `Trunk interface ${ifName} has no allowed VLANs configured.`,
        ruleId: 'AOSCX-L2-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Trunk interface has ${allowedVlans.length} VLANs allowed.`,
      ruleId: 'AOSCX-L2-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSCX-L2-002: Access ports must have a VLAN assigned (not default VLAN 1).
 */
export const AosCxAccessVlanAssigned: IRule = {
  id: 'AOSCX-L2-002',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "vlan access <vlan-id>" with a non-default VLAN.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports
    if (!isAosCxPhysicalPort(ifName)) {
      return { passed: true, message: 'Not a physical switchport.', ruleId: 'AOSCX-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Skip trunk ports
    if (isAosCxTrunk(node)) {
      return { passed: true, message: 'Port is a trunk.', ruleId: 'AOSCX-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Skip shutdown interfaces
    if (isShutdown(node)) {
      return { passed: true, message: 'Interface is shutdown.', ruleId: 'AOSCX-L2-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const vlanId = getAosCxVlanAccess(node);
    if (vlanId === null) {
      return {
        passed: false,
        message: `Access port ${ifName} has no VLAN assigned.`,
        ruleId: 'AOSCX-L2-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    if (vlanId === 1) {
      return {
        passed: false,
        message: `Access port ${ifName} is on default VLAN 1. Consider using a dedicated VLAN.`,
        ruleId: 'AOSCX-L2-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: `Access port is assigned to VLAN ${vlanId}.`,
      ruleId: 'AOSCX-L2-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSCX-L2-003: Native VLAN on trunks should not be VLAN 1.
 */
export const AosCxNativeVlanNotDefault: IRule = {
  id: 'AOSCX-L2-003',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'SecOps',
    remediation: 'Change native VLAN from default VLAN 1 to prevent VLAN hopping attacks.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-L2-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports and LAGs
    if (!isAosCxPhysicalPort(ifName) && !isAosCxLag(ifName)) {
      return { passed: true, message: 'Not a switchport interface.', ruleId: 'AOSCX-L2-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if it's a trunk
    if (!isAosCxTrunk(node)) {
      return { passed: true, message: 'Not a trunk port.', ruleId: 'AOSCX-L2-003', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const nativeVlan = getAosCxTrunkNative(node);
    if (nativeVlan === 1) {
      return {
        passed: false,
        message: `Trunk interface ${ifName} uses default native VLAN 1.`,
        ruleId: 'AOSCX-L2-003',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: nativeVlan ? `Native VLAN is ${nativeVlan}.` : 'Native VLAN checked.',
      ruleId: 'AOSCX-L2-003',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Spanning Tree Rules
// =============================================================================

/**
 * AOSCX-STP-001: Edge ports should have BPDU guard enabled.
 */
export const AosCxBpduGuardOnEdge: IRule = {
  id: 'AOSCX-STP-001',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Security',
    owner: 'NetOps',
    remediation: 'Enable "spanning-tree bpdu-guard" on edge ports to prevent rogue switches.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-STP-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports
    if (!isAosCxPhysicalPort(ifName)) {
      return { passed: true, message: 'Not a physical switchport.', ruleId: 'AOSCX-STP-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if it's an edge port
    if (!isAosCxEdgePort(node)) {
      return { passed: true, message: 'Not an edge port.', ruleId: 'AOSCX-STP-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Edge port should have BPDU guard
    if (!hasAosCxBpduGuard(node)) {
      return {
        passed: false,
        message: `Edge port ${ifName} does not have BPDU guard enabled.`,
        ruleId: 'AOSCX-STP-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Edge port has BPDU guard enabled.',
      ruleId: 'AOSCX-STP-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSCX-STP-002: Access ports should be edge ports.
 */
export const AosCxAccessPortEdge: IRule = {
  id: 'AOSCX-STP-002',
  selector: 'interface',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'info',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "spanning-tree port-type admin-edge" on access ports for faster convergence.',
  },
  check: (node: ConfigNode): RuleResult => {
    const ifName = getInterfaceName(node);
    if (!ifName) {
      return { passed: true, message: 'Not an interface.', ruleId: 'AOSCX-STP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Only check physical ports
    if (!isAosCxPhysicalPort(ifName)) {
      return { passed: true, message: 'Not a physical switchport.', ruleId: 'AOSCX-STP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Check if it's an access port
    if (!isAosCxAccess(node)) {
      return { passed: true, message: 'Not an access port.', ruleId: 'AOSCX-STP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    // Skip shutdown interfaces
    if (isShutdown(node)) {
      return { passed: true, message: 'Interface is shutdown.', ruleId: 'AOSCX-STP-002', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!isAosCxEdgePort(node)) {
      return {
        passed: false,
        message: `Access port ${ifName} should be configured as edge port.`,
        ruleId: 'AOSCX-STP-002',
        nodeId: node.id,
        level: 'info',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'Access port is configured as edge.',
      ruleId: 'AOSCX-STP-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// VLAN Rules
// =============================================================================

/**
 * AOSCX-VLAN-001: VLANs should have names.
 */
export const AosCxVlanName: IRule = {
  id: 'AOSCX-VLAN-001',
  selector: 'vlan',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Add a name to VLANs for documentation.',
  },
  check: (node: ConfigNode): RuleResult => {
    const match = node.id.match(/vlan\s+(\d+)/i);
    const vlanIdStr = match?.[1];
    if (!vlanIdStr) {
      return { passed: true, message: 'Not a VLAN definition.', ruleId: 'AOSCX-VLAN-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    const vlanId = parseInteger(vlanIdStr);

    // Skip VLAN 1 (default)
    if (vlanId === null || isDefaultVlan(vlanId)) {
      return { passed: true, message: 'Default VLAN 1.', ruleId: 'AOSCX-VLAN-001', nodeId: node.id, level: 'info', loc: node.loc };
    }

    if (!hasChildCommand(node, 'name')) {
      return {
        passed: false,
        message: `VLAN ${vlanId} has no name configured.`,
        ruleId: 'AOSCX-VLAN-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'VLAN has a name.',
      ruleId: 'AOSCX-VLAN-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Routing Rules
// =============================================================================

/**
 * AOSCX-ROUTE-001: OSPF must have router-id configured.
 */
export const AosCxOspfRouterId: IRule = {
  id: 'AOSCX-ROUTE-001',
  selector: 'router ospf',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure an explicit router-id under the OSPF process.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasChildCommand(node, 'router-id')) {
      return {
        passed: false,
        message: 'OSPF process missing explicit router-id.',
        ruleId: 'AOSCX-ROUTE-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'OSPF has router-id configured.',
      ruleId: 'AOSCX-ROUTE-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

/**
 * AOSCX-ROUTE-002: BGP must have router-id configured.
 */
export const AosCxBgpRouterId: IRule = {
  id: 'AOSCX-ROUTE-002',
  selector: 'router bgp',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure an explicit router-id under the BGP process.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasChildCommand(node, 'router-id')) {
      return {
        passed: false,
        message: 'BGP process missing explicit router-id.',
        ruleId: 'AOSCX-ROUTE-002',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'BGP has router-id configured.',
      ruleId: 'AOSCX-ROUTE-002',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// LAG Rules
// =============================================================================

/**
 * AOSCX-LAG-001: LAG interfaces should use LACP.
 */
export const AosCxLagLacp: IRule = {
  id: 'AOSCX-LAG-001',
  selector: 'interface lag',
  vendor: 'aruba-aoscx',
  metadata: {
    level: 'warning',
    obu: 'Network Engineering',
    owner: 'NetOps',
    remediation: 'Configure "lacp mode active" or "lacp mode passive" on LAG interfaces.',
  },
  check: (node: ConfigNode): RuleResult => {
    if (!hasChildCommand(node, 'lacp mode')) {
      return {
        passed: false,
        message: 'LAG interface not using LACP. Consider enabling LACP for dynamic aggregation.',
        ruleId: 'AOSCX-LAG-001',
        nodeId: node.id,
        level: 'warning',
        loc: node.loc,
      };
    }

    return {
      passed: true,
      message: 'LAG is using LACP.',
      ruleId: 'AOSCX-LAG-001',
      nodeId: node.id,
      level: 'info',
      loc: node.loc,
    };
  },
};

// =============================================================================
// Export all AOS-CX rules - proof-of-concept subset
// NOTE: Additional rules available in sf-essentials
// =============================================================================

export const allAosCxRules: IRule[] = [
  // Interface
  AosCxInterfaceDescription,
  // Layer 2
  AosCxTrunkAllowedVlans,
];
