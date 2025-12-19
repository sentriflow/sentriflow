// packages/core/src/helpers/index.ts
/**
 * Rule Helpers Module
 *
 * Provides vendor-specific and common helper functions for rule authoring.
 * Vendor namespaces are dynamically detected - add a new vendor by creating
 * a directory with index.ts and adding an export below.
 */

// Re-export all common helpers at top level
export * from './common';

// Vendor modules as namespaces
import * as arista from './arista';
import * as aruba from './aruba';
import * as cisco from './cisco';
import * as cumulus from './cumulus';
import * as extreme from './extreme';
import * as fortinet from './fortinet';
import * as huawei from './huawei';
import * as juniper from './juniper';
import * as mikrotik from './mikrotik';
import * as nokia from './nokia';
import * as paloalto from './paloalto';
import * as vyos from './vyos';

// Export vendor namespaces
export { arista, aruba, cisco, cumulus, extreme, fortinet, huawei, juniper, mikrotik, nokia, paloalto, vyos };

// Dynamically derive vendor namespaces from exports
const vendorModules = { arista, aruba, cisco, cumulus, extreme, fortinet, huawei, juniper, mikrotik, nokia, paloalto, vyos };

/**
 * List of all vendor namespace names, derived from actual exports.
 * Add a new vendor by importing it above and adding to vendorModules.
 */
export const VENDOR_NAMESPACES = Object.keys(vendorModules) as ReadonlyArray<keyof typeof vendorModules>;

export type VendorNamespace = keyof typeof vendorModules;

/**
 * Get a vendor module by name.
 */
export function getVendorModule(name: VendorNamespace): typeof vendorModules[typeof name] {
    return vendorModules[name];
}

/**
 * Get all vendor modules as a record.
 */
export function getAllVendorModules(): typeof vendorModules {
    return vendorModules;
}
