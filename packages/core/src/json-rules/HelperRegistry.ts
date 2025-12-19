// packages/core/src/json-rules/HelperRegistry.ts

/**
 * Helper Registry for JSON Rules
 *
 * Provides a registry of all helper functions available to JSON rules.
 * Helpers are organized by namespace (vendor) for clarity.
 * Vendor namespaces are derived dynamically from the helpers module.
 */

import * as helpers from '../helpers';
import { VENDOR_NAMESPACES as HELPER_VENDOR_NAMESPACES, getAllVendorModules } from '../helpers';

/**
 * Type representing any helper function.
 */
export type HelperFunction = (...args: unknown[]) => unknown;

/**
 * Vendor namespace containing helper functions.
 */
export type VendorHelpers = Record<string, HelperFunction>;

/**
 * Vendor namespaces for helper organization.
 * Dynamically derived from the helpers module - single source of truth.
 */
export const VENDOR_NAMESPACES = HELPER_VENDOR_NAMESPACES;

export type VendorNamespace = (typeof VENDOR_NAMESPACES)[number];

/**
 * Complete helper registry with common helpers and vendor namespaces.
 * Vendor properties are dynamically typed based on VendorNamespace.
 */
export type HelperRegistry = {
    // Common helpers (no namespace required)
    [key: string]: HelperFunction | VendorHelpers;
} & {
    // Vendor namespaces - dynamically typed from VendorNamespace
    [K in VendorNamespace]: VendorHelpers;
};

/**
 * Extract only function exports from a module object.
 */
function extractFunctions(module: Record<string, unknown>): VendorHelpers {
    const result: VendorHelpers = {};
    for (const [key, value] of Object.entries(module)) {
        if (typeof value === 'function') {
            result[key] = value as HelperFunction;
        }
    }
    return result;
}

/**
 * Create a helper registry with all available helpers.
 * Common helpers are available at the top level.
 * Vendor-specific helpers are namespaced (e.g., "cisco.isTrunkPort").
 */
export function createHelperRegistry(): HelperRegistry {
    // Extract common helpers (these are re-exported at the top level)
    const commonHelpers = extractFunctions(helpers as unknown as Record<string, unknown>);

    // Get all vendor modules dynamically
    const vendorModules = getAllVendorModules();

    // Build registry with common helpers and vendor namespaces
    const registry = { ...commonHelpers } as HelperRegistry;

    // Add each vendor namespace dynamically
    for (const namespace of VENDOR_NAMESPACES) {
        const vendorModule = vendorModules[namespace];
        if (vendorModule) {
            registry[namespace] = extractFunctions(vendorModule as unknown as Record<string, unknown>);
        }
    }

    return registry;
}

/**
 * Resolve a helper function by name.
 * Supports both flat names (e.g., "hasChildCommand") and
 * namespaced names (e.g., "cisco.isTrunkPort").
 *
 * @param registry The helper registry
 * @param helperName The helper name to resolve
 * @returns The helper function, or undefined if not found
 */
export function resolveHelper(
    registry: HelperRegistry,
    helperName: string
): HelperFunction | undefined {
    // Check for namespaced helper (e.g., "cisco.isTrunkPort")
    if (helperName.includes('.')) {
        const [namespace, name] = helperName.split('.', 2);
        if (!namespace || !name) return undefined;

        const vendorHelpers = registry[namespace];
        if (vendorHelpers && typeof vendorHelpers === 'object') {
            const helper = vendorHelpers[name];
            return typeof helper === 'function' ? helper : undefined;
        }
        return undefined;
    }

    // Try common helpers at top level
    const helper = registry[helperName];
    if (typeof helper === 'function') {
        return helper;
    }

    return undefined;
}

/**
 * Get a list of all available helper names.
 * Useful for validation and documentation.
 *
 * @param registry The helper registry
 * @returns Array of helper names (both flat and namespaced)
 */
export function getAvailableHelpers(registry: HelperRegistry): string[] {
    const helpers: string[] = [];

    // Add common helpers
    for (const [key, value] of Object.entries(registry)) {
        if (typeof value === 'function') {
            helpers.push(key);
        }
    }

    // Add namespaced helpers
    for (const namespace of VENDOR_NAMESPACES) {
        const vendorHelpers = registry[namespace];
        if (vendorHelpers && typeof vendorHelpers === 'object') {
            for (const key of Object.keys(vendorHelpers)) {
                helpers.push(`${namespace}.${key}`);
            }
        }
    }

    return helpers.sort();
}

/**
 * Check if a helper name exists in the registry.
 *
 * @param registry The helper registry
 * @param helperName The helper name to check
 * @returns true if the helper exists
 */
export function hasHelper(registry: HelperRegistry, helperName: string): boolean {
    return resolveHelper(registry, helperName) !== undefined;
}

// Singleton registry instance for performance
let cachedRegistry: HelperRegistry | null = null;

/**
 * Get the global helper registry (cached for performance).
 */
export function getHelperRegistry(): HelperRegistry {
    if (!cachedRegistry) {
        cachedRegistry = createHelperRegistry();
    }
    return cachedRegistry;
}

/**
 * Clear the cached registry (useful for testing).
 */
export function clearHelperRegistryCache(): void {
    cachedRegistry = null;
}
