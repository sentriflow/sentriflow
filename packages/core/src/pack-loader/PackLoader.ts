// packages/core/src/pack-loader/PackLoader.ts

/**
 * SEC-012: Encrypted Rule Pack Loader
 *
 * TIERED EXECUTION MODEL:
 * 1. LOAD-TIME (VM Sandboxed): Decrypt, validate expiry/license, extract rule definitions
 * 2. RUNTIME (Native): Compile check functions natively for high-performance execution
 *
 * Security model:
 * - Pack is encrypted with AES-256-GCM (authenticated encryption)
 * - Only valid license key holders can decrypt
 * - Self-validation (expiry check) runs in VM sandbox
 * - After validation, rules are compiled natively for performance
 */

import { createDecipheriv, pbkdf2Sync } from 'crypto';
import { createContext, Script, type Context as VMContext } from 'vm';
import {
    PackLoadError,
    type PackLoadOptions,
    type LoadedPack,
    type LicenseInfo,
    GRPX_CONSTANTS,
} from './types';
import type { IRule, RuleMetadata, RuleVendor, RulePackMetadata } from '../types/IRule';
import type { ConfigNode } from '../types/ConfigNode';
import type { Context } from '../types/IRule';

// Import all rule helpers for injection into compiled check functions
import * as helpers from '../helpers';
import { getAllVendorModules } from '../helpers';

/**
 * All rule helpers merged into a single object for injection.
 * This allows compiled check functions to access helpers by name.
 * Dynamically built from the helpers module.
 *
 * IMPORTANT: Vendor modules may have colliding helper names (e.g., both Cisco
 * and Cumulus export `hasBgpNeighborPassword` with different signatures).
 * To handle this:
 * 1. Vendor namespaces are added (e.g., `cisco.hasBgpNeighborPassword`)
 * 2. For flat/short names, FIRST vendor wins (no overwrites)
 *
 * Rules should use namespaced helpers for vendor-specific functions.
 */
function buildAllHelpers(): Record<string, unknown> {
    const result: Record<string, unknown> = { ...helpers };
    const vendorModules = getAllVendorModules();

    for (const [name, module] of Object.entries(vendorModules)) {
        // Add the entire vendor module under its namespace
        // e.g., result.cisco = { hasBgpNeighborPassword, getBgpNeighbors, ... }
        result[name] = module;

        // Add flat/short names ONLY if not already present (first vendor wins)
        // This prevents Cumulus from overwriting Cisco's hasBgpNeighborPassword
        for (const [key, value] of Object.entries(module as Record<string, unknown>)) {
            if (!(key in result)) {
                result[key] = value;
            }
        }
    }
    return result;
}

const allHelpers = buildAllHelpers();

/**
 * Intermediate result from VM execution.
 * Rules have serialized check functions that will be compiled natively.
 */
interface VMPackResult {
    metadata: RulePackMetadata;
    rules: Array<{
        id: string;
        selector?: string;
        vendor?: string | string[];
        metadata: RuleMetadata;
        checkSource: string; // Serialized function source from trusted pack
    }>;
    validUntil: string;
    licenseInfo?: LicenseInfo | null;
}

/**
 * Loads and validates an encrypted rule pack (.grpx).
 *
 * @param packData - The encrypted pack file contents
 * @param options - Load options including license key
 * @returns Promise resolving to the loaded pack with rules
 * @throws PackLoadError if loading fails
 */
export async function loadEncryptedPack(
    packData: Buffer,
    options: PackLoadOptions
): Promise<LoadedPack> {
    const { licenseKey, machineId, getActivationCount, timeout = 5000 } = options;

    // ========== PHASE 1: DECRYPT ==========
    if (packData.length < GRPX_CONSTANTS.HEADER_SIZE) {
        throw new PackLoadError('INVALID_FORMAT', 'Pack file too small');
    }

    const magic = packData.toString('utf8', 0, 4);
    if (magic !== GRPX_CONSTANTS.MAGIC) {
        throw new PackLoadError('INVALID_FORMAT', 'Invalid pack format (bad magic)');
    }

    const version = packData.readUInt8(4);
    const algorithm = packData.readUInt8(5);
    const kdf = packData.readUInt8(6);
    // bytes 7-11 are reserved
    const iv = packData.subarray(12, 24);
    const tag = packData.subarray(24, 40);
    const salt = packData.subarray(40, 72);
    const payloadLength = packData.readUInt32BE(72);
    const encryptedPayload = packData.subarray(
        GRPX_CONSTANTS.HEADER_SIZE,
        GRPX_CONSTANTS.HEADER_SIZE + payloadLength
    );

    if (version !== GRPX_CONSTANTS.CURRENT_VERSION) {
        throw new PackLoadError('INVALID_FORMAT', `Unsupported version: ${version}`);
    }

    if (algorithm !== GRPX_CONSTANTS.ALG_AES_256_GCM) {
        throw new PackLoadError('INVALID_FORMAT', `Unsupported algorithm: ${algorithm}`);
    }

    // Derive key from license key
    let key: Buffer;
    if (kdf === GRPX_CONSTANTS.KDF_PBKDF2) {
        key = pbkdf2Sync(
            licenseKey,
            salt,
            GRPX_CONSTANTS.PBKDF2_ITERATIONS,
            GRPX_CONSTANTS.KEY_LENGTH,
            'sha256'
        );
    } else {
        throw new PackLoadError('INVALID_FORMAT', `Unsupported KDF: ${kdf}`);
    }

    // Decrypt the payload
    let decryptedSource: string;
    try {
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([
            decipher.update(encryptedPayload),
            decipher.final(),
        ]);
        decryptedSource = decrypted.toString('utf8');
    } catch (error) {
        // Log decryption failure category (not key or payload details)
        const errorType = error instanceof Error ? error.name : 'Unknown';
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';

        // Only log in debug mode to avoid information leakage
        if (process.env.DEBUG) {
            console.error(`[PackLoader] Decryption failed: ${errorType} - ${errorMsg}`);
        }

        throw new PackLoadError(
            'DECRYPTION_FAILED',
            'Invalid license key or corrupted pack'
        );
    }

    // ========== PHASE 2: VM VALIDATION (Sandboxed) ==========
    // Execute factory in sandbox to validate expiry, machine ID, etc.
    const sandbox = createValidationSandbox({ machineId, getActivationCount });
    const context = createContext(sandbox);

    let vmResult: VMPackResult;
    try {
        const script = new Script(decryptedSource, {
            filename: 'pack.js',
            timeout,
        } as { filename: string; timeout: number });
        const factory = script.runInContext(context) as (ctx: typeof sandbox) => VMPackResult;
        vmResult = factory(sandbox);

        if (!vmResult || !Array.isArray(vmResult.rules)) {
            throw new PackLoadError('VALIDATION_FAILED', 'Invalid pack structure');
        }
    } catch (error) {
        if (error instanceof PackLoadError) {
            throw error;
        }
        const msg = error instanceof Error ? error.message : String(error);
        if (msg.includes('EXPIRED')) {
            throw new PackLoadError('EXPIRED', msg);
        }
        if (msg.includes('MACHINE_MISMATCH')) {
            throw new PackLoadError('MACHINE_MISMATCH', msg);
        }
        if (msg.includes('ACTIVATION_LIMIT')) {
            throw new PackLoadError('ACTIVATION_LIMIT', msg);
        }
        throw new PackLoadError('VALIDATION_FAILED', msg);
    }

    // ========== PHASE 3: NATIVE COMPILATION ==========
    // Convert serialized check functions to native functions.
    // This happens OUTSIDE the sandbox for full performance.
    //
    // SECURITY JUSTIFICATION for dynamic function compilation:
    // - The code originated from our trusted pack-builder tool
    // - It was encrypted with AES-256-GCM (authenticated, tamper-proof)
    // - Only holders of the valid license key can decrypt it
    // - The GCM auth tag ensures the payload wasn't modified
    // - This is equivalent to loading a signed plugin/extension
    const nativeRules: IRule[] = vmResult.rules.map(ruleDef => {
        const checkFn = compileNativeCheckFunction(ruleDef.checkSource);
        return {
            id: ruleDef.id,
            selector: ruleDef.selector,
            vendor: ruleDef.vendor as RuleVendor | RuleVendor[] | undefined,
            metadata: ruleDef.metadata,
            check: checkFn,
        };
    });

    return {
        metadata: vmResult.metadata,
        rules: nativeRules,
        validUntil: vmResult.validUntil,
        licenseInfo: vmResult.licenseInfo ?? undefined,
    };
}

/**
 * Generate helper names list for destructuring.
 * Cached to avoid recomputing on every function compilation.
 *
 * Includes:
 * - All function helpers (flat names)
 * - All vendor namespace objects (e.g., cisco, cumulus)
 */
const helperNames = Object.keys(allHelpers).filter(
    key => typeof allHelpers[key] === 'function' || typeof allHelpers[key] === 'object'
);
const helperDestructure = helperNames.join(', ');

/**
 * Compile a serialized check function to a native function.
 *
 * NOTE: This intentionally uses dynamic function compilation for performance.
 * See SECURITY JUSTIFICATION in loadEncryptedPack() above.
 *
 * The function is wrapped to inject all rule helpers into scope, allowing
 * serialized check functions to use helpers like hasChildCommand, findStanza, etc.
 *
 * @public Exported for use by GRX2ExtendedLoader
 */
export function compileNativeCheckFunction(
    source: string
): (node: ConfigNode, ctx: Context) => ReturnType<IRule['check']> {
    // The source is trusted (from authenticated encrypted pack)
    // Wrap the function to inject helpers into scope via destructuring
    // This allows the original function to reference helpers by name
    const wrappedSource = `
        (function(__helpers__) {
            const { ${helperDestructure} } = __helpers__;
            return (${source});
        })
    `;

    // Compile the wrapper and immediately invoke with helpers
    const wrapperFn = (0, eval)(wrappedSource) as (helpers: Record<string, unknown>) => IRule['check'];
    const compiledFn = wrapperFn(allHelpers);

    return compiledFn as IRule['check'];
}

/**
 * Create a minimal sandbox for validation phase only.
 * This sandbox is intentionally restricted to prevent malicious code execution.
 */
function createValidationSandbox(options: {
    machineId?: string;
    getActivationCount?: (packName: string) => number;
}): Record<string, unknown> {
    const RealDate = Date;
    return Object.freeze({
        // Safe Date access (read-only, can't be mocked)
        Date: Object.freeze({
            now: () => RealDate.now(),
            parse: (s: string) => RealDate.parse(s),
        }),
        // Safe JSON access
        JSON: Object.freeze({
            parse: JSON.parse,
            stringify: JSON.stringify,
        }),
        // Safe Math access
        Math: Object.freeze(Math),
        // No-op console (for debugging in pack factory)
        console: Object.freeze({
            log: () => {},
            warn: () => {},
            error: () => {},
        }),
        // Provided context for validation
        machineId: options.machineId,
        getActivationCount: options.getActivationCount,
        // Basic primitives
        undefined,
        null: null,
        NaN,
        Infinity,
        // Required for error throwing in factory
        Error,
    });
}

/**
 * Validate that a pack file has the correct format without decrypting.
 * Useful for quick format checks before attempting full load.
 *
 * @param packData - The pack file contents
 * @returns true if the format appears valid
 */
export function validatePackFormat(packData: Buffer): boolean {
    if (packData.length < GRPX_CONSTANTS.HEADER_SIZE) {
        return false;
    }

    const magic = packData.toString('utf8', 0, 4);
    if (magic !== GRPX_CONSTANTS.MAGIC) {
        return false;
    }

    const version = packData.readUInt8(4);
    if (version !== GRPX_CONSTANTS.CURRENT_VERSION) {
        return false;
    }

    const algorithm = packData.readUInt8(5);
    if (algorithm !== GRPX_CONSTANTS.ALG_AES_256_GCM) {
        return false;
    }

    const kdf = packData.readUInt8(6);
    if (kdf !== GRPX_CONSTANTS.KDF_PBKDF2) {
        return false;
    }

    const payloadLength = packData.readUInt32BE(72);
    if (packData.length < GRPX_CONSTANTS.HEADER_SIZE + payloadLength) {
        return false;
    }

    return true;
}
