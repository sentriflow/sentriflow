// packages/core/src/pack-loader/types.ts

/**
 * SEC-012: Types for the encrypted rule pack system (Consumer API).
 *
 * This module provides types for LOADING encrypted rule packs.
 * For BUILDING packs, use the separate @sentriflow/pack-builder package.
 */

import type { IRule, RulePackMetadata } from '../types/IRule';

/**
 * Error codes for pack loading failures.
 */
export const PackLoadErrors = {
    INVALID_FORMAT: 'PACK_INVALID_FORMAT',
    DECRYPTION_FAILED: 'PACK_DECRYPTION_FAILED',
    VALIDATION_FAILED: 'PACK_VALIDATION_FAILED',
    EXPIRED: 'PACK_EXPIRED',
    MACHINE_MISMATCH: 'PACK_MACHINE_MISMATCH',
    ACTIVATION_LIMIT: 'PACK_ACTIVATION_LIMIT',
    EXECUTION_ERROR: 'PACK_EXECUTION_ERROR',
} as const;

export type PackLoadErrorCode = keyof typeof PackLoadErrors;

/**
 * Error thrown when loading an encrypted pack fails.
 */
export class PackLoadError extends Error {
    constructor(
        public readonly code: PackLoadErrorCode,
        message: string,
        public readonly details?: Record<string, unknown>
    ) {
        super(message);
        this.name = 'PackLoadError';
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}

/**
 * Options for loading an encrypted pack.
 */
export interface PackLoadOptions {
    /** The license key for decryption */
    licenseKey: string;
    /** Optional machine ID for node-locked licenses */
    machineId?: string;
    /** Optional callback to get current activation count */
    getActivationCount?: (packName: string) => number;
    /** Execution timeout in milliseconds (default: 5000) */
    timeout?: number;
}

/**
 * License information embedded in the pack.
 * Displayed to users to show their subscription details.
 */
export interface LicenseInfo {
    /** Customer name */
    customerName: string;
    /** Customer email */
    customerEmail: string;
    /** Company name (if provided) */
    company?: string;
    /** Contract/subscription ID (if provided) */
    contractId?: string;
    /** ISO date string when the license was activated */
    activatedAt: string;
    /** ISO date string when the license expires */
    expiresAt: string;
}

/**
 * Result of successfully loading an encrypted pack.
 */
export interface LoadedPack {
    /** Pack metadata */
    metadata: RulePackMetadata;
    /** Validated and ready-to-use rules */
    rules: IRule[];
    /** ISO date string of when the pack expires */
    validUntil: string;
    /** License information for display purposes */
    licenseInfo?: LicenseInfo;
}

/**
 * Encrypted rule pack file format (.grpx).
 *
 * Binary structure:
 * - magic: 4 bytes ("GRPX")
 * - version: 1 byte (format version)
 * - algorithm: 1 byte (1=AES-256-GCM)
 * - kdf: 1 byte (1=PBKDF2, 2=Argon2id)
 * - reserved: 5 bytes
 * - iv: 12 bytes
 * - tag: 16 bytes (GCM auth tag)
 * - salt: 32 bytes (KDF salt)
 * - payloadLength: 4 bytes (uint32 BE)
 * - encryptedPayload: variable length
 *
 * Total header: 76 bytes + payload
 */
export interface EncryptedPackHeader {
    magic: 'GRPX';
    version: number;
    algorithm: number;
    kdf: number;
    iv: Buffer;
    tag: Buffer;
    salt: Buffer;
    payloadLength: number;
}

/**
 * Constants for the encrypted pack format.
 * Shared between builder (@sentriflow/pack-builder) and loader (@sentriflow/core).
 */
export const GRPX_CONSTANTS = {
    MAGIC: 'GRPX',
    HEADER_SIZE: 76,
    CURRENT_VERSION: 1,
    ALG_AES_256_GCM: 1,
    KDF_PBKDF2: 1,
    KDF_ARGON2ID: 2,
    PBKDF2_ITERATIONS: 100000,
    KEY_LENGTH: 32,
    IV_LENGTH: 12,
    TAG_LENGTH: 16,
    SALT_LENGTH: 32,
} as const;
