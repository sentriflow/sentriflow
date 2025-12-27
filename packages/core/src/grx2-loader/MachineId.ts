/**
 * Machine ID Module
 *
 * Provides cross-platform machine identification for license binding.
 * Uses node-machine-id library which derives a stable machine ID from OS-native identifiers.
 *
 * Security Notes:
 * - Machine ID is used as additional binding in key derivation, NOT as the primary salt
 * - Random cryptographic salt is always used for PBKDF2 (stored in wrapped TMK)
 * - Empty machine ID is allowed for portable packs (no device binding)
 *
 * @module @sentriflow/core/grx2-loader/MachineId
 */

import { machineId, machineIdSync } from 'node-machine-id';

/**
 * Get the machine identifier asynchronously
 *
 * Returns a unique machine ID derived from the operating system.
 * The ID is stable across reboots but may change if the OS is reinstalled.
 *
 * @returns Promise resolving to machine ID string
 *
 * @example
 * ```typescript
 * const mid = await getMachineId();
 * console.log(`Machine ID: ${mid}`);
 * ```
 */
export async function getMachineId(): Promise<string> {
  return machineId();
}

/**
 * Get the machine identifier synchronously
 *
 * Returns a unique machine ID derived from the operating system.
 * Prefer async version when possible.
 *
 * @returns Machine ID string
 *
 * @example
 * ```typescript
 * const mid = getMachineIdSync();
 * console.log(`Machine ID: ${mid}`);
 * ```
 */
export function getMachineIdSync(): string {
  return machineIdSync();
}
