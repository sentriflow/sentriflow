/**
 * Pack Provider System
 *
 * Provides registration and access to pack providers:
 * - Default: Local file-based pack loading
 * - Custom: Cloud licensing via @sentriflow/licensing
 *
 * @module pack-provider
 */

export * from './PackProvider';
export { LocalPackProvider, createLocalPackProvider } from './LocalPackProvider';

import type { IPackProvider } from './PackProvider';
import { LocalPackProvider } from './LocalPackProvider';

/**
 * Currently registered pack provider
 * Default: null (uses legacy local loading)
 */
let currentProvider: IPackProvider | null = null;

/**
 * Set the global pack provider
 *
 * This allows replacing the default local pack loading with
 * cloud-based providers from @sentriflow/licensing.
 *
 * @param provider - The pack provider to use
 *
 * @example
 * ```typescript
 * import { setPackProvider } from '@sentriflow/core';
 * import { CloudPackProvider } from '@sentriflow/licensing';
 *
 * // Enable cloud licensing
 * const cloudProvider = new CloudPackProvider({
 *   licenseKey: 'XXXX-XXXX-XXXX-XXXX',
 *   apiUrl: 'https://api.sentriflow.dev',
 * });
 * setPackProvider(cloudProvider);
 * ```
 */
export function setPackProvider(provider: IPackProvider): void {
  // Clean up previous provider if it has a destroy method
  if (currentProvider?.destroy) {
    currentProvider.destroy();
  }

  currentProvider = provider;
}

/**
 * Get the current pack provider
 *
 * Returns the registered provider, or null if using legacy loading.
 *
 * @returns The current pack provider or null
 */
export function getPackProvider(): IPackProvider | null {
  return currentProvider;
}

/**
 * Check if a custom pack provider is registered
 *
 * @returns true if a custom provider is set
 */
export function hasPackProvider(): boolean {
  return currentProvider !== null;
}

/**
 * Clear the current pack provider
 *
 * Resets to using legacy local pack loading.
 * Calls destroy() on the current provider if available.
 */
export function clearPackProvider(): void {
  if (currentProvider?.destroy) {
    currentProvider.destroy();
  }
  currentProvider = null;
}

/**
 * Create and set a local pack provider
 *
 * Convenience function to create a LocalPackProvider and set it
 * as the current provider.
 *
 * @param options - Provider options
 * @returns The created LocalPackProvider
 *
 * @example
 * ```typescript
 * import { createAndSetLocalProvider } from '@sentriflow/core';
 *
 * const provider = createAndSetLocalProvider({
 *   licenseKey: 'XXXX-XXXX-XXXX-XXXX',
 *   packPaths: ['./rules/custom.grpx'],
 * });
 *
 * const packs = await provider.loadPacks();
 * ```
 */
export function createAndSetLocalProvider(options: {
  licenseKey: string;
  packPaths: string[];
  machineId?: string;
  strict?: boolean;
}): LocalPackProvider {
  const provider = new LocalPackProvider(options);
  setPackProvider(provider);
  return provider;
}
