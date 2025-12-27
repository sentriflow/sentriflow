/**
 * GRX2 Extended Pack Loader
 *
 * Re-exports loader functions from @sentriflow/core/grx2-loader.
 * The implementation is now in core for shared use by CLI and VS Code extension.
 *
 * @module encryption/GRX2ExtendedLoader
 */

// Re-export all loader functions from core
export {
  isExtendedGRX2,
  loadExtendedPack,
  loadAllPacks,
  getPackInfo,
} from '@sentriflow/core/grx2-loader';

// Re-export machine ID functions for convenience
export {
  getMachineId,
  getMachineIdSync,
} from '@sentriflow/core/grx2-loader';
