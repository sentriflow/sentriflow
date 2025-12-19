// packages/rule-helpers/src/cisco/index.ts
// Re-export all Cisco helpers

export * from './helpers';

// Also re-export commonly used common helpers for convenience
export {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
} from '../common/helpers';
