// packages/rule-helpers/src/fortinet/index.ts
// Re-export all Fortinet FortiGate helpers

export * from './helpers';

// Also re-export commonly used common helpers for convenience
export {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
  parseIp,
} from '../common/helpers';
