// packages/rule-helpers/src/huawei/index.ts
// Re-export all Huawei VRP helpers

export * from './helpers';

// Also re-export commonly used common helpers for convenience
export {
  hasChildCommand,
  getChildCommand,
  getChildCommands,
} from '../common/helpers';
