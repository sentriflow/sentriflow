// packages/core/src/index.ts

export * from './types/ConfigNode';
export * from './types/IRule';
export * from './parser/SchemaAwareParser';
export * from './parser/IncrementalParser';
export * from './parser/VendorSchema';
export * from './parser/vendors';
export * from './engine/Runner';
export * from './engine/RuleExecutor';
export * from './parser/Sanitizer';
export * from './constants';
export * from './errors';

// SEC-012: Encrypted rule pack loader
export * from './pack-loader';

// Pack Provider abstraction for cloud licensing extension
export * from './pack-provider';

// GRX2 Extended Pack Loader - for CLI and VS Code extension
export * from './grx2-loader';

// SEC-001: Declarative rules and sandboxed execution
export * from './types/DeclarativeRule';
export * from './engine/SandboxedExecutor';

// JSON Rules - third-party rule authoring without TypeScript
export * from './json-rules';

// Rule Helpers - vendor-specific and common helper functions
export * as helpers from './helpers';
export { VENDOR_NAMESPACES, type VendorNamespace, getAllVendorModules, getVendorModule } from './helpers';

// Re-export common helpers at top level for convenience
export * from './helpers/common';

// IP/Subnet extraction module
export * from './ip';
