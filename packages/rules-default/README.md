# @sentriflow/rules-default

Default validation rules for SentriFlow network configuration linter.

## Overview

This package provides a **starter set of validation rules** demonstrating how to write rules for SentriFlow. These rules cover common security, policy, and network configuration patterns but are **not intended to be a comprehensive ruleset**.

Use these rules as:
- A starting point for your own validation rules
- Examples of rule structure and patterns
- A reference for using `@sentriflow/rule-helpers`

For production environments, you should extend these with rules specific to your organization's policies and compliance requirements.

## Installation

```bash
npm install @sentriflow/rules-default
# or
bun add @sentriflow/rules-default
```

## Usage

```typescript
import { validate } from '@sentriflow/core';
import { defaultRules, securityRules, complianceRules } from '@sentriflow/rules-default';

// Use all default rules
const results = validate(ast, defaultRules);

// Or use specific rule categories
const securityResults = validate(ast, securityRules);
```

## Rule Categories

### Security Rules (SEC-XXX)

| Rule ID | Description |
|---------|-------------|
| SEC-001 | Telnet enabled - use SSH |
| SEC-002 | Weak password encryption |
| SEC-003 | No enable secret configured |
| SEC-004 | HTTP server enabled |
| SEC-005 | No AAA authentication |
| SEC-006 | Insecure SNMP community |
| SEC-007 | No logging configured |

### Network Rules (NET-XXX)

| Rule ID | Description |
|---------|-------------|
| NET-001 | Interface without description |
| NET-002 | No CDP/LLDP on uplinks |
| NET-003 | Inconsistent MTU settings |
| NET-004 | No BFD on routing peers |
| NET-005 | Missing route summarization |

### Compliance Rules (CMP-XXX)

| Rule ID | Description |
|---------|-------------|
| CMP-001 | Banner missing |
| CMP-002 | NTP not configured |
| CMP-003 | Syslog not configured |
| CMP-004 | No access-class on VTY |
| CMP-005 | Password complexity |

## Customizing Rules

### Disable Specific Rules

```typescript
import { defaultRules } from '@sentriflow/rules-default';

const customRules = defaultRules.filter(rule =>
  rule.id !== 'NET-001' // Disable interface description check
);
```

### Override Rule Severity

```typescript
import { defaultRules } from '@sentriflow/rules-default';

const customRules = defaultRules.map(rule => {
  if (rule.id === 'SEC-001') {
    return { ...rule, severity: 'warning' };
  }
  return rule;
});
```

## Creating Custom Rules

See the [rule development guide](https://github.com/sentriflow/sentriflow/tree/main/docs/rules.md) and the [templates](https://github.com/sentriflow/sentriflow/tree/main/templates) for creating your own rule packs.

## Related Packages

- [`@sentriflow/core`](https://github.com/sentriflow/sentriflow/tree/main/packages/core) - Core parsing engine
- [`@sentriflow/rule-helpers`](https://github.com/sentriflow/sentriflow/tree/main/packages/rule-helpers) - Helper functions for rule development
- [`@sentriflow/cli`](https://github.com/sentriflow/sentriflow/tree/main/packages/cli) - Command-line interface

## License

Apache-2.0
