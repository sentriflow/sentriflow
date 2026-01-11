// packages/vscode/src/providers/CustomRulesCompletionProvider.ts

/**
 * CustomRulesCompletionProvider - IntelliSense for custom JSON rules
 *
 * Provides auto-completion for:
 * - Vendor values (17 RuleVendor types)
 * - Rule properties (id, vendor, selector, metadata, check, etc.)
 * - Metadata properties (level, obu, owner, description, remediation)
 * - Check types (13 JsonCheck types)
 * - Helper function names with signatures
 */

import * as vscode from 'vscode';

// RuleVendor values from @sentriflow/core
const VENDORS = [
  'common',
  'cisco-ios',
  'cisco-nxos',
  'juniper-junos',
  'aruba-aoscx',
  'aruba-aosswitch',
  'aruba-wlc',
  'paloalto-panos',
  'arista-eos',
  'vyos',
  'fortinet-fortigate',
  'extreme-exos',
  'extreme-voss',
  'huawei-vrp',
  'mikrotik-routeros',
  'nokia-sros',
  'cumulus-linux',
] as const;

// Vendor namespaces for helper functions
const VENDOR_NAMESPACES = [
  'arista',
  'aruba',
  'cisco',
  'cumulus',
  'extreme',
  'fortinet',
  'huawei',
  'juniper',
  'mikrotik',
  'nokia',
  'paloalto',
  'vyos',
] as const;

// Common helper functions available in all vendors
const COMMON_HELPERS = [
  { name: 'hasChildCommand', signature: '(node, prefix: string): boolean', description: 'Check if a node has a specific child command' },
  { name: 'getChildCommand', signature: '(node, prefix: string): ConfigNode | undefined', description: 'Get a child command node if it exists' },
  { name: 'getChildCommands', signature: '(node, prefix: string): ConfigNode[]', description: 'Get all child commands matching a prefix' },
  { name: 'getParamValue', signature: '(node, keyword: string): string | undefined', description: 'Extract a parameter value from params array' },
  { name: 'isShutdown', signature: '(node): boolean', description: 'Check if interface is administratively shutdown' },
  { name: 'isInterfaceDefinition', signature: '(node): boolean', description: 'Check if node is an actual interface definition' },
  { name: 'parseIp', signature: '(addr: string): number | null', description: 'Parse IP address to 32-bit number' },
  { name: 'numToIp', signature: '(num: number): string', description: 'Convert 32-bit number to IP string' },
  { name: 'isValidIpAddress', signature: '(value: string): boolean', description: 'Check if string is valid IP address' },
  { name: 'isPrivateAddress', signature: '(ipNum: number): boolean', description: 'Check if IP is RFC 1918 private' },
  { name: 'isMulticastAddress', signature: '(ipNum: number): boolean', description: 'Check if IP is multicast (224-239)' },
  { name: 'isBroadcastAddress', signature: '(ipNum: number): boolean', description: 'Check if IP is 255.255.255.255' },
  { name: 'parsePort', signature: '(value: string): number | null', description: 'Parse port number (1-65535)' },
  { name: 'isValidPort', signature: '(port: number): boolean', description: 'Check if port number is valid' },
  { name: 'parseVlanId', signature: '(value: string): number | null', description: 'Parse VLAN ID (1-4094)' },
  { name: 'isValidVlanId', signature: '(vlan: number): boolean', description: 'Check if VLAN ID is valid' },
  { name: 'isDefaultVlan', signature: '(vlan: number): boolean', description: 'Check if VLAN is default (1)' },
  { name: 'isReservedVlan', signature: '(vlan: number): boolean', description: 'Check if VLAN is reserved' },
  { name: 'isValidMacAddress', signature: '(mac: string): boolean', description: 'Check if MAC address is valid' },
  { name: 'normalizeMacAddress', signature: '(mac: string): string | null', description: 'Normalize MAC address format' },
  { name: 'parseCidr', signature: '(cidr: string): CidrInfo | null', description: 'Parse CIDR notation' },
  { name: 'isIpInCidr', signature: '(ip: string, cidr: string): boolean', description: 'Check if IP is in CIDR range' },
  { name: 'equalsIgnoreCase', signature: '(a: string, b: string): boolean', description: 'Case-insensitive string equality' },
  { name: 'includesIgnoreCase', signature: '(str: string, substr: string): boolean', description: 'Case-insensitive includes' },
  { name: 'startsWithIgnoreCase', signature: '(str: string, prefix: string): boolean', description: 'Case-insensitive startsWith' },
  { name: 'isFeatureEnabled', signature: '(node, feature: string): boolean', description: 'Check if feature is enabled on node' },
  { name: 'isFeatureDisabled', signature: '(node, feature: string): boolean', description: 'Check if feature is disabled on node' },
];

// Check types for JsonCheck
const CHECK_TYPES = [
  { type: 'match', description: 'Pattern matching on node.id', props: 'pattern, flags?' },
  { type: 'not_match', description: 'Negated pattern matching on node.id', props: 'pattern, flags?' },
  { type: 'contains', description: 'Text contains on node.id', props: 'text' },
  { type: 'not_contains', description: 'Negated text contains on node.id', props: 'text' },
  { type: 'child_exists', description: 'Child node existence check', props: 'selector' },
  { type: 'child_not_exists', description: 'Child node non-existence check', props: 'selector' },
  { type: 'child_matches', description: 'Child text matching', props: 'selector, pattern, flags?' },
  { type: 'child_contains', description: 'Child text contains', props: 'selector, text' },
  { type: 'helper', description: 'Helper function invocation', props: 'helper, args?, negate?' },
  { type: 'expr', description: 'JavaScript expression evaluation', props: 'expr' },
  { type: 'and', description: 'Logical AND of conditions', props: 'conditions' },
  { type: 'or', description: 'Logical OR of conditions', props: 'conditions' },
  { type: 'not', description: 'Logical NOT of condition', props: 'condition' },
];

// Rule property completions
const RULE_PROPERTIES = [
  { name: 'id', description: 'Unique rule identifier (e.g., "CUSTOM-SEC-001")', type: 'string' },
  { name: 'selector', description: 'Node filter (e.g., "interface", "router bgp")', type: 'string?' },
  { name: 'vendor', description: 'Vendor(s) this rule applies to', type: 'RuleVendor | RuleVendor[]' },
  { name: 'category', description: 'Category for tree view grouping', type: 'string | string[]' },
  { name: 'metadata', description: 'Rule metadata (level, obu, owner, etc.)', type: 'RuleMetadata' },
  { name: 'check', description: 'The check condition to evaluate', type: 'JsonCheck' },
  { name: 'failureMessage', description: 'Custom message for failures', type: 'string?' },
  { name: 'successMessage', description: 'Custom message for passes', type: 'string?' },
];

// Metadata property completions
const METADATA_PROPERTIES = [
  { name: 'level', description: 'Severity level', type: '"error" | "warning" | "info"' },
  { name: 'obu', description: 'Organizational Business Unit', type: 'string' },
  { name: 'owner', description: 'Rule logic owner', type: 'string' },
  { name: 'description', description: 'What the rule checks', type: 'string?' },
  { name: 'remediation', description: 'Steps to fix the violation', type: 'string?' },
];

// Severity levels
const SEVERITY_LEVELS = ['error', 'warning', 'info'];

/**
 * Context information for completion
 */
interface CompletionContext {
  /** Current JSON path (e.g., ["rules", 0, "metadata"]) */
  path: (string | number)[];
  /** Whether cursor is in property name position */
  isPropertyName: boolean;
  /** Current property name if in value position */
  currentProperty?: string;
  /** Whether inside an array */
  inArray: boolean;
}

export class CustomRulesCompletionProvider implements vscode.CompletionItemProvider {
  provideCompletionItems(
    document: vscode.TextDocument,
    position: vscode.Position,
    _token: vscode.CancellationToken,
    _context: vscode.CompletionContext
  ): vscode.ProviderResult<vscode.CompletionItem[] | vscode.CompletionList> {
    const ctx = this.getContext(document, position);
    const items: vscode.CompletionItem[] = [];

    // Top level in rules array - provide rule properties
    if (this.isInRulesArray(ctx) && ctx.isPropertyName) {
      items.push(...this.getRulePropertyCompletions());
    }

    // Inside metadata object
    if (this.isInMetadata(ctx)) {
      if (ctx.isPropertyName) {
        items.push(...this.getMetadataPropertyCompletions());
      } else if (ctx.currentProperty === 'level') {
        items.push(...this.getSeverityCompletions());
      }
    }

    // Inside check object
    if (this.isInCheck(ctx)) {
      if (ctx.isPropertyName) {
        items.push(...this.getCheckPropertyCompletions());
      } else if (ctx.currentProperty === 'type') {
        items.push(...this.getCheckTypeCompletions());
      } else if (ctx.currentProperty === 'helper') {
        items.push(...this.getHelperCompletions());
      }
    }

    // Vendor value
    if (ctx.currentProperty === 'vendor' && !ctx.isPropertyName) {
      items.push(...this.getVendorCompletions());
    }

    return items;
  }

  /**
   * Analyze document and position to determine completion context.
   */
  private getContext(document: vscode.TextDocument, position: vscode.Position): CompletionContext {
    const text = document.getText();
    const offset = document.offsetAt(position);

    // Find the path in the JSON structure
    const path = this.findJsonPath(text, offset);

    // Determine if we're in property name or value position
    const lineText = document.lineAt(position.line).text;
    const beforeCursor = lineText.substring(0, position.character);

    // Check if we're after a colon (value position)
    const colonIndex = beforeCursor.lastIndexOf(':');
    const quoteIndex = beforeCursor.lastIndexOf('"');

    let isPropertyName = true;
    let currentProperty: string | undefined;

    if (colonIndex > -1) {
      // We might be in value position
      // Check if the colon is for our current property
      const afterColon = beforeCursor.substring(colonIndex);
      if (!afterColon.includes('{') && !afterColon.includes('[')) {
        isPropertyName = false;
        // Extract the property name before the colon
        const beforeColon = beforeCursor.substring(0, colonIndex);
        const propMatch = beforeColon.match(/"([^"]+)"\s*$/);
        if (propMatch) {
          currentProperty = propMatch[1];
        }
      }
    }

    // If we're right after an opening quote for a property name
    if (quoteIndex > colonIndex && beforeCursor.endsWith('"')) {
      isPropertyName = true;
      currentProperty = undefined;
    }

    // Check if inside an array
    const inArray = path.some(p => typeof p === 'number');

    return { path, isPropertyName, currentProperty, inArray };
  }

  /**
   * Find the JSON path to the cursor position.
   */
  private findJsonPath(text: string, offset: number): (string | number)[] {
    const path: (string | number)[] = [];
    let depth = 0;
    let inString = false;
    let currentKey = '';
    let arrayIndex = -1;

    for (let i = 0; i < offset && i < text.length; i++) {
      const char = text[i];

      if (inString) {
        if (char === '"' && text[i - 1] !== '\\') {
          inString = false;
        } else {
          currentKey += char;
        }
        continue;
      }

      if (char === '"') {
        inString = true;
        currentKey = '';
        continue;
      }

      if (char === '{') {
        depth++;
        if (currentKey) {
          path.push(currentKey);
          currentKey = '';
        }
      } else if (char === '}') {
        depth--;
        if (path.length > 0) {
          const last = path[path.length - 1];
          if (typeof last === 'string') {
            path.pop();
          }
        }
      } else if (char === '[') {
        arrayIndex = 0;
        if (currentKey) {
          path.push(currentKey);
          currentKey = '';
        }
        path.push(arrayIndex);
      } else if (char === ']') {
        if (path.length > 0 && typeof path[path.length - 1] === 'number') {
          path.pop();
        }
        if (path.length > 0 && typeof path[path.length - 1] === 'string') {
          path.pop();
        }
        arrayIndex = -1;
      } else if (char === ',' && arrayIndex >= 0) {
        arrayIndex++;
        if (path.length > 0 && typeof path[path.length - 1] === 'number') {
          path[path.length - 1] = arrayIndex;
        }
      } else if (char === ':') {
        // Key-value separator - the key is already captured
      }
    }

    return path;
  }

  private isInRulesArray(ctx: CompletionContext): boolean {
    return ctx.path.includes('rules') && ctx.path.some(p => typeof p === 'number');
  }

  private isInMetadata(ctx: CompletionContext): boolean {
    return ctx.path.includes('metadata');
  }

  private isInCheck(ctx: CompletionContext): boolean {
    return ctx.path.includes('check') || ctx.path.includes('conditions') || ctx.path.includes('condition');
  }

  private getRulePropertyCompletions(): vscode.CompletionItem[] {
    return RULE_PROPERTIES.map(prop => {
      const item = new vscode.CompletionItem(prop.name, vscode.CompletionItemKind.Property);
      item.detail = prop.type;
      item.documentation = prop.description;
      item.insertText = new vscode.SnippetString(`"${prop.name}": $0`);
      return item;
    });
  }

  private getMetadataPropertyCompletions(): vscode.CompletionItem[] {
    return METADATA_PROPERTIES.map(prop => {
      const item = new vscode.CompletionItem(prop.name, vscode.CompletionItemKind.Property);
      item.detail = prop.type;
      item.documentation = prop.description;
      item.insertText = new vscode.SnippetString(`"${prop.name}": $0`);
      return item;
    });
  }

  private getSeverityCompletions(): vscode.CompletionItem[] {
    return SEVERITY_LEVELS.map(level => {
      const item = new vscode.CompletionItem(level, vscode.CompletionItemKind.EnumMember);
      item.detail = 'Severity level';
      item.insertText = new vscode.SnippetString(`"${level}"`);
      return item;
    });
  }

  private getCheckPropertyCompletions(): vscode.CompletionItem[] {
    const props = [
      { name: 'type', description: 'Check type', type: 'string' },
      { name: 'pattern', description: 'Regex pattern (for match/not_match)', type: 'string' },
      { name: 'flags', description: 'Regex flags (e.g., "i" for case-insensitive)', type: 'string?' },
      { name: 'text', description: 'Text to find (for contains/not_contains)', type: 'string' },
      { name: 'selector', description: 'Child node selector', type: 'string' },
      { name: 'helper', description: 'Helper function name', type: 'string' },
      { name: 'args', description: 'Arguments for helper function', type: 'JsonArgValue[]' },
      { name: 'negate', description: 'Negate helper result', type: 'boolean?' },
      { name: 'expr', description: 'JavaScript expression', type: 'string' },
      { name: 'conditions', description: 'Array of conditions (for and/or)', type: 'JsonCheck[]' },
      { name: 'condition', description: 'Condition to negate (for not)', type: 'JsonCheck' },
    ];

    return props.map(prop => {
      const item = new vscode.CompletionItem(prop.name, vscode.CompletionItemKind.Property);
      item.detail = prop.type;
      item.documentation = prop.description;
      item.insertText = new vscode.SnippetString(`"${prop.name}": $0`);
      return item;
    });
  }

  private getCheckTypeCompletions(): vscode.CompletionItem[] {
    return CHECK_TYPES.map(ct => {
      const item = new vscode.CompletionItem(ct.type, vscode.CompletionItemKind.EnumMember);
      item.detail = ct.props;
      item.documentation = ct.description;
      item.insertText = new vscode.SnippetString(`"${ct.type}"`);
      return item;
    });
  }

  private getVendorCompletions(): vscode.CompletionItem[] {
    return VENDORS.map(vendor => {
      const item = new vscode.CompletionItem(vendor, vscode.CompletionItemKind.EnumMember);
      item.detail = 'RuleVendor';
      item.insertText = new vscode.SnippetString(`"${vendor}"`);
      return item;
    });
  }

  private getHelperCompletions(): vscode.CompletionItem[] {
    const items: vscode.CompletionItem[] = [];

    // Add common helpers
    for (const helper of COMMON_HELPERS) {
      const item = new vscode.CompletionItem(helper.name, vscode.CompletionItemKind.Function);
      item.detail = helper.signature;
      item.documentation = helper.description;
      item.insertText = new vscode.SnippetString(`"${helper.name}"`);
      items.push(item);
    }

    // Add vendor-namespaced helper suggestions
    for (const namespace of VENDOR_NAMESPACES) {
      const item = new vscode.CompletionItem(`${namespace}.`, vscode.CompletionItemKind.Module);
      item.detail = `${namespace} vendor helpers`;
      item.documentation = `Helper functions specific to ${namespace} vendor`;
      item.insertText = new vscode.SnippetString(`"${namespace}.$1"`);
      item.command = {
        command: 'editor.action.triggerSuggest',
        title: 'Trigger Suggest',
      };
      items.push(item);
    }

    return items;
  }
}
