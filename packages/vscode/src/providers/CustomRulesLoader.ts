// packages/vscode/src/providers/CustomRulesLoader.ts

/**
 * CustomRulesLoader - Load and manage custom JSON rules from system directory
 *
 * Discovers and loads JSON rule files from the `~/.sentriflow/rules/` directory.
 * Provides file watching for live reload and validation diagnostics.
 */

import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { JsonRule, JsonRuleFile } from '@sentriflow/core';
import { isJsonRuleFile } from '@sentriflow/core';
import { DEFAULT_RULES_DIRECTORY } from '../encryption/types';

/** Debounce delay in milliseconds for file watcher events */
const DEBOUNCE_DELAY = 300;

/**
 * Loads custom JSON rules from the workspace's .sentriflow/rules/ directory.
 * Files are loaded alphabetically; later files take precedence for duplicate IDs.
 */
export class CustomRulesLoader {
  /** Rules indexed by file path for efficient add/remove operations */
  private rulesByFile: Map<string, JsonRule[]> = new Map();

  /** File system watcher for .sentriflow/rules/*.json */
  private watcher: vscode.FileSystemWatcher | undefined;

  /** Diagnostic collection for validation errors */
  private diagnostics: vscode.DiagnosticCollection;

  /** Event emitter for rules change notifications */
  private _onDidChangeRules = new vscode.EventEmitter<void>();
  readonly onDidChangeRules = this._onDidChangeRules.event;

  /** Debounce timers for file change events */
  private debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  /** Output channel for duplicate ID warnings */
  private outputChannel: vscode.OutputChannel;

  constructor(private context: vscode.ExtensionContext) {
    // T006: Create diagnostic collection for validation errors
    this.diagnostics = vscode.languages.createDiagnosticCollection('sentriflow-custom-rules');
    context.subscriptions.push(this.diagnostics);

    // Create output channel for warnings
    this.outputChannel = vscode.window.createOutputChannel('SentriFlow Custom Rules');
    context.subscriptions.push(this.outputChannel);
  }

  /**
   * Initialize the loader: set up file watcher and load existing rules.
   * Call this after construction to start watching for rule files.
   */
  async initialize(): Promise<void> {
    // Check if custom rules are enabled
    const config = vscode.workspace.getConfiguration('sentriflow');
    if (!config.get<boolean>('customRules.enabled', true)) {
      return;
    }

    // Ensure the rules directory exists
    await this.ensureRulesDirectory();

    // Set up file system watcher for ~/.sentriflow/rules/*.json (system directory)
    const rulesPattern = new vscode.RelativePattern(
      vscode.Uri.file(DEFAULT_RULES_DIRECTORY),
      '*.json'
    );
    this.watcher = vscode.workspace.createFileSystemWatcher(rulesPattern);

    // T035: Use debounced handlers for change events to handle rapid saves
    this.watcher.onDidChange(uri => this.debouncedLoadRulesFromFile(uri));
    this.watcher.onDidCreate(uri => this.debouncedLoadRulesFromFile(uri));
    this.watcher.onDidDelete(uri => this.unloadRulesFromFile(uri));

    this.context.subscriptions.push(this.watcher);

    // Initial load of existing files
    await this.findAndLoadRules();

    // T037: Check for duplicate IDs after initial load
    this.checkForDuplicateIds();
  }

  /**
   * Ensure the rules directory exists, creating it if necessary.
   */
  private async ensureRulesDirectory(): Promise<void> {
    try {
      await fs.promises.mkdir(DEFAULT_RULES_DIRECTORY, { recursive: true });
    } catch {
      // Directory may already exist or we don't have permissions
    }
  }

  /**
   * T035: Debounced file load to handle rapid successive saves.
   */
  private debouncedLoadRulesFromFile(uri: vscode.Uri): void {
    const key = uri.fsPath;

    // Clear any existing timer for this file
    const existingTimer = this.debounceTimers.get(key);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Set new timer
    const timer = setTimeout(async () => {
      this.debounceTimers.delete(key);
      await this.loadRulesFromFile(uri);
      // Check for duplicates after each load
      this.checkForDuplicateIds();
    }, DEBOUNCE_DELAY);

    this.debounceTimers.set(key, timer);
  }

  /**
   * Discover all JSON files in ~/.sentriflow/rules/ directory and load them.
   */
  async findAndLoadRules(): Promise<void> {
    try {
      const entries = await fs.promises.readdir(DEFAULT_RULES_DIRECTORY, { withFileTypes: true });

      // Filter to JSON files only and sort alphabetically
      const jsonFiles = entries
        .filter(entry => entry.isFile() && entry.name.endsWith('.json'))
        .map(entry => path.join(DEFAULT_RULES_DIRECTORY, entry.name))
        .sort((a, b) => a.localeCompare(b));

      for (const filePath of jsonFiles) {
        await this.loadRulesFromFile(vscode.Uri.file(filePath));
      }
    } catch {
      // Directory may not exist yet or we don't have read permissions
    }
  }

  /**
   * Load rules from a single JSON file.
   * @param uri The URI of the file to load
   */
  async loadRulesFromFile(uri: vscode.Uri): Promise<void> {
    try {
      const content = await vscode.workspace.fs.readFile(uri);
      const text = new TextDecoder().decode(content);
      const json = JSON.parse(text);

      // Validate the file structure
      if (!isJsonRuleFile(json)) {
        this.addDiagnostic(uri, 0, 'Invalid rule file structure. Check version and rules array.');
        this.rulesByFile.delete(uri.fsPath);
        this._onDidChangeRules.fire();
        return;
      }

      const ruleFile = json as JsonRuleFile;

      // Version check
      if (ruleFile.version !== '1.0') {
        this.addDiagnostic(uri, 0, `Invalid version "${ruleFile.version}". Expected "1.0".`);
        this.rulesByFile.delete(uri.fsPath);
        this._onDidChangeRules.fire();
        return;
      }

      // Store rules for this file
      this.rulesByFile.set(uri.fsPath, ruleFile.rules);
      this.diagnostics.delete(uri);

      // Notify listeners
      this._onDidChangeRules.fire();

      // Trigger tree refresh
      vscode.commands.executeCommand('sentriflow.refreshRulesTree');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.addDiagnostic(uri, 0, `Parse error: ${message}`);
      this.rulesByFile.delete(uri.fsPath);
      this._onDidChangeRules.fire();
    }
  }

  /**
   * Remove rules when a file is deleted.
   * @param uri The URI of the deleted file
   */
  unloadRulesFromFile(uri: vscode.Uri): void {
    this.rulesByFile.delete(uri.fsPath);
    this.diagnostics.delete(uri);
    this._onDidChangeRules.fire();
    vscode.commands.executeCommand('sentriflow.refreshRulesTree');
  }

  /**
   * Get all loaded custom rules, merged from all files.
   * Later files (alphabetically) override earlier files for duplicate IDs.
   * @param includeDisabled If true, includes disabled rules (for tree display)
   */
  getRules(includeDisabled: boolean = false): JsonRule[] {
    const config = vscode.workspace.getConfiguration('sentriflow');
    if (!config.get<boolean>('customRules.enabled', true)) {
      return [];
    }
    return this.getMergedRules(includeDisabled);
  }

  /**
   * Get all loaded custom rules for display purposes (ignores enabled setting).
   * Used by tree view to show the pack even when disabled.
   */
  getRulesForDisplay(): JsonRule[] {
    return this.getMergedRules(true);
  }

  /**
   * Internal method to merge rules from all files.
   * @param includeDisabled If true, includes disabled rules
   */
  private getMergedRules(includeDisabled: boolean): JsonRule[] {
    const config = vscode.workspace.getConfiguration('sentriflow');

    // Get disabled rules set
    const disabledRules = includeDisabled
      ? new Set<string>()
      : new Set(config.get<string[]>('customRules.disabledRules', []));

    // Merge rules from all files
    const allRules: JsonRule[] = [];
    const seenIds = new Set<string>();

    // Process in reverse alphabetical order so later files override earlier
    const sortedPaths = [...this.rulesByFile.keys()].sort().reverse();

    for (const path of sortedPaths) {
      const rules = this.rulesByFile.get(path) || [];
      for (const rule of rules) {
        // Skip disabled rules (unless includeDisabled is true)
        if (disabledRules.has(rule.id)) {
          continue;
        }

        // Only add if not already seen (first wins in reverse order = last file wins)
        if (!seenIds.has(rule.id)) {
          allRules.push(rule);
          seenIds.add(rule.id);
        }
      }
    }

    // Restore original order (reverse of reverse = original)
    return allRules.reverse();
  }

  /**
   * Reload all rules from the system directory.
   * Call this after creating/modifying files via commands since
   * VS Code's file watcher may not detect changes outside the workspace.
   */
  async reload(): Promise<void> {
    this.rulesByFile.clear();
    this.diagnostics.clear();
    await this.findAndLoadRules();
    this.checkForDuplicateIds();
  }

  /**
   * Get the number of loaded rule files.
   */
  getFileCount(): number {
    return this.rulesByFile.size;
  }

  /**
   * Get the total number of loaded rules (before filtering).
   */
  getTotalRuleCount(): number {
    let count = 0;
    for (const rules of this.rulesByFile.values()) {
      count += rules.length;
    }
    return count;
  }

  /**
   * Find the original JsonRule by ID.
   * Returns the rule and its source file path, or undefined if not found.
   */
  findRuleById(ruleId: string): { rule: JsonRule; filePath: string } | undefined {
    for (const [filePath, rules] of this.rulesByFile) {
      const rule = rules.find(r => r.id === ruleId);
      if (rule) {
        return { rule, filePath };
      }
    }
    return undefined;
  }

  /**
   * Delete a rule from its source file.
   * @param ruleId The ID of the rule to delete
   * @returns true if the rule was deleted, false if not found
   */
  async deleteRule(ruleId: string): Promise<boolean> {
    // Find which file contains this rule
    for (const [filePath, rules] of this.rulesByFile) {
      const ruleIndex = rules.findIndex(r => r.id === ruleId);
      if (ruleIndex === -1) continue;

      // Read the file
      const uri = vscode.Uri.file(filePath);
      const content = await vscode.workspace.fs.readFile(uri);
      const json = JSON.parse(new TextDecoder().decode(content));

      // Remove the rule
      json.rules = json.rules.filter((r: { id: string }) => r.id !== ruleId);

      // Write the file back
      await vscode.workspace.fs.writeFile(
        uri,
        new TextEncoder().encode(JSON.stringify(json, null, 2))
      );

      // The file watcher will trigger a reload
      return true;
    }
    return false;
  }

  /**
   * Add a diagnostic error for a file.
   */
  private addDiagnostic(uri: vscode.Uri, line: number, message: string): void {
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(line, 0, line, 100),
      message,
      vscode.DiagnosticSeverity.Error
    );
    diagnostic.source = 'SentriFlow';
    this.diagnostics.set(uri, [diagnostic]);
  }

  /**
   * T037: Check for duplicate rule IDs across all files and warn the user.
   */
  private checkForDuplicateIds(): void {
    // Map of rule ID to list of file paths that define it
    const idToFiles = new Map<string, string[]>();

    for (const [path, rules] of this.rulesByFile) {
      const fileName = path.split(/[/\\]/).pop() || path;
      for (const rule of rules) {
        const files = idToFiles.get(rule.id) || [];
        files.push(fileName);
        idToFiles.set(rule.id, files);
      }
    }

    // Find duplicates
    const duplicates: Array<{ id: string; files: string[] }> = [];
    for (const [id, files] of idToFiles) {
      if (files.length > 1) {
        duplicates.push({ id, files });
      }
    }

    // Report duplicates
    if (duplicates.length > 0) {
      this.outputChannel.clear();
      this.outputChannel.appendLine('=== Duplicate Rule IDs Detected ===');
      this.outputChannel.appendLine('');
      this.outputChannel.appendLine('The following rule IDs appear in multiple files.');
      this.outputChannel.appendLine('The rule from the alphabetically last file will be used.');
      this.outputChannel.appendLine('');

      for (const { id, files } of duplicates) {
        this.outputChannel.appendLine(`Rule "${id}" defined in: ${files.join(', ')}`);
      }

      this.outputChannel.appendLine('');
      this.outputChannel.appendLine(`Total: ${duplicates.length} duplicate ID(s)`);

      // Show warning message with option to view details
      vscode.window
        .showWarningMessage(
          `${duplicates.length} duplicate custom rule ID(s) found. Later files override earlier ones.`,
          'View Details'
        )
        .then(choice => {
          if (choice === 'View Details') {
            this.outputChannel.show();
          }
        });
    }
  }

  /**
   * Clean up resources.
   */
  dispose(): void {
    // Clear all debounce timers
    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();

    this.watcher?.dispose();
    this.diagnostics.dispose();
    this._onDidChangeRules.dispose();
    this.rulesByFile.clear();
  }
}
