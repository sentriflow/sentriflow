/**
 * Suppression Manager Service
 *
 * Manages CRUD operations for diagnostic suppressions.
 * Allows users to suppress specific diagnostic occurrences or entire rules per file.
 */

import * as vscode from 'vscode';

// Import and re-export pure helper functions (for testability)
export {
  contentHash,
  truncateForPreview,
  MAX_PREVIEW_LENGTH,
} from './suppressionHelpers';
import { contentHash, truncateForPreview } from './suppressionHelpers';

// ============================================================================
// Types
// ============================================================================

/**
 * Scope of a suppression.
 */
export type SuppressionType = 'line' | 'file';

/**
 * A single suppressed diagnostic.
 */
export interface Suppression {
  /** Scope: line-level or file-level */
  type: SuppressionType;

  /** Relative path from workspace root */
  filePath: string;

  /** Rule ID (e.g., "NET-001") */
  ruleId: string;

  /** Unix timestamp (ms) when created */
  timestamp: number;

  /** Content hash for line-level suppressions */
  contentHash?: string;

  /** Preview text for UI display (max 80 chars) */
  lineText?: string;
}

/**
 * Persisted suppression collection.
 */
export interface SuppressionStore {
  /** Schema version for migrations */
  version: number;

  /** All active suppressions */
  suppressions: Suppression[];
}

/**
 * Result of a suppression operation.
 */
export interface SuppressionResult {
  success: boolean;
  suppression?: Suppression;
  error?: string;
}

// ============================================================================
// Constants
// ============================================================================

/** Storage key for workspace state */
export const SUPPRESSION_STORAGE_KEY = 'sentriflow.suppressions';

/** Current schema version */
export const SUPPRESSION_SCHEMA_VERSION = 1;

// ============================================================================
// Helper Functions (vscode-dependent)
// ============================================================================

/**
 * Get relative path from workspace root.
 *
 * @param uri - Document URI
 * @returns Relative path string
 */
export function getRelativePath(uri: vscode.Uri): string {
  return vscode.workspace.asRelativePath(uri, false);
}

// ============================================================================
// Suppression Manager Class
// ============================================================================

/**
 * Manages diagnostic suppressions with persistence and change events.
 */
export class SuppressionManager implements vscode.Disposable {
  private _context: vscode.ExtensionContext | undefined;
  private _suppressions: Suppression[] = [];

  // Indexes for efficient lookup
  private _byFile: Map<string, Suppression[]> = new Map();
  private _byFileRule: Set<string> = new Set();
  private _byFileHashRule: Set<string> = new Set();

  // Event emitter for change notifications
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  // -------------------------------------------------------------------------
  // Disposal
  // -------------------------------------------------------------------------

  /**
   * Dispose of resources held by this manager.
   */
  dispose(): void {
    this._onDidChange.dispose();
  }

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------

  /**
   * Initialize the suppression manager.
   * Loads suppressions from workspaceState and builds indexes.
   */
  async initialize(context: vscode.ExtensionContext): Promise<void> {
    this._context = context;
    await this._load();
    this._buildIndexes();
  }

  // -------------------------------------------------------------------------
  // Create Operations
  // -------------------------------------------------------------------------

  /**
   * Suppress a specific diagnostic occurrence on a line.
   */
  async suppressLine(
    document: vscode.TextDocument,
    lineNumber: number,
    ruleId: string
  ): Promise<SuppressionResult> {
    const filePath = getRelativePath(document.uri);
    if (lineNumber < 0 || lineNumber >= document.lineCount) {
      return { success: false, error: 'Line number out of bounds' };
    }
    const lineText = document.lineAt(lineNumber).text;
    const hash = contentHash(lineText);

    // Check for duplicate
    const key = `${filePath}:${hash}:${ruleId}`;
    if (this._byFileHashRule.has(key)) {
      return { success: false, error: 'Suppression already exists' };
    }

    const suppression: Suppression = {
      type: 'line',
      filePath,
      ruleId,
      timestamp: Date.now(),
      contentHash: hash,
      lineText: truncateForPreview(lineText),
    };

    this._suppressions.push(suppression);
    await this._save();
    this._buildIndexes();
    this._onDidChange.fire();

    return { success: true, suppression };
  }

  /**
   * Suppress all occurrences of a rule in a file.
   */
  async suppressFile(
    document: vscode.TextDocument,
    ruleId: string
  ): Promise<SuppressionResult> {
    const filePath = getRelativePath(document.uri);

    // Check for duplicate
    const key = `${filePath}:${ruleId}`;
    if (this._byFileRule.has(key)) {
      return { success: false, error: 'File suppression already exists' };
    }

    const suppression: Suppression = {
      type: 'file',
      filePath,
      ruleId,
      timestamp: Date.now(),
    };

    this._suppressions.push(suppression);
    await this._save();
    this._buildIndexes();
    this._onDidChange.fire();

    return { success: true, suppression };
  }

  // -------------------------------------------------------------------------
  // Read Operations
  // -------------------------------------------------------------------------

  /**
   * Get all suppressions for a document.
   */
  getSuppressionsForDocument(documentUri: vscode.Uri): Suppression[] {
    const filePath = getRelativePath(documentUri);
    return this._byFile.get(filePath) || [];
  }

  /**
   * Get all suppressions in the workspace.
   */
  getAllSuppressions(): Map<string, Suppression[]> {
    return new Map(this._byFile);
  }

  /**
   * Get total count of suppressions.
   */
  getSuppressionCount(): number {
    return this._suppressions.length;
  }

  // -------------------------------------------------------------------------
  // Check Operations (for filtering)
  // -------------------------------------------------------------------------

  /**
   * Check if a specific diagnostic should be suppressed.
   */
  isSuppressed(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): boolean {
    const ruleId = typeof diagnostic.code === 'string' ? diagnostic.code : undefined;
    if (!ruleId) return false;

    const filePath = getRelativePath(document.uri);

    // Check file-level suppression first
    if (this._byFileRule.has(`${filePath}:${ruleId}`)) {
      return true;
    }

    // Check line-level suppression
    const lineNumber = diagnostic.range.start.line;
    if (lineNumber < 0 || lineNumber >= document.lineCount) {
      return false;
    }
    const lineText = document.lineAt(lineNumber).text;
    const hash = contentHash(lineText);

    return this._byFileHashRule.has(`${filePath}:${hash}:${ruleId}`);
  }

  /**
   * Check if a rule is suppressed for entire file.
   */
  isFileSuppressed(documentUri: vscode.Uri, ruleId: string): boolean {
    const filePath = getRelativePath(documentUri);
    return this._byFileRule.has(`${filePath}:${ruleId}`);
  }

  /**
   * Check if a specific line+rule combination is suppressed.
   */
  isLineSuppressed(
    document: vscode.TextDocument,
    lineNumber: number,
    ruleId: string
  ): boolean {
    const filePath = getRelativePath(document.uri);
    if (lineNumber < 0 || lineNumber >= document.lineCount) {
      return false;
    }
    const lineText = document.lineAt(lineNumber).text;
    const hash = contentHash(lineText);

    return this._byFileHashRule.has(`${filePath}:${hash}:${ruleId}`);
  }

  // -------------------------------------------------------------------------
  // Delete Operations
  // -------------------------------------------------------------------------

  /**
   * Remove a specific suppression.
   */
  async removeSuppression(suppression: Suppression): Promise<boolean> {
    const index = this._suppressions.findIndex(
      s =>
        s.type === suppression.type &&
        s.filePath === suppression.filePath &&
        s.ruleId === suppression.ruleId &&
        s.contentHash === suppression.contentHash
    );

    if (index === -1) {
      return false;
    }

    this._suppressions.splice(index, 1);
    await this._save();
    this._buildIndexes();
    this._onDidChange.fire();

    return true;
  }

  /**
   * Remove all suppressions for a file.
   */
  async clearFileSuppressions(filePath: string): Promise<number> {
    const before = this._suppressions.length;
    this._suppressions = this._suppressions.filter(s => s.filePath !== filePath);
    const removed = before - this._suppressions.length;

    if (removed > 0) {
      await this._save();
      this._buildIndexes();
      this._onDidChange.fire();
    }

    return removed;
  }

  /**
   * Remove all suppressions in the workspace.
   */
  async clearAllSuppressions(): Promise<number> {
    const count = this._suppressions.length;

    if (count > 0) {
      this._suppressions = [];
      await this._save();
      this._buildIndexes();
      this._onDidChange.fire();
    }

    return count;
  }

  // -------------------------------------------------------------------------
  // Private Methods
  // -------------------------------------------------------------------------

  /**
   * Load suppressions from workspace state.
   */
  private async _load(): Promise<void> {
    if (!this._context) return;

    const stored = this._context.workspaceState.get<SuppressionStore>(SUPPRESSION_STORAGE_KEY);

    if (stored && stored.version === SUPPRESSION_SCHEMA_VERSION) {
      this._suppressions = stored.suppressions || [];
    } else {
      this._suppressions = [];
    }
  }

  /**
   * Save suppressions to workspace state.
   */
  private async _save(): Promise<void> {
    if (!this._context) return;

    const store: SuppressionStore = {
      version: SUPPRESSION_SCHEMA_VERSION,
      suppressions: this._suppressions,
    };

    await this._context.workspaceState.update(SUPPRESSION_STORAGE_KEY, store);
  }

  /**
   * Build lookup indexes from suppressions array.
   */
  private _buildIndexes(): void {
    this._byFile.clear();
    this._byFileRule.clear();
    this._byFileHashRule.clear();

    for (const s of this._suppressions) {
      // By file index
      const existing = this._byFile.get(s.filePath) || [];
      existing.push(s);
      this._byFile.set(s.filePath, existing);

      // By file+rule (for file-level suppressions)
      if (s.type === 'file') {
        this._byFileRule.add(`${s.filePath}:${s.ruleId}`);
      }

      // By file+hash+rule (for line-level suppressions)
      if (s.type === 'line' && s.contentHash) {
        this._byFileHashRule.add(`${s.filePath}:${s.contentHash}:${s.ruleId}`);
      }
    }
  }
}
