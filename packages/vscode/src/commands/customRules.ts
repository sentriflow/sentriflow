/**
 * Custom Rules Commands
 *
 * Commands for creating, copying, editing, and deleting custom JSON rules.
 * Custom rules are stored in .sentriflow/rules/*.json files in the workspace.
 */

import * as vscode from 'vscode';
import type { IRule } from '@sentriflow/core';
import { getState } from '../state/context';
import { RuleTreeItem } from '../providers/RulesTreeProvider';

// ============================================================================
// Logging Helpers
// ============================================================================

/**
 * Log a debug message to the output channel.
 */
function log(message: string): void {
  const state = getState();
  if (state.debugMode) {
    state.outputChannel.appendLine(`[DEBUG] ${message}`);
  }
}

// ============================================================================
// Create Custom Rules File
// ============================================================================

/**
 * Command: Create a new custom rules file in .sentriflow/rules/
 */
export async function cmdCreateCustomRulesFile(): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage(
      'No workspace folder open. Open a folder to create custom rules.'
    );
    return;
  }

  // Prompt for file name
  const fileName = await vscode.window.showInputBox({
    prompt: 'Enter the name for the custom rules file',
    placeHolder: 'my_rules.json',
    validateInput: (value) => {
      if (!value) return 'File name is required';
      if (!value.endsWith('.json')) return 'File name must end with .json';
      if (!/^[a-zA-Z0-9_-]+\.json$/.test(value)) {
        return 'File name can only contain letters, numbers, underscores, and hyphens';
      }
      return undefined;
    },
  });

  if (!fileName) return;

  // Ensure .sentriflow/rules directory exists
  const rulesDir = vscode.Uri.joinPath(
    workspaceFolder.uri,
    '.sentriflow',
    'rules'
  );
  try {
    await vscode.workspace.fs.createDirectory(rulesDir);
  } catch {
    // Directory may already exist
  }

  const fileUri = vscode.Uri.joinPath(rulesDir, fileName);

  // Check if file already exists
  try {
    await vscode.workspace.fs.stat(fileUri);
    const overwrite = await vscode.window.showWarningMessage(
      `File "${fileName}" already exists. Overwrite?`,
      'Overwrite',
      'Cancel'
    );
    if (overwrite !== 'Overwrite') return;
  } catch {
    // File doesn't exist, good to create
  }

  // Create template file with example rule
  // See: https://github.com/sentriflow/sentriflow/blob/main/docs/RULE_AUTHORING_GUIDE.md
  const template = {
    version: '1.0',
    meta: {
      name: fileName.replace('.json', ''),
      description: 'Custom rules for organization-specific checks',
      author: '',
    },
    rules: [
      {
        id: 'CUSTOM-EXAMPLE-001',
        selector: 'interface',
        vendor: 'cisco-ios',
        metadata: {
          level: 'warning',
          obu: 'Network Engineering',
          owner: 'NetOps',
          description: 'Non-loopback interfaces should have a description',
          remediation: "Add 'description <text>' to document interface purpose",
        },
        check: {
          type: 'and',
          conditions: [
            {
              type: 'not_match',
              pattern: 'loopback',
              flags: 'i',
            },
            {
              type: 'helper',
              helper: 'isShutdown',
              args: [{ $ref: 'node' }],
              negate: true,
            },
            {
              type: 'child_not_exists',
              selector: 'description',
            },
          ],
        },
        failureMessage: 'Interface {nodeId} is missing a description',
      },
    ],
  };

  const content = new TextEncoder().encode(JSON.stringify(template, null, 2));
  await vscode.workspace.fs.writeFile(fileUri, content);

  // Open the new file
  const doc = await vscode.workspace.openTextDocument(fileUri);
  await vscode.window.showTextDocument(doc);

  vscode.window.showInformationMessage(
    `Created custom rules file: ${fileName}`
  );
}

// ============================================================================
// Copy Rule to Custom
// ============================================================================

/**
 * Command: Copy an existing rule to a custom rules file
 */
export async function cmdCopyRuleToCustom(item?: RuleTreeItem): Promise<void> {
  const state = getState();
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];

  if (!workspaceFolder) {
    vscode.window.showErrorMessage(
      'No workspace folder open. Open a folder to create custom rules.'
    );
    return;
  }

  // Get the rule to copy
  let rule: IRule | undefined;
  if (item?.rule) {
    rule = item.rule;
  } else {
    // Prompt for rule ID
    const ruleId = await vscode.window.showInputBox({
      prompt: 'Enter the rule ID to copy',
      placeHolder: 'e.g., NET-SEC-001',
    });
    if (!ruleId) return;

    rule = state.currentRuleMap.get(ruleId);
    if (!rule) {
      vscode.window.showErrorMessage(`Rule "${ruleId}" not found.`);
      return;
    }
  }

  // Find existing custom rules files or create new one
  const rulesDir = vscode.Uri.joinPath(
    workspaceFolder.uri,
    '.sentriflow',
    'rules'
  );
  let existingFiles: vscode.Uri[] = [];
  try {
    const files = await vscode.workspace.findFiles(
      '.sentriflow/rules/*.json',
      '**/node_modules/**'
    );
    existingFiles = files.sort((a, b) => a.fsPath.localeCompare(b.fsPath));
  } catch {
    // Directory may not exist
  }

  // Let user choose target file
  interface FilePickItem extends vscode.QuickPickItem {
    uri?: vscode.Uri;
    isNew: boolean;
  }

  const items: FilePickItem[] = [
    {
      label: '$(new-file) Create New File...',
      isNew: true,
    },
    ...existingFiles.map((uri) => ({
      label: `$(file) ${uri.path.split('/').pop()}`,
      description: uri.fsPath,
      uri,
      isNew: false,
    })),
  ];

  const selected = await vscode.window.showQuickPick(items, {
    placeHolder: 'Select target custom rules file',
  });

  if (!selected) return;

  let targetUri: vscode.Uri;
  if (selected.isNew) {
    // Create new file
    const fileName = await vscode.window.showInputBox({
      prompt: 'Enter the name for the custom rules file',
      placeHolder: 'custom_rules.json',
      validateInput: (value) => {
        if (!value) return 'File name is required';
        if (!value.endsWith('.json')) return 'File name must end with .json';
        return undefined;
      },
    });
    if (!fileName) return;

    // Ensure directory exists
    try {
      await vscode.workspace.fs.createDirectory(rulesDir);
    } catch {
      // Directory may already exist
    }

    targetUri = vscode.Uri.joinPath(rulesDir, fileName);

    // Create with template
    const template = {
      version: '1.0',
      meta: { name: fileName.replace('.json', '') },
      rules: [],
    };
    await vscode.workspace.fs.writeFile(
      targetUri,
      new TextEncoder().encode(JSON.stringify(template, null, 2))
    );
  } else {
    targetUri = selected.uri!;
  }

  // Read existing file and add rule
  const fileContent = await vscode.workspace.fs.readFile(targetUri);
  const json = JSON.parse(new TextDecoder().decode(fileContent));

  // Check if this is a custom rule we can copy directly
  const existingCustomRule = state.customRulesLoader?.findRuleById(rule.id);
  let jsonRule: Record<string, unknown>;
  let isFullCopy = false;

  if (existingCustomRule) {
    // Copy the original JSON rule as-is, just change the ID
    jsonRule = JSON.parse(JSON.stringify(existingCustomRule.rule));
    jsonRule.id = `COPY-${rule.id}`;
    isFullCopy = true;
  } else {
    // Built-in rule: function-based checks can't be serialized
    // Create a template with placeholder check
    jsonRule = {
      id: `CUSTOM-${rule.id}`,
      metadata: {
        level: rule.metadata.level,
        obu: rule.metadata.obu,
        owner: rule.metadata.owner,
        description:
          rule.metadata.description ||
          `Custom version of ${rule.id}. TODO: Update this description.`,
        remediation: rule.metadata.remediation,
      },
      // Placeholder check - user MUST customize this
      check: {
        type: 'child_not_exists',
        selector: 'TODO: specify what command should exist',
      },
    };

    // Add optional fields only if they exist
    if (rule.selector) {
      jsonRule.selector = rule.selector;
    }
    if (rule.vendor) {
      jsonRule.vendor = rule.vendor;
    }
    if (rule.category) {
      jsonRule.category = rule.category;
    }
  }

  // Check for duplicate ID
  const existingIndex = json.rules.findIndex(
    (r: { id: string }) => r.id === jsonRule.id
  );
  if (existingIndex >= 0) {
    const replace = await vscode.window.showWarningMessage(
      `Rule "${jsonRule.id}" already exists in this file. Replace?`,
      'Replace',
      'Cancel'
    );
    if (replace !== 'Replace') return;
    json.rules[existingIndex] = jsonRule;
  } else {
    json.rules.push(jsonRule);
  }

  const newContent = JSON.stringify(json, null, 2);

  // Check if file is already open and handle it
  const existingDoc = vscode.workspace.textDocuments.find(
    (d) => d.uri.fsPath === targetUri.fsPath
  );
  if (existingDoc && existingDoc.isDirty) {
    // File is open with unsaved changes - warn user
    const choice = await vscode.window.showWarningMessage(
      'The target file has unsaved changes. Save and update?',
      'Save & Update',
      'Cancel'
    );
    if (choice !== 'Save & Update') return;
    await existingDoc.save();
  }

  // Write the file
  await vscode.workspace.fs.writeFile(
    targetUri,
    new TextEncoder().encode(newContent)
  );

  // Open/refresh the file in editor
  const doc = await vscode.workspace.openTextDocument(targetUri);
  await vscode.window.showTextDocument(doc);

  // Show appropriate message based on copy type
  if (isFullCopy) {
    vscode.window.showInformationMessage(
      `Copied "${rule.id}" as "${jsonRule.id}" with all original settings.`
    );
  } else {
    vscode.window.showInformationMessage(
      `Copied "${rule.id}" as "${jsonRule.id}". The check is a placeholder - edit it to define your custom logic.`,
      'OK'
    );
  }
}

// ============================================================================
// Delete Custom Rule
// ============================================================================

/**
 * Command: Delete a custom rule from its source file
 */
export async function cmdDeleteCustomRule(item?: RuleTreeItem): Promise<void> {
  const state = getState();

  if (!item?.rule) {
    vscode.window.showErrorMessage('No rule selected.');
    return;
  }

  const ruleId = item.rule.id;

  // Confirm deletion
  const confirm = await vscode.window.showWarningMessage(
    `Delete custom rule "${ruleId}"? This cannot be undone.`,
    { modal: true },
    'Delete'
  );

  if (confirm !== 'Delete') {
    return;
  }

  // Use the CustomRulesLoader to delete the rule
  if (!state.customRulesLoader) {
    vscode.window.showErrorMessage('Custom rules loader not available.');
    return;
  }

  const deleted = await state.customRulesLoader.deleteRule(ruleId);
  if (deleted) {
    vscode.window.showInformationMessage(`Deleted rule "${ruleId}".`);
  } else {
    vscode.window.showErrorMessage(
      `Rule "${ruleId}" not found in custom rules files.`
    );
  }
}

// ============================================================================
// Edit Custom Rule
// ============================================================================

/**
 * Command: Edit a custom rule - open the source file and navigate to the rule
 */
export async function cmdEditCustomRule(item?: RuleTreeItem): Promise<void> {
  const state = getState();

  if (!item?.rule) {
    vscode.window.showErrorMessage('No rule selected.');
    return;
  }

  const ruleId = item.rule.id;

  // Find the file containing this rule
  if (!state.customRulesLoader) {
    vscode.window.showErrorMessage('Custom rules loader not available.');
    return;
  }

  const found = state.customRulesLoader.findRuleById(ruleId);
  if (!found) {
    vscode.window.showErrorMessage(
      `Rule "${ruleId}" not found in custom rules files.`
    );
    return;
  }

  const fileUri = vscode.Uri.file(found.filePath);

  // Open the document
  const doc = await vscode.workspace.openTextDocument(fileUri);
  const editor = await vscode.window.showTextDocument(doc);

  // Find the rule in the file and navigate to it
  const text = doc.getText();
  // Escape special regex characters in ruleId
  const escapedRuleId = ruleId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ruleIdPattern = new RegExp(`"id"\\s*:\\s*"${escapedRuleId}"`);
  const match = ruleIdPattern.exec(text);

  if (match) {
    const position = doc.positionAt(match.index);
    // Move cursor to the rule ID line and reveal it
    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(
      new vscode.Range(position, position),
      vscode.TextEditorRevealType.InCenter
    );
  }
}
