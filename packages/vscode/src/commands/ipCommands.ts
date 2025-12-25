// packages/vscode/src/commands/ipCommands.ts

import * as vscode from 'vscode';
import { extractIPSummary, type IPSummary } from '@sentriflow/core';

// Output channel for IP summary display
let outputChannel: vscode.OutputChannel | undefined;

/**
 * Get or create the output channel for IP display.
 */
function getOutputChannel(): vscode.OutputChannel {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel('SentriFlow IP Summary');
  }
  return outputChannel;
}

/**
 * Format IP summary for clipboard (one IP per line).
 */
function formatForClipboard(summary: IPSummary): string {
  const lines: string[] = [];

  // IPv4 Addresses
  if (summary.ipv4Addresses.length > 0) {
    lines.push('# IPv4 Addresses');
    lines.push(...summary.ipv4Addresses);
    lines.push('');
  }

  // IPv6 Addresses
  if (summary.ipv6Addresses.length > 0) {
    lines.push('# IPv6 Addresses');
    lines.push(...summary.ipv6Addresses);
    lines.push('');
  }

  // IPv4 Subnets
  if (summary.ipv4Subnets.length > 0) {
    lines.push('# IPv4 Subnets');
    lines.push(...summary.ipv4Subnets);
    lines.push('');
  }

  // IPv6 Subnets
  if (summary.ipv6Subnets.length > 0) {
    lines.push('# IPv6 Subnets');
    lines.push(...summary.ipv6Subnets);
    lines.push('');
  }

  return lines.join('\n').trim();
}

/**
 * Format IP summary for Output panel display.
 */
function formatForOutput(summary: IPSummary, fileName: string): string {
  const lines: string[] = [];

  lines.push(`IP Summary for: ${fileName}`);
  lines.push('='.repeat(50));
  lines.push('');

  // Counts summary
  lines.push('Counts:');
  lines.push(`  IPv4 Addresses: ${summary.counts.ipv4}`);
  lines.push(`  IPv6 Addresses: ${summary.counts.ipv6}`);
  lines.push(`  IPv4 Subnets:   ${summary.counts.ipv4Subnets}`);
  lines.push(`  IPv6 Subnets:   ${summary.counts.ipv6Subnets}`);
  lines.push(`  Total:          ${summary.counts.total}`);
  lines.push('');

  // IPv4 Addresses
  if (summary.ipv4Addresses.length > 0) {
    lines.push('IPv4 Addresses:');
    for (const ip of summary.ipv4Addresses) {
      lines.push(`  ${ip}`);
    }
    lines.push('');
  }

  // IPv6 Addresses
  if (summary.ipv6Addresses.length > 0) {
    lines.push('IPv6 Addresses:');
    for (const ip of summary.ipv6Addresses) {
      lines.push(`  ${ip}`);
    }
    lines.push('');
  }

  // IPv4 Subnets
  if (summary.ipv4Subnets.length > 0) {
    lines.push('IPv4 Subnets:');
    for (const subnet of summary.ipv4Subnets) {
      lines.push(`  ${subnet}`);
    }
    lines.push('');
  }

  // IPv6 Subnets
  if (summary.ipv6Subnets.length > 0) {
    lines.push('IPv6 Subnets:');
    for (const subnet of summary.ipv6Subnets) {
      lines.push(`  ${subnet}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Copy IP addresses from the current document to clipboard.
 */
async function copyIPAddresses(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No active editor. Open a file to extract IPs.');
    return;
  }

  const content = editor.document.getText();
  const summary = extractIPSummary(content);

  if (summary.counts.total === 0) {
    vscode.window.showInformationMessage('No IP addresses or subnets found in this file.');
    return;
  }

  const clipboardText = formatForClipboard(summary);
  await vscode.env.clipboard.writeText(clipboardText);

  vscode.window.showInformationMessage(
    `Copied ${summary.counts.total} IP addresses/subnets to clipboard.`
  );
}

/**
 * Show IP addresses from the current document in Output panel.
 */
async function showIPAddresses(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No active editor. Open a file to extract IPs.');
    return;
  }

  const content = editor.document.getText();
  const summary = extractIPSummary(content);

  if (summary.counts.total === 0) {
    vscode.window.showInformationMessage('No IP addresses or subnets found in this file.');
    return;
  }

  const fileName = editor.document.fileName.split(/[/\\]/).pop() || 'Unknown';
  const outputText = formatForOutput(summary, fileName);

  const channel = getOutputChannel();
  channel.clear();
  channel.appendLine(outputText);
  channel.show(true); // Preserve focus on editor
}

/**
 * Register IP-related commands.
 *
 * @param context - VS Code extension context
 * @returns Disposables for registered commands
 */
export function registerIPCommands(
  context: vscode.ExtensionContext
): vscode.Disposable[] {
  const disposables: vscode.Disposable[] = [];

  // Register copyIPAddresses command
  disposables.push(
    vscode.commands.registerCommand('sentriflow.copyIPAddresses', copyIPAddresses)
  );

  // Register showIPAddresses command
  disposables.push(
    vscode.commands.registerCommand('sentriflow.showIPAddresses', showIPAddresses)
  );

  return disposables;
}

/**
 * Cleanup IP command resources.
 */
export function deactivateIPCommands(): void {
  if (outputChannel) {
    outputChannel.dispose();
    outputChannel = undefined;
  }
}
