import * as vscode from 'vscode';
import type { IRule, RulePack, RuleVendor } from '@sentriflow/core';

/**
 * Provides a webview-based settings panel for SentriFlow configuration
 */
export class SettingsWebviewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = 'sentriflowSettings';

  private _view?: vscode.WebviewView;
  private _getDefaultPack: () => RulePack = () => ({ name: 'sf-default', version: '0.0.0', publisher: '', description: '', license: '', priority: 0, rules: [] });
  private _getRegisteredPacks: () => Map<string, RulePack> = () => new Map();
  private _getAllRules: () => IRule[] = () => [];
  private _getDisabledRulesSet: () => Set<string> = () => new Set();

  constructor(private readonly _extensionUri: vscode.Uri) {}

  /**
   * Initialize the provider with callbacks to access extension state
   */
  initialize(
    getDefaultPack: () => RulePack,
    getRegisteredPacks: () => Map<string, RulePack>,
    getAllRules: () => IRule[],
    getDisabledRulesSet: () => Set<string>,
  ): void {
    this._getDefaultPack = getDefaultPack;
    this._getRegisteredPacks = getRegisteredPacks;
    this._getAllRules = getAllRules;
    this._getDisabledRulesSet = getDisabledRulesSet;
  }

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlContent(webviewView.webview);

    // Handle messages from webview
    webviewView.webview.onDidReceiveMessage(async (message) => {
      switch (message.command) {
        case 'getSettings':
          await this._sendSettings();
          break;
        case 'updateSetting':
          await this._updateSetting(message.key, message.value);
          break;
        case 'toggleRule':
          await this._toggleRule(message.ruleId);
          break;
        case 'enableRule':
          await this._enableRule(message.ruleId);
          break;
      }
    });

    // Send initial settings
    this._sendSettings();
  }

  /**
   * Refresh the webview when settings change
   */
  refresh(): void {
    if (this._view) {
      this._sendSettings();
    }
  }

  private async _sendSettings(): Promise<void> {
    if (!this._view) return;

    const config = vscode.workspace.getConfiguration('sentriflow');
    const settings = {
      defaultVendor: config.get<string>('defaultVendor', 'auto'),
      showVendorInStatusBar: config.get<boolean>('showVendorInStatusBar', true),
      treeGrouping: config.get<string>('treeGrouping', 'vendor'),
      showTagsSection: config.get<boolean>('showTagsSection', true),
      tagTypeFilter: config.get<string>('tagTypeFilter', 'all'),
      enableDefaultRules: config.get<boolean>('enableDefaultRules', true),
      blockedPacks: config.get<string[]>('blockedPacks', []),
      packVendorOverrides: config.get<Record<string, { disabledVendors?: string[] }>>(
        'packVendorOverrides',
        {}
      ),
      disabledRules: Array.from(this._getDisabledRulesSet()),
    };

    // Build pack list
    const packs = [];
    const defaultPack = this._getDefaultPack();
    packs.push({
      name: defaultPack.name,
      isDefault: true,
      ruleCount: this._getAllRules().length,
      isEnabled: settings.enableDefaultRules,
      vendors: this._getVendorsForPack(defaultPack.name),
      disabledVendors: settings.packVendorOverrides[defaultPack.name]?.disabledVendors ?? [],
    });

    for (const [name, pack] of this._getRegisteredPacks()) {
      packs.push({
        name,
        isDefault: false,
        ruleCount: pack.rules.length,
        isEnabled: !settings.blockedPacks.includes(name),
        vendors: this._getVendorsForPack(name),
        disabledVendors: settings.packVendorOverrides[name]?.disabledVendors ?? [],
      });
    }

    // Get all unique vendors from rules
    const allVendors = this._getAllVendors();

    this._view.webview.postMessage({
      command: 'settings',
      settings,
      packs,
      allRulesCount: this._getAllRules().length,
      disabledRulesCount: settings.disabledRules.length,
      allVendors,
    });
  }

  private _getVendorsForPack(packName: string): string[] {
    const defaultPack = this._getDefaultPack();
    const rules = packName === defaultPack.name
      ? this._getAllRules()
      : (this._getRegisteredPacks().get(packName)?.rules ?? []);

    const vendors = new Set<string>();
    for (const rule of rules) {
      if (rule.vendor) {
        const ruleVendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
        ruleVendors.forEach((v) => vendors.add(v));
      } else {
        vendors.add('common');
      }
    }

    return Array.from(vendors).sort();
  }

  private _getAllVendors(): string[] {
    const vendors = new Set<string>();

    // Collect from all rules across all packs
    for (const rule of this._getAllRules()) {
      if (rule.vendor) {
        const ruleVendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
        ruleVendors.forEach((v) => vendors.add(v));
      }
    }

    // Also collect from registered packs
    for (const [, pack] of this._getRegisteredPacks()) {
      for (const rule of pack.rules) {
        if (rule.vendor) {
          const ruleVendors = Array.isArray(rule.vendor) ? rule.vendor : [rule.vendor];
          ruleVendors.forEach((v) => vendors.add(v));
        }
      }
    }

    return Array.from(vendors).sort();
  }

  private async _updateSetting(key: string, value: unknown): Promise<void> {
    const config = vscode.workspace.getConfiguration('sentriflow');
    await config.update(key, value, vscode.ConfigurationTarget.Workspace);
    await this._sendSettings();
  }

  private async _toggleRule(ruleId: string): Promise<void> {
    const config = vscode.workspace.getConfiguration('sentriflow');
    const disabledRules = config.get<string[]>('disabledRules', []);
    const isDisabled = disabledRules.includes(ruleId);

    const newDisabledRules = isDisabled
      ? disabledRules.filter((id) => id !== ruleId)
      : [...disabledRules, ruleId];

    await config.update(
      'disabledRules',
      newDisabledRules,
      vscode.ConfigurationTarget.Workspace
    );
    await this._sendSettings();
  }

  private async _enableRule(ruleId: string): Promise<void> {
    const config = vscode.workspace.getConfiguration('sentriflow');
    const disabledRules = config.get<string[]>('disabledRules', []);
    const newDisabledRules = disabledRules.filter((id) => id !== ruleId);

    await config.update(
      'disabledRules',
      newDisabledRules,
      vscode.ConfigurationTarget.Workspace
    );
    await this._sendSettings();
  }

  private _getHtmlContent(webview: vscode.Webview): string {
    const nonce = this._getNonce();

    // Note: This HTML is static and safe. Dynamic content is handled via
    // postMessage and DOM APIs in the script, using textContent for text
    // and createElement for structure.
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <title>SentriFlow Settings</title>
  <style>
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
      padding: 0 10px 10px 10px;
      margin: 0;
    }
    h3 {
      margin: 16px 0 8px 0;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--vscode-sideBarSectionHeader-foreground);
      border-bottom: 1px solid var(--vscode-sideBarSectionHeader-border);
      padding-bottom: 4px;
    }
    .setting-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid var(--vscode-widget-border, transparent);
    }
    .setting-row:last-child { border-bottom: none; }
    .setting-label { flex: 1; font-size: 12px; }
    .setting-description {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      margin-top: 2px;
    }
    select {
      background: var(--vscode-dropdown-background);
      color: var(--vscode-dropdown-foreground);
      border: 1px solid var(--vscode-dropdown-border);
      padding: 4px 8px;
      font-size: 12px;
      border-radius: 2px;
      cursor: pointer;
    }
    select:focus { outline: 1px solid var(--vscode-focusBorder); }
    .toggle {
      position: relative;
      width: 36px;
      height: 20px;
      background: var(--vscode-checkbox-background);
      border: 1px solid var(--vscode-checkbox-border);
      border-radius: 10px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .toggle.active { background: var(--vscode-button-background); }
    .toggle::after {
      content: '';
      position: absolute;
      width: 14px;
      height: 14px;
      background: var(--vscode-checkbox-foreground);
      border-radius: 50%;
      top: 2px;
      left: 2px;
      transition: left 0.2s;
    }
    .toggle.active::after { left: 18px; }
    .pack-card {
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-widget-border);
      border-radius: 4px;
      padding: 10px;
      margin-bottom: 8px;
    }
    .pack-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }
    .pack-name { font-weight: 600; font-size: 12px; }
    .pack-info {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .vendor-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      margin-top: 8px;
    }
    .vendor-chip {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 11px;
      cursor: pointer;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
      transition: opacity 0.2s;
    }
    .vendor-chip.disabled {
      opacity: 0.5;
      text-decoration: line-through;
    }
    .vendor-chip:hover { opacity: 0.8; }
    .disabled-rules-list {
      max-height: 200px;
      overflow-y: auto;
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-widget-border);
      border-radius: 4px;
      padding: 4px;
    }
    .disabled-rule-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 4px 8px;
      font-size: 11px;
      border-radius: 2px;
    }
    .disabled-rule-item:hover {
      background: var(--vscode-list-hoverBackground);
    }
    .remove-btn {
      background: none;
      border: none;
      color: var(--vscode-errorForeground);
      cursor: pointer;
      padding: 2px 6px;
      font-size: 12px;
      border-radius: 2px;
    }
    .remove-btn:hover {
      background: var(--vscode-inputValidation-errorBackground);
    }
    .empty-state {
      text-align: center;
      padding: 16px;
      color: var(--vscode-descriptionForeground);
      font-size: 11px;
    }
  </style>
</head>
<body>
  <h3>General</h3>
  <div class="setting-row">
    <div class="setting-label">
      Default Vendor
      <div class="setting-description">Vendor for parsing configuration files</div>
    </div>
    <select id="defaultVendor">
      <option value="auto">Auto-detect</option>
    </select>
  </div>
  <div class="setting-row">
    <div class="setting-label">
      Show Vendor in Status Bar
      <div class="setting-description">Display detected vendor name</div>
    </div>
    <div class="toggle" id="showVendorInStatusBar"></div>
  </div>
  <div class="setting-row">
    <div class="setting-label">
      Tree Grouping
      <div class="setting-description">How to organize rules in the tree view</div>
    </div>
    <select id="treeGrouping">
      <option value="vendor">Vendor → Rules</option>
      <option value="category">Category → Rules</option>
      <option value="category-vendor">Category → Vendor → Rules</option>
      <option value="vendor-category">Vendor → Category → Rules</option>
    </select>
  </div>
  <div class="setting-row">
    <div class="setting-label">
      Show Tags Section
      <div class="setting-description">Show "By Tag" section in tree view</div>
    </div>
    <div class="toggle" id="showTagsSection"></div>
  </div>
  <div class="setting-row">
    <div class="setting-label">
      Tag Type Filter
      <div class="setting-description">Filter tags by type in tree view</div>
    </div>
    <select id="tagTypeFilter">
      <option value="all">All Types</option>
      <option value="security">Security</option>
      <option value="operational">Operational</option>
      <option value="compliance">Compliance</option>
      <option value="general">General</option>
    </select>
  </div>

  <h3>Rule Packs</h3>
  <div id="packsContainer"></div>

  <h3>Disabled Rules (<span id="disabledCount">0</span>)</h3>
  <div id="disabledRulesContainer" class="disabled-rules-list">
    <div class="empty-state">No rules disabled</div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    let currentSettings = {};

    const defaultVendorSelect = document.getElementById('defaultVendor');
    const showVendorToggle = document.getElementById('showVendorInStatusBar');
    const treeGroupingSelect = document.getElementById('treeGrouping');
    const showTagsSectionToggle = document.getElementById('showTagsSection');
    const tagTypeFilterSelect = document.getElementById('tagTypeFilter');
    const packsContainer = document.getElementById('packsContainer');
    const disabledRulesContainer = document.getElementById('disabledRulesContainer');
    const disabledCountSpan = document.getElementById('disabledCount');

    vscode.postMessage({ command: 'getSettings' });

    window.addEventListener('message', (event) => {
      const message = event.data;
      if (message.command === 'settings') {
        currentSettings = message.settings;
        updateUI(message);
      }
    });

    defaultVendorSelect.addEventListener('change', () => {
      vscode.postMessage({
        command: 'updateSetting',
        key: 'defaultVendor',
        value: defaultVendorSelect.value,
      });
    });

    showVendorToggle.addEventListener('click', () => {
      const newValue = !showVendorToggle.classList.contains('active');
      vscode.postMessage({
        command: 'updateSetting',
        key: 'showVendorInStatusBar',
        value: newValue,
      });
    });

    treeGroupingSelect.addEventListener('change', () => {
      vscode.postMessage({
        command: 'updateSetting',
        key: 'treeGrouping',
        value: treeGroupingSelect.value,
      });
    });

    showTagsSectionToggle.addEventListener('click', () => {
      const newValue = !showTagsSectionToggle.classList.contains('active');
      vscode.postMessage({
        command: 'updateSetting',
        key: 'showTagsSection',
        value: newValue,
      });
    });

    tagTypeFilterSelect.addEventListener('change', () => {
      vscode.postMessage({
        command: 'updateSetting',
        key: 'tagTypeFilter',
        value: tagTypeFilterSelect.value,
      });
    });

    function updateUI(data) {
      // Populate vendors dropdown dynamically
      const currentValue = data.settings.defaultVendor;
      while (defaultVendorSelect.options.length > 1) {
        defaultVendorSelect.remove(1);
      }
      if (data.allVendors && data.allVendors.length > 0) {
        data.allVendors.forEach(vendor => {
          const option = document.createElement('option');
          option.value = vendor;
          option.textContent = vendor;
          defaultVendorSelect.appendChild(option);
        });
      }
      defaultVendorSelect.value = currentValue;

      showVendorToggle.classList.toggle('active', data.settings.showVendorInStatusBar);
      treeGroupingSelect.value = data.settings.treeGrouping || 'vendor';
      showTagsSectionToggle.classList.toggle('active', data.settings.showTagsSection !== false);
      tagTypeFilterSelect.value = data.settings.tagTypeFilter || 'all';

      // Clear and rebuild packs using DOM APIs
      while (packsContainer.firstChild) {
        packsContainer.removeChild(packsContainer.firstChild);
      }

      data.packs.forEach(pack => {
        const card = document.createElement('div');
        card.className = 'pack-card';

        const header = document.createElement('div');
        header.className = 'pack-header';

        const nameContainer = document.createElement('div');
        const nameSpan = document.createElement('span');
        nameSpan.className = 'pack-name';
        nameSpan.textContent = pack.name;
        const infoSpan = document.createElement('span');
        infoSpan.className = 'pack-info';
        infoSpan.textContent = ' (' + pack.ruleCount + ' rules)';
        nameContainer.appendChild(nameSpan);
        nameContainer.appendChild(infoSpan);

        const toggle = document.createElement('div');
        toggle.className = 'toggle' + (pack.isEnabled ? ' active' : '');
        toggle.addEventListener('click', () => {
          if (pack.isDefault) {
            vscode.postMessage({
              command: 'updateSetting',
              key: 'enableDefaultRules',
              value: !pack.isEnabled,
            });
          } else {
            const blockedPacks = currentSettings.blockedPacks || [];
            const newBlockedPacks = pack.isEnabled
              ? [...blockedPacks, pack.name]
              : blockedPacks.filter(p => p !== pack.name);
            vscode.postMessage({
              command: 'updateSetting',
              key: 'blockedPacks',
              value: newBlockedPacks,
            });
          }
        });

        header.appendChild(nameContainer);
        header.appendChild(toggle);
        card.appendChild(header);

        if (pack.vendors.length > 0) {
          const chipsContainer = document.createElement('div');
          chipsContainer.className = 'vendor-chips';

          pack.vendors.forEach(v => {
            const chip = document.createElement('span');
            chip.className = 'vendor-chip' + (pack.disabledVendors.includes(v) ? ' disabled' : '');
            chip.textContent = v;
            chip.addEventListener('click', () => {
              const isDisabled = pack.disabledVendors.includes(v);
              const overrides = currentSettings.packVendorOverrides || {};
              const packOverride = overrides[pack.name] || { disabledVendors: [] };
              const disabledVendors = packOverride.disabledVendors || [];

              const newDisabledVendors = isDisabled
                ? disabledVendors.filter(vendor => vendor !== v)
                : [...disabledVendors, v];

              const newOverrides = { ...overrides };
              if (newDisabledVendors.length > 0) {
                newOverrides[pack.name] = { disabledVendors: newDisabledVendors };
              } else {
                delete newOverrides[pack.name];
              }

              vscode.postMessage({
                command: 'updateSetting',
                key: 'packVendorOverrides',
                value: Object.keys(newOverrides).length > 0 ? newOverrides : undefined,
              });
            });
            chipsContainer.appendChild(chip);
          });

          card.appendChild(chipsContainer);
        }

        packsContainer.appendChild(card);
      });

      // Update disabled rules using DOM APIs
      disabledCountSpan.textContent = String(data.settings.disabledRules.length);

      while (disabledRulesContainer.firstChild) {
        disabledRulesContainer.removeChild(disabledRulesContainer.firstChild);
      }

      if (data.settings.disabledRules.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        emptyState.textContent = 'No rules disabled';
        disabledRulesContainer.appendChild(emptyState);
      } else {
        data.settings.disabledRules.sort().forEach(ruleId => {
          const item = document.createElement('div');
          item.className = 'disabled-rule-item';

          const ruleSpan = document.createElement('span');
          ruleSpan.textContent = ruleId;

          const removeBtn = document.createElement('button');
          removeBtn.className = 'remove-btn';
          removeBtn.textContent = '×';
          removeBtn.title = 'Enable rule';
          removeBtn.addEventListener('click', () => {
            vscode.postMessage({
              command: 'enableRule',
              ruleId: ruleId,
            });
          });

          item.appendChild(ruleSpan);
          item.appendChild(removeBtn);
          disabledRulesContainer.appendChild(item);
        });
      }
    }
  </script>
</body>
</html>`;
  }

  private _getNonce(): string {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 32; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
  }
}
