# @sentriflow/cli

Command-line interface for SentriFlow - check network configurations for compliance against best practices or organization-specific policies.

## Installation

```bash
# Using npm
npm install -g @sentriflow/cli

# Using bun
bun add -g @sentriflow/cli
```

**Requirements:** Node.js 18+ or Bun 1.0+

## Quick Start

```bash
# Check a single configuration file
sentriflow router.conf

# Check with specific vendor
sentriflow -v cisco-ios router.conf

# Scan a directory of configs
sentriflow -D configs/

# Scan directory recursively
sentriflow -D configs/ -R

# Output results in SARIF format
sentriflow router.conf -f sarif

# List available vendors
sentriflow --list-vendors

# List active rules
sentriflow --list-rules

# List rules by category
sentriflow --list-rules --category authentication

# List all categories
sentriflow --list-categories

# Read from stdin
cat router.conf | sentriflow -
```

## Usage

```
Usage: sentriflow [options] [file]

SentriFlow Network Configuration Compliance Checker

Arguments:
  file                          Path to the configuration file (use - for stdin)

Options:
  -V, --version                 output the version number
  -h, --help                    display help for command
```

### Output Options

| Option | Description |
|--------|-------------|
| `-f, --format <format>` | Output format: `json` (default), `sarif` |
| `-q, --quiet` | Only output failures (suppress passed results) |
| `--ast` | Output the parsed AST instead of rule results |
| `--relative-paths` | Use relative paths in SARIF output |

### Vendor Options

| Option | Description |
|--------|-------------|
| `-v, --vendor <vendor>` | Vendor type (default: `auto`) |
| `--list-vendors` | List all supported vendors and exit |

Supported vendors: `cisco-ios`, `juniper-junos`, `palo-alto`, `fortinet`, `arista-eos`, `mikrotik`, and more.

### Rule Configuration

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Path to config file (default: auto-detect `.sentriflowrc`) |
| `--no-config` | Ignore config file |
| `-d, --disable <ids>` | Comma-separated rule IDs to disable |
| `--list-rules` | List all active rules and exit |
| `--list-categories` | List all rule categories with counts |
| `--category <name>` | Filter `--list-rules` by category |
| `--list-format <fmt>` | Format for `--list-rules`: `table` (default), `json`, `csv` |
| `-p, --rule-pack <path>` | Rule pack file to load |
| `--json-rules <path...>` | Path(s) to JSON rules file(s) |
| `-r, --rules <path>` | Additional rules file (legacy) |

### IP Extraction

| Option | Description |
|--------|-------------|
| `--extract-ips` | Extract and display all IP addresses/subnets from configuration |
| `--copy-ips` | Copy extracted IPs to clipboard (requires xclip/pbcopy) |

### Encrypted Rule Packs

| Option | Description |
|--------|-------------|
| `--encrypted-pack <path...>` | Path(s) to encrypted rule pack(s) (.grpx) |
| `--license-key <key>` | License key (or set `SENTRIFLOW_LICENSE_KEY` env var) |
| `--strict-packs` | Fail if encrypted pack cannot be loaded |

### Extended Encrypted Packs (GRX2)

Extended GRX2 packs (.grx2) embed wrapped encryption keys, enabling offline scanning without network access.

| Option | Description |
|--------|-------------|
| `--grx2-pack <path...>` | Path(s) to extended encrypted rule pack(s) (.grx2) |
| `--strict-grx2` | Fail immediately if any GRX2 pack cannot be loaded |
| `--show-machine-id` | Display the current machine ID (for license binding support) |

**Environment Variable:**
- `SENTRIFLOW_LICENSE_KEY` - License key for decrypting packs

**Offline Usage:**

GRX2 packs contain embedded wrapped keys, allowing complete offline operation:

```bash
# Scan with portable pack (no network required)
SENTRIFLOW_LICENSE_KEY=ey... sentriflow --grx2-pack ./enterprise-rules.grx2 router.conf

# Scan with multiple packs
sentriflow --grx2-pack pack1.grx2 pack2.grx2 --license-key ey... configs/

# Strict mode: fail on pack load errors
sentriflow --grx2-pack rules.grx2 --strict-grx2 router.conf
```

**Machine-Bound vs Portable Packs:**

- **Portable packs**: Work on any machine with a valid license key
- **Machine-bound packs**: Tied to a specific machine ID for additional security

Use `--show-machine-id` to display your machine ID when requesting machine-bound packs:

```bash
sentriflow --show-machine-id
# Output: Machine ID: a1b2c3d4...
```

### Cloud Licensing Commands

Cloud licensing features require the `@sentriflow/licensing` package, which is provided to customers after purchasing a license. Visit [sentriflow.com.au/pricing](https://sentriflow.com.au/pricing) for more information.

| Command | Description |
|---------|-------------|
| `sentriflow activate --license-key <key>` | Activate license and download entitled packs |
| `sentriflow update` | Check for and download pack updates |
| `sentriflow offline --bundle <path>` | Create offline bundle for air-gapped environments |
| `sentriflow license` | Show license status and entitled feeds |

**Activate a license:**

```bash
# Activate license and download all entitled packs
sentriflow activate --license-key eyJhbGciOiJIUzI1Ni...

# Or use environment variable
export SENTRIFLOW_LICENSE_KEY=eyJhbGciOiJIUzI1Ni...
sentriflow activate
```

**Check for updates:**

```bash
# Check and download available pack updates
sentriflow update
```

**Offline mode:**

Downloaded packs are cached in `~/.sentriflow/cache/` and work offline for 72 hours (entitlement cache). The pack files themselves work indefinitely once downloaded.

If `@sentriflow/licensing` is not installed, these commands display a message with information on how to obtain access.

### Directory Scanning

| Option | Description |
|--------|-------------|
| `-D, --directory <path>` | Scan all config files in a directory |
| `-R, --recursive` | Scan directories recursively |
| `--glob <pattern>` | Glob pattern for file matching (e.g., `"*.cfg"`) |
| `--extensions <exts>` | File extensions to include (comma-separated) |
| `--exclude <patterns>` | Exclude patterns (comma-separated glob patterns) |
| `--progress` | Show progress during directory scanning |

### Security Options

| Option | Description |
|--------|-------------|
| `--allow-external` | Allow reading files outside the current directory |

## Output Formats

### JSON (default)

```json
{
  "vendor": {
    "id": "cisco-ios",
    "name": "Cisco IOS"
  },
  "results": [
    {
      "ruleId": "SEC-001",
      "passed": false,
      "message": "Telnet is enabled - use SSH instead",
      "line": 12,
      "column": 1,
      "category": "authentication",
      "tags": [
        { "type": "security", "label": "plaintext-protocol" }
      ]
    }
  ]
}
```

### JSON (directory mode)

```json
{
  "summary": {
    "filesScanned": 3,
    "totalResults": 15,
    "failures": 5,
    "passed": 10
  },
  "files": [
    {
      "file": "/path/to/router.conf",
      "vendor": { "id": "cisco-ios", "name": "Cisco IOS" },
      "results": [...]
    }
  ]
}
```

### SARIF

Produces SARIF 2.1.0 compliant output for integration with GitHub Code Scanning, VS Code, and other tools.

```bash
sentriflow router.conf -f sarif > results.sarif
```

SARIF output includes rule categories and tags in the `properties` block:

```json
{
  "rules": [{
    "id": "SEC-001",
    "properties": {
      "category": "authentication",
      "tags": ["security:plaintext-protocol"]
    }
  }]
}
```

## Rule Categories

List all available categories:

```bash
sentriflow --list-categories
```

Filter rules by category:

```bash
# List only authentication rules
sentriflow --list-rules --category authentication

# Output as JSON
sentriflow --list-rules --category encryption --list-format json
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Check network config compliance
  run: |
    npx @sentriflow/cli -D configs/ -R -f sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Configuration File

SentriFlow automatically looks for `.sentriflowrc` or `.sentriflowrc.json` in the config file directory and its parents.

```json
{
  "extends": "@sentriflow/rules-default",
  "rules": {
    "SEC-001": "error",
    "NET-003": "off"
  }
}
```

## Related Packages

- [`@sentriflow/core`](https://github.com/sentriflow/sentriflow/tree/main/packages/core) - Core parsing and compliance engine
- [`@sentriflow/rules-default`](https://github.com/sentriflow/sentriflow/tree/main/packages/rules-default) - Default compliance rules

## License

Apache-2.0
