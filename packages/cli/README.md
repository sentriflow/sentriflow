# @sentriflow/cli

Command-line interface for SentriFlow - lint and validate network configurations.

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
# Validate a single configuration file
sentriflow router.conf

# Validate with specific vendor
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
```

## Usage

```
Usage: sentriflow [options] [file]

SentriFlow Network Configuration Validator

Arguments:
  file                          Path to the configuration file

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
| `-p, --rule-pack <path>` | Rule pack file to load |
| `--json-rules <path...>` | Path(s) to JSON rules file(s) |
| `-r, --rules <path>` | Additional rules file (legacy) |

### Encrypted Rule Packs

| Option | Description |
|--------|-------------|
| `--encrypted-pack <path...>` | Path(s) to encrypted rule pack(s) (.grpx) |
| `--license-key <key>` | License key (or set `SENTRIFLOW_LICENSE_KEY` env var) |
| `--strict-packs` | Fail if encrypted pack cannot be loaded |

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
      "column": 1
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

## CI/CD Integration

### GitHub Actions

```yaml
- name: Lint network configs
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

- [`@sentriflow/core`](https://github.com/sentriflow/sentriflow/tree/main/packages/core) - Core parsing engine
- [`@sentriflow/rules-default`](https://github.com/sentriflow/sentriflow/tree/main/packages/rules-default) - Default validation rules

## License

Apache-2.0
