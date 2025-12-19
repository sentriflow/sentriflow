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
sentriflow scan router.conf

# Validate multiple files
sentriflow scan configs/*.conf

# Output results in SARIF format (for CI/CD integration)
sentriflow scan router.conf --format sarif -o results.sarif

# Auto-detect vendor from file content
sentriflow scan unknown.conf --detect
```

## Usage

```
Usage: sentriflow [options] [command]

Network configuration linter and validator

Options:
  -V, --version              output the version number
  -h, --help                 display help for command

Commands:
  scan [options] <files...>  Scan configuration files for issues
  help [command]             display help for command
```

### Scan Command Options

```
Usage: sentriflow scan [options] <files...>

Options:
  -v, --vendor <vendor>     Specify vendor (cisco-ios, juniper-junos, etc.)
  -f, --format <format>     Output format: text, json, sarif (default: "text")
  -o, --output <file>       Write output to file
  -s, --severity <level>    Minimum severity: info, warning, error (default: "warning")
  --detect                  Auto-detect vendor from file content
  -h, --help                display help for command
```

## Output Formats

### Text (default)

```
router.conf:12:5 error SEC-001 Telnet is enabled - use SSH instead
router.conf:45:1 warning NET-003 No description on interface GigabitEthernet0/1
```

### JSON

```json
{
  "files": 1,
  "issues": [
    {
      "file": "router.conf",
      "line": 12,
      "column": 5,
      "severity": "error",
      "ruleId": "SEC-001",
      "message": "Telnet is enabled - use SSH instead"
    }
  ]
}
```

### SARIF

Produces SARIF 2.1.0 compliant output for integration with GitHub Code Scanning, VS Code, and other tools.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Lint network configs
  run: |
    npx @sentriflow/cli scan configs/*.conf --format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Related Packages

- [`@sentriflow/core`](https://github.com/sentriflow/sentriflow/tree/main/packages/core) - Core parsing engine
- [`@sentriflow/rules-default`](https://github.com/sentriflow/sentriflow/tree/main/packages/rules-default) - Default validation rules

## License

Apache-2.0
