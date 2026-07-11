# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes    |
| < 0.2   | ❌ No     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via one of:

- **GitHub private reporting**: [Security Advisories](https://github.com/artificemachine/shipguard/security/advisories/new)
- **Email**: security@devopscelstn.com *(replace with real address before publishing)*

### What to include

- Description of the vulnerability and potential impact
- Steps to reproduce (minimal example preferred)
- Affected version(s)
- Any suggested fix or mitigation

### Response timeline

- Acknowledgement: within 48 hours
- Status update: within 7 days
- Fix + disclosure: coordinated with reporter

## Security design notes

`shipguard` performs **read-only static analysis** — it reads files and matches patterns. It does not:
- Make network requests during scans
- Store, transmit, or log file contents
- Require elevated permissions
- Execute code from scanned repositories

Findings are printed to stdout or written to a local report file only.
