# OgunScan ⚔️

**MCP server security scanner. Find vulnerabilities before attackers do.**

Built by Ten30 Studios. Named for Ogun — Yoruba orisha of iron and protection.

## Install

```bash
npm install -g ogunscan
# or
pip install ogunscan
```

## Usage

```bash
ogunscan scan ./mcp-config.json
ogunscan scan ~/.cursor/mcp.json
ogunscan scan --dir . --recursive
```

## What it catches

- Prompt injection vectors in tool descriptions
- Exposed credentials and API keys in config files  
- Server-side request forgery (SSRF) exposure
- Malicious server URL patterns
- Overly permissive tool scopes
- Double-hop latency exploits
- Unverified server origins

## Plans

| Plan | Price | Features |
|------|-------|----------|
| Free | $0 | Single scan, CLI only |
| Shield | $9/mo | Continuous monitoring, CI/CD integration, private server scanning, alerts |

## Links

- Site: https://ogunscan.dev
- Docs: https://ogunscan.dev/docs
- GitHub: https://github.com/ten30studio/ogunscan
