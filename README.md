# @diffdelta/mcp-server

[Model Context Protocol](https://modelcontextprotocol.io) server for [DiffDelta](https://diffdelta.io) — lets AI agents discover and consume intelligence feeds natively.

## Install

```bash
npm install -g @diffdelta/mcp-server
```

Or run directly with npx:

```bash
npx @diffdelta/mcp-server
```

## Quick Start (30 seconds)

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "diffdelta": {
      "command": "npx",
      "args": ["-y", "@diffdelta/mcp-server"]
    }
  }
}
```

**Cursor** — add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "diffdelta": {
      "command": "npx",
      "args": ["-y", "@diffdelta/mcp-server"]
    }
  }
}
```

Then ask your AI agent:

> "Check DiffDelta for any security issues affecting my stack: openai, langchain, pinecone"

The agent will call `diffdelta_discover_stack` → `diffdelta_check_head` → `diffdelta_poll` and give you a structured answer with action codes.

### More prompts to try

- *"Is anything broken right now? Check cloud status."*
- *"Are there any CVEs I should patch immediately?"*
- *"What changed in the last day across all my dependencies?"*
- *"Check if it's safe to deploy — any critical vulnerabilities?"*

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DIFFDELTA_API_KEY` | Pro/Enterprise API key (optional, free tier works without it) |
| `DIFFDELTA_BASE_URL` | Override base URL (default: `https://diffdelta.io`) |

## Tools

### `diffdelta_check_head`

Check if anything changed — ~200 bytes, nearly free. **Always call this first.**

Returns cursor, item counts, verified silence status (`allClear`, `confidence`), and pipeline freshness. If nothing changed and confidence is high, you can report "all N sources verified, no changes" without fetching anything else.

### `diffdelta_poll`

Fetch new, updated, and flagged items. Only fetches if cursor has changed. Each item includes:

- **Structured signals**: severity (CVE/CVSS), release (version), incident (status), deprecation (breaking changes)
- **Action codes**: `PATCH_IMMEDIATELY`, `PATCH_SOON`, `VERSION_PIN`, `REVIEW_CHANGELOG`, `MONITOR_STATUS`, `ACKNOWLEDGE`, `NO_ACTION`
- **Provenance**: authority name and evidence URL for every signal

Filter by `tags` (e.g. `["security"]`) or `sources` (e.g. `["cisa_kev"]`).

### `diffdelta_poll_source`

Same as `diffdelta_poll` but for a single source — smaller payload, faster response.

### `diffdelta_list_sources`

List all available intelligence sources with tags and descriptions. 46+ sources covering security advisories, cloud status, AI/ML releases, infrastructure, and more.

### `diffdelta_discover_stack`

**The killer feature.** Give it your dependency names and get back exactly which sources to monitor:

```
Input: ["openai", "langchain", "pinecone"]
Output: openai_sdk_releases, openai_api_changelog, langchain_releases, pinecone_status
```

### `diffdelta_check_health`

Verify the DiffDelta pipeline is running. Returns last engine run time and source health counts. A stale timestamp means the pipeline may be down.

## Workflow

### Normal operation (nothing changed)

```
Agent: diffdelta_check_head()
→ { changed: false, all_clear: true, sources_checked: 46, confidence: 1.0 }
→ "All 46 sources verified 2 minutes ago. Nothing changed."
```

Cost: ~200 bytes. The agent can confidently report "all clear" without fetching anything else.

### When something is flagged

```
Agent: diffdelta_check_head()
→ { changed: true, counts: { flagged: 3, new: 12 } }

Agent: diffdelta_poll({ tags: ["security"] })
→ [FLAGGED] ⚡PATCH_IMMEDIATELY github_advisories: Critical RCE in openssl [risk: 9.8/10]
   Signals: severity:critical(9.8) | 🔴 EXPLOITED
   Source: GitHub Advisory Database
   URL: https://github.com/advisories/GHSA-...

Agent: "Triggering emergency patch based on DiffDelta advisory GHSA-...,
        verified via GitHub Advisory Database (CVSS 9.8, actively exploited)."
```

### Stack-aware monitoring

```
Agent: diffdelta_discover_stack({ dependencies: ["openai", "langchain", "pinecone"] })
→ Matched 3/3 dependencies, 4 sources to monitor
→ openai_sdk_releases, openai_api_changelog, langchain_releases, pinecone_status

Agent: diffdelta_poll({ sources: ["openai_sdk_releases", "langchain_releases", "pinecone_status"] })
→ 2 items: langchain security patch, pinecone investigating latency
```

### Pre-deploy safety check

```
Agent: diffdelta_check_health()
→ { status: "healthy", sources_checked: 46, sources_ok: 46 }

Agent: diffdelta_check_head()
→ { all_clear: true, confidence: 0.98 }

Agent: "Pipeline healthy. 46/46 sources verified. No critical issues. Safe to deploy."
```

## License

MIT
