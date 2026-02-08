/**
 * DiffDelta MCP Server
 *
 * Lets AI agents discover and consume DiffDelta intelligence feeds
 * natively via the Model Context Protocol.
 *
 * Tools:
 *   - diffdelta_check_head  → 400-byte heartbeat: "has anything changed?"
 *   - diffdelta_poll        → Fetch new/updated items from the global feed
 *   - diffdelta_poll_source → Fetch new/updated items from a specific source
 *   - diffdelta_list_sources → List all available intelligence sources
 *
 * Resources:
 *   - diffdelta://sources          → JSON list of all sources
 *   - diffdelta://head             → Global head pointer (cursor + changed flag)
 *   - diffdelta://feed/global      → Full global feed
 *   - diffdelta://feed/{source_id} → Per-source feed
 */

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";

const VERSION = "0.1.0";
const BASE_URL = process.env.DIFFDELTA_BASE_URL || "https://diffdelta.io";
const API_KEY = process.env.DIFFDELTA_API_KEY || process.env.DD_API_KEY || "";
const TIMEOUT = 15_000;

// ── HTTP helpers ──

function headers(): Record<string, string> {
  const h: Record<string, string> = {
    "User-Agent": `diffdelta-mcp/${VERSION}`,
    Accept: "application/json",
  };
  if (API_KEY) h["X-DiffDelta-Key"] = API_KEY;
  return h;
}

async function fetchJson(url: string): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const res = await fetch(url, { headers: headers(), signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// ── Feed parsing helpers ──

interface RawItem {
  source?: string;
  id?: string;
  headline?: string;
  url?: string;
  risk_score?: number;
  summary?: { risk_score?: number; logic?: string };
  content?: { excerpt_text?: string; summary?: string } | string;
  published_at?: string;
  updated_at?: string;
  provenance?: Record<string, unknown>;
}

function formatItem(item: RawItem, bucket: string): string {
  const risk = item.risk_score ?? item.summary?.risk_score ?? null;
  const riskStr = risk !== null ? ` [risk: ${risk}/10]` : "";
  const excerpt =
    typeof item.content === "object" && item.content !== null
      ? (item.content.excerpt_text || item.content.summary || "")
      : typeof item.content === "string"
        ? item.content
        : "";
  const lines = [
    `[${bucket.toUpperCase()}] ${item.source}: ${item.headline}${riskStr}`,
  ];
  if (item.url) lines.push(`  URL: ${item.url}`);
  if (excerpt) lines.push(`  ${excerpt.slice(0, 200)}`);
  return lines.join("\n");
}

function formatFeedItems(data: Record<string, unknown>, buckets: string[]): string {
  const rawBuckets = (data.buckets || {}) as Record<string, RawItem[]>;
  const lines: string[] = [];
  let count = 0;

  for (const bucket of buckets) {
    const items = rawBuckets[bucket] || [];
    for (const item of items) {
      lines.push(formatItem(item, bucket));
      count++;
    }
  }

  if (count === 0) return "No items found.";

  const header = `${count} item(s) found:`;
  return [header, "", ...lines].join("\n");
}

// ── Cursor store (in-memory per session) ──

const cursors = new Map<string, string>();

// ── Create server ──

const server = new McpServer(
  {
    name: "diffdelta",
    version: VERSION,
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
    instructions: [
      "DiffDelta provides agent-ready intelligence feeds — security advisories, cloud status pages, changelogs, and more — as structured, risk-scored data.",
      "",
      "Quick workflow:",
      "1. Call diffdelta_check_head to see if anything changed (400 bytes, nearly free).",
      "2. If changed=true, call diffdelta_poll to get the new items.",
      "3. Use diffdelta_list_sources to see all available feeds.",
      "4. Use diffdelta_poll_source for targeted per-source polling.",
      "",
      "Every item includes a risk_score (0-10) and summary so you can prioritize without reading full text.",
    ].join("\n"),
  }
);

// ── Tools ──

// 1. Check Head — the 400-byte heartbeat
server.tool(
  "diffdelta_check_head",
  "Check if anything has changed in a DiffDelta feed. Returns a ~400-byte response with cursor, hash, and changed flag. Use this FIRST before fetching full feeds to save tokens.",
  {
    source_id: z.optional(
      z.string().describe(
        "Optional source ID (e.g. 'cisa_kev'). Omit to check the global feed."
      )
    ),
  },
  async ({ source_id }) => {
    const url = source_id
      ? `${BASE_URL}/diff/source/${source_id}/head.json`
      : `${BASE_URL}/diff/head.json`;

    const data = (await fetchJson(url)) as Record<string, unknown>;
    const cursor = data.cursor as string;
    const cursorKey = source_id ? `source:${source_id}` : "global";
    const storedCursor = cursors.get(cursorKey);
    const changed = !storedCursor || storedCursor !== cursor;

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              changed,
              cursor: cursor,
              hash: data.hash,
              generated_at: data.generated_at,
              ttl_sec: data.ttl_sec,
              source: source_id || "global",
              note: changed
                ? "Feed has new content. Call diffdelta_poll to retrieve items."
                : "No changes since last check. No need to fetch the full feed.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// 2. Poll — fetch new items from the global feed
server.tool(
  "diffdelta_poll",
  "Fetch new and updated items from DiffDelta. Checks head.json first; only fetches the full feed if the cursor has changed. Automatically tracks cursors between calls. Returns formatted items with risk scores.",
  {
    tags: z.optional(
      z.array(z.string()).describe(
        "Filter by tags (e.g. ['security', 'cloud-status']). Available tags: security, cloud-status, releases, news, cloud, ai-ml."
      )
    ),
    sources: z.optional(
      z.array(z.string()).describe(
        "Filter by source IDs (e.g. ['cisa_kev', 'nist_nvd'])."
      )
    ),
    include_removed: z.optional(
      z.boolean().describe(
        "Include removed items. Default: false."
      )
    ),
  },
  async ({ tags, sources, include_removed }) => {
    const cursorKey = "global";
    const buckets = include_removed
      ? ["new", "updated", "removed"]
      : ["new", "updated"];

    // Step 1: Check head
    const headData = (await fetchJson(
      `${BASE_URL}/diff/head.json`
    )) as Record<string, unknown>;
    const newCursor = headData.cursor as string;
    const storedCursor = cursors.get(cursorKey);

    if (storedCursor && storedCursor === newCursor) {
      return {
        content: [
          {
            type: "text" as const,
            text: "No changes since last poll. Feed is up to date.",
          },
        ],
      };
    }

    // Step 2: Fetch full feed
    const feed = (await fetchJson(
      `${BASE_URL}/diff/latest.json`
    )) as Record<string, unknown>;

    // Step 3: Save cursor
    const feedCursor = feed.cursor as string;
    if (feedCursor) cursors.set(cursorKey, feedCursor);

    // Step 4: Filter and format
    let result = formatFeedItems(feed, buckets);

    // Apply source filter
    if (sources?.length) {
      const rawBuckets = (feed.buckets || {}) as Record<string, RawItem[]>;
      const filtered: string[] = [];
      let count = 0;
      for (const bucket of buckets) {
        for (const item of rawBuckets[bucket] || []) {
          if (sources.includes(item.source || "")) {
            filtered.push(formatItem(item, bucket));
            count++;
          }
        }
      }
      result = count > 0
        ? [`${count} item(s) matching sources [${sources.join(", ")}]:`, "", ...filtered].join("\n")
        : `No items from sources [${sources.join(", ")}].`;
    }

    // Apply tag filter (requires source metadata)
    if (tags?.length && !sources?.length) {
      try {
        const sourcesData = (await fetchJson(
          `${BASE_URL}/diff/sources.json`
        )) as { sources: Array<{ source_id: string; tags: string[] }> };
        const tagMap = new Map(
          sourcesData.sources.map((s) => [s.source_id, s.tags])
        );

        const rawBuckets = (feed.buckets || {}) as Record<string, RawItem[]>;
        const filtered: string[] = [];
        let count = 0;
        for (const bucket of buckets) {
          for (const item of rawBuckets[bucket] || []) {
            const itemTags = tagMap.get(item.source || "") || [];
            if (tags.some((t) => itemTags.includes(t))) {
              filtered.push(formatItem(item, bucket));
              count++;
            }
          }
        }
        result = count > 0
          ? [`${count} item(s) matching tags [${tags.join(", ")}]:`, "", ...filtered].join("\n")
          : `No items matching tags [${tags.join(", ")}].`;
      } catch {
        // If sources.json fails, return unfiltered
      }
    }

    // Add narrative if present
    const narrative = feed.batch_narrative as string;
    if (narrative) {
      result = `Summary: ${narrative}\n\n${result}`;
    }

    return {
      content: [{ type: "text" as const, text: result }],
    };
  }
);

// 3. Poll Source — fetch items from a specific source
server.tool(
  "diffdelta_poll_source",
  "Fetch new items from a specific DiffDelta source. More efficient than global poll when you only care about one source.",
  {
    source_id: z.string().describe(
      "The source ID to poll (e.g. 'cisa_kev', 'nist_nvd', 'github_advisory')."
    ),
    include_removed: z.optional(
      z.boolean().describe("Include removed items. Default: false.")
    ),
  },
  async ({ source_id, include_removed }) => {
    const cursorKey = `source:${source_id}`;
    const buckets = include_removed
      ? ["new", "updated", "removed"]
      : ["new", "updated"];

    // Step 1: Check head
    const headData = (await fetchJson(
      `${BASE_URL}/diff/source/${source_id}/head.json`
    )) as Record<string, unknown>;
    const newCursor = headData.cursor as string;
    const storedCursor = cursors.get(cursorKey);

    if (storedCursor && storedCursor === newCursor) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No changes in ${source_id} since last poll.`,
          },
        ],
      };
    }

    // Step 2: Fetch feed
    const feed = (await fetchJson(
      `${BASE_URL}/diff/source/${source_id}/latest.json`
    )) as Record<string, unknown>;

    // Step 3: Save cursor
    const feedCursor = feed.cursor as string;
    if (feedCursor) cursors.set(cursorKey, feedCursor);

    // Step 4: Format
    let result = formatFeedItems(feed, buckets);
    const narrative = feed.batch_narrative as string;
    if (narrative) {
      result = `Summary: ${narrative}\n\n${result}`;
    }

    return {
      content: [{ type: "text" as const, text: result }],
    };
  }
);

// 4. List Sources — discover all available feeds
server.tool(
  "diffdelta_list_sources",
  "List all available DiffDelta intelligence sources with their tags, status, and descriptions. Use this to discover what feeds are available.",
  {},
  async () => {
    const data = (await fetchJson(
      `${BASE_URL}/diff/sources.json`
    )) as { sources: Array<Record<string, unknown>> };

    const lines = data.sources.map((s) => {
      const tags = (s.tags as string[]) || [];
      const status = s.status as string || "ok";
      const statusIcon = status === "ok" ? "✓" : status === "degraded" ? "⚠" : "✗";
      return `${statusIcon} ${s.source_id} [${tags.join(", ")}] — ${s.name}${s.description ? `: ${s.description}` : ""}`;
    });

    const tagCounts = new Map<string, number>();
    for (const s of data.sources) {
      for (const t of (s.tags as string[]) || []) {
        tagCounts.set(t, (tagCounts.get(t) || 0) + 1);
      }
    }
    const tagSummary = [...tagCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([tag, count]) => `  ${tag}: ${count} sources`)
      .join("\n");

    const result = [
      `${data.sources.length} intelligence sources available:`,
      "",
      `Tags:`,
      tagSummary,
      "",
      "Sources:",
      ...lines,
    ].join("\n");

    return {
      content: [{ type: "text" as const, text: result }],
    };
  }
);

// ── Resources ──

// Static: Sources list
server.resource(
  "sources",
  "diffdelta://sources",
  { description: "List of all DiffDelta intelligence sources", mimeType: "application/json" },
  async () => {
    const data = await fetchJson(`${BASE_URL}/diff/sources.json`);
    return {
      contents: [
        {
          uri: "diffdelta://sources",
          text: JSON.stringify(data, null, 2),
          mimeType: "application/json",
        },
      ],
    };
  }
);

// Static: Global head pointer
server.resource(
  "head",
  "diffdelta://head",
  { description: "Global feed head pointer — cursor, hash, and change detection", mimeType: "application/json" },
  async () => {
    const data = await fetchJson(`${BASE_URL}/diff/head.json`);
    return {
      contents: [
        {
          uri: "diffdelta://head",
          text: JSON.stringify(data, null, 2),
          mimeType: "application/json",
        },
      ],
    };
  }
);

// Static: Global feed
server.resource(
  "global-feed",
  "diffdelta://feed/global",
  { description: "Full global DiffDelta feed with all sources", mimeType: "application/json" },
  async () => {
    const data = await fetchJson(`${BASE_URL}/diff/latest.json`);
    return {
      contents: [
        {
          uri: "diffdelta://feed/global",
          text: JSON.stringify(data, null, 2),
          mimeType: "application/json",
        },
      ],
    };
  }
);

// Dynamic: Per-source feed
server.resource(
  "source-feed",
  new ResourceTemplate("diffdelta://feed/{source_id}", {
    list: async () => {
      // List all available source feeds
      const data = (await fetchJson(
        `${BASE_URL}/diff/sources.json`
      )) as { sources: Array<{ source_id: string; name: string }> };
      return {
        resources: data.sources.map((s) => ({
          uri: `diffdelta://feed/${s.source_id}`,
          name: `${s.name} Feed`,
          description: `Intelligence feed for ${s.name}`,
          mimeType: "application/json",
        })),
      };
    },
    complete: {
      source_id: async () => {
        const data = (await fetchJson(
          `${BASE_URL}/diff/sources.json`
        )) as { sources: Array<{ source_id: string }> };
        return data.sources.map((s) => s.source_id);
      },
    },
  }),
  { description: "Per-source intelligence feed", mimeType: "application/json" },
  async (uri, { source_id }) => {
    const data = await fetchJson(
      `${BASE_URL}/diff/source/${source_id}/latest.json`
    );
    return {
      contents: [
        {
          uri: uri.href,
          text: JSON.stringify(data, null, 2),
          mimeType: "application/json",
        },
      ],
    };
  }
);

// ── Start ──

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Server is now listening on stdin/stdout
  console.error(`[diffdelta-mcp] Server v${VERSION} running on stdio`);
  console.error(`[diffdelta-mcp] Base URL: ${BASE_URL}`);
  console.error(`[diffdelta-mcp] API Key: ${API_KEY ? "configured" : "none (free tier)"}`);
}

main().catch((err) => {
  console.error("[diffdelta-mcp] Fatal error:", err);
  process.exit(1);
});
