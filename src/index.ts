/**
 * DiffDelta MCP Server
 *
 * Lets AI agents discover and consume DiffDelta intelligence feeds
 * natively via the Model Context Protocol.
 *
 * Tools:
 *   - diffdelta_check_head     → ~200-byte heartbeat: "has anything changed?"
 *   - diffdelta_poll           → Fetch new/flagged items from the global feed
 *   - diffdelta_poll_source    → Fetch items from a specific source
 *   - diffdelta_list_sources   → List all available intelligence sources
 *   - diffdelta_discover_stack → Map your dependencies to DiffDelta sources
 *   - diffdelta_check_health   → Pipeline health check
 *
 * Resources:
 *   - diffdelta://sources          → JSON list of all sources
 *   - diffdelta://head             → Global head pointer
 *   - diffdelta://feed/global      → Full global feed
 *   - diffdelta://feed/{source_id} → Per-source feed
 */

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";

const VERSION = "0.1.2";
const BASE_URL = process.env.DIFFDELTA_BASE_URL || "https://diffdelta.io";
const API_KEY = process.env.DIFFDELTA_API_KEY || process.env.DD_API_KEY || "";
const TIMEOUT = 15_000;

// ── HTTP helpers ──

function buildHeaders(): Record<string, string> {
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
    const res = await fetch(url, {
      headers: buildHeaders(),
      signal: controller.signal,
    });
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
  risk?: { score?: number; reasons?: string[] };
  risk_score?: number;
  signals?: {
    severity?: {
      level?: string;
      cvss?: number;
      exploited?: boolean;
      provenance?: { authority?: string; evidence_url?: string };
    };
    release?: { version?: string; prerelease?: boolean; security_patch?: boolean };
    incident?: { status?: string; impact?: string };
    deprecation?: { type?: string; affects?: string[]; confidence?: string };
    suggested_action?: string;
  };
  content?: { excerpt_text?: string; summary?: string } | string;
  published_at?: string;
  updated_at?: string;
  provenance?: Record<string, unknown>;
}

function formatItem(item: RawItem, bucket: string): string {
  const signals = item.signals || {};
  const action = signals.suggested_action;

  // Risk from new format (risk.score 0-1) or legacy (risk_score 0-10)
  const risk = item.risk?.score ?? (item.risk_score ? item.risk_score / 10 : null);
  const riskStr = risk !== null ? ` [risk: ${(risk * 10).toFixed(1)}/10]` : "";

  // Build signal tags
  const tags: string[] = [];
  if (signals.severity) {
    const sev = signals.severity;
    tags.push(`severity:${sev.level}${sev.cvss ? `(${sev.cvss})` : ""}`);
    if (sev.exploited) tags.push("🔴 EXPLOITED");
  }
  if (signals.release) {
    const rel = signals.release;
    tags.push(`release:${rel.version || "?"}${rel.security_patch ? " [SECURITY]" : ""}${rel.prerelease ? " [pre]" : ""}`);
  }
  if (signals.incident) {
    tags.push(`incident:${signals.incident.status}${signals.incident.impact ? `(${signals.incident.impact})` : ""}`);
  }
  if (signals.deprecation) {
    const dep = signals.deprecation;
    tags.push(`deprecation:${dep.type}${dep.affects?.length ? ` affects:[${dep.affects.join(",")}]` : ""}`);
  }

  const excerpt =
    typeof item.content === "object" && item.content !== null
      ? (item.content.excerpt_text || item.content.summary || "")
      : typeof item.content === "string"
        ? item.content
        : "";

  const lines = [
    `[${bucket.toUpperCase()}]${action ? ` ⚡${action}` : ""} ${item.source}: ${item.headline}${riskStr}`,
  ];
  if (tags.length) lines.push(`  Signals: ${tags.join(" | ")}`);
  if (signals.severity?.provenance?.authority) {
    lines.push(`  Source: ${signals.severity.provenance.authority}`);
  }
  if (item.url) lines.push(`  URL: ${item.url}`);
  if (excerpt) lines.push(`  ${excerpt.slice(0, 200)}`);
  return lines.join("\n");
}

function formatFeedItems(
  data: Record<string, unknown>,
  buckets: string[]
): string {
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
      "DiffDelta provides agent-ready intelligence feeds — security advisories, cloud status, changelogs, and more — as structured, signal-rich data.",
      "",
      "Quick workflow:",
      "1. Call diffdelta_check_head to see if anything changed (~200 bytes, nearly free).",
      "   - If allClear=true and confidence is high, nothing happened. You can report 'N sources verified, all clear.'",
      "2. If changed=true and counts.flagged > 0, call diffdelta_poll to get items.",
      "   - Each item has signals (severity, release, incident, deprecation) and a suggested_action code.",
      "   - Action codes: PATCH_IMMEDIATELY, PATCH_SOON, VERSION_PIN, REVIEW_CHANGELOG, MONITOR_STATUS, ACKNOWLEDGE, NO_ACTION.",
      "3. Use diffdelta_discover_stack with dependency names to find which sources to watch.",
      "4. Use diffdelta_check_health to verify the pipeline is running.",
      "",
      "Every signal includes provenance (authority, evidence URL) so you can verify claims.",
    ].join("\n"),
  }
);

// ── Tools ──

// 1. Check Head — the ~200-byte heartbeat
server.tool(
  "diffdelta_check_head",
  "Check if anything has changed in a DiffDelta feed. Returns cursor, counts, verified silence status, and freshness. Use this FIRST — only costs ~200 bytes. If allClear is true and confidence is high, you can skip fetching the full feed and report 'all sources verified, no changes.'",
  {
    source_id: z.optional(
      z.string().describe(
        "Optional source ID (e.g. 'cisa_kev'). Omit to check the global feed."
      )
    ),
  },
  async ({ source_id }) => {
    const url = source_id
      ? `${BASE_URL}/diff/${source_id}/head.json`
      : `${BASE_URL}/diff/head.json`;

    const data = (await fetchJson(url)) as Record<string, unknown>;
    const cursor = data.cursor as string;
    const cursorKey = source_id ? `source:${source_id}` : "global";
    const storedCursor = cursors.get(cursorKey);
    const changedSinceLastCheck = !storedCursor || storedCursor !== cursor;

    const counts = (data.counts as Record<string, number>) || {};
    const freshness = data.freshness as Record<string, unknown> | undefined;

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              changed_since_last_check: changedSinceLastCheck,
              cursor,
              feed_changed: data.changed,
              generated_at: data.generated_at,
              ttl_sec: data.ttl_sec,
              source: source_id || "global",
              counts: {
                new: counts.new || 0,
                updated: counts.updated || 0,
                removed: counts.removed || 0,
                flagged: counts.flagged || 0,
              },
              sources_checked: data.sources_checked,
              sources_ok: data.sources_ok,
              all_clear: data.all_clear,
              all_clear_confidence: data.all_clear_confidence ?? data.confidence,
              freshness: freshness || null,
              next_step: changedSinceLastCheck
                ? (counts.flagged || 0) > 0
                  ? "Flagged items detected. Call diffdelta_poll to get items with action codes."
                  : (counts.new || 0) > 0
                    ? "New items available. Call diffdelta_poll to review."
                    : "Cursor changed but no flagged/new items. Low priority."
                : "No changes since last check. Feed is up to date.",
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
  "Fetch new, updated, and flagged items from DiffDelta. Checks head.json first; only fetches the full feed if the cursor has changed. Returns items with structured signals (severity, release, incident, deprecation) and action codes (PATCH_IMMEDIATELY, VERSION_PIN, etc.).",
  {
    tags: z.optional(
      z.array(z.string()).describe(
        "Filter by tags (e.g. ['security', 'cloud-status']). Available tags: security, cloud-status, releases, news, ai."
      )
    ),
    sources: z.optional(
      z.array(z.string()).describe(
        "Filter by source IDs (e.g. ['cisa_kev', 'github_advisories'])."
      )
    ),
    include_removed: z.optional(
      z.boolean().describe("Include removed items. Default: false.")
    ),
  },
  async ({ tags, sources, include_removed }) => {
    const cursorKey = "global";
    const buckets = include_removed
      ? ["flagged", "new", "updated", "removed"]
      : ["flagged", "new", "updated"];

    // Step 1: Check head
    const headData = (await fetchJson(
      `${BASE_URL}/diff/head.json`
    )) as Record<string, unknown>;
    const newCursor = headData.cursor as string;
    const storedCursor = cursors.get(cursorKey);

    if (storedCursor && storedCursor === newCursor) {
      const allClear = headData.all_clear as boolean;
      const checked = headData.sources_checked as number;
      const confidence = headData.all_clear_confidence ?? headData.confidence;
      return {
        content: [
          {
            type: "text" as const,
            text: allClear
              ? `No changes since last poll. ${checked} sources verified, all clear (confidence: ${confidence}).`
              : "No changes since last poll. Feed is up to date.",
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

    // Step 4: Build items (apply source/tag filters if needed)
    const rawBuckets = (feed.buckets || {}) as Record<string, RawItem[]>;

    // Get tag map if needed
    let tagMap: Map<string, string[]> | null = null;
    if (tags?.length) {
      try {
        const sourcesData = (await fetchJson(
          `${BASE_URL}/diff/sources.json`
        )) as { sources: Array<{ source_id: string; tags: string[] }> };
        tagMap = new Map(
          sourcesData.sources.map((s) => [s.source_id, s.tags])
        );
      } catch {
        // Continue without tag filter
      }
    }

    const lines: string[] = [];
    let count = 0;
    for (const bucket of buckets) {
      for (const item of rawBuckets[bucket] || []) {
        // Source filter
        if (sources?.length && !sources.includes(item.source || "")) continue;
        // Tag filter
        if (tags?.length && tagMap) {
          const itemTags = tagMap.get(item.source || "") || [];
          if (!tags.some((t) => itemTags.includes(t))) continue;
        }
        lines.push(formatItem(item, bucket));
        count++;
      }
    }

    let result =
      count > 0
        ? [`${count} item(s) found:`, "", ...lines].join("\n")
        : "No matching items found.";

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
  "Fetch items from a specific DiffDelta source. More efficient than global poll when you only care about one source. Returns items with structured signals and action codes.",
  {
    source_id: z.string().describe(
      "The source ID to poll (e.g. 'cisa_kev', 'github_advisories', 'openai_sdk_releases')."
    ),
    include_removed: z.optional(
      z.boolean().describe("Include removed items. Default: false.")
    ),
  },
  async ({ source_id, include_removed }) => {
    const cursorKey = `source:${source_id}`;
    const buckets = include_removed
      ? ["flagged", "new", "updated", "removed"]
      : ["flagged", "new", "updated"];

    // Step 1: Check head
    const headData = (await fetchJson(
      `${BASE_URL}/diff/${source_id}/head.json`
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
      `${BASE_URL}/diff/${source_id}/latest.json`
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
      const status = (s.status as string) || "ok";
      const statusIcon =
        status === "ok" ? "✓" : status === "degraded" ? "⚠" : "✗";
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

// 5. Discover Stack — map dependencies to sources
server.tool(
  "diffdelta_discover_stack",
  "Given a list of dependency/technology names you use, returns which DiffDelta sources to monitor. Use this to auto-configure monitoring for your stack.",
  {
    dependencies: z
      .array(z.string())
      .describe(
        "Dependency or technology names (e.g. ['openai', 'langchain', 'pinecone', 'kubernetes', 'postgresql']). Case-insensitive."
      ),
  },
  async ({ dependencies }) => {
    const data = (await fetchJson(
      `${BASE_URL}/diff/stacks.json`
    )) as Record<string, unknown>;

    // Support both formats
    const depsObj = (data.dependencies || data.dependency_map || {}) as Record<
      string,
      { sources?: string[]; description?: string } | string[]
    >;

    const matched: Array<{ dep: string; sources: string[]; description: string }> = [];
    const unmatched: string[] = [];

    for (const dep of dependencies) {
      const entry = depsObj[dep.toLowerCase()];
      if (!entry) {
        unmatched.push(dep);
        continue;
      }
      const sources = Array.isArray(entry) ? entry : entry.sources || [];
      const description =
        !Array.isArray(entry) && entry.description
          ? entry.description
          : "";
      matched.push({ dep, sources, description });
    }

    const allSources = new Set<string>();
    for (const m of matched) {
      for (const s of m.sources) allSources.add(s);
    }

    const lines: string[] = [
      `Stack Discovery Results:`,
      `  Matched: ${matched.length}/${dependencies.length} dependencies`,
      `  Total sources to monitor: ${allSources.size}`,
      "",
    ];

    if (matched.length > 0) {
      lines.push("Matched dependencies:");
      for (const m of matched) {
        lines.push(`  ${m.dep} → [${m.sources.join(", ")}]${m.description ? ` (${m.description})` : ""}`);
      }
      lines.push("");
    }

    if (unmatched.length > 0) {
      lines.push(`Unmatched (not in our graph yet): ${unmatched.join(", ")}`);
      lines.push("");
    }

    lines.push(`Sources to watch: ${[...allSources].join(", ")}`);
    lines.push("");
    lines.push(
      "Tip: Use diffdelta_poll with sources filter, or diffdelta_poll_source for each source."
    );

    return {
      content: [{ type: "text" as const, text: lines.join("\n") }],
    };
  }
);

// 6. Check Health — pipeline health check
server.tool(
  "diffdelta_check_health",
  "Check if the DiffDelta pipeline is running and healthy. Returns when the engine last ran and how many sources are OK. A stale timestamp means the pipeline may be down.",
  {},
  async () => {
    const data = (await fetchJson(
      `${BASE_URL}/healthz.json`
    )) as Record<string, unknown>;

    const ok = data.ok as boolean;
    const checked = data.sources_checked as number;
    const healthy = data.sources_ok as number;
    const time = data.time as string;
    const version = data.engine_version as string;

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              status: ok ? "healthy" : "degraded",
              last_run: time,
              sources_checked: checked,
              sources_ok: healthy,
              engine_version: version,
              note: ok
                ? `Pipeline healthy. ${checked} sources checked, all OK.`
                : `Pipeline degraded: ${healthy}/${checked} sources OK. Some data may be stale.`,
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// ── Resources ──

// Static: Sources list
server.resource(
  "sources",
  "diffdelta://sources",
  {
    description: "List of all DiffDelta intelligence sources",
    mimeType: "application/json",
  },
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
  {
    description:
      "Global feed head pointer — cursor, counts, verified silence, freshness",
    mimeType: "application/json",
  },
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
  {
    description: "Full global DiffDelta feed with all sources",
    mimeType: "application/json",
  },
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
  {
    description: "Per-source intelligence feed",
    mimeType: "application/json",
  },
  async (uri, { source_id }) => {
    const data = await fetchJson(
      `${BASE_URL}/diff/${source_id}/latest.json`
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
  console.error(`[diffdelta-mcp] Server v${VERSION} running on stdio`);
  console.error(`[diffdelta-mcp] Base URL: ${BASE_URL}`);
  console.error(
    `[diffdelta-mcp] API Key: ${API_KEY ? "configured" : "none (free tier)"}`
  );
}

main().catch((err) => {
  console.error("[diffdelta-mcp] Fatal error:", err);
  process.exit(1);
});
