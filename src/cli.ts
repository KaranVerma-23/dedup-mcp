#!/usr/bin/env node
/**
 * dedup-mcp — MCP server exposing same-type vulnerability deduplication
 * for Harness STO findings.
 *
 * Tools:
 *   - normalize_sto_issues   — convert raw STO API JSON to RefinedIssue shape
 *   - find_duplicate_groups  — cluster RefinedIssue records into duplicate groups
 *   - compare_pair           — single-pair tier check (debug helper)
 *
 * Transport:
 *   - stdio (default)        — for Cursor / Claude Desktop / local AI clients
 *   - http  --port <n>       — for remote/shared (Worker Agent + ngrok)
 *                              Uses Streamable HTTP with session management
 *                              per the MCP spec.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { findDuplicateGroups } from "./tools/find-duplicate-groups.js";
import { normalizeStoIssues } from "./tools/normalize-sto-issues.js";
import { dedupePipeline } from "./tools/dedupe-pipeline.js";
import { matchPair } from "./lib/tier-match.js";

// ── shared input shape: a permissive RefinedIssue ──────────────────
const RefinedIssueSchema = z
  .object({
    internal_id: z.string().optional(),
    id: z.string().optional(),
    account_id: z.string().optional(),
    scan_id: z.string().optional(),
    product_id: z.string().optional(),
    product_name: z.string().optional(),
    issue_type: z.enum(["SAST","SCA","DAST","IAC","SECRET","MISCONFIG","CONTAINER"]).optional(),
    reference_identifiers: z
      .array(z.object({ type: z.string(), id: z.string() }))
      .optional(),
    severity: z.number().optional(),
    severity_code: z.string().optional(),
    title: z.string().optional(),
    issue_description: z.string().optional(),
    library_name: z.string().optional(),
    current_version: z.string().optional(),
    file_name: z.string().optional(),
    line_number: z.number().optional(),
    start_line: z.number().optional(),
    end_line: z.number().optional(),
    image_layer_id: z.string().optional(),
    image_registry: z.string().optional(),
    image_tag: z.string().optional(),
  })
  .passthrough();

/** Build a fresh McpServer with all tools registered.
 *  HTTP mode creates a new server per session (per MCP spec).
 *  stdio mode reuses a single instance.
 */
function buildServer(): McpServer {
  const server = new McpServer({
    name: "dedup-mcp",
    version: "0.1.0",
  });

  server.tool(
    "normalize_sto_issues",
    "Convert raw STO Core API issue payloads (the camelCase shape returned by `harness_list(security_issue, ...)`) into the snake_case `RefinedIssue` shape that `find_duplicate_groups` expects. Tolerant of multiple wrapping shapes: a flat array, `{data:[...]}`, `{issues:[...]}`, `{content:[...]}`, etc. Always call this BEFORE `find_duplicate_groups` when the data came from harness-mcp.",
    {
      issues: z.unknown().describe("Raw response from harness_list(security_issue, ...) — array or wrapper object"),
      default_product_name: z.string().optional()
        .describe("Optional fallback scanner name if the API doesn't include productName"),
    },
    async ({ issues, default_product_name }) => {
      const result = normalizeStoIssues({ issues, default_product_name });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "find_duplicate_groups",
    "Cluster STO RefinedIssue records into same-type duplicate groups. Returns groups with confidence tier (HIGH / MEDIUM / LOW), matched signals as evidence, and a deterministically-picked primary per group. Group threshold defaults to HIGH; pairs at lower tiers are surfaced as review_candidates instead.",
    {
      issues: z.array(RefinedIssueSchema).describe("Flat list of RefinedIssue records"),
      group_threshold: z.enum(["HIGH","MEDIUM","LOW"]).optional()
        .describe("Lowest tier to auto-group (default HIGH)"),
    },
    async ({ issues, group_threshold }) => {
      const result = findDuplicateGroups({
        issues: issues as any,
        group_threshold,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "dedupe_pipeline",
    "ONE-SHOT: fetch + (optionally enrich) + normalize + dedup STO issues. Scope is optional — pass pipeline_id, target_id, both (intersection), or neither (all-issues across the project, capped by max_issues). Returns only the small final summary (groups, headlines, suggested actions, timings) — large payloads stay inside dedup-mcp so the LLM never has to relay them. The `enrich` parameter controls per-issue detail fetching for the API backend ('auto' default = enrich only cross-scanner candidates; 'never' = fast list-only; 'always' = enrich every issue). The `backend` parameter selects how STO data is fetched: 'api' (default) uses the Harness STO REST API; 'sql' uses direct read-only Postgres against STO Core (~5-10x faster, includes per-occurrence file/line for SAST HIGH matching).",
    {
      pipeline_id: z.string().optional()
        .describe("STO pipeline identifier. Optional."),
      target_id: z.string().optional()
        .describe("STO target identifier (repo/image/etc). Optional. Combine with pipeline_id for intersection filter; omit both to dedup across all-issues."),
      project_id: z.string().describe("Harness project identifier"),
      org_id: z.string().optional().describe("Harness org identifier (omit for default)"),
      page_size: z.number().int().positive().max(100).optional()
        .describe("STO API page size (max 100, default 100)"),
      max_pages: z.number().int().positive().optional()
        .describe("Max pages to fetch (API backend, defaults to ceil(max_issues/page_size))"),
      max_issues: z.number().int().positive().max(5000).optional()
        .describe("Hard cap on issues processed (default 1000). Bounds the O(N²) match step. Most-recent issues kept when truncated."),
      group_threshold: z.enum(["HIGH","MEDIUM","LOW"]).optional()
        .describe("Lowest tier to auto-group (default LOW — catches sibling-package fanout)"),
      enrich: z.enum(["never","auto","always"]).optional()
        .describe("Detail-enrichment mode (default 'auto'). API backend only. See tool description."),
      backend: z.enum(["api","sql"]).optional()
        .describe("Data source. 'api' (default, production-shaped) uses the Harness STO REST API. 'sql' uses direct read-only Postgres against STO Core; ~10x faster and includes per-occurrence file/line for SAST. SQL backend requires STO_DATABASE_URL env. Demo/QA only."),
      sto_database_url: z.string().optional()
        .describe("Override STO_DATABASE_URL for sql backend (Postgres connection string)."),
      default_product_name: z.string().optional()
        .describe("Fallback scanner name when STO API doesn't include one"),
      harness_base_url: z.string().optional()
        .describe("Override HARNESS_BASE_URL env (e.g. https://qa.harness.io)"),
      harness_api_key: z.string().optional()
        .describe("Override HARNESS_API_KEY env (Harness PAT)"),
      harness_account_id: z.string().optional()
        .describe("Override account id (otherwise parsed from PAT)"),
    },
    async (input) => {
      const result = await dedupePipeline(input);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "compare_pair",
    "Check whether two RefinedIssue records are duplicates. Returns the highest tier they match at (HIGH / MEDIUM / LOW) plus the matched signals, or null if they don't match. Useful for ad-hoc investigation.",
    {
      issue_a: RefinedIssueSchema,
      issue_b: RefinedIssueSchema,
    },
    async ({ issue_a, issue_b }) => {
      const result = matchPair(issue_a as any, issue_b as any);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(result ?? { tier: null, rationale: "Not duplicates." }, null, 2),
        }],
      };
    },
  );

  return server;
}

// ──────────────────────────────────────────────────────────────────
// Transport selection
// ──────────────────────────────────────────────────────────────────

const mode = process.argv[2] === "http" ? "http" : "stdio";

if (mode === "stdio") {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
} else {
  // ── HTTP mode with proper Streamable HTTP session management ──
  // Pattern mirrors harness-mcp's server (src/index.ts ~line 333).
  // See: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
  const { StreamableHTTPServerTransport } = await import(
    "@modelcontextprotocol/sdk/server/streamableHttp.js"
  );
  const { createServer } = await import("node:http");
  const { randomUUID } = await import("node:crypto");
  const port = Number(process.env.PORT ?? 8080);

  type Session = {
    server: McpServer;
    transport: InstanceType<typeof StreamableHTTPServerTransport>;
  };
  const sessions = new Map<string, Session>();

  const httpServer = createServer(async (req, res) => {
    // Parse URL (strip query params, normalize trailing slash)
    const rawUrl = req.url ?? "/";
    const pathname = rawUrl.split("?")[0].replace(/\/+$/, "") || "/";

    // Health endpoint — separate from /mcp so platform connectivity checks
    // don't get confused with MCP protocol traffic.
    if (pathname === "/health" || pathname === "/") {
      res.writeHead(200, { "content-type": "application/json" })
         .end(JSON.stringify({
           name: "dedup-mcp",
           status: "ok",
           sessions: sessions.size,
           endpoints: {
             "POST /mcp":   "MCP JSON-RPC (initialize without session header; subsequent calls include mcp-session-id)",
             "GET /mcp":    "MCP server-sent events (requires mcp-session-id header)",
             "DELETE /mcp": "Terminate a session (requires mcp-session-id header)",
             "GET /health": "Health check",
           },
         }));
      return;
    }

    if (pathname !== "/mcp") {
      res.writeHead(404, { "content-type": "application/json" })
         .end(JSON.stringify({ error: "Not found", expected: "/mcp" }));
      return;
    }

    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // Helper: read full request body as parsed JSON (or undefined)
    async function readBody(): Promise<unknown> {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      if (chunks.length === 0) return undefined;
      try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return undefined;
      }
    }

    try {
      // ── Existing session: route to that session's transport
      if (sessionId) {
        const session = sessions.get(sessionId);
        if (!session) {
          res.writeHead(404, { "content-type": "application/json" })
             .end(JSON.stringify({
               jsonrpc: "2.0",
               error: { code: -32000, message: "Session not found. Send an initialize request to start a new session." },
               id: null,
             }));
          return;
        }
        const body = req.method === "POST" ? await readBody() : undefined;
        await session.transport.handleRequest(req, res, body);
        return;
      }

      // ── No session header
      if (req.method !== "POST") {
        res.writeHead(400, { "content-type": "application/json" })
           .end(JSON.stringify({
             jsonrpc: "2.0",
             error: { code: -32000, message: "mcp-session-id header required for non-POST requests. Initialize a session first via POST /mcp." },
             id: null,
           }));
        return;
      }

      // POST without session — must be an initialize request. Create a new session.
      const body = await readBody();
      const server = buildServer();
      let createdId: string | undefined;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id: string) => {
          createdId = id;
          sessions.set(id, { server, transport });
          process.stderr.write(`[dedup-mcp] session created: ${id} (total: ${sessions.size})\n`);
        },
      });
      transport.onclose = () => {
        if (createdId) {
          sessions.delete(createdId);
          process.stderr.write(`[dedup-mcp] session closed: ${createdId} (total: ${sessions.size})\n`);
        }
      };
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      process.stderr.write(`[dedup-mcp] error handling ${req.method} ${pathname}: ${String(err)}\n`);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" })
           .end(JSON.stringify({
             jsonrpc: "2.0",
             error: { code: -32700, message: "Internal server error", details: String(err) },
             id: null,
           }));
      }
    }
  });

  httpServer.listen(port, () => {
    process.stderr.write(
      `dedup-mcp HTTP listening on port ${port}\n` +
      `  POST   /mcp    — MCP JSON-RPC (sessioned)\n` +
      `  GET    /mcp    — SSE stream (sessioned)\n` +
      `  DELETE /mcp    — Terminate session\n` +
      `  GET    /health — Health check\n`,
    );
  });
}
