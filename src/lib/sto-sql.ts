/**
 * Direct SQL backend for fetching STO issues + occurrences.
 *
 * Why this exists alongside the API client:
 *   - API path (harness-client.ts) is what would ship in production. Honors
 *     RBAC, scopes by PAT, doesn't need DB credentials. Slower because we
 *     pay one HTTP round-trip per issue for detail enrichment, and the issue
 *     detail endpoint omits per-occurrence fields like fileName/lineNumber
 *     for SAST.
 *   - SQL path (this file) is the fast/rich backend used for QA testing and
 *     the dev-day demo. ONE query returns issues + occurrences + scanner
 *     attribution + per-occurrence file/line in seconds. Lets SAST HIGH-tier
 *     dedup actually fire (because semgrep's file/line are in
 *     occurrence.unique_details, not the API response).
 *
 * Configuration:
 *   STO_DATABASE_URL  postgres://USER:PASS@HOST:PORT/DB?search_path=sto
 *
 * Read-only by design — this module never INSERTs, UPDATEs, or DELETEs.
 */

import pgPkg from "pg";
const { Pool } = pgPkg;

export interface StoSqlFetchOptions {
  /** Postgres URL. Falls back to STO_DATABASE_URL env. */
  database_url?: string;
  /** Optional. If both pipeline_id AND target_id are omitted, the query
   *  runs against ALL issues for the (org_id, project_id) scope — capped
   *  by `max_issues` so the O(N²) downstream matching stays bounded. */
  pipeline_id?: string;
  /** Filter by STO target id (e.g. "Z7NnNDEBhUSxl9gv8CGz8U" — what STO calls
   *  a "target", typically a repo or container image). When combined with
   *  pipeline_id, both filters apply (intersection). */
  target_id?: string;
  /** Optional org/project filters (defensive — the pipeline_id is usually
   *  globally unique within an account but we honor scope when given). */
  org_id?: string;
  project_id?: string;
  /** Hard cap on returned issues. Default 1000 — keeps O(N²) match within
   *  ~1M comparisons (~1s on modern hardware). When the underlying issue
   *  count exceeds the cap, the most recent issues are kept (ORDER BY
   *  i.created DESC). */
  max_issues?: number;
}

/** One row per (issue, occurrence) — flat enough that the rest of the dedup
 *  pipeline can treat them like API issues with extra fields. */
export interface StoSqlIssueRow {
  issue_id: string;
  scanner: string;
  issue_title: string;
  severity_code: string;
  pipeline_id: string;
  org_id: string;
  project_id: string;
  /** Total occurrences for this issue across all scans (the pre-STO-dedup
   *  raw finding count we use for the headline noise-reduction metric). */
  occurrence_count: number;
  /** Sample occurrence's unique_details — for SCA carries libraryName,
   *  currentVersion, referenceIdentifiers; for SAST carries fileName,
   *  lineNumber, referenceIdentifiers, etc. Schema varies by scanner. */
  unique_details: Record<string, unknown> | null;
}

export interface StoSqlFetchResult {
  issues: StoSqlIssueRow[];
  /** Sum of occurrence_count across returned issues — pre-STO-dedup raw count. */
  total_occurrences: number;
  /** True if the underlying issue count exceeded `max_issues` and the result
   *  was truncated. */
  capped: boolean;
  /** True total before capping (when known). */
  total_available: number;
}

let cachedPool: InstanceType<typeof Pool> | undefined;

function getPool(databaseUrl: string): InstanceType<typeof Pool> {
  if (cachedPool) return cachedPool;
  cachedPool = new Pool({
    connectionString: databaseUrl,
    max: 4,
    idleTimeoutMillis: 30_000,
    application_name: "dedup-mcp",
  });
  return cachedPool;
}

/** Single-query fetch: issue + scanner + total occurrence count + a
 *  representative occurrence's unique_details for downstream parsing. */
export async function fetchStoIssuesSql(
  opts: StoSqlFetchOptions,
): Promise<StoSqlFetchResult> {
  const url = opts.database_url ?? process.env.STO_DATABASE_URL;
  if (!url) {
    throw new Error(
      "STO_DATABASE_URL not set. SQL backend requires read-only Postgres credentials (e.g. from sto-core/.env).",
    );
  }
  // No pipeline/target filter is fine — we'll scope by (org_id, project_id)
  // if given, or run against the whole account, capped by max_issues.
  const pool = getPool(url);
  const maxIssues = Math.max(1, Math.min(opts.max_issues ?? 1000, 5000));

  // The aggregation strategy:
  //   - one row per (issue, scan) is fanned out by the join; we group back
  //     to one row per (issue, scanner). Different scanners stay separate
  //     because issue.product_id is part of the natural key.
  //   - count(o.internal_id) = number of occurrences across all (issue, scan)
  //     pairings — STO's `numOccurrences` equivalent (per-scanner).
  //   - (array_agg(o.unique_details))[1] = pick any one occurrence's details.
  //     They're materially equivalent across occurrences of the same issue
  //     (issue.key, the dedup hash, derives from these fields).
  //   - org_id/project_id were dropped from `scan` and now live in
  //     `hierarchy_lookup`. We join LEFT (defensive — some old scans may
  //     not have a hierarchy row) and filter only when the caller supplied
  //     a value.
  // target_variant.target_id is what users see as the "target" (a repo,
  // container image, etc). We join target_variant only when target_id is
  // supplied — saves a join on the common pipeline-only path.
  // scan.target_variant_id is the varchar uuid (target_variant.id), not the
  // serial internal_id — so we join on .id.
  const joinTargetVariant = opts.target_id
    ? "JOIN sto.target_variant tv ON tv.id = s.target_variant_id"
    : "";

  // Three-stage query — the only shape that's both correct and fast:
  //   Stage 1 (scope_scans):       filter scans by scope (pipeline/target/
  //                                org/project). Cheap and indexed.
  //   Stage 2 (recent_issue_ids):  pick the N most recent issue IDs that
  //                                have ≥1 in-scope scan. ORDER BY +
  //                                LIMIT happens here on the slim
  //                                (issue_id, created) projection — no
  //                                aggregation in the way of pushdown.
  //   Stage 3 (main SELECT):       aggregate occurrences ONLY for the
  //                                capped issue IDs and ONLY across the
  //                                in-scope scans. Bounded N → bounded
  //                                work (~ms instead of minutes).
  //
  //   Without stage 2, PG had to aggregate every (issue, scan, occurrence)
  //   tuple across the entire project before the LIMIT could be applied.
  const targetParamIdx = opts.target_id ? 4 : null;
  const limitParamIdx = targetParamIdx ? 5 : 4;

  const sql = `
    WITH scope_scans AS (
      SELECT s.internal_id
      FROM sto.scan s
      ${joinTargetVariant}
      LEFT JOIN sto.hierarchy_lookup h
        ON h.parent_unique_id = s.parent_unique_id AND h.account_id = s.account_id
      WHERE NOT s.is_deleted
        AND ($1::text IS NULL OR s.pipeline_id = $1)
        AND ($2::text IS NULL OR h.org_id = $2)
        AND ($3::text IS NULL OR h.project_id = $3)
        ${targetParamIdx ? `AND tv.target_id = $${targetParamIdx}` : ""}
    ),
    recent_issue_ids AS (
      SELECT i.internal_id, i.created
      FROM sto.issue i
      WHERE NOT i.is_deleted
        AND EXISTS (
          SELECT 1
          FROM sto.issue_scan ix
          JOIN scope_scans ss ON ss.internal_id = ix.scan_internal_id
          WHERE ix.issue_internal_id = i.internal_id
        )
      ORDER BY i.created DESC
      LIMIT $${limitParamIdx}
    )
    ,
    per_issue_count AS (
      -- Pure count, no JSONB read. Uses unnest of the int8[] occurrence
      -- list which is cheap. Only counts occurrences from in-scope scans.
      SELECT
        ix.issue_internal_id,
        count(occ_id) AS occurrence_count
      FROM sto.issue_scan ix
      JOIN scope_scans ss ON ss.internal_id = ix.scan_internal_id
      JOIN recent_issue_ids ri ON ri.internal_id = ix.issue_internal_id
      LEFT JOIN LATERAL unnest(ix.occurrence_internal_ids) AS occ_id ON TRUE
      GROUP BY ix.issue_internal_id
    ),
    per_issue_sample AS (
      -- ONE sample unique_details per issue. DISTINCT ON lets PG stop after
      -- the first qualifying occurrence rather than aggregating every JSONB.
      SELECT DISTINCT ON (ix.issue_internal_id)
        ix.issue_internal_id,
        o.unique_details
      FROM sto.issue_scan ix
      JOIN scope_scans ss ON ss.internal_id = ix.scan_internal_id
      JOIN recent_issue_ids ri ON ri.internal_id = ix.issue_internal_id
      JOIN sto.occurrence o ON o.internal_id = ANY(ix.occurrence_internal_ids)
      ORDER BY ix.issue_internal_id, o.internal_id
    )
    SELECT
      i.id                        AS issue_id,
      p.name                      AS scanner,
      i.title                     AS issue_title,
      i.severity_code::text       AS severity_code,
      ''                          AS pipeline_id,
      ''                          AS org_id,
      ''                          AS project_id,
      coalesce(pc.occurrence_count, 0) AS occurrence_count,
      ps.unique_details           AS unique_details
    FROM recent_issue_ids ri
    JOIN sto.issue            i  ON i.internal_id  = ri.internal_id
    JOIN sto.product          p  ON p.id           = i.product_id
    LEFT JOIN per_issue_count   pc ON pc.issue_internal_id = i.internal_id
    LEFT JOIN per_issue_sample  ps ON ps.issue_internal_id = i.internal_id
    ORDER BY ri.created DESC
  `;
  const params: Array<string | number | null> = [
    opts.pipeline_id ?? null,
    opts.org_id ?? null,
    opts.project_id ?? null,
  ];
  if (opts.target_id) params.push(opts.target_id);
  // Fetch one extra row to detect if the result was capped.
  params.push(maxIssues + 1);

  const res = await pool.query(sql, params);
  // We asked for maxIssues+1; if we got that many, the underlying total
  // exceeded the cap. Drop the extra row before returning.
  const capped = res.rows.length > maxIssues;
  const rows = capped ? res.rows.slice(0, maxIssues) : res.rows;

  let totalOccurrences = 0;
  const issues: StoSqlIssueRow[] = rows.map((r) => {
    const oc = Number(r.occurrence_count ?? 0);
    totalOccurrences += oc;
    return {
      issue_id: String(r.issue_id),
      scanner: String(r.scanner),
      issue_title: String(r.issue_title ?? ""),
      severity_code: String(r.severity_code ?? ""),
      pipeline_id: String(r.pipeline_id ?? ""),
      org_id: String(r.org_id ?? ""),
      project_id: String(r.project_id ?? ""),
      occurrence_count: oc,
      unique_details:
        r.unique_details && typeof r.unique_details === "object"
          ? (r.unique_details as Record<string, unknown>)
          : null,
    };
  });

  return {
    issues,
    total_occurrences: totalOccurrences,
    capped,
    // We only know "≥ cap+1 exists"; not the true total. Surface that honestly.
    total_available: capped ? -1 : issues.length,
  };
}

/** Translate a SQL row into the STO API-shape that normalize_sto_issues
 *  already understands. This way the same downstream pipeline (normalize →
 *  SCA tuple bucket / pairwise dedup) handles both backends without
 *  branching on backend type. */
export function sqlRowToApiShape(row: StoSqlIssueRow): Record<string, unknown> {
  const ud = row.unique_details ?? {};
  // Try to pull the standard fields out of unique_details. Field names vary
  // by scanner — be tolerant.
  const fileName =
    pickStr(ud, "fileName") ?? pickStr(ud, "file_name") ?? pickStr(ud, "filePath");
  const lineNumber =
    pickNum(ud, "lineNumber") ?? pickNum(ud, "line_number") ?? pickNum(ud, "line");
  const libraryName =
    pickStr(ud, "libraryName") ?? pickStr(ud, "componentName");
  const currentVersion =
    pickStr(ud, "currentVersion") ?? pickStr(ud, "componentVersion");
  // Canonicalize bare CVE/CWE ids to "CVE-YYYY-NNNN" / "CWE-NNN" so they
  // line up with API-shape output (where the title parser also adds the prefix).
  const refIds = pickArray(ud, "referenceIdentifiers")?.map((r) => {
    if (!r || typeof r !== "object") return r;
    const o = r as Record<string, unknown>;
    const type = typeof o.type === "string" ? o.type.toLowerCase() : "";
    let id = typeof o.id === "string" ? o.id.trim().toUpperCase() : "";
    if (type === "cve" && /^\d{4}-\d+$/.test(id)) id = `CVE-${id}`;
    if (type === "cwe" && /^\d+$/.test(id)) id = `CWE-${id}`;
    return { type, id };
  });
  const description = pickStr(ud, "issueDescription") ?? pickStr(ud, "description");
  const targetType = pickStr(ud, "targetType");

  return {
    id: row.issue_id,
    title: row.issue_title,
    severityCode: row.severity_code,
    scanTool: row.scanner,
    issueType: inferIssueType(ud, row.scanner),
    numOccurrences: row.occurrence_count,
    referenceIdentifiers: refIds,
    fileName,
    lineNumber,
    libraryName,
    currentVersion,
    description,
    targetType,
  };
}

function pickStr(o: Record<string, unknown>, k: string): string | undefined {
  const v = o[k];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function pickNum(o: Record<string, unknown>, k: string): number | undefined {
  const v = o[k];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function pickArray(o: Record<string, unknown>, k: string): unknown[] | undefined {
  const v = o[k];
  return Array.isArray(v) ? v : undefined;
}

/** Best-effort issue-type inference. Some scanners stuff issue type into
 *  unique_details; otherwise infer from the package's known scanner type. */
function inferIssueType(
  ud: Record<string, unknown>,
  scanner: string,
): string | undefined {
  const direct = pickStr(ud, "issueType") ?? pickStr(ud, "issue_type");
  if (direct) return direct.toUpperCase();
  // Heuristic by scanner — covers the common QA-pipeline tools.
  const s = scanner.toLowerCase();
  if (s.includes("trivy") || s.includes("grype") || s.includes("sca")) return "SCA";
  if (s.includes("sast") || s.includes("semgrep") || s.includes("bandit")) return "SAST";
  if (s.includes("zap") || s.includes("dast")) return "DAST";
  if (s.includes("checkov") || s.includes("tfsec") || s.includes("kics")) return "IAC";
  if (s.includes("gitleaks") || s.includes("trufflehog") || s.includes("secret")) return "SECRET";
  return undefined;
}

/** Close the cached pool — useful for clean shutdown in CLI scripts. */
export async function closeStoSql(): Promise<void> {
  if (cachedPool) {
    await cachedPool.end();
    cachedPool = undefined;
  }
}
