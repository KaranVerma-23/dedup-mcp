/**
 * Minimal Harness STO API client used by `dedupe_pipeline`.
 *
 * We deliberately do NOT depend on harness-mcp here — that would route the
 * payload back through the LLM. Going direct keeps all 200+ issues inside
 * dedup-mcp's process so only the small final summary crosses the wire.
 *
 * Endpoint reference (mirrors mcp-server/src/registry/toolsets/sto.ts):
 *   GET {baseUrl}/sto/api/v2/frontend/all-issues/issues
 *     ?accountId=<acct>
 *     &orgId=<org>
 *     &projectId=<proj>
 *     &pipelineIds=<pipelineId>
 *     &page=<n>
 *     &pageSize=<size>
 *
 * Auth:
 *   x-api-key: <PAT>
 *   Harness-Account: <accountId>
 */

export interface StoFetchOptions {
  /** e.g. "https://qa.harness.io" — no trailing slash. */
  base_url: string;
  /** Harness PAT (pat.<accountId>.<userId>.<token>). */
  api_key: string;
  /** Optional override; otherwise extracted from the PAT. */
  account_id?: string;
  org_id?: string;
  project_id: string;
  /** At least one of pipeline_id / target_id must be provided. */
  pipeline_id?: string;
  /** Filter by STO target id. When combined with pipeline_id both apply. */
  target_id?: string;
  /** Page size cap is 100 server-side. */
  page_size?: number;
  /** Max pages to fetch (safety bound). */
  max_pages?: number;
}

export interface StoFetchResult {
  /** Concatenated issues across all fetched pages. */
  issues: unknown[];
  /** From the first page's pagination block — the true total on the pipeline. */
  total_items: number;
  /** Number of pages we actually fetched. */
  pages_fetched: number;
  /** Server-reported total page count (capped by max_pages on our end). */
  total_pages: number;
}

/** Extract the accountId from a Harness PAT.
 *  Format: `pat.<accountId>.<userId>.<token>`
 */
export function accountIdFromPat(pat: string): string | undefined {
  const parts = pat.split(".");
  if (parts.length >= 4 && parts[0] === "pat") return parts[1];
  return undefined;
}

// ──────────────────────────────────────────────────────────────────────────
// Per-issue detail (used by deep enrichment for cross-scanner HIGH matches)
// ──────────────────────────────────────────────────────────────────────────

export interface StoIssueDetail {
  issue_id: string;
  scan_tool?: string;
  /** Already-structured ref ids (no title-parsing fallback needed). */
  reference_identifiers?: Array<{ type: string; id: string }>;
  description?: string;
  /** Sum of numOccurrences across impactedTargets — within-scanner raw-finding count. */
  num_occurrences?: number;
  /** Number of distinct targets this issue spans. */
  num_targets_impacted?: number;
  epss_score?: number;
  target_type?: string;
}

export interface FetchDetailsOptions {
  base_url: string;
  api_key: string;
  account_id?: string;
  org_id?: string;
  project_id: string;
  /** Issue IDs to enrich. */
  issue_ids: string[];
  /** Parallelism cap. Default 10. */
  concurrency?: number;
}

async function fetchOneDetail(
  baseUrl: string,
  apiKey: string,
  accountId: string,
  orgId: string | undefined,
  projectId: string,
  issueId: string,
): Promise<StoIssueDetail | null> {
  const url = new URL(
    `${baseUrl}/sto/api/v2/frontend/all-issues/issues/${issueId}`,
  );
  url.searchParams.set("accountId", accountId);
  if (orgId) url.searchParams.set("orgId", orgId);
  url.searchParams.set("projectId", projectId);
  // We only need the first page of impactedTargets to count occurrences.
  url.searchParams.set("page", "0");
  url.searchParams.set("pageSize", "100");

  const res = await fetch(url, {
    method: "GET",
    headers: {
      "x-api-key": apiKey,
      "Harness-Account": accountId,
      "accept": "application/json",
    },
  });
  if (!res.ok) {
    // Best-effort enrichment — skip an issue we can't fetch instead of failing the whole dedup.
    return null;
  }
  const json = (await res.json()) as Record<string, unknown>;

  const impacted = (json.impactedTargets as Array<Record<string, unknown>> | undefined) ?? [];
  let numOcc = 0;
  for (const t of impacted) {
    const n = Number(t.numOccurrences ?? 0);
    if (Number.isFinite(n)) numOcc += n;
  }

  const refs = (json.referenceIdentifiers as Array<Record<string, unknown>> | undefined) ?? [];
  const cleanRefs = refs
    .map((r) => ({
      type: typeof r.type === "string" ? r.type.toLowerCase() : "",
      // STO returns CVE ids without the "CVE-" prefix on the detail endpoint; restore it.
      id: typeof r.id === "string" ? canonicalizeRefId(String(r.type ?? ""), r.id) : "",
    }))
    .filter((r) => r.type && r.id);

  return {
    issue_id: issueId,
    scan_tool: typeof json.scanTool === "string" ? json.scanTool : undefined,
    reference_identifiers: cleanRefs.length > 0 ? cleanRefs : undefined,
    description: typeof json.description === "string" ? json.description : undefined,
    num_occurrences: numOcc || undefined,
    num_targets_impacted: impacted.length || undefined,
    epss_score:
      typeof json.epssScore === "number" ? json.epssScore : undefined,
    target_type: typeof json.targetType === "string" ? json.targetType : undefined,
  };
}

/** STO detail returns CVE ids as bare numbers (e.g. "2017-12424") — re-add the prefix
 *  so they line up with list-endpoint titles like "CVE-2017-12424". */
function canonicalizeRefId(type: string, id: string): string {
  const t = type.toLowerCase();
  const upper = String(id).trim().toUpperCase();
  if (t === "cve" && /^\d{4}-\d+$/.test(upper)) return `CVE-${upper}`;
  if (t === "cwe" && /^\d+$/.test(upper)) return `CWE-${upper}`;
  return upper;
}

/** Fetch details for many issues in parallel. Skips any individual failures
 *  (returns null for those) so a single 404/timeout doesn't fail the run. */
export async function fetchIssueDetails(
  opts: FetchDetailsOptions,
): Promise<Map<string, StoIssueDetail>> {
  const baseUrl = opts.base_url.replace(/\/+$/, "");
  const accountIdMaybe = opts.account_id ?? accountIdFromPat(opts.api_key);
  if (!accountIdMaybe) {
    throw new Error(
      "account_id missing — pass `account_id` explicitly or use a PAT in the standard `pat.<accountId>.<userId>.<token>` format.",
    );
  }
  const accountId: string = accountIdMaybe;
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? 10, 20));

  const out = new Map<string, StoIssueDetail>();
  let cursor = 0;
  async function worker() {
    while (cursor < opts.issue_ids.length) {
      const idx = cursor++;
      const id = opts.issue_ids[idx];
      const detail = await fetchOneDetail(
        baseUrl,
        opts.api_key,
        accountId,
        opts.org_id,
        opts.project_id,
        id,
      );
      if (detail) out.set(id, detail);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, opts.issue_ids.length) }, () => worker()),
  );
  return out;
}

/** Build the canonical STO list URL for one page. */
function buildPageUrl(
  baseUrl: string,
  opts: StoFetchOptions,
  accountId: string,
  page: number,
  pageSize: number,
): URL {
  const url = new URL(`${baseUrl}/sto/api/v2/frontend/all-issues/issues`);
  url.searchParams.set("accountId", accountId);
  if (opts.org_id) url.searchParams.set("orgId", opts.org_id);
  url.searchParams.set("projectId", opts.project_id);
  if (opts.pipeline_id) url.searchParams.set("pipelineIds", opts.pipeline_id);
  if (opts.target_id) url.searchParams.set("targetIds", opts.target_id);
  url.searchParams.set("page", String(page));
  url.searchParams.set("pageSize", String(pageSize));
  return url;
}

interface PageResponse {
  issues: unknown[];
  totalItems?: number;
  totalPages?: number;
}

async function fetchOnePage(
  baseUrl: string,
  opts: StoFetchOptions,
  accountId: string,
  page: number,
  pageSize: number,
): Promise<PageResponse> {
  const url = buildPageUrl(baseUrl, opts, accountId, page, pageSize);
  const res = await fetch(url, {
    method: "GET",
    headers: {
      "x-api-key": opts.api_key,
      "Harness-Account": accountId,
      "accept": "application/json",
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "<no body>");
    throw new Error(
      `STO API returned HTTP ${res.status} on page ${page}: ${body.slice(0, 500)}`,
    );
  }
  const json = (await res.json()) as Record<string, unknown>;
  const pagination =
    (json.pagination as Record<string, unknown> | undefined) ?? {};
  return {
    issues: Array.isArray(json.issues) ? (json.issues as unknown[]) : [],
    totalItems: pagination.totalItems != null ? Number(pagination.totalItems) : undefined,
    totalPages: pagination.totalPages != null ? Number(pagination.totalPages) : undefined,
  };
}

/** Fetch all (capped) pages of STO issues for a single pipeline.
 *  Strategy: fetch page 0 to learn `totalPages`, then fan out the remaining
 *  pages in parallel. For a 9-page pipeline this turns 9 sequential round
 *  trips into 1 + 1 (parallel batch) ≈ ~5x speedup on fetch latency.
 */
export async function fetchStoIssuesForPipeline(
  opts: StoFetchOptions,
): Promise<StoFetchResult> {
  const baseUrl = opts.base_url.replace(/\/+$/, "");
  const pageSize = Math.min(opts.page_size ?? 100, 100);
  const maxPages = Math.max(1, opts.max_pages ?? 10);
  const accountIdMaybe = opts.account_id ?? accountIdFromPat(opts.api_key);
  if (!accountIdMaybe) {
    throw new Error(
      "account_id missing — pass `account_id` explicitly or use a PAT in the standard `pat.<accountId>.<userId>.<token>` format.",
    );
  }
  const accountId: string = accountIdMaybe;
  // Scope is optional — if no pipeline/target filter is given, the API
  // returns all issues for the (org, project) scope. The caller is expected
  // to bound this with max_pages × page_size to stay within reasonable
  // limits (default 10 × 100 = 1000 issues).

  // Page 0 (sequential — we need its `totalPages`).
  const first = await fetchOnePage(baseUrl, opts, accountId, 0, pageSize);
  const totalItems = first.totalItems ?? first.issues.length;
  const totalPages = first.totalPages ?? 1;

  // How many more pages to fetch? Bounded by maxPages and by short-page early stop.
  if (first.issues.length < pageSize || totalPages <= 1 || maxPages <= 1) {
    return {
      issues: first.issues,
      total_items: totalItems,
      pages_fetched: 1,
      total_pages: totalPages,
    };
  }

  const lastPage = Math.min(totalPages - 1, maxPages - 1);
  const remainingPages: number[] = [];
  for (let p = 1; p <= lastPage; p++) remainingPages.push(p);

  // Cap parallelism at 6 so we don't get rate-limited.
  const CONCURRENCY = 6;
  const results: PageResponse[] = new Array(remainingPages.length);
  let cursor = 0;
  async function worker() {
    while (cursor < remainingPages.length) {
      const idx = cursor++;
      results[idx] = await fetchOnePage(
        baseUrl,
        opts,
        accountId,
        remainingPages[idx],
        pageSize,
      );
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, remainingPages.length) }, () => worker()),
  );

  // STO's pagination is occasionally not stable across concurrent reads (the
  // same issue can land on adjacent pages when the index reshuffles between
  // requests). Dedupe by id here so downstream code never sees the same issue
  // twice — keeps the find_duplicate_groups warnings list clean and avoids
  // an O(N²) match noise pass.
  const seen = new Set<string>();
  const allIssues: unknown[] = [];
  for (const issue of [...first.issues, ...results.flatMap((r) => r.issues)]) {
    const id = (issue as { id?: unknown })?.id;
    if (typeof id === "string") {
      if (seen.has(id)) continue;
      seen.add(id);
    }
    allIssues.push(issue);
  }

  return {
    issues: allIssues,
    total_items: totalItems,
    pages_fetched: 1 + remainingPages.length,
    total_pages: totalPages,
  };
}
