/**
 * dedupe_pipeline
 *
 * One-shot tool for the Worker Agent: fetch + (optionally enrich) + normalize
 * + dedup, return only the small final summary. All large payloads stay
 * inside this process — nothing the LLM has to "type out" character-by-
 * character.
 *
 * Two modes:
 *   - enrich="never"  (fast, ~10s for 863 issues)
 *       List endpoint only. Title-parsed CVEs. No scanner attribution.
 *       Cross-scanner duplicates collapse to LOW (sibling-package fanout)
 *       because library names differ between scanner formats.
 *
 *   - enrich="auto"   (smart-deep, ~60-90s for 863 issues)  [DEFAULT]
 *       After the cheap list pass, group by CVE. For CVEs that appear on
 *       MORE THAN ONE issue (cross-issue candidates), fetch the issue-detail
 *       endpoint to get `scanTool` + clean `referenceIdentifiers`. This
 *       upgrades cross-scanner exact matches from LOW → HIGH while keeping
 *       the runtime bounded.
 *
 *   - enrich="always" (~3min for 863 issues)
 *       Detail-fetch every issue regardless. Useful when scanners use
 *       title formats the parser can't recognise.
 */

import { Tier } from "../lib/tier-match.js";
import {
  fetchStoIssuesForPipeline,
  fetchIssueDetails,
  StoIssueDetail,
} from "../lib/harness-client.js";
import { fetchStoIssuesSql, sqlRowToApiShape } from "../lib/sto-sql.js";
import { findScaTupleGroups } from "../lib/sca-bucket.js";
import { normalizeStoIssues } from "./normalize-sto-issues.js";
import {
  findDuplicateGroups,
  DuplicateGroup,
  ReviewCandidatePair,
} from "./find-duplicate-groups.js";

export type EnrichmentMode = "never" | "auto" | "always";
export type Backend = "api" | "sql";

export interface DedupePipelineInput {
  /** STO pipeline id. Optional. */
  pipeline_id?: string;
  /** STO target id (a repo or container image). Optional. When BOTH
   *  pipeline_id and target_id are given the result is the intersection.
   *  When NEITHER is given, dedup runs across ALL issues in scope (capped
   *  by max_issues). */
  target_id?: string;
  project_id: string;
  org_id?: string;
  page_size?: number;
  max_pages?: number;
  /** Hard cap on issues processed. Default 1000 — keeps the O(N²) match
   *  step bounded (~1M comparisons, sub-second). Honoured by both backends.
   *  Most-recent issues are kept when truncated. */
  max_issues?: number;
  group_threshold?: Tier;
  default_product_name?: string;
  /** Whether to fetch per-issue details for richer cross-scanner HIGH matching.
   *  Default "auto" (smart-deep). API backend only — SQL backend gets full
   *  per-occurrence data in one query, no enrichment step needed. */
  enrich?: EnrichmentMode;
  /** Data source. "api" (default) = Harness STO REST API + PAT. "sql" =
   *  direct read-only Postgres against STO Core DB; ~10x faster and includes
   *  per-occurrence file/line for SAST. Demo/QA use only — production needs
   *  the API path. Configure with STO_DATABASE_URL env. */
  backend?: Backend;
  /** Override STO_DATABASE_URL for the sql backend. */
  sto_database_url?: string;
  harness_base_url?: string;
  harness_api_key?: string;
  harness_account_id?: string;
}

export interface DedupePipelineOutput {
  scope: {
    pipeline_id?: string;
    target_id?: string;
    project_id: string;
    org_id?: string;
    issue_count_sampled: number;
    total_items_on_pipeline: number;
    pages_fetched: number;
    types_seen: string[];
    /** Sum of numOccurrences across enriched issues — pre-STO-dedup raw
     *  finding count (per-scanner). Only present when enrich != "never". */
    total_raw_occurrences?: number;
    /** How many issues were enriched with detail-endpoint data. */
    enriched_count: number;
    enrichment_mode: EnrichmentMode;
    backend: Backend;
    /** True when the underlying issue count exceeded max_issues and the
     *  result was truncated (most-recent kept). */
    capped: boolean;
    max_issues: number;
  };
  duplicate_groups: DuplicateGroup[];
  review_candidates: ReviewCandidatePair[];
  ungrouped_count: number;
  stats: {
    duplicate_group_count: number;
    review_candidate_count: number;
    unique_after_dedup: number;
    /** Percentage of sampled issues collapsed by our dedup
     *  (issue_count_sampled → unique_after_dedup). */
    noise_reduction_pct: number;
    /** End-to-end percentage including STO Core's per-scanner pre-dedup
     *  (total_raw_occurrences → unique_after_dedup). The real "developer
     *  pain reduction" headline. Only present when enrichment ran. */
    end_to_end_noise_reduction_pct?: number;
    groups_by_tier: Record<Tier, number>;
  };
  timings_ms: {
    fetch: number;
    enrich: number;
    normalize: number;
    dedup: number;
    total: number;
  };
  warnings: string[];
}

export async function dedupePipeline(
  input: DedupePipelineInput,
): Promise<DedupePipelineOutput> {
  const t0 = Date.now();
  const warnings: string[] = [];
  const enrichmentMode: EnrichmentMode = input.enrich ?? "auto";
  const backend: Backend = input.backend ?? "api";
  // 1000 is the sweet spot for O(N²) matching (~1M comparisons, ~1s).
  const maxIssues = Math.max(1, Math.min(input.max_issues ?? 1000, 5000));

  let issuesForNormalize: Array<Record<string, unknown>>;
  let totalItems = 0;
  let pagesFetched = 0;
  let totalRawOccurrences: number | undefined;
  let enrichedCount = 0;
  let fetchMs = 0;
  let enrichMs = 0;
  let capped = false;

  if (backend === "sql") {
    // ── SQL path: ONE query returns issue + scanner + occurrence_count +
    //    per-occurrence unique_details (with SAST fileName/lineNumber).
    //    No N+1 enrichment phase needed.
    const tFetch = Date.now();
    // Trim env-sourced values defensively (see API path above for why).
    const trim = (s: string | undefined) => s?.trim() || undefined;
    const sqlResult = await fetchStoIssuesSql({
      database_url: trim(input.sto_database_url) ?? trim(process.env.STO_DATABASE_URL),
      pipeline_id: input.pipeline_id,
      target_id: input.target_id,
      org_id: input.org_id,
      project_id: input.project_id,
      max_issues: maxIssues,
    });
    fetchMs = Date.now() - tFetch;
    issuesForNormalize = sqlResult.issues.map(sqlRowToApiShape);
    totalItems = sqlResult.issues.length;
    pagesFetched = 1; // single SQL query
    totalRawOccurrences = sqlResult.total_occurrences;
    enrichedCount = sqlResult.issues.length; // all rows are "fully enriched" by construction
    capped = sqlResult.capped;
  } else {
    // ── API path (production-shaped): list endpoint + smart per-issue detail
    //    enrichment via the Harness REST API.
    // Trim env values defensively — bash .env loaders sometimes leave a
    // trailing newline on the value, which silently breaks PAT parsing
    // (accountIdFromPat split-by-"." then leaves \n on the last token).
    const trim = (s: string | undefined) => s?.trim() || undefined;
    const baseUrl = trim(input.harness_base_url) ?? trim(process.env.HARNESS_BASE_URL);
    const apiKey = trim(input.harness_api_key) ?? trim(process.env.HARNESS_API_KEY);
    const accountId =
      trim(input.harness_account_id) ?? trim(process.env.HARNESS_ACCOUNT_ID);
    if (!baseUrl) throw new Error("HARNESS_BASE_URL not set (env or input)");
    if (!apiKey) throw new Error("HARNESS_API_KEY not set (env or input)");

    const tFetch = Date.now();
    const pageSize = input.page_size ?? 100;
    // Derive max_pages from max_issues so the cap holds regardless of the
    // caller passing max_pages explicitly. Round up so we don't undershoot.
    const derivedMaxPages = Math.max(
      1,
      Math.min(input.max_pages ?? Math.ceil(maxIssues / pageSize), 50),
    );
    const fetched = await fetchStoIssuesForPipeline({
      base_url: baseUrl,
      api_key: apiKey,
      account_id: accountId,
      org_id: input.org_id,
      project_id: input.project_id,
      pipeline_id: input.pipeline_id,
      target_id: input.target_id,
      page_size: pageSize,
      max_pages: derivedMaxPages,
    });
    fetchMs = Date.now() - tFetch;
    totalItems = fetched.total_items;
    pagesFetched = fetched.pages_fetched;
    capped = totalItems > maxIssues;
    // Trim to maxIssues if we overshot (max_pages × page_size can exceed cap).
    if (fetched.issues.length > maxIssues) {
      fetched.issues.splice(maxIssues);
    }

    // Optional enrichment phase (API-only).
    let details = new Map<string, StoIssueDetail>();
    const tEnrich = Date.now();
    if (enrichmentMode !== "never") {
      const candidateIds = pickEnrichmentCandidates(
        fetched.issues,
        enrichmentMode,
      );
      if (candidateIds.length > 0) {
        details = await fetchIssueDetails({
          base_url: baseUrl,
          api_key: apiKey,
          account_id: accountId,
          org_id: input.org_id,
          project_id: input.project_id,
          issue_ids: candidateIds,
          concurrency: 12,
        });
        totalRawOccurrences = 0;
        for (const d of details.values()) {
          totalRawOccurrences += d.num_occurrences ?? 0;
        }
      }
    }
    enrichMs = Date.now() - tEnrich;
    enrichedCount = details.size;
    issuesForNormalize = (fetched.issues as Array<Record<string, unknown>>).map(
      (raw) => mergeDetailIntoRaw(raw, details),
    );
  }

  // ── 3. Normalize ────────────────────────────────────────────────────
  const tNorm = Date.now();
  const normalized = normalizeStoIssues({
    issues: issuesForNormalize,
    default_product_name: input.default_product_name ?? "multi_scanner",
  });
  warnings.push(...normalized.warnings);
  const normalizeMs = Date.now() - tNorm;

  // ── 4. Dedup ────────────────────────────────────────────────────────
  // Three-path strategy for healthy HIGH/MEDIUM/LOW distribution:
  //   - SCA tuple bucket → exact (CVE, lib, ver) match → HIGH (3+ scanners)
  //     or MEDIUM (2 scanners). No chaining via multi-CVE bridges.
  //   - SCA residue (issues NOT in any tuple group) → legacy pairwise+DSU at
  //     LOW threshold, retain only LOW groups. Surfaces sibling-package
  //     fanout (libfoo + libfoo-dev) and version-fanout (lodash@2 + 3 + 4)
  //     that the strict tuple bucket misses. Removing tuple-grouped issues
  //     first prevents the multi-CVE bridge from re-creating mega-groups.
  //   - Non-SCA (SAST/CONTAINER/cross-type) → pairwise+DSU at user threshold.
  const tDedup = Date.now();
  const allRefined = normalized.refined_issues;
  const threshold = input.group_threshold ?? "LOW";

  const scaGroups = findScaTupleGroups(allRefined);
  const inTupleGroup = new Set<string>();
  for (const g of scaGroups) {
    for (const m of g.members) inTupleGroup.add(m.internal_id);
  }

  // SCA residue → LOW-tier sibling-package and version-fanout signal.
  const scaResidue = allRefined.filter(
    (i) => i.issue_type === "SCA" && !inTupleGroup.has(i.internal_id ?? i.id ?? ""),
  );
  const scaResidueGrouped = findDuplicateGroups({
    issues: scaResidue,
    group_threshold: "LOW",
  });
  // Keep only LOW-tier residue groups — anything stronger should already
  // have appeared in the tuple bucket (defensive).
  const scaLowGroups = scaResidueGrouped.duplicate_groups.filter(
    (g) => g.confidence_tier === "LOW",
  );

  // Non-SCA → pairwise+DSU at user-supplied threshold.
  const nonSca = allRefined.filter((i) => i.issue_type && i.issue_type !== "SCA");
  const grouped = findDuplicateGroups({
    issues: nonSca,
    group_threshold: threshold,
  });
  warnings.push(...grouped.warnings);

  // Combine. Order: HIGH/MEDIUM SCA tuple → SCA residue LOW → non-SCA.
  const combinedGroups: DuplicateGroup[] = [
    ...scaGroups,
    ...scaLowGroups,
    ...grouped.duplicate_groups,
  ];
  const dedupMs = Date.now() - tDedup;

  const sampled = allRefined.length;
  // For tuple-mode SCA, an issue can appear in multiple groups. Count the
  // unique deduplicated outcome by counting distinct issue ids that are
  // duplicates (non-primary). dupReduction = sum of (members - 1) per group
  // overcounts when issues appear in multiple groups; instead count distinct
  // issues that are members of ANY group beyond the primary.
  const allDupIds = new Set<string>();
  const allMemberIds = new Set<string>();
  for (const g of combinedGroups) {
    for (const id of g.duplicate_issue_ids) allDupIds.add(id);
    for (const m of g.members) allMemberIds.add(m.internal_id);
  }
  const dupReduction = allDupIds.size;
  const uniqueAfter = sampled - dupReduction;
  const ungroupedCount = sampled - allMemberIds.size;

  return {
    scope: {
      pipeline_id: input.pipeline_id,
      target_id: input.target_id,
      project_id: input.project_id,
      org_id: input.org_id,
      issue_count_sampled: sampled,
      total_items_on_pipeline: totalItems || sampled,
      pages_fetched: pagesFetched,
      types_seen: grouped.scope.types_seen,
      total_raw_occurrences: totalRawOccurrences,
      enriched_count: enrichedCount,
      enrichment_mode: enrichmentMode,
      backend,
      capped,
      max_issues: maxIssues,
    },
    duplicate_groups: combinedGroups,
    // Cap review_candidates (only from the non-SCA pairwise path) so they
    // don't dominate the LLM context. Sort by tier (MEDIUM > LOW).
    review_candidates: grouped.review_candidates
      .slice()
      .sort((a, b) =>
        a.confidence_tier === b.confidence_tier
          ? 0
          : a.confidence_tier === "MEDIUM"
            ? -1
            : 1,
      )
      .slice(0, 25),
    ungrouped_count: ungroupedCount,
    stats: {
      duplicate_group_count: combinedGroups.length,
      review_candidate_count: grouped.review_candidates.length,
      unique_after_dedup: uniqueAfter,
      noise_reduction_pct:
        sampled > 0 ? Math.round((dupReduction / sampled) * 1000) / 10 : 0,
      end_to_end_noise_reduction_pct:
        totalRawOccurrences && totalRawOccurrences > 0
          ? Math.round(((totalRawOccurrences - uniqueAfter) / totalRawOccurrences) * 1000) / 10
          : undefined,
      groups_by_tier: combinedGroups.reduce(
        (acc, g) => {
          acc[g.confidence_tier] = (acc[g.confidence_tier] ?? 0) + 1;
          return acc;
        },
        { HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<Tier, number>,
      ),
    },
    timings_ms: {
      fetch: fetchMs,
      enrich: enrichMs,
      normalize: normalizeMs,
      dedup: dedupMs,
      total: Date.now() - t0,
    },
    warnings,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

/** Extract a CVE id from a raw STO list-endpoint issue (best-effort).
 *  Looks at title (`CVE-2021-12345: ...`) and existing reference_identifiers. */
function extractCveFromRaw(raw: Record<string, unknown>): string | null {
  const refs = raw.referenceIdentifiers as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(refs)) {
    for (const r of refs) {
      if (typeof r.id === "string" && /^CVE-\d{4}-\d+$/i.test(r.id)) {
        return r.id.toUpperCase();
      }
    }
  }
  const title = typeof raw.title === "string" ? raw.title : "";
  const m = title.match(/CVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : null;
}

/** Decide which issue ids to detail-fetch.
 *
 *  "always" → every issue with an id.
 *  "auto"   → enrich an issue when EITHER:
 *               (a) its CVE appears on more than one issue (potential cross-
 *                   scanner HIGH-tier candidate), OR
 *               (b) its title doesn't expose a CVE at all (e.g. shiftleftsca's
 *                   bare PURL titles `pkg:pkg/debian/bzip2@...`) — we must
 *                   fetch detail to know what vuln this even is, otherwise
 *                   it can never match anything.
 *
 *  In practice (b) catches the OTHER side of cross-scanner pairs: aqua-trivy
 *  puts CVEs in the title (so (a) finds it), shiftleftsca uses PURLs (so (b)
 *  finds it). Enriching both sides is what lets HIGH-tier matches surface.
 */
function pickEnrichmentCandidates(
  issues: unknown[],
  mode: EnrichmentMode,
): string[] {
  const all: Array<{ id: string; cve: string | null }> = [];
  for (const raw of issues) {
    const o = raw as Record<string, unknown>;
    const id = typeof o.id === "string" ? o.id : null;
    if (!id) continue;
    all.push({ id, cve: extractCveFromRaw(o) });
  }

  if (mode === "always") return all.map((x) => x.id);

  // "auto"
  const cveCount = new Map<string, number>();
  for (const x of all) {
    if (x.cve) cveCount.set(x.cve, (cveCount.get(x.cve) ?? 0) + 1);
  }
  const ids: string[] = [];
  for (const x of all) {
    if (x.cve === null) {
      // Title doesn't expose a CVE — must enrich to learn what vuln this is.
      ids.push(x.id);
    } else if ((cveCount.get(x.cve) ?? 0) > 1) {
      // CVE appears on multiple issues — potential cross-scanner pair.
      ids.push(x.id);
    }
  }
  return ids;
}

/** Merge detail-endpoint data into the raw list-endpoint issue.
 *  Detail wins for: scanTool, referenceIdentifiers, description.
 *  Raw wins for everything else (title, severityCode, numOccurrences, etc). */
function mergeDetailIntoRaw(
  raw: Record<string, unknown>,
  details: Map<string, StoIssueDetail>,
): Record<string, unknown> {
  const id = typeof raw.id === "string" ? raw.id : null;
  const d = id ? details.get(id) : undefined;
  if (!d) return raw;
  const merged: Record<string, unknown> = { ...raw };
  if (d.scan_tool) merged.scanTool = d.scan_tool;
  if (d.reference_identifiers && d.reference_identifiers.length > 0) {
    merged.referenceIdentifiers = d.reference_identifiers;
  }
  if (d.description) merged.description = d.description;
  return merged;
}
