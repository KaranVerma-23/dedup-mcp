/**
 * normalize_sto_issues
 *
 * Convert raw STO Core API issue objects (camelCase) into the snake_case
 * RefinedIssue shape our dedup logic expects.
 *
 * Why this exists: harness-mcp's `harness_list(security_issue, ...)` returns
 * raw STO API JSON via `passthrough`. The field names there (`severityCode`,
 * `issueType`, `referenceIdentifiers`, `libraryName`, `currentVersion`) don't
 * match the sto_plugin RefinedIssue shape (snake_case). Asking the LLM to
 * map them is unreliable. Map deterministically here.
 *
 * Source for STO API field names: sto-core/design/issues.go (Issue, IssueInScan)
 * Source for RefinedIssue:        sto_plugin/.../refined_issue.py
 */

import { RefinedIssue, IssueType, ReferenceIdentifier } from "../frameworks/refined-issue.js";
import { extractFromTitle } from "../lib/title-parser.js";

/** Wrapper around any plausible STO list/search response shape. */
export interface NormalizeInput {
  /** Either a flat array of API issues, or the wrapper object the API returns. */
  issues: unknown;
  /** Optional default scanner name (used as fallback when API doesn't include it). */
  default_product_name?: string;
}

export interface NormalizeOutput {
  refined_issues: RefinedIssue[];
  stats: {
    input_count: number;
    output_count: number;
    skipped: number;
    issue_types: Record<string, number>;
    scanners: Record<string, number>;
    /** Number of issues where reference_identifiers/library_name/current_version were filled from title parsing because the API payload omitted them. */
    title_enriched_count: number;
  };
  warnings: string[];
}

/** Heuristically extract the issues array from anything we get.
 *  Tolerant of:
 *    - plain arrays
 *    - {data|issues|content|results|items: [...]}
 *    - paginated {data: {content: [...]}}
 *    - JSON-encoded STRINGS of any of the above (the orchestrating LLM
 *      sometimes JSON.stringifies the harness_list response when passing
 *      between MCP tool calls; auto-parse so the human doesn't have to
 *      re-prompt for that).
 */
function asIssueArray(input: unknown): unknown[] {
  // Auto-parse JSON-encoded strings — the LLM sometimes stringifies the
  // harness_list response between tool calls.
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        input = JSON.parse(trimmed);
      } catch {
        return [];
      }
    } else {
      return [];
    }
  }
  if (Array.isArray(input)) return input;
  if (input && typeof input === "object") {
    const obj = input as Record<string, unknown>;
    // Common wrappers: {data:[...]}, {issues:[...]}, {content:[...]}, {results:[...]}
    for (const key of ["data", "issues", "content", "results", "items"]) {
      if (Array.isArray(obj[key])) return obj[key] as unknown[];
    }
    // Pagination pattern: {data: {content: [...]}}
    if (obj.data && typeof obj.data === "object") {
      const inner = obj.data as Record<string, unknown>;
      for (const key of ["content", "issues", "results", "items"]) {
        if (Array.isArray(inner[key])) return inner[key] as unknown[];
      }
    }
  }
  return [];
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/** Map STO `issueType` (any case, may be numeric or string) to our enum. */
function normalizeIssueType(raw: unknown): IssueType | undefined {
  if (typeof raw !== "string") return undefined;
  const upper = raw.toUpperCase();
  switch (upper) {
    case "SAST":
    case "SCA":
    case "DAST":
    case "IAC":
    case "SECRET":
    case "MISCONFIG":
    case "CONTAINER":
      return upper;
    default:
      return undefined;
  }
}

/** Normalize a single reference identifier entry (camel/snake/lowercase tolerant). */
function normalizeRefId(raw: unknown): ReferenceIdentifier | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const o = raw as Record<string, unknown>;
  const type = asString(o.type) ?? asString((o as any).Type);
  const id = asString(o.id) ?? asString((o as any).ID) ?? asString(o.identifier);
  if (!type || !id) return undefined;
  return { type: type.toLowerCase(), id: id.toUpperCase() };
}

/** Where might a scanner name live in the API response.
 *  STO's issue-detail endpoint uses `scanTool` (e.g. "aqua-trivy",
 *  "shiftleftsca"); the list endpoint omits scanner attribution entirely.
 *  The dedupe_pipeline tool merges scanTool from the detail endpoint into
 *  the raw issue before calling us, so we just need to find it wherever
 *  STO put it. */
function extractScannerName(o: Record<string, unknown>): string | undefined {
  return (
    asString(o.scan_tool) ??          // detail-endpoint normalized into raw
    asString(o.scanTool) ??           // detail endpoint camelCase
    asString(o.product_name) ??       // sto_plugin RefinedIssue shape
    asString(o.productName) ??        // STO Core API camelCase (older)
    asString((o as any).tool)
  );
}

/** Where might the issue id live. */
function extractInternalId(o: Record<string, unknown>): string | undefined {
  return (
    asString(o.internal_id) ??
    asString(o.internalId) ??
    asString(o.issue_id) ??
    asString(o.issueId) ??
    asString(o.id)
  );
}

function normalizeOne(raw: unknown, defaultProductName?: string):
  | { ok: true; issue: RefinedIssue; enrichment_used: boolean }
  | { ok: false; reason: string } {
  if (!raw || typeof raw !== "object") {
    return { ok: false, reason: "not an object" };
  }
  const o = raw as Record<string, unknown>;

  const issue: RefinedIssue = {
    // identity
    internal_id: extractInternalId(o),
    account_id: asString(o.account_id) ?? asString(o.accountId),
    scan_id: asString(o.scan_id) ?? asString(o.scanId),
    product_id: asString(o.product_id) ?? asString(o.productId),
    product_name: extractScannerName(o) ?? defaultProductName,

    // classification
    issue_type: normalizeIssueType(o.issue_type ?? o.issueType ?? o.type),

    reference_identifiers: Array.isArray(o.reference_identifiers ?? o.referenceIdentifiers)
      ? ((o.reference_identifiers ?? o.referenceIdentifiers) as unknown[])
          .map(normalizeRefId)
          .filter((x): x is ReferenceIdentifier => x !== undefined)
      : undefined,

    // severity
    severity: asNumber(o.severity),
    severity_code:
      asString(o.severity_code) ??
      asString(o.severityCode) ??
      (typeof o.severity === "string" ? o.severity.toLowerCase() : undefined),

    // content
    title: asString(o.title),
    issue_description: asString(o.issue_description) ?? asString(o.description),

    // SCA
    library_name: asString(o.library_name) ?? asString(o.libraryName) ?? asString(o.componentName),
    current_version: asString(o.current_version) ?? asString(o.currentVersion) ?? asString(o.componentVersion),

    // SAST
    file_name: asString(o.file_name) ?? asString(o.fileName) ?? asString(o.filePath),
    line_number: asNumber(o.line_number) ?? asNumber(o.lineNumber) ?? asNumber(o.line),
    start_line: asNumber(o.start_line) ?? asNumber(o.startLine),
    end_line: asNumber(o.end_line) ?? asNumber(o.endLine),

    // Container
    image_layer_id: asString(o.image_layer_id) ?? asString(o.imageLayerId) ?? asString(o.layerId),
    image_registry: asString(o.image_registry) ?? asString(o.imageRegistry),
    image_tag: asString(o.image_tag) ?? asString(o.imageTag),
  };

  if (!issue.internal_id) {
    return { ok: false, reason: "no usable id (internal_id/id/issue_id all missing)" };
  }

  // ── Title enrichment ─────────────────────────────────────────────────
  // STO Core's compact list endpoint omits referenceIdentifiers / libraryName
  // / currentVersion but bakes them into `title`. Backfill from the title
  // ONLY for fields the API didn't already provide — never overwrite
  // structured data with parsed data.
  let enrichmentUsed = false;
  const fromTitle = extractFromTitle(issue.title);
  const refIdsEmpty =
    !issue.reference_identifiers || issue.reference_identifiers.length === 0;
  if (refIdsEmpty && fromTitle.reference_identifiers.length > 0) {
    issue.reference_identifiers = fromTitle.reference_identifiers;
    enrichmentUsed = true;
  }
  if (!issue.library_name && fromTitle.library_name) {
    issue.library_name = fromTitle.library_name;
    enrichmentUsed = true;
  }
  if (!issue.current_version && fromTitle.current_version) {
    issue.current_version = fromTitle.current_version;
    enrichmentUsed = true;
  }
  if (!issue.file_name && fromTitle.file_name) {
    issue.file_name = fromTitle.file_name;
    enrichmentUsed = true;
  }

  return { ok: true, issue, enrichment_used: enrichmentUsed };
}

export function normalizeStoIssues(input: NormalizeInput): NormalizeOutput {
  const arr = asIssueArray(input.issues);
  const warnings: string[] = [];
  const refined: RefinedIssue[] = [];
  const issueTypes: Record<string, number> = {};
  const scanners: Record<string, number> = {};
  let skipped = 0;
  let titleEnriched = 0;

  for (const item of arr) {
    const result = normalizeOne(item, input.default_product_name);
    if (!result.ok) {
      skipped++;
      if (warnings.length < 5) warnings.push(`Skipped issue: ${result.reason}`);
      continue;
    }
    refined.push(result.issue);
    if (result.enrichment_used) titleEnriched++;
    if (result.issue.issue_type) {
      issueTypes[result.issue.issue_type] = (issueTypes[result.issue.issue_type] ?? 0) + 1;
    }
    if (result.issue.product_name) {
      scanners[result.issue.product_name] = (scanners[result.issue.product_name] ?? 0) + 1;
    }
  }

  if (skipped > 5) warnings.push(`...and ${skipped - 5} more skipped issues.`);

  return {
    refined_issues: refined,
    stats: {
      input_count: arr.length,
      output_count: refined.length,
      skipped,
      issue_types: issueTypes,
      scanners: scanners,
      title_enriched_count: titleEnriched,
    },
    warnings,
  };
}
