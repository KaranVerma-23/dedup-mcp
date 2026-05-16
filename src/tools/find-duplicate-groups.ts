/**
 * find_duplicate_groups
 *
 * Given a flat list of STO `RefinedIssue` objects, cluster them into duplicate
 * groups using same-type tiered matching, and return groups with confidence
 * tier, primary issue, and matched-signal evidence.
 *
 * Architecture:
 *   1. For each pair (a, b) where a.issue_type === b.issue_type, run matchPair
 *   2. If tier ≥ threshold (default HIGH, configurable), union them in DSU
 *   3. Read the resulting groups; for each multi-issue group:
 *      - pick primary deterministically
 *      - record the highest tier seen across pairs in the group
 *      - emit a structured group record
 *
 * Complexity: O(N²) on issues per type. Acceptable for typical scan sizes
 * (hundreds of issues per type). Bucket-by-refid optimisation deferred.
 */

import { RefinedIssue, issueId, IssueType } from "../frameworks/refined-issue.js";
import { matchPair, Tier, TierMatch } from "../lib/tier-match.js";
import { UnionFind } from "../lib/union-find.js";
import { pickPrimary } from "../lib/primary-selection.js";

export interface FindGroupsInput {
  issues: RefinedIssue[];
  /** Lowest tier to use for grouping. Default: HIGH (auto-group only). */
  group_threshold?: Tier;
}

/** Per-member enrichment so consumers don't have to cross-reference IDs back
 *  to the original issue list when formatting a human-readable report. */
export interface GroupMember {
  internal_id: string;
  title?: string;
  severity_code?: string;
  library_name?: string;
  current_version?: string;
  /** Scanner that reported this finding (e.g. "aqua-trivy", "shiftleftsca").
   *  Only present when issue-detail enrichment ran — otherwise absent. */
  scanner?: string;
  is_primary: boolean;
}

export interface DuplicateGroup {
  primary_issue_id: string;
  duplicate_issue_ids: string[];
  /** Same data as primary + duplicates but enriched with title/severity/etc.
   *  Use this for rendering reports — it's self-contained. */
  members: GroupMember[];
  /** One-line human-readable summary, e.g.
   *  "CVE-2016-10144 across 6 ImageMagick sibling packages". */
  headline: string;
  /** Suggested action for downstream consumers / Slack messages.
   *  e.g. "Apply one component-level exemption to cover all 6 packages." */
  suggested_action: string;
  confidence_tier: Tier;
  scanners: string[];
  matched_signals: Record<string, string | string[]>;
  rationale: string;
}

export interface ReviewCandidatePair {
  issue_a_id: string;
  issue_b_id: string;
  confidence_tier: Tier;
  matched_signals: Record<string, string | string[]>;
  rationale: string;
}

export interface FindGroupsOutput {
  scope: { issue_count: number; types_seen: IssueType[] };
  duplicate_groups: DuplicateGroup[];
  review_candidates: ReviewCandidatePair[];
  stats: {
    input_issue_count: number;
    output_unique_issue_count: number;
    dedup_ratio: number;
    groups_by_tier: Record<Tier, number>;
  };
  framework: string;
  warnings: string[];
}

const TIER_RANK: Record<Tier, number> = { LOW: 1, MEDIUM: 2, HIGH: 3 };

export function findDuplicateGroups(input: FindGroupsInput): FindGroupsOutput {
  const issues = input.issues;
  const threshold: Tier = input.group_threshold ?? "HIGH";
  const warnings: string[] = [];

  // Index issues by id for primary selection later
  const byId = new Map<string, RefinedIssue>();
  for (const issue of issues) {
    const id = issueId(issue);
    if (byId.has(id)) {
      warnings.push(`Duplicate input issue id "${id}" — keeping first occurrence.`);
    } else {
      byId.set(id, issue);
    }
  }

  // Track every pairwise match (for review candidates and group tier reporting)
  const allPairs: Array<{
    a: RefinedIssue;
    b: RefinedIssue;
    match: TierMatch;
  }> = [];

  // Compare ALL pairs (O(N²)). matchPair short-circuits on type-mismatch
  // EXCEPT for the cross-type title-equality rescue rule (which catches
  // STO API tagging quirks). For typical scan sizes (≤500 issues) this
  // is ~125K comparisons — milliseconds. Bucket-by-refid optimisation
  // can be added later if N grows past that.
  const typed = issues.filter((i) => i.issue_type);
  for (let i = 0; i < typed.length; i++) {
    for (let j = i + 1; j < typed.length; j++) {
      const m = matchPair(typed[i], typed[j]);
      if (m) allPairs.push({ a: typed[i], b: typed[j], match: m });
    }
  }

  // Build the union-find using only pairs at or above threshold
  const dsu = new UnionFind<string>();
  for (const id of byId.keys()) dsu.add(id);
  for (const { a, b, match } of allPairs) {
    if (TIER_RANK[match.tier] >= TIER_RANK[threshold]) {
      dsu.union(issueId(a), issueId(b));
    }
  }

  // Materialize duplicate groups (size >= 2)
  const dupGroups: DuplicateGroup[] = [];
  for (const [, members] of dsu.groups()) {
    if (members.length < 2) continue;
    const memberIssues = members
      .map((id) => byId.get(id))
      .filter((x): x is RefinedIssue => !!x);
    if (memberIssues.length < 2) continue;

    const primary = pickPrimary(memberIssues);
    const primaryId = issueId(primary);

    // Find the BEST (highest-tier) match within this group to label confidence.
    // Use `>=` so the first match initializes bestMatch even when the only
    // tier seen is LOW (otherwise matched_signals would be empty).
    let bestTier: Tier | null = null;
    let bestMatch: TierMatch | null = null;
    for (const { a, b, match } of allPairs) {
      const ai = issueId(a);
      const bi = issueId(b);
      const aIn = members.includes(ai);
      const bIn = members.includes(bi);
      if (aIn && bIn) {
        if (bestTier === null || TIER_RANK[match.tier] > TIER_RANK[bestTier]) {
          bestTier = match.tier;
          bestMatch = match;
        }
      }
    }
    const finalTier: Tier = bestTier ?? "LOW";

    const scanners = [
      ...new Set(memberIssues.map((m) => m.product_name).filter(Boolean)),
    ] as string[];

    const enrichedMembers: GroupMember[] = members.map((id) => {
      const issue = byId.get(id);
      return {
        internal_id: id,
        title: issue?.title,
        severity_code: issue?.severity_code,
        library_name: issue?.library_name,
        current_version: issue?.current_version,
        scanner: issue?.product_name,
        is_primary: id === primaryId,
      };
    });

    dupGroups.push({
      primary_issue_id: primaryId,
      duplicate_issue_ids: members.filter((id) => id !== primaryId),
      members: enrichedMembers,
      headline: buildHeadline(memberIssues, bestMatch, finalTier),
      suggested_action: buildSuggestedAction(memberIssues, finalTier),
      confidence_tier: finalTier,
      scanners,
      matched_signals: bestMatch?.matched_signals ?? {},
      rationale: bestMatch?.rationale ?? "Grouped via transitive duplicate match.",
    });
  }

  // Review candidates: pairs that matched at MEDIUM or LOW but didn't meet threshold,
  // AND aren't already in an auto-group together
  const groupedPairs = new Set<string>();
  for (const g of dupGroups) {
    const ids = [g.primary_issue_id, ...g.duplicate_issue_ids];
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        groupedPairs.add(`${ids[i]}|${ids[j]}`);
        groupedPairs.add(`${ids[j]}|${ids[i]}`);
      }
    }
  }
  const reviewCandidates: ReviewCandidatePair[] = [];
  for (const { a, b, match } of allPairs) {
    if (TIER_RANK[match.tier] >= TIER_RANK[threshold]) continue;
    const ai = issueId(a);
    const bi = issueId(b);
    if (groupedPairs.has(`${ai}|${bi}`)) continue;
    reviewCandidates.push({
      issue_a_id: ai,
      issue_b_id: bi,
      confidence_tier: match.tier,
      matched_signals: match.matched_signals,
      rationale: match.rationale,
    });
  }

  const groupsByTier: Record<Tier, number> = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const g of dupGroups) groupsByTier[g.confidence_tier]++;

  // unique issue count = total - sum(group_size - 1) — each group collapses to 1
  const dupReduction = dupGroups.reduce(
    (sum, g) => sum + g.duplicate_issue_ids.length,
    0,
  );
  const uniqueCount = byId.size - dupReduction;

  return {
    scope: {
      issue_count: byId.size,
      types_seen: [...new Set(issues.map((i) => i.issue_type).filter(Boolean))] as IssueType[],
    },
    duplicate_groups: dupGroups,
    review_candidates: reviewCandidates,
    stats: {
      input_issue_count: byId.size,
      output_unique_issue_count: uniqueCount,
      dedup_ratio: byId.size > 0 ? dupReduction / byId.size : 0,
      groups_by_tier: groupsByTier,
    },
    framework:
      "DefectDojo-style hash-field tiering (https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/) + Trivy/Snyk per-scanner field practice",
    warnings,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// Human-readable summaries
// ──────────────────────────────────────────────────────────────────────────

/** Build a one-line "what is this group" summary for display. */
function buildHeadline(
  members: RefinedIssue[],
  match: TierMatch | null,
  tier: Tier,
): string {
  const cves = uniqueRefIds(members, "cve");
  const cwes = uniqueRefIds(members, "cwe");
  const libs = uniqueLibraries(members);
  const versions = uniqueVersions(members);
  const scanners = uniqueScanners(members);
  const n = members.length;

  // SCA case: shared CVE on packages (most common pattern)
  if (cves.length > 0) {
    const cveStr = cves.length === 1 ? cves[0] : `${cves[0]} (+${cves.length - 1} more)`;
    // HIGH cross-scanner: same vuln + same package + same version, ≥2 scanners
    if (tier === "HIGH" && scanners.length > 1 && libs.length === 1) {
      return `${cveStr} on ${libs[0]}@${versions[0] ?? "?"} — reported by ${scanners.length} scanners (${scanners.join(", ")})`;
    }
    if (libs.length > 1) {
      const libFamily = sharedPrefix(libs) || libs[0].split(/[-/_]/)[0];
      return `${cveStr} across ${n} sibling ${libFamily} packages`;
    }
    if (libs.length === 1 && versions.length > 1) {
      return `${cveStr} on ${libs[0]} (${versions.length} versions: ${versions.join(", ")})`;
    }
    if (libs.length === 1) {
      return `${cveStr} on ${libs[0]}@${versions[0] ?? "?"}`;
    }
    return `${cveStr} across ${n} findings`;
  }

  // SAST case: shared CWE
  if (cwes.length > 0) {
    const cweStr = cwes.length === 1 ? cwes[0] : `${cwes[0]} (+${cwes.length - 1} more)`;
    return `${cweStr} across ${n} findings`;
  }

  // SAST T2b: same library/version, no CWE
  if (libs.length === 1 && versions.length === 1) {
    return `Same library ${libs[0]}@${versions[0]} flagged ${n}×`;
  }

  // SAST T3b: identical title (re-scan duplicates)
  if (match?.matched_signals?.title) {
    return `Identical-title cluster (${n} findings)`;
  }

  // Cross-type rescue
  if (match?.matched_signals?.cross_type) {
    return `Cross-type duplicate: ${match.matched_signals.cross_type}`;
  }

  return `Cluster of ${n} ${tier.toLowerCase()}-confidence duplicates`;
}

/** Build a one-line action recommendation. */
function buildSuggestedAction(members: RefinedIssue[], tier: Tier): string {
  const libs = uniqueLibraries(members);
  const versions = uniqueVersions(members);
  const scanners = uniqueScanners(members);
  // HIGH cross-scanner: prioritise this messaging — it's the strongest signal.
  if (tier === "HIGH" && scanners.length > 1) {
    return `Cross-scanner duplicate (${scanners.join(" + ")}) — same vuln on the same package. Keep the primary, exempt the ${members.length - 1} other(s) as confirmed duplicates.`;
  }
  if (libs.length > 1) {
    return `Apply one component-level exemption — single fix to the parent library will resolve all ${members.length} sibling packages.`;
  }
  if (libs.length === 1 && versions.length > 1) {
    return `Same library affected at ${versions.length} versions — likely fixed by upgrading to a single safe version.`;
  }
  if (tier === "HIGH") {
    return `High-confidence duplicate — keep the primary, exempt the others as duplicates.`;
  }
  return `Review and exempt the ${members.length - 1} duplicate(s) of the primary issue.`;
}

function uniqueScanners(issues: RefinedIssue[]): string[] {
  const set = new Set<string>();
  for (const i of issues) {
    if (i.product_name) set.add(i.product_name);
  }
  return [...set];
}

function uniqueRefIds(issues: RefinedIssue[], type: "cve" | "cwe" | "ghsa"): string[] {
  const set = new Set<string>();
  for (const i of issues) {
    for (const r of i.reference_identifiers ?? []) {
      if (r.type.toLowerCase() === type) set.add(r.id.toUpperCase());
    }
  }
  return [...set];
}

function uniqueLibraries(issues: RefinedIssue[]): string[] {
  const set = new Set<string>();
  for (const i of issues) {
    if (i.library_name) set.add(i.library_name);
  }
  return [...set];
}

function uniqueVersions(issues: RefinedIssue[]): string[] {
  const set = new Set<string>();
  for (const i of issues) {
    if (i.current_version) set.add(i.current_version);
  }
  return [...set];
}

/** Find the longest common prefix of a list of strings, ending at a word
 *  boundary (so we get "imagemagick" from ["imagemagick", "imagemagick-common", ...]
 *  rather than the more precise but less readable longest substring). */
function sharedPrefix(strs: string[]): string {
  if (strs.length === 0) return "";
  let prefix = strs[0];
  for (const s of strs.slice(1)) {
    let i = 0;
    while (i < prefix.length && i < s.length && prefix[i] === s[i]) i++;
    prefix = prefix.slice(0, i);
    if (!prefix) break;
  }
  // Trim trailing separator garbage
  return prefix.replace(/[-_./0-9]+$/, "");
}
