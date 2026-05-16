/**
 * SCA dedup via (CVE, library, version) bucketing.
 *
 * Why this exists: pairwise + Union-Find chaining breaks down for SCA when an
 * issue carries multiple CVE refs (some scanners do — they bundle CVE +
 * vendor advisory IDs). The multi-CVE issue acts as a bridge that fuses
 * otherwise-unrelated CVE clusters into one mega-group. Demo-killer.
 *
 * Tuple-keyed bucketing gives the correct model: each duplicate group
 * represents EXACTLY ONE (CVE × library × version) tuple. An issue with N
 * CVEs is a member of up to N groups. Within a bucket, ≥2 distinct scanners
 * means HIGH (true cross-scanner duplicate); 1 scanner means STO didn't
 * dedup it (rare; surfaces as MEDIUM).
 */

import { RefinedIssue, issueId } from "../frameworks/refined-issue.js";
import {
  GroupMember,
  DuplicateGroup,
} from "../tools/find-duplicate-groups.js";
import { normalizeLibraryName, normalizeVersion } from "./normalize.js";
import { pickPrimary } from "./primary-selection.js";
import { Tier } from "./tier-match.js";

export function findScaTupleGroups(issues: RefinedIssue[]): DuplicateGroup[] {
  // Map from "CVE|lib|ver" → unique RefinedIssue[] (deduped by internal id).
  const buckets = new Map<string, Map<string, RefinedIssue>>();

  for (const issue of issues) {
    if (issue.issue_type !== "SCA") continue;
    const lib = normalizeLibraryName(issue.library_name);
    const ver = normalizeVersion(issue.current_version);
    if (!lib || !ver) continue;
    const cves = (issue.reference_identifiers ?? [])
      .filter((r) => r.type?.toLowerCase() === "cve")
      .map((r) => r.id.toUpperCase());
    if (cves.length === 0) continue;
    for (const cve of cves) {
      const key = `${cve}|${lib}|${ver}`;
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = new Map();
        buckets.set(key, bucket);
      }
      const id = issueId(issue);
      if (!bucket.has(id)) bucket.set(id, issue);
    }
  }

  const groups: DuplicateGroup[] = [];
  for (const [key, memberMap] of buckets) {
    if (memberMap.size < 2) continue;
    const members = [...memberMap.values()];
    const [cve, lib, ver] = key.split("|");

    const scanners = [
      ...new Set(members.map((m) => m.product_name).filter(Boolean)),
    ] as string[];
    const knownScanners = scanners.filter((s) => s !== "multi_scanner");
    // Tier criteria — calibrated so HIGH means "user can auto-exempt without
    // review":
    //   3+ scanners → HIGH    (overwhelming cross-scanner consensus)
    //   2  scanners → MEDIUM  (strong corroboration, glance + approve)
    //   1  scanner  → LOW     (within-scanner cluster STO didn't pre-dedup)
    const tier: Tier =
      knownScanners.length >= 3
        ? "HIGH"
        : knownScanners.length === 2
          ? "MEDIUM"
          : "LOW";

    const primary = pickPrimary(members);
    const primaryId = issueId(primary);

    const enrichedMembers: GroupMember[] = members.map((m) => ({
      internal_id: issueId(m),
      title: m.title,
      severity_code: m.severity_code,
      library_name: m.library_name,
      current_version: m.current_version,
      scanner: m.product_name,
      is_primary: issueId(m) === primaryId,
    }));

    const headline =
      tier === "HIGH"
        ? `${cve} on ${lib}@${ver} — confirmed by ${knownScanners.length} scanners (${knownScanners.join(", ")})`
        : tier === "MEDIUM"
          ? `${cve} on ${lib}@${ver} — reported by 2 scanners (${knownScanners.join(", ")})`
          : `${cve} on ${lib}@${ver} (${members.length} STO records, ${knownScanners.length || 1} scanner)`;

    const suggestedAction =
      tier === "HIGH"
        ? `Auto-exempt candidate: ${knownScanners.length} independent scanners (${knownScanners.join(", ")}) agree on the same CVE × package × version. Safe to bulk-exempt the ${members.length - 1} duplicate(s).`
        : tier === "MEDIUM"
          ? `Review and exempt: 2 scanners (${knownScanners.join(", ")}) corroborate the same CVE × package × version. Glance and approve.`
          : `Within-scanner cluster: same CVE/lib/version on ${members.length} STO records from one scanner — likely a STO pre-dedup gap.`;

    groups.push({
      primary_issue_id: primaryId,
      duplicate_issue_ids: members
        .map((m) => issueId(m))
        .filter((id) => id !== primaryId),
      members: enrichedMembers,
      headline,
      suggested_action: suggestedAction,
      confidence_tier: tier,
      scanners,
      matched_signals: {
        reference_identifiers: [`cve:${cve}`],
        library_name: lib,
        current_version: ver,
        ...(knownScanners.length > 1 ? { scanners: knownScanners } : {}),
      },
      rationale:
        tier === "HIGH"
          ? `SCA tuple match: same (${cve}, ${lib}, ${ver}) reported by ${knownScanners.length} distinct scanners.`
          : `SCA tuple match: same (${cve}, ${lib}, ${ver}) on multiple STO records (likely missing scanner attribution).`,
    });
  }

  // Sort: HIGH first, then by member count descending.
  groups.sort((a, b) => {
    if (a.confidence_tier !== b.confidence_tier) {
      return a.confidence_tier === "HIGH" ? -1 : 1;
    }
    return b.members.length - a.members.length;
  });
  return groups;
}
