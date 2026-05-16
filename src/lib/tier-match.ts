/**
 * Tier-based duplicate matching.
 *
 * For each issue type (SCA / SAST / Container) we define three tiers, ordered
 * by strength of match. The HIGHEST tier that A and B both satisfy becomes
 * the confidence label. Inspired by DefectDojo's per-scanner hash-field sets
 * (https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/),
 * adapted for cross-scanner matching where field availability varies.
 *
 *   T1 (HIGH)   — strict: every discriminating field matches
 *   T2 (MEDIUM) — one supporting field may differ; surface for human review
 *   T3 (LOW)    — only the universal identifier matches; report only
 *
 * Returning `null` means "not duplicates at any tier."
 */

import { RefinedIssue } from "../frameworks/refined-issue.js";
import {
  expandIdentifierSet,
} from "../frameworks/cve-ghsa-map.js";
import {
  intersect,
  lower,
  normalizeLibraryName,
  normalizePath,
  normalizeVersion,
  refIdSet,
} from "./normalize.js";

export type Tier = "HIGH" | "MEDIUM" | "LOW";

export interface TierMatch {
  tier: Tier;
  matched_signals: Record<string, string | string[]>;
  rationale: string;
}

/** Whether two SAST line numbers count as "same location" (within ±3 lines). */
const SAST_LINE_TOLERANCE = 3;

function refIdsOverlap(a: RefinedIssue, b: RefinedIssue): string[] {
  const aSet = expandIdentifierSet(refIdSet(a.reference_identifiers));
  const bSet = expandIdentifierSet(refIdSet(b.reference_identifiers));
  return [...intersect(aSet, bSet)];
}

function bestLine(issue: RefinedIssue): number | undefined {
  return issue.line_number ?? issue.start_line;
}

// ─────────────────────────────────────────────────────────────────
// SCA
// ─────────────────────────────────────────────────────────────────

function matchSca(a: RefinedIssue, b: RefinedIssue): TierMatch | null {
  const overlap = refIdsOverlap(a, b);
  // Use ecosystem-stripped library names so PURL-style ("pkg/debian/bzip2")
  // and bare names ("bzip2") collapse to the same package.
  const libA = normalizeLibraryName(a.library_name);
  const libB = normalizeLibraryName(b.library_name);
  const verA = normalizeVersion(a.current_version);
  const verB = normalizeVersion(b.current_version);

  const sameLib = libA && libB && libA === libB;
  const sameVer = verA && verB && verA === verB;
  const scannerA = lower(a.product_name);
  const scannerB = lower(b.product_name);
  const crossScanner = scannerA && scannerB && scannerA !== scannerB;

  // T1 — exact: ref_id ∩ + library + version
  if (overlap.length > 0 && sameLib && sameVer) {
    return {
      tier: "HIGH",
      matched_signals: {
        reference_identifiers: overlap,
        library_name: libA,
        current_version: verA,
        ...(crossScanner ? { scanners: [scannerA, scannerB] } : {}),
      },
      rationale: crossScanner
        ? `SCA T1 cross-scanner match: ${scannerA} and ${scannerB} both reported ` +
          `${overlap.join(", ")} on ${libA}@${verA}.`
        : `SCA T1 match: shared identifier ${overlap.join(", ")} on ${libA}@${verA}.`,
    };
  }
  // T2 — version-loose: ref_id ∩ + library
  if (overlap.length > 0 && sameLib) {
    return {
      tier: "MEDIUM",
      matched_signals: {
        reference_identifiers: overlap,
        library_name: libA,
        current_version_a: verA || "?",
        current_version_b: verB || "?",
      },
      rationale:
        `SCA T2 match: shared identifier on ${libA} but versions differ ` +
        `(${verA || "?"} vs ${verB || "?"}).`,
    };
  }
  // T3 — cve-only: ref_id ∩ alone
  if (overlap.length > 0) {
    return {
      tier: "LOW",
      matched_signals: { reference_identifiers: overlap },
      rationale:
        `SCA T3 weak signal: shared identifier ${overlap.join(", ")} but ` +
        `package coordinates differ (false-positive risk per Grype #2993, #495).`,
    };
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────
// SAST
// ─────────────────────────────────────────────────────────────────

function matchSast(a: RefinedIssue, b: RefinedIssue): TierMatch | null {
  // For SAST we only care about CWE-typed identifiers in the overlap
  const cweOverlap = refIdsOverlap(a, b).filter((id) => id.startsWith("cwe:"));
  const fileA = normalizePath(a.file_name);
  const fileB = normalizePath(b.file_name);
  const lineA = bestLine(a);
  const lineB = bestLine(b);
  const sameFile = fileA && fileB && fileA === fileB;
  const sameishLine =
    lineA !== undefined &&
    lineB !== undefined &&
    Math.abs(lineA - lineB) <= SAST_LINE_TOLERANCE;

  // T1 — exact: cwe + file + line proximity
  if (cweOverlap.length > 0 && sameFile && sameishLine) {
    return {
      tier: "HIGH",
      matched_signals: {
        cwe: cweOverlap,
        file_name: fileA,
        line_number: `${lineA} ≈ ${lineB} (±${SAST_LINE_TOLERANCE})`,
      },
      rationale:
        `SAST T1 match: shared CWE ${cweOverlap.join(", ")} at ${fileA}:${lineA}.`,
    };
  }
  // T2 — file-loose: cwe + file (line may differ)
  if (cweOverlap.length > 0 && sameFile) {
    const haveLines = lineA !== undefined || lineB !== undefined;
    return {
      tier: "MEDIUM",
      matched_signals: {
        cwe: cweOverlap,
        file_name: fileA,
        ...(haveLines
          ? { line_a: lineA !== undefined ? String(lineA) : "?",
              line_b: lineB !== undefined ? String(lineB) : "?" }
          : {}),
      },
      rationale: haveLines
        ? `SAST T2 match: shared CWE in ${fileA} but reported lines differ (${lineA ?? "?"} vs ${lineB ?? "?"}).`
        : `SAST T2 match: shared CWE in ${fileA} (no line numbers in payload).`,
    };
  }

  // T2b — SCA-shaped data mislabeled as SAST.
  // STO occasionally returns SCA findings (e.g. minimist@0.0.8) under
  // issue_type=SAST. When both issues carry library_name+current_version,
  // treat that as a MEDIUM signal regardless of CWE.
  const libA = lower(a.library_name);
  const libB = lower(b.library_name);
  const verA = normalizeVersion(a.current_version);
  const verB = normalizeVersion(b.current_version);
  if (libA && libB && libA === libB) {
    if (verA && verB && verA === verB) {
      return {
        tier: "HIGH",
        matched_signals: { library_name: libA, current_version: verA },
        rationale: `SAST T2b match: same library ${libA}@${verA} (SCA-shaped data labeled SAST).`,
      };
    }
    return {
      tier: "MEDIUM",
      matched_signals: {
        library_name: libA,
        current_version_a: verA || "?",
        current_version_b: verB || "?",
      },
      rationale:
        `SAST T2b match: same library ${libA} but versions differ (${verA || "?"} vs ${verB || "?"}).`,
    };
  }

  // T3 — cwe-only
  if (cweOverlap.length > 0) {
    return {
      tier: "LOW",
      matched_signals: { cwe: cweOverlap },
      rationale:
        `SAST T3 weak signal: shared CWE ${cweOverlap.join(", ")} but in ` +
        `different files (likely independent findings).`,
    };
  }

  // T3b — exact-title equality (catches re-scan literal duplicates that
  // carry no CWE / file / library signals).
  const titleA = lower(a.title);
  const titleB = lower(b.title);
  if (titleA && titleB && titleA === titleB) {
    return {
      tier: "LOW",
      matched_signals: { title: titleA },
      rationale: "SAST T3b weak signal: identical title text (likely re-scan duplicate).",
    };
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────
// Container
// ─────────────────────────────────────────────────────────────────

function matchContainer(a: RefinedIssue, b: RefinedIssue): TierMatch | null {
  const overlap = refIdsOverlap(a, b);
  const libA = lower(a.library_name);
  const libB = lower(b.library_name);
  const verA = normalizeVersion(a.current_version);
  const verB = normalizeVersion(b.current_version);
  const layerA = lower(a.image_layer_id);
  const layerB = lower(b.image_layer_id);
  const sameLib = libA && libB && libA === libB;
  const sameVer = verA && verB && verA === verB;
  const sameLayer = layerA && layerB && layerA === layerB;

  // T1 — exact: ref_id + library + version + layer
  if (overlap.length > 0 && sameLib && sameVer && sameLayer) {
    return {
      tier: "HIGH",
      matched_signals: {
        reference_identifiers: overlap,
        library_name: libA,
        current_version: verA,
        image_layer_id: layerA,
      },
      rationale:
        `Container T1 match: ${overlap.join(", ")} on ${libA}@${verA} in layer ${layerA}.`,
    };
  }
  // T2 — either (ref + lib + ver) OR (ref + layer)
  if (overlap.length > 0 && sameLib && sameVer) {
    return {
      tier: "MEDIUM",
      matched_signals: {
        reference_identifiers: overlap,
        library_name: libA,
        current_version: verA,
      },
      rationale:
        `Container T2 match: ${overlap.join(", ")} on ${libA}@${verA} (image layer not compared).`,
    };
  }
  if (overlap.length > 0 && sameLayer) {
    return {
      tier: "MEDIUM",
      matched_signals: {
        reference_identifiers: overlap,
        image_layer_id: layerA,
      },
      rationale:
        `Container T2 match: ${overlap.join(", ")} in shared layer ${layerA} (package coords missing on one side).`,
    };
  }
  // T3 — ref only
  if (overlap.length > 0) {
    return {
      tier: "LOW",
      matched_signals: { reference_identifiers: overlap },
      rationale:
        `Container T3 weak signal: ${overlap.join(", ")} but layer/package context missing.`,
    };
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────

export function matchPair(a: RefinedIssue, b: RefinedIssue): TierMatch | null {
  // V1 scope: same-type only EXCEPT a narrow rescue rule for cross-type
  // title-equality — covers STO API quirks where the same finding is
  // tagged SECRET on one side and SAST on the other.
  if (!a.issue_type || !b.issue_type) return null;

  if (a.issue_type !== b.issue_type) {
    return rescueByTitleEquality(a, b);
  }

  switch (a.issue_type) {
    case "SCA":
      return matchSca(a, b);
    case "SAST":
      return matchSast(a, b);
    case "CONTAINER":
      return matchContainer(a, b);
    default:
      // DAST, IAC, MISCONFIG — out of v1 scope
      return null;
  }
}

/**
 * Cross-type T-RESCUE: returns LOW when the issue types differ but the
 * normalized titles are byte-for-byte identical. Surfaces in
 * `review_candidates` (never auto-grouped at HIGH threshold) so this
 * never silently merges legitimately-different findings.
 *
 * Real-world trigger: STO sometimes tags the same Eval-Injection finding
 * as SECRET on one row and SAST on the other.
 */
function rescueByTitleEquality(a: RefinedIssue, b: RefinedIssue): TierMatch | null {
  const titleA = lower(a.title);
  const titleB = lower(b.title);
  if (!titleA || titleA !== titleB) return null;
  return {
    tier: "LOW",
    matched_signals: {
      cross_type: `${a.issue_type} vs ${b.issue_type}`,
      title: titleA,
    },
    rationale:
      `Cross-type rescue: identical title across issue_type=${a.issue_type} and ${b.issue_type} ` +
      `(likely STO API tagging quirk). Surfaces in review_candidates only.`,
  };
}
