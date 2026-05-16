/**
 * Field normalization for cross-scanner comparison.
 *
 * Rules are intentionally narrow — only changes that don't lose information
 * (case, leading whitespace, version-prefix glyphs).
 */

import { ReferenceIdentifier } from "../frameworks/refined-issue.js";

export function lower(s: string | undefined | null): string {
  return (s ?? "").trim().toLowerCase();
}

/**
 * Strip common version-prefix glyphs and trailing punctuation that titles
 * sometimes leak in (e.g. trailing `:` or `,` from `pkg@1.2.3: vuln description`).
 *   "v4.17.20"      → "4.17.20"
 *   "^4.17.20"      → "4.17.20"
 *   "~4.17.20"      → "4.17.20"
 *   "= 4.17.20"     → "4.17.20"
 *   "  4.17.20  "   → "4.17.20"
 *   "0.6.9:"        → "0.6.9"
 *   "1.5.3-5ubuntu5.1," → "1.5.3-5ubuntu5.1"
 */
export function normalizeVersion(v: string | undefined | null): string {
  if (!v) return "";
  return v
    .trim()
    .replace(/^[v^~=\s]+/i, "")
    .replace(/[:,;.\s]+$/, "")
    .trim()
    .toLowerCase();
}

/**
 * Path-normalize a file name: lowercase only on Windows-like paths is a
 * footgun, so we leave case alone but strip "./" and trailing whitespace.
 */
export function normalizePath(p: string | undefined | null): string {
  if (!p) return "";
  return p.trim().replace(/^\.\//, "");
}

/**
 * Normalize a library/component name across scanners.
 *
 * Different scanners label the same package differently:
 *   shiftleftsca:   "pkg/debian/bzip2"      (PURL-style with ecosystem prefix)
 *   aqua-trivy:     "bzip2"                  (bare package name)
 *   snyk:           "deb/bzip2"              (alternate prefix)
 *   github-deps:    "pkg:deb/debian/bzip2"   (full PURL)
 *
 * Without normalization, cross-scanner T1 (HIGH) match never fires because
 * `library_name` differs. This strips the ecosystem prefix so the
 * underlying package name is comparable.
 *
 * Strips (case-insensitive):
 *   leading "pkg:" or "pkg/"
 *   ecosystem segment + "/" (debian, ubuntu, alpine, npm, pip, pypi, maven,
 *                            golang, gem, nuget, deb, rpm, apk, hex, cargo, ...)
 *   distro segment when present (e.g. "deb/debian/...")
 */
export function normalizeLibraryName(name: string | undefined | null): string {
  if (!name) return "";
  let s = name.trim().toLowerCase();
  // Strip "pkg:" or "pkg/" prefix
  s = s.replace(/^pkg[:/]/, "");
  // Strip up to 2 leading ecosystem/distro segments
  const ECOSYSTEMS = new Set([
    "debian", "ubuntu", "alpine", "rhel", "centos", "amazon", "wolfi",
    "npm", "pip", "pypi", "maven", "golang", "go", "gem", "rubygems",
    "nuget", "hex", "cargo", "composer", "deb", "rpm", "apk",
    "github", "gitlab", "bitbucket", "node-pkg", "lang-pkgs", "os-pkgs",
  ]);
  for (let i = 0; i < 2; i++) {
    const slash = s.indexOf("/");
    if (slash < 0) break;
    const head = s.slice(0, slash);
    if (!ECOSYSTEMS.has(head)) break;
    s = s.slice(slash + 1);
  }
  return s;
}

/**
 * Build a canonical Set<string> of "type:id" tokens from a reference
 * identifiers list. Type is lowercased; id is uppercased (CVE/GHSA convention).
 */
export function refIdSet(
  refs: ReferenceIdentifier[] | undefined,
): Set<string> {
  const out = new Set<string>();
  for (const r of refs ?? []) {
    if (!r?.type || !r?.id) continue;
    out.add(`${r.type.toLowerCase()}:${r.id.toUpperCase()}`);
  }
  return out;
}

/** Set intersection convenience. */
export function intersect<T>(a: Set<T>, b: Set<T>): Set<T> {
  const out = new Set<T>();
  for (const x of a) if (b.has(x)) out.add(x);
  return out;
}
