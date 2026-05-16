#!/usr/bin/env node
/**
 * scripts/bench-local.mjs
 *
 * Run the full dedupe_pipeline flow locally against a real Harness STO
 * pipeline and print timings. Use this BEFORE pushing changes to the Worker
 * Agent in QA — it gives you a tight feedback loop and a hard timing number
 * so you know if the new architecture actually moved the needle.
 *
 * Usage:
 *   npm run build
 *   node scripts/bench-local.mjs --pipeline-id dedupdemo --project-id STO
 *
 * Env (or pass --harness-base-url / --harness-api-key as CLI flags):
 *   HARNESS_BASE_URL  e.g. https://qa.harness.io
 *   HARNESS_API_KEY   pat.<accountId>.<userId>.<token>
 *
 * Auto-loads .env files from (in order):
 *   ./.env, ../mcp-server/.env, ../harness-mcp/.env
 * (The harness-mcp project usually has these set already from earlier setup.)
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { dedupePipeline } from "../dist/tools/dedupe-pipeline.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// ── tiny .env loader (avoids adding dotenv as a dep) ───────────────────────
function loadEnvFile(path) {
  if (!existsSync(path)) return false;
  const raw = readFileSync(path, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = val;
  }
  return true;
}

const candidates = [
  resolve(ROOT, ".env"),
  resolve(ROOT, "../mcp-server/.env"),
  resolve(ROOT, "../harness-mcp/.env"),
];
for (const p of candidates) {
  if (loadEnvFile(p)) {
    process.stderr.write(`[bench] loaded env from ${p}\n`);
    break;
  }
}
// Also pull APP_DATABASE_DATASOURCE from sto-core/.env (sibling of dedup-mcp).
// We don't *use* sto-core's other env vars — just the DB URL.
{
  const stoCoreEnv = resolve(ROOT, "../STO/sto-core/.env");
  if (loadEnvFile(stoCoreEnv)) {
    process.stderr.write(`[bench] also loaded ${stoCoreEnv} for STO DB url\n`);
  }
}

// ── arg parsing ────────────────────────────────────────────────────────────
function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const pipelineId = arg("pipeline-id");
const targetId = arg("target-id");
const projectId = arg("project-id", "STO");
const orgId = arg("org-id", "default");
const maxPages = arg("max-pages") ? Number(arg("max-pages")) : undefined;
const pageSize = Number(arg("page-size", "100"));
const maxIssues = Number(arg("max-issues", "1000"));
// Default LOW so all tiers surface in duplicate_groups with their tier label.
// Tier LABEL governs user action: HIGH = auto-exempt, MEDIUM = review/approve,
// LOW = manual review. Override with `--group-threshold HIGH` to see only
// auto-exemptable groups.
const groupThreshold = arg("group-threshold", "LOW");
const enrich = arg("enrich", "auto"); // never | auto | always
const backend = arg("backend", "api"); // api | sql
const baseUrl = arg("harness-base-url", process.env.HARNESS_BASE_URL);
const apiKey = arg("harness-api-key", process.env.HARNESS_API_KEY);
const stoDbUrl = arg("sto-database-url", process.env.STO_DATABASE_URL || process.env.APP_DATABASE_DATASOURCE);
const showAllGroups = process.argv.includes("--all-groups");
const dumpJson = process.argv.includes("--json");

// pipeline_id and target_id are both optional. With neither, dedup runs
// across all issues in the (org, project) scope, capped by --max-issues.
if (backend === "api" && (!baseUrl || !apiKey)) {
  console.error(
    `[bench] missing credentials for API backend.\n  HARNESS_BASE_URL=${baseUrl ? "set" : "MISSING"}\n  HARNESS_API_KEY=${apiKey ? "set" : "MISSING"}\nSet them in env or pass --harness-base-url / --harness-api-key.`,
  );
  process.exit(2);
}
if (backend === "sql" && !stoDbUrl) {
  console.error(
    `[bench] missing STO_DATABASE_URL for sql backend.\nLoad from sto-core/.env (APP_DATABASE_DATASOURCE) or pass --sto-database-url.`,
  );
  process.exit(2);
}

// ── run ────────────────────────────────────────────────────────────────────
process.stderr.write(`\n[bench] dedupe_pipeline\n`);
process.stderr.write(`  backend:         ${backend}\n`);
if (backend === "api") {
  process.stderr.write(`  base_url:        ${baseUrl}\n`);
} else {
  // Mask password in logged URL
  process.stderr.write(`  database_url:    ${stoDbUrl ? stoDbUrl.replace(/\/\/[^@]+@/, "//***:***@") : "?"}\n`);
}
process.stderr.write(`  org_id:          ${orgId}\n`);
process.stderr.write(`  project_id:      ${projectId}\n`);
process.stderr.write(`  pipeline_id:     ${pipelineId ?? "(none)"}\n`);
process.stderr.write(`  target_id:       ${targetId ?? "(none)"}\n`);
if (backend === "api") {
  process.stderr.write(`  page_size:       ${pageSize}\n`);
  process.stderr.write(`  max_pages:       ${maxPages}\n`);
  process.stderr.write(`  enrich:          ${enrich}\n`);
}
process.stderr.write(`  group_threshold: ${groupThreshold}\n\n`);

const wallStart = Date.now();
let result;
try {
  result = await dedupePipeline({
    pipeline_id: pipelineId,
    target_id: targetId,
    project_id: projectId,
    org_id: orgId,
    page_size: pageSize,
    max_pages: maxPages,
    max_issues: maxIssues,
    group_threshold: groupThreshold,
    enrich: enrich,
    backend: backend,
    sto_database_url: stoDbUrl,
    harness_base_url: baseUrl,
    harness_api_key: apiKey,
  });
} catch (err) {
  console.error(`[bench] FAILED after ${Date.now() - wallStart} ms: ${err?.message ?? err}`);
  process.exit(1);
}
const wallMs = Date.now() - wallStart;

// ── render summary ─────────────────────────────────────────────────────────
const fmt = (ms) => `${(ms / 1000).toFixed(2)}s (${ms}ms)`;

console.log("");
console.log("═══════════════════════════════════════════════════════════════");
console.log(" Vulnerability Dedup — bench result");
console.log("═══════════════════════════════════════════════════════════════");
console.log(` pipeline:               ${result.scope.pipeline_id}`);
console.log(` issues sampled:         ${result.scope.issue_count_sampled}${result.scope.capped ? `  ⚠ capped at max_issues=${result.scope.max_issues}` : ""}`);
console.log(` pages fetched:          ${result.scope.pages_fetched}`);
console.log(` types seen:             ${result.scope.types_seen.join(", ") || "—"}`);
console.log(` backend:                ${result.scope.backend}`);
console.log(` enrichment mode:        ${result.scope.enrichment_mode}  (${result.scope.enriched_count} issues detail-fetched)`);
if (result.scope.total_raw_occurrences != null) {
  console.log(` raw findings (pre-dedup): ${result.scope.total_raw_occurrences}  ← summed numOccurrences from enriched issues`);
}
console.log("");
console.log(` duplicate groups:       ${result.stats.duplicate_group_count}`);
const tier = result.stats.groups_by_tier ?? {};
console.log(`   ─ HIGH:                ${tier.HIGH ?? 0}`);
console.log(`   ─ MEDIUM:              ${tier.MEDIUM ?? 0}`);
console.log(`   ─ LOW:                 ${tier.LOW ?? 0}`);
console.log(` review candidates:      ${result.stats.review_candidate_count}`);
console.log(` unique after dedup:     ${result.stats.unique_after_dedup}`);
console.log(` noise reduction (issues→unique):        ${result.stats.noise_reduction_pct}%`);
if (result.stats.end_to_end_noise_reduction_pct != null) {
  console.log(` ★ end-to-end (raw→unique):              ${result.stats.end_to_end_noise_reduction_pct}%   ← demo headline`);
}
console.log("");
console.log(" Timings");
console.log(` ─ fetch (Harness API):  ${fmt(result.timings_ms.fetch)}`);
console.log(` ─ enrich (per-issue):   ${fmt(result.timings_ms.enrich)}`);
console.log(` ─ normalize:            ${fmt(result.timings_ms.normalize)}`);
console.log(` ─ dedup (O(N²) match):  ${fmt(result.timings_ms.dedup)}`);
console.log(` ─ tool total:           ${fmt(result.timings_ms.total)}`);
console.log(` ─ wall (incl. startup): ${fmt(wallMs)}`);
console.log("═══════════════════════════════════════════════════════════════");

const groupsToShow = showAllGroups
  ? result.duplicate_groups
  : result.duplicate_groups.slice(0, 12);
// Sort: HIGH first, then MEDIUM, then LOW; within each tier by member count desc.
const TIER_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const sorted = [...groupsToShow].sort((a, b) => {
  const tierDiff = (TIER_RANK[b.confidence_tier] ?? 0) - (TIER_RANK[a.confidence_tier] ?? 0);
  return tierDiff !== 0 ? tierDiff : b.members.length - a.members.length;
});

if (sorted.length > 0) {
  console.log("");
  console.log(` Top ${sorted.length} duplicate clusters (HIGH → MEDIUM → LOW):`);
  for (let i = 0; i < sorted.length; i++) {
    const g = sorted[i];
    const primary = g.members.find((m) => m.is_primary) ?? g.members[0];
    const scannerSet = new Set(g.members.map((m) => m.scanner).filter(Boolean));
    const scannerNote = scannerSet.size > 1 ? `  scanners=[${[...scannerSet].join(",")}]` : "";
    console.log(`  ${i + 1}. [${g.confidence_tier}, ${g.members.length} members]${scannerNote} ${g.headline}`);
    console.log(`       primary: ${primary.title ?? primary.internal_id}${primary.scanner ? ` (${primary.scanner})` : ""}`);
  }
  if (!showAllGroups && result.duplicate_groups.length > 12) {
    console.log(`  … (${result.duplicate_groups.length - 12} more — pass --all-groups to see all)`);
  }
}

if (result.warnings.length > 0) {
  console.log("");
  console.log(` Warnings (${result.warnings.length}):`);
  for (const w of result.warnings.slice(0, 5)) console.log(`   - ${w}`);
  if (result.warnings.length > 5) {
    console.log(`   … (${result.warnings.length - 5} more)`);
  }
}

if (dumpJson) {
  console.log("");
  console.log(" Full JSON output:");
  console.log(JSON.stringify(result, null, 2));
}

console.log("");
