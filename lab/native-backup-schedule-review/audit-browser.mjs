// Read-only independent audit. No browser, process, HTTP, state or credential access.
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const check = (ok, code) => { if (!ok) throw new Error(code); };
const digest = raw => createHash("sha256").update(raw).digest("hex");
const hex = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
function exact(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function read(root, label, maximum) {
  check(typeof label === "string" && label && !isAbsolute(label) && !label.split(/[\\/]/).some(part => ["", ".", ".."].includes(part)), "path_shape");
  let path = root;
  for (const part of label.split("/")) {
    path = join(path, part);
    const stat = lstatSync(path);
    check(!stat.isSymbolicLink() && realpathSync(path) === path, "path_alias");
  }
  const stat = lstatSync(path);
  check(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= maximum, "file_bound");
  const raw = readFileSync(path);
  check(raw.length === stat.size, "file_changed");
  return raw;
}
function inventory(root, folders, accepts, maxFiles, maxBytes) {
  const found = [];
  let bytes = 0;
  function walk(path) {
    const stat = lstatSync(path);
    check(!stat.isSymbolicLink() && realpathSync(path) === path, "inventory_alias");
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) walk(join(path, name));
      return;
    }
    const label = relative(root, path).split(sep).join("/");
    if (!accepts(label)) return;
    const raw = read(root, label, 8 << 20);
    bytes += raw.length;
    check(found.length < maxFiles && bytes <= maxBytes, "inventory_bound");
    found.push({ path: label, bytes: raw.length, sha256: digest(raw) });
  }
  for (const folder of folders) walk(join(root, folder));
  found.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return found;
}
function catalog(actual, expected, sha, count, code) {
  check(Array.isArray(expected) && expected.length === count && hex(sha), code + "_shape");
  let previous = "";
  for (const entry of expected) {
    check(exact(entry, ["path", "bytes", "sha256"]) && typeof entry.path === "string" && entry.path > previous && Number.isSafeInteger(entry.bytes) && entry.bytes > 0 && hex(entry.sha256), code + "_entry");
    previous = entry.path;
  }
  check(digest(Buffer.from(JSON.stringify(expected))) === sha, code + "_receipt_hash");
  check(JSON.stringify(actual) === JSON.stringify(expected), code + "_current_inventory");
}

export function auditBrowser({ sourceRoot, workerRoot, reportPath, reportSHA }) {
  for (const root of [sourceRoot, workerRoot]) check(isAbsolute(root) && realpathSync(root) === root, "root_alias");
  check(basename(sourceRoot) === "backup-schedules-integration" && basename(workerRoot) === "backup-schedules-ui-sol" && dirname(sourceRoot) === dirname(workerRoot) && basename(dirname(sourceRoot)) === ".worktrees", "assigned_roots");
  const reportRelative = relative(workerRoot, reportPath).split(sep).join("/");
  check(/^artifacts\/backup-schedules-ui\/\d{8}T\d{9}-[a-f0-9]{8}\/report\.json$/.test(reportRelative), "report_path");
  const raw = read(workerRoot, reportRelative, 2 << 20);
  check(hex(reportSHA) && digest(raw) === reportSHA, "report_hash");
  const r = JSON.parse(raw);
  const fields = ["schema_version", "run_id", "checked_at", "evidence_kind", "passed", "platform", "fixture_only", "main_state_mutated", "shared_inputs_mutated", "live_activation", "paid_provider_calls", "compatibility_certified", "native_scheduled_job_execution_qualified", "source_role", "workflow", "private_viewports", "public_viewports", "cleanup", "screenshots", "timing_limit", "public_limit", "runner_limit", "harness_sha256", "source_catalog", "source_catalog_sha256", "ui_assets", "ui_catalog_sha256", "binary_sha256", "playwright", "node_version", "browser_tool_sha256", "browser_version", "source_binary_ui_harness_unchanged"];
  check(exact(r, fields) && r.schema_version === 1 && r.run_id === basename(dirname(reportPath)) && r.passed === true && r.platform === "win32" && r.evidence_kind === "observed_isolated_native_backup_schedules_browser_qa", "report_success");
  check(r.fixture_only === true && r.main_state_mutated === false && r.shared_inputs_mutated === false && r.live_activation === false && r.paid_provider_calls === 0 && r.compatibility_certified === false && r.native_scheduled_job_execution_qualified === false && r.source_binary_ui_harness_unchanged === true, "claim_bounds");
  check(r.source_role === "reviewed backup-schedules-integration read-only inputs" &&
    r.timing_limit.startsWith("Synthetic 503 is an intercepted PUT response.") && r.timing_limit.includes("programmatic navigation bypasses the modal") &&
    r.public_limit.startsWith("Local HTML public-mode/read-only metrics fixture;") &&
    r.runner_limit.includes("Future due-time execution is qualified separately"), "authority_labels");
  const workflow = ["actual_ui_login_absent_schedule", "confirmation_cancel_escape_focus", "actual_daily_pause_resume", "actual_dual_revision_conflict_draft_refresh_review", "synthetic_503_draft_retention_explicit_retry", "actual_manual_native_backup_schedule_history_preserved", "cross_site_draft_boundary", "delayed_real_put_navigation_late_state_guard_duplicate_block", "actual_runner_off_enable_disabled_paused_save", "actual_logout_delayed_get_private_clear", "actual_isolated_tcp"];
  check(exact(r.workflow, workflow) && workflow.every(key => r.workflow[key] === true), "workflow");
  const cleanup = ["browser_closed", "public_fixture_closed", "owned_children_stopped", "owned_listeners_closed"];
  check(exact(r.cleanup, cleanup) && cleanup.every(key => r.cleanup[key] === true), "cleanup");
  const stats = ["page_errors", "external_requests", "session_requests", "site_requests", "schedule_requests", "schedule_puts", "mutation_requests", "asset_failures", "out_of_scope_mutations"];
  for (const [name, privateMode] of [["private_viewports", true], ["public_viewports", false]]) {
    check(Array.isArray(r[name]) && r[name].length === 6, "viewport_count");
    const seen = new Set();
    for (const row of r[name]) {
      const keys = ["width", "theme", "passed", "overflow", ...(privateMode ? ["schedule_visible", "dialog_bounds", "visible_credentials", "browser_storage_credentials"] : ["schedule_hidden"]), ...stats];
      const key = `${row.width}-${row.theme}`;
      check(exact(row, keys) && [390, 768, 1440].includes(row.width) && ["light", "dark"].includes(row.theme) && !seen.has(key) && row.passed === true && row.overflow === false, "viewport_matrix");
      seen.add(key);
      for (const stat of stats) check(Number.isSafeInteger(row[stat]) && row[stat] >= 0, "viewport_stat");
      for (const stat of ["page_errors", "external_requests", "asset_failures", "out_of_scope_mutations", "schedule_puts", "mutation_requests"]) check(row[stat] === 0, "viewport_error_or_mutation");
      if (privateMode) check(row.schedule_visible && row.dialog_bounds && row.visible_credentials === false && row.browser_storage_credentials === false && row.session_requests >= 1 && row.site_requests >= 1 && row.schedule_requests >= 1, "private_viewport");
      else check(row.schedule_hidden === true && ["session_requests", "site_requests", "schedule_requests"].every(key => row[key] === 0), "public_private_boundary");
    }
  }
  const folders = ["cmd", "internal", "config", "web/src", "go.mod", "go.sum", "package.json", "package-lock.json", "web/package.json", "web/package-lock.json", "web/tsconfig.json", "web/vite.config.ts", "web/scripts/sync-brand.mjs"];
  catalog(inventory(sourceRoot, folders, path => /\.(go|json|sum|mod|ts|tsx|css|mjs)$/.test(path), 2048, 32 << 20), r.source_catalog, r.source_catalog_sha256, 191, "source");
  catalog(inventory(join(sourceRoot, "web/dist"), [""], () => true, 512, 80 << 20), r.ui_assets, r.ui_catalog_sha256, 91, "ui");
  check(digest(read(sourceRoot, ".cache/backup-schedules/sifruno.exe", 80 << 20)) === r.binary_sha256, "binary_hash");
  check(digest(read(workerRoot, "scripts/verify-backup-schedules-ui.mjs", 1 << 20)) === r.harness_sha256, "harness_hash");
  const images = [];
  const reportDir = dirname(reportRelative);
  for (const width of [390, 768, 1440]) for (const theme of ["light", "dark"]) for (const type of ["private", "dialog", "public"]) {
    const name = `${type}-${width}-${theme}.png`;
    check(hex(r.screenshots[name]), "screenshot_receipt");
    const png = read(workerRoot, `${reportDir}/${name}`, 8 << 20);
    check(digest(png) === r.screenshots[name] && png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) && png.readUInt32BE(16) === width && png.readUInt32BE(20) >= 300 && png.readUInt32BE(20) <= 10000, "screenshot_hash_dimensions");
    images.push({ name, sha256: r.screenshots[name], width, height: png.readUInt32BE(20) });
  }
  check(Object.keys(r.screenshots).length === 18 && readdirSync(dirname(reportPath)).sort().join("|") === ["report.json", ...images.map(item => item.name)].sort().join("|"), "artifact_inventory");
  return { schema: 1, kind: "independent-read-only-backup-schedule-browser-audit", passed: true, report_sha256: reportSHA, source_entries: 191, ui_entries: 91, source_catalog_sha256: r.source_catalog_sha256, ui_catalog_sha256: r.ui_catalog_sha256, binary_sha256: r.binary_sha256, harness_sha256: r.harness_sha256, workflow_flags: 11, private_cases: 6, public_cases: 6, cleanup_flags: 4, screenshots: images, limitations: ["Receipt/source/hash audit; browser run belongs to worker.", "Synthetic 503 and modal-bypassed programmatic navigation retain their separate labels.", "Public-mode fixture is local, with no remote/proxy/tunnel acceptance.", "No scheduled due-job, service/reboot/all-OS or cPanel qualification follows from this browser report."] };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    check(process.argv.length === 6, "usage");
    console.log(JSON.stringify(auditBrowser({ sourceRoot: resolve(process.argv[2]), workerRoot: resolve(process.argv[3]), reportPath: resolve(process.argv[4]), reportSHA: process.argv[5] }), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ passed: false, code: /^[a-z_]+$/.test(error.message) ? error.message : "bounded_audit_failure" }));
    process.exitCode = 1;
  }
}
