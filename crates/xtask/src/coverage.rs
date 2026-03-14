#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use glob::glob;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct CoverageSummary {
    pub functions_percent: f64,
    pub summary_lines_percent: f64,
    pub summary_regions_percent: f64,
}

#[derive(Debug, Clone, Copy)]
pub enum ExecutableSource {
    Da,
    LfLh,
}

#[derive(Debug, Clone)]
pub struct LcovCoverage {
    pub executable_total: u64,
    pub executable_covered: u64,
    pub executable_percent: f64,
    pub executable_source: ExecutableSource,
    pub branch_total: u64,
    pub branch_covered: u64,
    pub branches_available: bool,
    pub branch_percent: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct CoverageThresholds {
    pub fail_under_exec_lines: f64,
    pub fail_under_functions: f64,
    pub fail_under_regions: f64,
    pub fail_under_branches: f64,
    pub require_branches: bool,
}

#[derive(Debug, Clone)]
pub struct CoverageGateResult {
    pub pass: bool,
    pub fail_reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LlvmCovSummaryRoot {
    data: Vec<LlvmCovSummaryData>,
}

#[derive(Debug, Deserialize)]
struct LlvmCovSummaryData {
    totals: LlvmCovSummaryTotals,
}

#[derive(Debug, Deserialize)]
struct LlvmCovSummaryTotals {
    functions: LlvmCovSummaryMetric,
    lines: LlvmCovSummaryMetric,
    regions: LlvmCovSummaryMetric,
}

#[derive(Debug, Deserialize)]
struct LlvmCovSummaryMetric {
    percent: f64,
}

#[derive(Debug, Deserialize)]
struct WorkspaceManifest {
    workspace: WorkspaceMembers,
}

#[derive(Debug, Deserialize)]
struct WorkspaceMembers {
    members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PackageManifest {
    package: PackageSection,
}

#[derive(Debug, Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Debug, Deserialize)]
struct CoverageRolloutContract {
    policy: CoveragePolicyContract,
    rollout: CoverageRolloutSection,
}

#[derive(Debug, Deserialize)]
struct CoveragePolicyContract {
    fail_under_exec_lines: f64,
    fail_under_functions: f64,
    fail_under_regions: f64,
    fail_under_branches: f64,
    require_branches: bool,
}

#[derive(Debug, Deserialize)]
struct CoverageRolloutSection {
    strategy: String,
    entry_crate: String,
    crates: Vec<CoverageRolloutCrate>,
}

#[derive(Debug, Deserialize)]
struct CoverageRolloutCrate {
    name: String,
    status: String,
    order: u32,
}

#[derive(Debug, Deserialize)]
struct CoverageRequiredContract {
    required: CoverageRequiredList,
    policy: CoverageRequiredPolicy,
}

#[derive(Debug, Deserialize)]
struct CoverageRequiredList {
    crates: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoverageRequiredPolicy {
    mode: String,
    threshold_profile: String,
}

#[derive(Debug, Deserialize)]
struct CoverageReleaseContract {
    release: CoverageReleaseList,
}

#[derive(Debug, Deserialize)]
struct CoverageReleaseList {
    crates: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct CoverageProfilesFile {
    #[serde(default)]
    profiles: CoverageProfilesSection,
}

#[derive(Debug, Deserialize, Default)]
struct CoverageProfilesSection {
    #[serde(default)]
    default: CoverageProfileRaw,
    #[serde(default)]
    crates: BTreeMap<String, CoverageProfileRaw>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct CoverageProfileRaw {
    no_default_features: Option<bool>,
    features: Option<Vec<String>>,
    test_threads: Option<u32>,
}

#[derive(Debug, Clone)]
struct CoverageProfile {
    no_default_features: bool,
    features: Vec<String>,
    test_threads: Option<u32>,
}

#[derive(Debug, Serialize)]
struct CoverageGateReport {
    scope: String,
    thresholds: CoverageGateReportThresholds,
    measured: CoverageGateReportMeasured,
    counts: CoverageGateReportCounts,
    result: CoverageGateReportResult,
}

#[derive(Debug, Serialize)]
struct CoverageGateReportThresholds {
    executable_lines: f64,
    functions: f64,
    regions: f64,
    branches: f64,
    branches_required: bool,
}

#[derive(Debug, Serialize)]
struct CoverageGateReportMeasured {
    executable_lines_percent: f64,
    executable_lines_source: String,
    functions_percent: f64,
    branches_percent: Option<f64>,
    branches_available: bool,
    summary_lines_percent: f64,
    summary_regions_percent: f64,
}

#[derive(Debug, Serialize)]
struct CoverageGateReportCounts {
    executable_lines: CoverageCount,
    branches: CoverageCount,
}

#[derive(Debug, Serialize)]
struct CoverageCount {
    covered: u64,
    total: u64,
}

#[derive(Debug, Serialize)]
struct CoverageGateReportResult {
    pass: bool,
    fail_reasons: Vec<String>,
}

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("validate-contract") => validate_contract(),
        Some("required-crates") => list_required_crates(),
        Some("release-crates") => list_release_crates(),
        Some("workspace-crates") => list_workspace_crates(),
        Some("run-crate") => run_crate(&args[1..]),
        Some("report") => report_gate(&args[1..]),
        Some(command) => Err(format!("unknown coverage subcommand `{command}`")),
        None => Err("missing coverage subcommand".to_string()),
    }
}

pub fn read_summary(path: &Path) -> Result<CoverageSummary, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read summary {}: {err}", path.display()))?;
    let parsed: LlvmCovSummaryRoot = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse summary {}: {err}", path.display()))?;
    let totals = &parsed
        .data
        .first()
        .ok_or_else(|| format!("summary data is empty in {}", path.display()))?
        .totals;

    Ok(CoverageSummary {
        functions_percent: totals.functions.percent,
        summary_lines_percent: totals.lines.percent,
        summary_regions_percent: totals.regions.percent,
    })
}

pub fn read_lcov(path: &Path) -> Result<LcovCoverage, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read lcov {}: {err}", path.display()))?;

    let mut da_total: u64 = 0;
    let mut da_covered: u64 = 0;
    let mut executable_total: u64 = 0;
    let mut executable_covered: u64 = 0;
    let mut branch_total_lcov: u64 = 0;
    let mut branch_covered_lcov: u64 = 0;
    let mut branch_total_brda: u64 = 0;
    let mut branch_covered_brda: u64 = 0;
    let mut saw_branch_records = false;

    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("DA:") {
            let Some((_, hit)) = value.split_once(',') else {
                return Err(format!("invalid DA record in {}", path.display()));
            };
            let hit_count: u64 = hit.parse().map_err(|err| {
                format!("invalid DA hit count `{hit}` in {}: {err}", path.display())
            })?;
            da_total = da_total.saturating_add(1);
            if hit_count > 0 {
                da_covered = da_covered.saturating_add(1);
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("LF:") {
            let parsed: u64 = value.parse().map_err(|err| {
                format!("invalid LF value `{value}` in {}: {err}", path.display())
            })?;
            executable_total = executable_total.saturating_add(parsed);
            continue;
        }
        if let Some(value) = line.strip_prefix("LH:") {
            let parsed: u64 = value.parse().map_err(|err| {
                format!("invalid LH value `{value}` in {}: {err}", path.display())
            })?;
            executable_covered = executable_covered.saturating_add(parsed);
            continue;
        }
        if let Some(value) = line.strip_prefix("BRF:") {
            saw_branch_records = true;
            let parsed: u64 = value.parse().map_err(|err| {
                format!("invalid BRF value `{value}` in {}: {err}", path.display())
            })?;
            branch_total_lcov = branch_total_lcov.saturating_add(parsed);
            continue;
        }
        if let Some(value) = line.strip_prefix("BRH:") {
            saw_branch_records = true;
            let parsed: u64 = value.parse().map_err(|err| {
                format!("invalid BRH value `{value}` in {}: {err}", path.display())
            })?;
            branch_covered_lcov = branch_covered_lcov.saturating_add(parsed);
            continue;
        }
        if let Some(value) = line.strip_prefix("BRDA:") {
            saw_branch_records = true;
            let fields = value.split(',').collect::<Vec<_>>();
            if fields.len() != 4 {
                return Err(format!("invalid BRDA record in {}", path.display()));
            }
            let taken = fields[3];
            if taken == "-" {
                continue;
            }
            let hit_count: u64 = taken.parse().map_err(|err| {
                format!(
                    "invalid BRDA taken count `{taken}` in {}: {err}",
                    path.display()
                )
            })?;
            branch_total_brda = branch_total_brda.saturating_add(1);
            if hit_count > 0 {
                branch_covered_brda = branch_covered_brda.saturating_add(1);
            }
        }
    }

    let (executable_total, executable_covered, executable_percent, executable_source) =
        if da_total > 0 {
            (
                da_total,
                da_covered,
                (da_covered as f64 / da_total as f64) * 100.0,
                ExecutableSource::Da,
            )
        } else if executable_total > 0 {
            (
                executable_total,
                executable_covered,
                (executable_covered as f64 / executable_total as f64) * 100.0,
                ExecutableSource::LfLh,
            )
        } else {
            (0, 0, 100.0, ExecutableSource::Da)
        };

    let (branch_total, branch_covered) = if branch_total_brda > 0 {
        (branch_total_brda, branch_covered_brda)
    } else {
        (branch_total_lcov, branch_covered_lcov)
    };
    let branches_available = saw_branch_records;
    let branch_percent = if branch_total > 0 {
        Some((branch_covered as f64 / branch_total as f64) * 100.0)
    } else if branches_available {
        Some(100.0)
    } else {
        None
    };

    Ok(LcovCoverage {
        executable_total,
        executable_covered,
        executable_percent,
        executable_source,
        branch_total,
        branch_covered,
        branches_available,
        branch_percent,
    })
}

pub fn evaluate_gate(
    summary: &CoverageSummary,
    lcov: &LcovCoverage,
    thresholds: CoverageThresholds,
) -> CoverageGateResult {
    let exec_ok = lcov.executable_percent >= thresholds.fail_under_exec_lines;
    let functions_ok = summary.functions_percent >= thresholds.fail_under_functions;
    let regions_ok = summary.summary_regions_percent >= thresholds.fail_under_regions;
    let branch_presence_ok = !thresholds.require_branches || lcov.branches_available;
    let branch_ok = lcov
        .branch_percent
        .is_none_or(|branch_percent| branch_percent >= thresholds.fail_under_branches);

    let pass = [
        exec_ok,
        functions_ok,
        regions_ok,
        branch_presence_ok,
        branch_ok,
    ]
    .into_iter()
    .all(|flag| flag);
    let mut fail_reasons = Vec::new();

    if !exec_ok {
        fail_reasons.push(format!(
            "executable_lines={:.6} < {:.6}",
            lcov.executable_percent, thresholds.fail_under_exec_lines
        ));
    }
    if !functions_ok {
        fail_reasons.push(format!(
            "functions={:.6} < {:.6}",
            summary.functions_percent, thresholds.fail_under_functions
        ));
    }
    if !regions_ok {
        fail_reasons.push(format!(
            "regions={:.6} < {:.6}",
            summary.summary_regions_percent, thresholds.fail_under_regions
        ));
    }
    if thresholds.require_branches && !lcov.branches_available {
        fail_reasons.push("branches=unavailable".to_string());
    }
    if lcov.branches_available && !branch_ok {
        fail_reasons.push(format!(
            "branches={:.6} < {:.6}",
            lcov.branch_percent.unwrap_or(0.0),
            thresholds.fail_under_branches
        ));
    }

    CoverageGateResult { pass, fail_reasons }
}

fn parse_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    toml::from_str::<T>(&raw).map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn workspace_root() -> PathBuf {
    let override_root = std::env::var("NOSTR_MCP_WORKSPACE_ROOT")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty());
    if let Some(root) = override_root {
        return PathBuf::from(root);
    }
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest_dir)
        .to_path_buf()
}

fn coverage_contract_dir(root: &Path) -> PathBuf {
    root.join("contract").join("coverage")
}

fn parse_thresholds_from_contract(root: &Path) -> Result<CoverageThresholds, String> {
    let contract =
        parse_toml::<CoverageRolloutContract>(&coverage_contract_dir(root).join("rollout.toml"))?;
    Ok(CoverageThresholds {
        fail_under_exec_lines: contract.policy.fail_under_exec_lines,
        fail_under_functions: contract.policy.fail_under_functions,
        fail_under_regions: contract.policy.fail_under_regions,
        fail_under_branches: contract.policy.fail_under_branches,
        require_branches: contract.policy.require_branches,
    })
}

fn expand_workspace_member(root: &Path, member: &str) -> Result<Vec<PathBuf>, String> {
    let candidate = root.join(member);
    let pattern = candidate.to_string_lossy().to_string();
    if !member.contains('*') && !member.contains('?') && !member.contains('[') {
        return Ok(vec![candidate]);
    }

    let mut results = Vec::new();
    let entries =
        glob(&pattern).map_err(|err| format!("invalid workspace member glob `{member}`: {err}"))?;
    for entry in entries {
        let path =
            entry.map_err(|err| format!("failed to expand workspace member `{member}`: {err}"))?;
        results.push(path);
    }
    results.sort();
    Ok(results)
}

fn read_workspace_crates(root: &Path) -> Result<Vec<String>, String> {
    let manifest = parse_toml::<WorkspaceManifest>(&root.join("Cargo.toml"))?;
    if manifest.workspace.members.is_empty() {
        return Err("workspace members list must not be empty".to_string());
    }

    let mut crates = Vec::new();
    let mut seen = BTreeSet::new();
    for member in manifest.workspace.members {
        for member_path in expand_workspace_member(root, &member)? {
            if !member_path.join("Cargo.toml").exists() {
                continue;
            }
            let package_manifest = parse_toml::<PackageManifest>(&member_path.join("Cargo.toml"))?;
            let package_name = package_manifest.package.name;
            if !seen.insert(package_name.clone()) {
                return Err(format!(
                    "workspace includes duplicate package name `{package_name}`"
                ));
            }
            crates.push(package_name);
        }
    }
    crates.sort();
    Ok(crates)
}

fn read_required_contract(root: &Path) -> Result<CoverageRequiredContract, String> {
    parse_toml::<CoverageRequiredContract>(
        &coverage_contract_dir(root).join("required-crates.toml"),
    )
}

fn read_release_contract(root: &Path) -> Result<CoverageReleaseContract, String> {
    parse_toml::<CoverageReleaseContract>(&coverage_contract_dir(root).join("release-crates.toml"))
}

fn read_rollout_contract(root: &Path) -> Result<CoverageRolloutContract, String> {
    parse_toml::<CoverageRolloutContract>(&coverage_contract_dir(root).join("rollout.toml"))
}

fn merge_coverage_profile(
    base: CoverageProfileRaw,
    overlay: CoverageProfileRaw,
) -> CoverageProfile {
    CoverageProfile {
        no_default_features: overlay
            .no_default_features
            .unwrap_or(base.no_default_features.unwrap_or(false)),
        features: overlay
            .features
            .unwrap_or_else(|| base.features.unwrap_or_default()),
        test_threads: overlay.test_threads.or(base.test_threads),
    }
}

fn read_coverage_profiles(root: &Path) -> Result<CoverageProfilesFile, String> {
    parse_toml::<CoverageProfilesFile>(&coverage_contract_dir(root).join("profiles.toml"))
}

fn read_coverage_profile(root: &Path, crate_name: &str) -> Result<CoverageProfile, String> {
    let profiles = read_coverage_profiles(root)?;
    let base = profiles.profiles.default;
    let overlay = profiles
        .profiles
        .crates
        .get(crate_name)
        .cloned()
        .unwrap_or_default();
    let resolved = merge_coverage_profile(base, overlay);
    if resolved
        .features
        .iter()
        .any(|feature| feature.trim().is_empty())
    {
        return Err(format!(
            "coverage profile for `{crate_name}` includes an empty feature value"
        ));
    }
    if resolved.test_threads == Some(0) {
        return Err(format!(
            "coverage profile for `{crate_name}` must set test_threads > 0"
        ));
    }
    Ok(resolved)
}

fn validate_contract_at_root(root: &Path) -> Result<(), String> {
    let workspace_crates = read_workspace_crates(root)?;
    let workspace_set = workspace_crates.iter().cloned().collect::<BTreeSet<_>>();

    let rollout = read_rollout_contract(root)?;
    let required = read_required_contract(root)?;
    let release = read_release_contract(root)?;
    let profiles = read_coverage_profiles(root)?;

    let policy = rollout.policy;
    if policy.fail_under_exec_lines != 100.0
        || policy.fail_under_functions != 100.0
        || policy.fail_under_regions != 100.0
        || policy.fail_under_branches != 100.0
    {
        return Err("coverage thresholds must remain locked at 100/100/100/100".to_string());
    }
    if !policy.require_branches {
        return Err("coverage policy must require branch data".to_string());
    }

    if rollout.rollout.strategy != "crate-by-crate" {
        return Err("coverage rollout strategy must be `crate-by-crate`".to_string());
    }
    if rollout.rollout.entry_crate.trim().is_empty() {
        return Err("coverage rollout entry crate must not be empty".to_string());
    }

    let mut rollout_names = BTreeSet::new();
    let mut rollout_required = BTreeSet::new();
    let mut rollout_orders = BTreeSet::new();
    let mut rollout_order_map = BTreeMap::new();
    for item in &rollout.rollout.crates {
        if item.name.trim().is_empty() {
            return Err("coverage rollout includes an empty crate name".to_string());
        }
        if !rollout_names.insert(item.name.clone()) {
            return Err(format!(
                "coverage rollout includes duplicate crate `{}`",
                item.name
            ));
        }
        if !rollout_orders.insert(item.order) {
            return Err(format!(
                "coverage rollout includes duplicate order `{}`",
                item.order
            ));
        }
        match item.status.as_str() {
            "planned" => {}
            "required" => {
                rollout_required.insert(item.name.clone());
            }
            other => {
                return Err(format!(
                    "coverage rollout includes invalid status `{other}` for `{}`",
                    item.name
                ));
            }
        }
        rollout_order_map.insert(item.name.clone(), item.order);
    }
    if !rollout_names.contains(&rollout.rollout.entry_crate) {
        return Err(format!(
            "coverage rollout entry crate `{}` is not listed in rollout crates",
            rollout.rollout.entry_crate
        ));
    }

    let expected_orders = (1..=rollout.rollout.crates.len() as u32).collect::<BTreeSet<_>>();
    if rollout_orders != expected_orders {
        return Err("coverage rollout orders must be contiguous starting at 1".to_string());
    }
    if rollout_names != workspace_set {
        let missing = workspace_set
            .difference(&rollout_names)
            .cloned()
            .collect::<Vec<_>>();
        let extra = rollout_names
            .difference(&workspace_set)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "coverage rollout must match workspace crates exactly; missing={missing:?} extra={extra:?}"
        ));
    }

    let mut release_set = BTreeSet::new();
    let mut release_orders = Vec::new();
    for crate_name in &release.release.crates {
        if crate_name.trim().is_empty() {
            return Err("coverage release crates list includes an empty crate name".to_string());
        }
        if !release_set.insert(crate_name.clone()) {
            return Err(format!(
                "coverage release crates list includes duplicate crate `{crate_name}`"
            ));
        }
        if !workspace_set.contains(crate_name) {
            return Err(format!(
                "coverage release crates list includes unknown workspace crate `{crate_name}`"
            ));
        }
        let Some(order) = rollout_order_map.get(crate_name) else {
            return Err(format!(
                "coverage release crate `{crate_name}` is missing from rollout.toml"
            ));
        };
        release_orders.push(*order);
    }
    if release_set.is_empty() {
        return Err("coverage release crates list must not be empty".to_string());
    }
    let mut sorted_release_orders = release_orders.clone();
    sorted_release_orders.sort_unstable();
    if release_orders != sorted_release_orders {
        return Err("coverage release crates must follow rollout.toml order exactly".to_string());
    }
    if !release_set.contains(&rollout.rollout.entry_crate) {
        return Err(format!(
            "coverage rollout entry crate `{}` must be part of release-crates.toml",
            rollout.rollout.entry_crate
        ));
    }

    if required.policy.threshold_profile != "strict_100" {
        return Err(
            "coverage required-crates policy must use threshold_profile = `strict_100`".to_string(),
        );
    }
    match required.policy.mode.as_str() {
        "staged" | "blocking" => {}
        other => {
            return Err(format!(
                "coverage required-crates policy includes invalid mode `{other}`"
            ));
        }
    }

    let mut required_set = BTreeSet::new();
    for crate_name in &required.required.crates {
        if crate_name.trim().is_empty() {
            return Err("coverage required crates list includes an empty crate name".to_string());
        }
        if !required_set.insert(crate_name.clone()) {
            return Err(format!(
                "coverage required crates list includes duplicate crate `{crate_name}`"
            ));
        }
        if !workspace_set.contains(crate_name) {
            return Err(format!(
                "coverage required crates list includes unknown workspace crate `{crate_name}`"
            ));
        }
        if !release_set.contains(crate_name) {
            return Err(format!(
                "coverage required crate `{crate_name}` must be part of release-crates.toml"
            ));
        }
        if !rollout_required.contains(crate_name) {
            return Err(format!(
                "coverage required crate `{crate_name}` must be marked `required` in rollout.toml"
            ));
        }
    }

    if required.policy.mode == "blocking" && required_set.is_empty() {
        return Err("coverage blocking mode requires at least one required crate".to_string());
    }
    if required.policy.mode == "staged" && required_set.is_empty() && !rollout_required.is_empty() {
        return Err(
            "coverage staged mode with an empty required set cannot mark rollout crates as `required`"
                .to_string(),
        );
    }
    if required_set != rollout_required {
        return Err(format!(
            "coverage required crates must match rollout required crates exactly; required={required_set:?} rollout_required={rollout_required:?}"
        ));
    }

    for crate_name in profiles.profiles.crates.keys() {
        if !workspace_set.contains(crate_name) {
            return Err(format!(
                "coverage profile references unknown workspace crate `{crate_name}`"
            ));
        }
        let _ = read_coverage_profile(root, crate_name)?;
    }
    for crate_name in &workspace_crates {
        let _ = read_coverage_profile(root, crate_name)?;
    }

    Ok(())
}

fn validate_contract() -> Result<(), String> {
    let root = workspace_root();
    validate_contract_at_root(&root)?;
    println!("coverage contract valid");
    Ok(())
}

fn list_required_crates() -> Result<(), String> {
    let root = workspace_root();
    let required = read_required_contract(&root)?;
    for crate_name in required.required.crates {
        println!("{crate_name}");
    }
    Ok(())
}

fn list_release_crates() -> Result<(), String> {
    let root = workspace_root();
    let release = read_release_contract(&root)?;
    for crate_name in release.release.crates {
        println!("{crate_name}");
    }
    Ok(())
}

fn list_workspace_crates() -> Result<(), String> {
    let root = workspace_root();
    let workspace_crates = read_workspace_crates(&root)?;
    for crate_name in workspace_crates {
        println!("{crate_name}");
    }
    Ok(())
}

fn parse_string_arg(args: &[String], name: &str) -> Result<String, String> {
    let flag = format!("--{name}");
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == flag {
            let Some(value) = args.get(index + 1) else {
                return Err(format!("missing value for --{name}"));
            };
            return Ok(value.clone());
        }
        index += 1;
    }
    Err(format!("missing --{name}"))
}

fn parse_optional_string_arg(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == flag {
            return args.get(index + 1).cloned();
        }
        index += 1;
    }
    None
}

fn parse_f64_arg(args: &[String], name: &str, default: f64) -> Result<f64, String> {
    if let Some(raw) = parse_optional_string_arg(args, name) {
        return raw
            .parse::<f64>()
            .map_err(|err| format!("invalid --{name} value `{raw}`: {err}"));
    }
    Ok(default)
}

fn parse_optional_u32_arg(args: &[String], name: &str) -> Result<Option<u32>, String> {
    if let Some(raw) = parse_optional_string_arg(args, name) {
        let parsed = raw
            .parse::<u32>()
            .map_err(|err| format!("invalid --{name} value `{raw}`: {err}"))?;
        return Ok(Some(parsed));
    }
    Ok(None)
}

fn run_command(mut command: Command, name: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|err| format!("failed to run {name}: {err}"))?;
    if !status.success() {
        return Err(format!("{name} failed with status {status}"));
    }
    Ok(())
}

fn coverage_cargo_command() -> Command {
    if let Some(binary) = std::env::var("NOSTR_MCP_COVERAGE_CARGO")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
    {
        return Command::new(binary);
    }
    let mut command = Command::new("rustup");
    command.arg("run").arg("nightly").arg("cargo");
    command
}

fn coverage_llvm_cov_command() -> Command {
    let mut command = coverage_cargo_command();
    command.arg("llvm-cov");
    command
}

fn apply_coverage_profile_flags(command: &mut Command, profile: &CoverageProfile) {
    if profile.no_default_features {
        command.arg("--no-default-features");
    }
    if !profile.features.is_empty() {
        command.arg("--features").arg(profile.features.join(","));
    }
}

fn run_crate_with_runner_at_root(
    args: &[String],
    root: &Path,
    runner: &mut dyn FnMut(Command, &str) -> Result<(), String>,
) -> Result<(), String> {
    let crate_name = parse_string_arg(args, "crate")?;
    let profile = read_coverage_profile(root, &crate_name)?;
    let out_dir = if let Some(raw) = parse_optional_string_arg(args, "out") {
        PathBuf::from(raw)
    } else {
        root.join("target")
            .join("coverage")
            .join(crate_name.replace('-', "_"))
    };
    let test_threads = parse_optional_u32_arg(args, "test-threads")?
        .or(profile.test_threads)
        .unwrap_or(1);

    fs::create_dir_all(&out_dir)
        .map_err(|err| format!("failed to create {}: {err}", out_dir.display()))?;

    runner(
        {
            let mut command = coverage_llvm_cov_command();
            command.arg("clean").arg("--workspace").current_dir(root);
            command
        },
        "cargo llvm-cov clean --workspace",
    )?;

    runner(
        {
            let mut command = coverage_llvm_cov_command();
            command.arg("-p").arg(&crate_name);
            apply_coverage_profile_flags(&mut command, &profile);
            command
                .arg("--no-report")
                .arg("--branch")
                .arg("--")
                .arg(format!("--test-threads={test_threads}"))
                .current_dir(root);
            command
        },
        "cargo llvm-cov --no-report",
    )?;

    let summary_path = out_dir.join("coverage-summary.json");
    runner(
        {
            let mut command = coverage_llvm_cov_command();
            command
                .arg("report")
                .arg("-p")
                .arg(&crate_name)
                .arg("--json")
                .arg("--summary-only")
                .arg("--branch")
                .arg("--output-path")
                .arg(&summary_path)
                .current_dir(root);
            command
        },
        "cargo llvm-cov report --json --summary-only",
    )?;

    let lcov_path = out_dir.join("coverage-lcov.info");
    runner(
        {
            let mut command = coverage_llvm_cov_command();
            command
                .arg("report")
                .arg("-p")
                .arg(&crate_name)
                .arg("--lcov")
                .arg("--branch")
                .arg("--output-path")
                .arg(&lcov_path)
                .current_dir(root);
            command
        },
        "cargo llvm-cov report --lcov",
    )?;

    eprintln!("coverage summary: {}", summary_path.display());
    eprintln!("coverage lcov: {}", lcov_path.display());
    Ok(())
}

fn run_crate(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let mut runner = run_command;
    run_crate_with_runner_at_root(args, &root, &mut runner)
}

fn executable_source_label(source: ExecutableSource) -> &'static str {
    match source {
        ExecutableSource::Da => "da",
        ExecutableSource::LfLh => "lf_lh",
    }
}

fn report_gate(args: &[String]) -> Result<(), String> {
    let root = workspace_root();
    let contract_thresholds = parse_thresholds_from_contract(&root)?;
    let scope = parse_string_arg(args, "scope")?;
    let summary_path = PathBuf::from(parse_string_arg(args, "summary")?);
    let lcov_path = PathBuf::from(parse_string_arg(args, "lcov")?);
    let out_path = PathBuf::from(parse_string_arg(args, "out")?);
    let thresholds = CoverageThresholds {
        fail_under_exec_lines: parse_f64_arg(
            args,
            "fail-under-exec-lines",
            contract_thresholds.fail_under_exec_lines,
        )?,
        fail_under_functions: parse_f64_arg(
            args,
            "fail-under-functions",
            contract_thresholds.fail_under_functions,
        )?,
        fail_under_regions: parse_f64_arg(
            args,
            "fail-under-regions",
            contract_thresholds.fail_under_regions,
        )?,
        fail_under_branches: parse_f64_arg(
            args,
            "fail-under-branches",
            contract_thresholds.fail_under_branches,
        )?,
        require_branches: contract_thresholds.require_branches,
    };
    let summary = read_summary(&summary_path)?;
    let lcov = read_lcov(&lcov_path)?;
    let gate = evaluate_gate(&summary, &lcov, thresholds);

    let report = CoverageGateReport {
        scope,
        thresholds: CoverageGateReportThresholds {
            executable_lines: thresholds.fail_under_exec_lines,
            functions: thresholds.fail_under_functions,
            regions: thresholds.fail_under_regions,
            branches: thresholds.fail_under_branches,
            branches_required: thresholds.require_branches,
        },
        measured: CoverageGateReportMeasured {
            executable_lines_percent: lcov.executable_percent,
            executable_lines_source: executable_source_label(lcov.executable_source).to_string(),
            functions_percent: summary.functions_percent,
            branches_percent: lcov.branch_percent,
            branches_available: lcov.branches_available,
            summary_lines_percent: summary.summary_lines_percent,
            summary_regions_percent: summary.summary_regions_percent,
        },
        counts: CoverageGateReportCounts {
            executable_lines: CoverageCount {
                covered: lcov.executable_covered,
                total: lcov.executable_total,
            },
            branches: CoverageCount {
                covered: lcov.branch_covered,
                total: lcov.branch_total,
            },
        },
        result: CoverageGateReportResult {
            pass: gate.pass,
            fail_reasons: gate.fail_reasons.clone(),
        },
    };

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("failed to serialize coverage report: {err}"))?;
    fs::write(&out_path, json)
        .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;

    if !gate.pass {
        return Err(format!(
            "coverage gate failed for {}: {}",
            report.scope,
            gate.fail_reasons.join(", ")
        ));
    }
    println!("coverage gate passed for {}", report.scope);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageSummary, CoverageThresholds, evaluate_gate, read_coverage_profile, read_lcov,
        read_summary, run, validate_contract_at_root,
    };
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write file");
    }

    fn write_workspace(root: &Path) {
        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
resolver = "2"
members = ["crates/*"]
"#,
        );
        for crate_name in ["crate-a", "crate-b", "xtask"] {
            write_file(
                &root.join("crates").join(crate_name).join("Cargo.toml"),
                &format!(
                    r#"[package]
name = "{crate_name}"
version = "0.1.0"
edition = "2024"
"#
                ),
            );
            write_file(
                &root
                    .join("crates")
                    .join(crate_name)
                    .join("src")
                    .join("lib.rs"),
                "",
            );
        }
    }

    fn write_contract(
        root: &Path,
        required_block: &str,
        release_block: &str,
        rollout_block: &str,
        profiles_block: &str,
    ) {
        write_file(
            &root
                .join("contract")
                .join("coverage")
                .join("required-crates.toml"),
            required_block,
        );
        write_file(
            &root
                .join("contract")
                .join("coverage")
                .join("release-crates.toml"),
            release_block,
        );
        write_file(
            &root.join("contract").join("coverage").join("rollout.toml"),
            rollout_block,
        );
        write_file(
            &root.join("contract").join("coverage").join("profiles.toml"),
            profiles_block,
        );
    }

    #[test]
    fn validate_contract_allows_staged_empty_required_set() {
        let dir = tempdir().expect("tempdir");
        write_workspace(dir.path());
        write_contract(
            dir.path(),
            r#"[required]
crates = []

[policy]
mode = "staged"
threshold_profile = "strict_100"
"#,
            r#"[release]
crates = ["crate-a", "crate-b"]
"#,
            r#"[policy]
fail_under_exec_lines = 100.0
fail_under_functions = 100.0
fail_under_regions = 100.0
fail_under_branches = 100.0
require_branches = true

[rollout]
strategy = "crate-by-crate"
entry_crate = "crate-a"

[[rollout.crates]]
name = "crate-a"
status = "planned"
order = 1

[[rollout.crates]]
name = "crate-b"
status = "planned"
order = 2

[[rollout.crates]]
name = "xtask"
status = "planned"
order = 3
"#,
            r#"[profiles.default]
no_default_features = false
features = []
test_threads = 1
"#,
        );

        validate_contract_at_root(dir.path()).expect("contract should validate");
    }

    #[test]
    fn validate_contract_rejects_rollout_drift() {
        let dir = tempdir().expect("tempdir");
        write_workspace(dir.path());
        write_contract(
            dir.path(),
            r#"[required]
crates = []

[policy]
mode = "staged"
threshold_profile = "strict_100"
"#,
            r#"[release]
crates = ["crate-a", "crate-b"]
"#,
            r#"[policy]
fail_under_exec_lines = 100.0
fail_under_functions = 100.0
fail_under_regions = 100.0
fail_under_branches = 100.0
require_branches = true

[rollout]
strategy = "crate-by-crate"
entry_crate = "crate-a"

[[rollout.crates]]
name = "crate-a"
status = "planned"
order = 1

[[rollout.crates]]
name = "xtask"
status = "planned"
order = 2
"#,
            r#"[profiles.default]
no_default_features = false
features = []
test_threads = 1
"#,
        );

        let err = validate_contract_at_root(dir.path()).expect_err("rollout drift should fail");
        assert!(err.contains("missing="));
    }

    #[test]
    fn read_coverage_profile_merges_defaults_and_overrides() {
        let dir = tempdir().expect("tempdir");
        write_workspace(dir.path());
        write_contract(
            dir.path(),
            r#"[required]
crates = []

[policy]
mode = "staged"
threshold_profile = "strict_100"
"#,
            r#"[release]
crates = ["crate-a", "crate-b"]
"#,
            r#"[policy]
fail_under_exec_lines = 100.0
fail_under_functions = 100.0
fail_under_regions = 100.0
fail_under_branches = 100.0
require_branches = true

[rollout]
strategy = "crate-by-crate"
entry_crate = "crate-a"

[[rollout.crates]]
name = "crate-a"
status = "planned"
order = 1

[[rollout.crates]]
name = "crate-b"
status = "planned"
order = 2

[[rollout.crates]]
name = "xtask"
status = "planned"
order = 3
"#,
            r#"[profiles.default]
no_default_features = false
features = ["std"]
test_threads = 1

[profiles.crates."crate-a"]
no_default_features = true
features = ["custom"]
test_threads = 4
"#,
        );

        let profile = read_coverage_profile(dir.path(), "crate-a").expect("profile");
        assert!(profile.no_default_features);
        assert_eq!(profile.features, vec!["custom".to_string()]);
        assert_eq!(profile.test_threads, Some(4));
    }

    #[test]
    fn validate_contract_rejects_required_crate_outside_release_set() {
        let dir = tempdir().expect("tempdir");
        write_workspace(dir.path());
        write_contract(
            dir.path(),
            r#"[required]
crates = ["xtask"]

[policy]
mode = "blocking"
threshold_profile = "strict_100"
"#,
            r#"[release]
crates = ["crate-a", "crate-b"]
"#,
            r#"[policy]
fail_under_exec_lines = 100.0
fail_under_functions = 100.0
fail_under_regions = 100.0
fail_under_branches = 100.0
require_branches = true

[rollout]
strategy = "crate-by-crate"
entry_crate = "crate-a"

[[rollout.crates]]
name = "crate-a"
status = "planned"
order = 1

[[rollout.crates]]
name = "crate-b"
status = "planned"
order = 2

[[rollout.crates]]
name = "xtask"
status = "required"
order = 3
"#,
            r#"[profiles.default]
no_default_features = false
features = []
test_threads = 1
"#,
        );

        let err = validate_contract_at_root(dir.path()).expect_err("release drift should fail");
        assert!(err.contains("release-crates.toml"));
    }

    #[test]
    fn validate_contract_rejects_release_order_drift() {
        let dir = tempdir().expect("tempdir");
        write_workspace(dir.path());
        write_contract(
            dir.path(),
            r#"[required]
crates = []

[policy]
mode = "staged"
threshold_profile = "strict_100"
"#,
            r#"[release]
crates = ["crate-b", "crate-a"]
"#,
            r#"[policy]
fail_under_exec_lines = 100.0
fail_under_functions = 100.0
fail_under_regions = 100.0
fail_under_branches = 100.0
require_branches = true

[rollout]
strategy = "crate-by-crate"
entry_crate = "crate-a"

[[rollout.crates]]
name = "crate-a"
status = "planned"
order = 1

[[rollout.crates]]
name = "crate-b"
status = "planned"
order = 2

[[rollout.crates]]
name = "xtask"
status = "planned"
order = 3
"#,
            r#"[profiles.default]
no_default_features = false
features = []
test_threads = 1
"#,
        );

        let err = validate_contract_at_root(dir.path()).expect_err("release order should fail");
        assert!(err.contains("follow rollout.toml order"));
    }

    #[test]
    fn evaluate_gate_requires_branches() {
        let summary = CoverageSummary {
            functions_percent: 100.0,
            summary_lines_percent: 100.0,
            summary_regions_percent: 100.0,
        };
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("coverage.info");
        write_file(&path, "DA:1,1\nDA:2,1\n");
        let lcov = read_lcov(&path).expect("lcov");
        let result = evaluate_gate(
            &summary,
            &lcov,
            CoverageThresholds {
                fail_under_exec_lines: 100.0,
                fail_under_functions: 100.0,
                fail_under_regions: 100.0,
                fail_under_branches: 100.0,
                require_branches: true,
            },
        );
        assert!(!result.pass);
        assert!(
            result
                .fail_reasons
                .iter()
                .any(|reason| reason == "branches=unavailable")
        );
    }

    #[test]
    fn read_summary_and_lcov_parse_expected_shapes() {
        let dir = tempdir().expect("tempdir");
        let summary_path = dir.path().join("summary.json");
        write_file(
            &summary_path,
            r#"{"data":[{"totals":{"functions":{"percent":100.0},"lines":{"percent":100.0},"regions":{"percent":100.0}}}]}"#,
        );
        let lcov_path = dir.path().join("coverage.info");
        write_file(&lcov_path, "LF:2\nLH:2\nBRF:2\nBRH:2\n");

        let summary = read_summary(&summary_path).expect("summary");
        let lcov = read_lcov(&lcov_path).expect("lcov");

        assert_eq!(summary.functions_percent, 100.0);
        assert_eq!(lcov.executable_total, 2);
        assert_eq!(lcov.branch_total, 2);
        assert_eq!(lcov.branch_percent, Some(100.0));
    }

    #[test]
    fn read_lcov_treats_explicit_zero_branch_records_as_available() {
        let dir = tempdir().expect("tempdir");
        let lcov_path = dir.path().join("coverage.info");
        write_file(&lcov_path, "LF:2\nLH:2\nBRF:0\nBRH:0\n");

        let lcov = read_lcov(&lcov_path).expect("lcov");

        assert!(lcov.branches_available);
        assert_eq!(lcov.branch_total, 0);
        assert_eq!(lcov.branch_covered, 0);
        assert_eq!(lcov.branch_percent, Some(100.0));
    }

    #[test]
    fn evaluate_gate_accepts_explicit_zero_branch_records() {
        let summary = CoverageSummary {
            functions_percent: 100.0,
            summary_lines_percent: 100.0,
            summary_regions_percent: 100.0,
        };
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("coverage.info");
        write_file(&path, "DA:1,1\nDA:2,1\nBRF:0\nBRH:0\n");
        let lcov = read_lcov(&path).expect("lcov");

        let result = evaluate_gate(
            &summary,
            &lcov,
            CoverageThresholds {
                fail_under_exec_lines: 100.0,
                fail_under_functions: 100.0,
                fail_under_regions: 100.0,
                fail_under_branches: 100.0,
                require_branches: true,
            },
        );

        assert!(result.pass);
        assert!(result.fail_reasons.is_empty());
    }

    #[test]
    fn run_rejects_unknown_coverage_subcommand() {
        let err = run(&["unknown".to_string()]).expect_err("unknown coverage subcommand");
        assert!(err.contains("unknown coverage subcommand"));
    }
}
