use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};
use walkdir::WalkDir;

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    IsUserAnAdmin, SHEmptyRecycleBinW, ShellExecuteW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI,
    SHERB_NOSOUND,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

#[cfg(not(windows))]
compile_error!("DCleaner only supports Windows targets.");

#[cfg(windows)]
#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

#[derive(Default)]
struct AppState {
    items: Mutex<Vec<ScannedItem>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum ModuleKind {
    System,
    Browser,
    Application,
    Registry,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RiskLevel {
    Safe,
    Medium,
    High,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FilePreview {
    path: String,
    size_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanerItem {
    id: String,
    whitelist_key: String,
    module: ModuleKind,
    category: String,
    name: String,
    path: String,
    detail: String,
    size_bytes: u64,
    risk: RiskLevel,
    selected_by_default: bool,
    process_names: Vec<String>,
    children: Vec<FilePreview>,
}

#[derive(Clone)]
struct ScannedItem {
    public: CleanerItem,
    action: CleanAction,
}

#[derive(Clone)]
enum CleanAction {
    DeleteDirectoryContents(Vec<PathBuf>),
    DeletePaths(Vec<PathBuf>),
    FlushDns,
    ClearClipboard,
    ClearRecycleBin(Vec<PathBuf>),
    CompactDatabases(Vec<PathBuf>),
    BrowserJson {
        path: PathBuf,
        kind: BrowserJsonKind,
    },
    BrowserSql {
        db_path: PathBuf,
        kind: BrowserDbKind,
    },
    RegistryDelete {
        key_path: String,
        value_name: Option<String>,
        delete_key: bool,
    },
}

#[derive(Clone)]
enum BrowserDbKind {
    ChromiumCookies,
    ChromiumHistory,
    ChromiumDownloads,
    ChromiumAutofill,
    ChromiumPasswords,
    FirefoxCookies,
    FirefoxHistory,
    FirefoxDownloads,
    FirefoxFormHistory,
}

#[derive(Clone)]
enum BrowserJsonKind {
    ChromiumLastDownloadLocation,
    ChromiumSitePreferences,
    FirefoxPasswords,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanOptions {
    include_system: bool,
    include_browsers: bool,
    include_applications: bool,
    include_registry: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanResponse {
    is_admin: bool,
    items: Vec<CleanerItem>,
    total_size_bytes: u64,
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvInfo {
    is_admin: bool,
    backup_dir: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessConflict {
    item_id: String,
    app_name: String,
    process_names: Vec<String>,
    running_processes: Vec<String>,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteCleanRequest {
    selected_ids: Vec<String>,
    conflict_decisions: HashMap<String, ConflictDecision>,
    item_whitelist_keys: Vec<String>,
    cookie_whitelist: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ConflictDecision {
    Kill,
    Skip,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CleanProgress {
    total: usize,
    completed: usize,
    current: String,
    status: String,
    freed_bytes: u64,
    errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanSummary {
    requested_count: usize,
    cleaned_count: usize,
    skipped_count: usize,
    freed_bytes: u64,
    backup_created: Option<String>,
    errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupEntry {
    name: String,
    path: String,
    size_bytes: u64,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreResult {
    success: bool,
    message: String,
}

struct ActionOutcome {
    freed_bytes: u64,
    errors: Vec<String>,
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_environment,
            scan_all,
            detect_conflicts,
            execute_clean,
            list_backups,
            restore_backup,
            relaunch_as_admin
        ])
        .run(tauri::generate_context!())
        .expect("failed to run DCleaner");
}

#[tauri::command]
fn get_environment(app: tauri::AppHandle) -> EnvInfo {
    EnvInfo {
        is_admin: is_admin(),
        backup_dir: backup_dir(&app).display().to_string(),
    }
}

#[tauri::command]
fn scan_all(
    options: ScanOptions,
    state: tauri::State<'_, AppState>,
) -> Result<ScanResponse, String> {
    let mut warnings = Vec::new();
    let mut scanned = Vec::new();
    let mut counter = 0usize;

    if options.include_system {
        scan_system_items(&mut scanned, &mut counter, &mut warnings);
    }
    if options.include_browsers {
        scan_browser_items(&mut scanned, &mut counter, &mut warnings);
    }
    if options.include_applications {
        scan_application_items(&mut scanned, &mut counter, &mut warnings);
    }
    if options.include_registry {
        scan_registry_items(&mut scanned, &mut counter, &mut warnings);
    }

    let total_size_bytes = scanned
        .iter()
        .map(|item| item.public.size_bytes)
        .sum::<u64>();
    let public_items = scanned
        .iter()
        .map(|item| item.public.clone())
        .collect::<Vec<_>>();

    let mut guard = state
        .items
        .lock()
        .map_err(|_| "扫描状态锁定失败".to_string())?;
    *guard = scanned;

    Ok(ScanResponse {
        is_admin: is_admin(),
        items: public_items,
        total_size_bytes,
        warnings,
    })
}

#[tauri::command]
fn detect_conflicts(
    item_ids: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<ProcessConflict>, String> {
    let items = selected_scanned_items(&state, &item_ids)?;
    Ok(conflicts_for_items(&items))
}

#[tauri::command]
fn execute_clean(
    request: ExecuteCleanRequest,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<CleanSummary, String> {
    let mut items = selected_scanned_items(&state, &request.selected_ids)?;
    if items.is_empty() {
        return Err("没有可执行的清理项目".to_string());
    }
    let original_count = items.len();
    let item_whitelist_keys = request.item_whitelist_keys.iter().collect::<HashSet<_>>();
    if !item_whitelist_keys.is_empty() {
        items.retain(|item| !item_whitelist_keys.contains(&item.public.whitelist_key));
    }
    if items.is_empty() {
        return Ok(CleanSummary {
            requested_count: original_count,
            cleaned_count: 0,
            skipped_count: original_count,
            freed_bytes: 0,
            backup_created: None,
            errors: Vec::new(),
        });
    }

    for conflict in conflicts_for_items(&items) {
        match request.conflict_decisions.get(&conflict.item_id) {
            Some(ConflictDecision::Kill) => {
                for process in &conflict.process_names {
                    kill_process(process);
                }
            }
            Some(ConflictDecision::Skip) => {}
            None => return Err("PROCESS_CONFLICT".to_string()),
        }
    }

    let backup_created = backup_registry_before_delete(&app, &items)?;
    let total = items.len();
    let mut cleaned_count = 0usize;
    let mut skipped_count = 0usize;
    let mut freed_bytes = 0u64;
    let mut errors = Vec::new();

    for (index, item) in items.iter().enumerate() {
        if matches!(
            request.conflict_decisions.get(&item.public.id),
            Some(ConflictDecision::Skip)
        ) {
            skipped_count += 1;
            continue;
        }

        emit_progress(
            &app,
            CleanProgress {
                total,
                completed: index,
                current: item.public.name.clone(),
                status: "running".to_string(),
                freed_bytes,
                errors: errors.clone(),
            },
        );

        match execute_action(&item.action, &request.cookie_whitelist) {
            Ok(outcome) => {
                cleaned_count += 1;
                freed_bytes = freed_bytes.saturating_add(outcome.freed_bytes);
                errors.extend(outcome.errors);
            }
            Err(error) => {
                errors.push(format!("{}: {}", item.public.name, error));
            }
        }
    }

    emit_progress(
        &app,
        CleanProgress {
            total,
            completed: total,
            current: "完成".to_string(),
            status: "done".to_string(),
            freed_bytes,
            errors: errors.clone(),
        },
    );

    Ok(CleanSummary {
        requested_count: total,
        cleaned_count,
        skipped_count,
        freed_bytes,
        backup_created: backup_created.map(|path| path.display().to_string()),
        errors,
    })
}

#[tauri::command]
fn list_backups(app: tauri::AppHandle) -> Result<Vec<BackupEntry>, String> {
    let dir = backup_dir(&app);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("reg") {
            continue;
        }
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        let created_at = metadata
            .modified()
            .ok()
            .and_then(system_time_to_seconds)
            .map(|seconds| seconds.to_string())
            .unwrap_or_else(|| "-".to_string());
        entries.push(BackupEntry {
            name: path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or("registry_backup.reg")
                .to_string(),
            path: path.display().to_string(),
            size_bytes: metadata.len(),
            created_at,
        });
    }
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(entries)
}

#[tauri::command]
fn restore_backup(path: String) -> Result<RestoreResult, String> {
    let path = PathBuf::from(path);
    if path.extension().and_then(OsStr::to_str) != Some("reg") || !path.exists() {
        return Err("备份文件不存在或格式不正确".to_string());
    }

    shell_execute("open", &path.display().to_string(), None).map(|_| RestoreResult {
        success: true,
        message: "已交给 Windows 注册表编辑器导入，请按系统提示确认。".to_string(),
    })
}

#[tauri::command]
fn relaunch_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    if is_admin() {
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    shell_execute("runas", &exe.display().to_string(), None)?;
    app.exit(0);
    Ok(())
}

fn push_item(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    mut public: CleanerItem,
    action: CleanAction,
) {
    *counter += 1;
    public.id = format!("item-{}", counter);
    items.push(ScannedItem { public, action });
}

fn make_item(
    module: ModuleKind,
    category: &str,
    name: &str,
    path: String,
    detail: &str,
    size_bytes: u64,
    risk: RiskLevel,
    selected_by_default: bool,
    process_names: Vec<String>,
    children: Vec<FilePreview>,
) -> CleanerItem {
    let whitelist_key = item_whitelist_key(&module, category, name, &path);
    CleanerItem {
        id: String::new(),
        whitelist_key,
        module,
        category: category.to_string(),
        name: name.to_string(),
        path,
        detail: detail.to_string(),
        size_bytes,
        risk,
        selected_by_default,
        process_names,
        children,
    }
}

fn item_whitelist_key(module: &ModuleKind, category: &str, name: &str, path: &str) -> String {
    format!(
        "v1|{}|{}|{}|{}",
        module_kind_key(module),
        normalize_whitelist_part(category),
        normalize_whitelist_part(name),
        normalize_whitelist_part(path)
    )
}

fn module_kind_key(module: &ModuleKind) -> &'static str {
    match module {
        ModuleKind::System => "system",
        ModuleKind::Browser => "browser",
        ModuleKind::Application => "application",
        ModuleKind::Registry => "registry",
    }
}

fn normalize_whitelist_part(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn selected_scanned_items(
    state: &tauri::State<'_, AppState>,
    item_ids: &[String],
) -> Result<Vec<ScannedItem>, String> {
    let ids = item_ids.iter().collect::<HashSet<_>>();
    let guard = state
        .items
        .lock()
        .map_err(|_| "扫描状态锁定失败".to_string())?;
    Ok(guard
        .iter()
        .filter(|item| ids.contains(&item.public.id))
        .cloned()
        .collect())
}

fn conflicts_for_items(items: &[ScannedItem]) -> Vec<ProcessConflict> {
    items
        .iter()
        .filter_map(|item| {
            if item.public.process_names.is_empty() {
                return None;
            }
            let running = running_processes(&item.public.process_names);
            if running.is_empty() {
                return None;
            }
            Some(ProcessConflict {
                item_id: item.public.id.clone(),
                app_name: item.public.name.clone(),
                process_names: item.public.process_names.clone(),
                running_processes: running.clone(),
                message: format!(
                    "检测到 {} 正在运行，清理需要关闭该程序。是否立即结束该进程？",
                    running.join(", ")
                ),
            })
        })
        .collect()
}

#[cfg(windows)]
fn scan_system_items(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    _warnings: &mut Vec<String>,
) {
    let windows = windows_dir();
    let temp_dirs = unique_existing_dirs(vec![
        env_path("TEMP"),
        env_path("TMP"),
        Some(windows.join("Temp")),
    ]);
    if !temp_dirs.is_empty() {
        let (size, children) = dirs_size_preview(&temp_dirs, 180);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "系统临时文件",
                "系统临时文件",
                join_paths(&temp_dirs),
                "清理用户与 Windows 临时目录中可删除的缓存文件。",
                size,
                RiskLevel::Safe,
                true,
                Vec::new(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(temp_dirs),
        );
    }

    let recycle_roots = recycle_bin_roots();
    if !recycle_roots.is_empty() {
        let (size, children) = dirs_size_preview(&recycle_roots, 260);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "回收站",
                "回收站内容",
                join_paths(&recycle_roots),
                "允许展开查看回收站中的文件预览。",
                size,
                RiskLevel::Safe,
                true,
                Vec::new(),
                children,
            ),
            CleanAction::ClearRecycleBin(recycle_roots),
        );
    }

    push_item(
        items,
        counter,
        make_item(
            ModuleKind::System,
            "剪贴板",
            "剪贴板内容",
            "Windows 剪贴板".to_string(),
            "清空当前剪贴板内容。",
            0,
            RiskLevel::Safe,
            false,
            Vec::new(),
            Vec::new(),
        ),
        CleanAction::ClearClipboard,
    );

    scan_explorer_history_items(items, counter);
    scan_explorer_cache_items(items, counter);
    scan_system_extra_items(items, counter);
    scan_advanced_windows_items(items, counter);

    let dump_paths = collect_existing_files(vec![
        windows.join("MEMORY.DMP"),
        windows.join("Minidump"),
        env_path("LOCALAPPDATA")
            .unwrap_or_default()
            .join("CrashDumps"),
    ]);
    if !dump_paths.files.is_empty() {
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "内存转储",
                "内存转储文件",
                join_paths(&dump_paths.files),
                "删除崩溃诊断生成的转储文件。",
                dump_paths.size,
                RiskLevel::Safe,
                true,
                Vec::new(),
                dump_paths.preview,
            ),
            CleanAction::DeletePaths(dump_paths.files),
        );
    }

    let log_files = collect_files_matching(vec![windows.join("Logs")], |path| {
        matches!(
            path.extension()
                .and_then(OsStr::to_str)
                .map(|value| value.to_ascii_lowercase()),
            Some(ext) if matches!(ext.as_str(), "log" | "old" | "etl" | "tmp")
        )
    });
    if !log_files.files.is_empty() {
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "Windows 日志",
                "Windows 日志文件",
                windows.join("Logs").display().to_string(),
                "删除 Windows 日志目录中的普通日志文件，不直接清空事件日志。",
                log_files.size,
                RiskLevel::Medium,
                true,
                Vec::new(),
                log_files.preview,
            ),
            CleanAction::DeletePaths(log_files.files),
        );
    }

    push_item(
        items,
        counter,
        make_item(
            ModuleKind::System,
            "DNS 缓存",
            "DNS 解析缓存",
            "Win32 DNS Resolver Cache API".to_string(),
            "刷新本机 DNS 解析缓存。",
            0,
            RiskLevel::Safe,
            true,
            Vec::new(),
            Vec::new(),
        ),
        CleanAction::FlushDns,
    );

    let prefetch = windows.join("Prefetch");
    if prefetch.exists() {
        let (size, children) = dirs_size_preview(&[prefetch.clone()], 160);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "系统预读",
                "系统预读文件",
                prefetch.display().to_string(),
                "删除预读缓存，系统会按需重建。",
                size,
                RiskLevel::Medium,
                false,
                Vec::new(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(vec![prefetch]),
        );
    }
}

#[cfg(windows)]
fn scan_explorer_history_items(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let registry_targets = [
        (
            "Explorer 地址栏输入记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            "清理文件资源管理器地址栏中手动输入过的路径。",
        ),
        (
            "Explorer 搜索框记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
            "清理文件资源管理器右上角搜索框的历史记录。",
        ),
        (
            "运行对话框输入记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            "清理 Win+R 运行框的输入历史。",
        ),
        (
            "最近打开文档记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "清理 Explorer 维护的最近文档 MRU 记录。",
        ),
        (
            "打开/保存对话框历史",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
            "清理系统打开/保存文件对话框中的历史位置记录。",
        ),
        (
            "最近访问文件夹记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
            "清理系统打开/保存文件对话框最近访问的文件夹记录。",
        ),
    ];

    for (name, key_path, detail) in registry_targets {
        if registry_key_has_content(key_path) {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::System,
                    "Explorer 历史记录",
                    name,
                    key_path.to_string(),
                    detail,
                    0,
                    RiskLevel::Safe,
                    false,
                    Vec::new(),
                    Vec::new(),
                ),
                CleanAction::RegistryDelete {
                    key_path: key_path.to_string(),
                    value_name: None,
                    delete_key: true,
                },
            );
        }
    }

    if let Some(appdata) = env_path("APPDATA") {
        let recent_dirs = existing_dirs(vec![
            appdata.join("Microsoft").join("Windows").join("Recent"),
            appdata
                .join("Microsoft")
                .join("Windows")
                .join("Recent")
                .join("AutomaticDestinations"),
            appdata
                .join("Microsoft")
                .join("Windows")
                .join("Recent")
                .join("CustomDestinations"),
        ]);
        if !recent_dirs.is_empty() {
            let (size, children) = dirs_size_preview(&recent_dirs, 180);
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::System,
                    "Explorer 历史记录",
                    "快速访问与跳转列表历史",
                    join_paths(&recent_dirs),
                    "清理快速访问、最近项目与任务栏跳转列表缓存。",
                    size,
                    RiskLevel::Medium,
                    false,
                    Vec::new(),
                    children,
                ),
                CleanAction::DeleteDirectoryContents(recent_dirs),
            );
        }
    }
}

#[cfg(windows)]
fn scan_explorer_cache_items(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let local = env_path("LOCALAPPDATA").unwrap_or_default();
    let explorer_dir = local.join("Microsoft").join("Windows").join("Explorer");
    let thumbnails = collect_files_matching(vec![explorer_dir], |path| {
        path.file_name()
            .and_then(OsStr::to_str)
            .map(|name| {
                let lower = name.to_ascii_lowercase();
                lower.starts_with("thumbcache_") || lower.starts_with("iconcache_")
            })
            .unwrap_or(false)
    });
    if !thumbnails.files.is_empty() {
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "Windows Explorer",
                "缩略图与图标缓存",
                join_paths(&thumbnails.files),
                "清理 Explorer 生成的图片、视频缩略图和图标缓存数据库。",
                thumbnails.size,
                RiskLevel::Safe,
                false,
                Vec::new(),
                thumbnails.preview,
            ),
            CleanAction::DeletePaths(thumbnails.files),
        );
    }
}

#[cfg(windows)]
fn scan_system_extra_items(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let windows = windows_dir();
    let program_data = env_path("PROGRAMDATA").unwrap_or_default();
    let local = env_path("LOCALAPPDATA").unwrap_or_default();

    let wer_dirs = existing_dirs(vec![
        program_data
            .join("Microsoft")
            .join("Windows")
            .join("WER")
            .join("ReportArchive"),
        program_data
            .join("Microsoft")
            .join("Windows")
            .join("WER")
            .join("ReportQueue"),
        program_data
            .join("Microsoft")
            .join("Windows")
            .join("WER")
            .join("Temp"),
        local
            .join("Microsoft")
            .join("Windows")
            .join("WER")
            .join("ReportArchive"),
        local
            .join("Microsoft")
            .join("Windows")
            .join("WER")
            .join("ReportQueue"),
    ]);
    if !wer_dirs.is_empty() {
        let (size, children) = dirs_size_preview(&wer_dirs, 160);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "系统",
                "Windows 错误报告",
                join_paths(&wer_dirs),
                "清理 Windows Error Reporting 收集的崩溃报告与上传队列。",
                size,
                RiskLevel::Safe,
                false,
                Vec::new(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(wer_dirs),
        );
    }

    let font_cache = collect_files_matching(
        vec![
            windows.join("System32").join("FNTCACHE.DAT"),
            windows
                .join("ServiceProfiles")
                .join("LocalService")
                .join("AppData")
                .join("Local")
                .join("FontCache"),
            local.join("FontCache"),
        ],
        |path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .map(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower == "fntcache.dat"
                        || (lower.starts_with("fontcache") && lower.ends_with(".dat"))
                })
                .unwrap_or(false)
        },
    );
    if !font_cache.files.is_empty() {
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "系统",
                "字体缓存",
                join_paths(&font_cache.files),
                "清理字体预览和字体枚举缓存，系统会自动重建。",
                font_cache.size,
                RiskLevel::Medium,
                false,
                Vec::new(),
                font_cache.preview,
            ),
            CleanAction::DeletePaths(font_cache.files),
        );
    }

    let chkdsk_paths = chkdsk_fragment_paths();
    if !chkdsk_paths.is_empty() {
        let size = chkdsk_paths.iter().map(|path| path_size(path)).sum::<u64>();
        let preview = chkdsk_paths
            .iter()
            .take(120)
            .map(|path| FilePreview {
                path: path.display().to_string(),
                size_bytes: path_size(path),
            })
            .collect::<Vec<_>>();
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "系统",
                "Chkdsk 文件碎片",
                join_paths(&chkdsk_paths),
                "清理磁盘检查留下的 FOUND.* 和 .chk 文件碎片。",
                size,
                RiskLevel::Medium,
                false,
                Vec::new(),
                preview,
            ),
            CleanAction::DeletePaths(chkdsk_paths),
        );
    }

    let iis_dirs = existing_dirs(vec![PathBuf::from(
        std::env::var("SystemDrive")
            .map(|drive| format!("{}\\inetpub\\logs\\LogFiles", drive))
            .unwrap_or_else(|_| r"C:\inetpub\logs\LogFiles".to_string()),
    )]);
    if !iis_dirs.is_empty() {
        let (size, children) = dirs_size_preview(&iis_dirs, 160);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::System,
                "高级",
                "IIS 日志文件",
                join_paths(&iis_dirs),
                "清理本机 IIS 服务产生的网站访问日志。",
                size,
                RiskLevel::Medium,
                false,
                Vec::new(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(iis_dirs),
        );
    }
}

#[cfg(windows)]
fn scan_advanced_windows_items(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let key_targets = [
        (
            "菜单顺序缓存",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MenuOrder",
            "清理开始菜单项目排序缓存。",
            RiskLevel::Medium,
        ),
        (
            "窗口大小和位置缓存",
            "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
            "清理 Explorer 记录的文件夹窗口大小、视图和位置。",
            RiskLevel::Medium,
        ),
        (
            "窗口大小和位置缓存",
            "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            "清理 Explorer 记录的文件夹窗口大小、视图和位置。",
            RiskLevel::Medium,
        ),
        (
            "用户助手历史记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
            "清理系统记录的程序运行频率历史。",
            RiskLevel::High,
        ),
        (
            "网络驱动器映射记录",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU",
            "清理映射网络驱动器对话框中的历史记录。",
            RiskLevel::Safe,
        ),
    ];

    for (name, key_path, detail, risk) in key_targets {
        if registry_key_has_content(key_path) {
            push_registry_cleanup_item(
                items,
                counter,
                ModuleKind::System,
                "高级",
                name,
                key_path,
                None,
                true,
                detail,
                risk,
                false,
            );
        }
    }

    let tray_key =
        "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify";
    for value in ["IconStreams", "PastIconsStream"] {
        if registry_value_exists(tray_key, value) {
            push_registry_cleanup_item(
                items,
                counter,
                ModuleKind::System,
                "高级",
                "托盘通知缓存",
                tray_key,
                Some(value.to_string()),
                false,
                "清理任务栏通知区域图标显示历史。",
                RiskLevel::Medium,
                false,
            );
        }
    }
}

#[cfg(windows)]
fn scan_browser_items(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    _warnings: &mut Vec<String>,
) {
    let appdata = env_path("APPDATA").unwrap_or_default();
    if let Some(local) = env_path("LOCALAPPDATA") {
        add_chromium_browser(
            items,
            counter,
            "Chrome",
            local.join("Google").join("Chrome").join("User Data"),
            vec!["chrome.exe"],
        );
        add_chromium_browser(
            items,
            counter,
            "Edge",
            local.join("Microsoft").join("Edge").join("User Data"),
            vec!["msedge.exe"],
        );
        add_chromium_browser(
            items,
            counter,
            "Chromium",
            local.join("Chromium").join("User Data"),
            vec!["chromium.exe", "chrome.exe"],
        );
        add_chromium_browser(
            items,
            counter,
            "Brave",
            local
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data"),
            vec!["brave.exe"],
        );
        add_chromium_browser(
            items,
            counter,
            "Vivaldi",
            local.join("Vivaldi").join("User Data"),
            vec!["vivaldi.exe"],
        );
    }

    add_chromium_browser(
        items,
        counter,
        "Opera",
        appdata.join("Opera Software").join("Opera Stable"),
        vec!["opera.exe"],
    );
    add_chromium_browser(
        items,
        counter,
        "Opera GX",
        appdata.join("Opera Software").join("Opera GX Stable"),
        vec!["opera.exe"],
    );
    add_firefox_browser(items, counter);
}

#[cfg(windows)]
fn scan_application_items(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    _warnings: &mut Vec<String>,
) {
    let appdata = env_path("APPDATA").unwrap_or_default();
    let local = env_path("LOCALAPPDATA").unwrap_or_default();

    add_application_dirs(
        items,
        counter,
        "开发工具",
        "Visual Studio Code 缓存",
        vec![
            appdata.join("Code").join("Cache"),
            appdata.join("Code").join("CachedData"),
            appdata.join("Code").join("Code Cache"),
            appdata.join("Code").join("GPUCache"),
            appdata.join("Code").join("logs"),
        ],
        vec!["Code.exe"],
        RiskLevel::Safe,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "互联网与通信",
        "Slack 缓存",
        vec![
            appdata.join("Slack").join("Cache"),
            appdata.join("Slack").join("Code Cache"),
            appdata.join("Slack").join("GPUCache"),
            appdata.join("Slack").join("logs"),
        ],
        vec!["slack.exe"],
        RiskLevel::Safe,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "互联网与通信",
        "Discord 缓存",
        vec![
            appdata.join("discord").join("Cache"),
            appdata.join("discord").join("Code Cache"),
            appdata.join("discord").join("GPUCache"),
        ],
        vec!["Discord.exe"],
        RiskLevel::Safe,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "互联网与通信",
        "Microsoft Teams 缓存",
        vec![
            appdata.join("Microsoft").join("Teams").join("Cache"),
            appdata.join("Microsoft").join("Teams").join("Code Cache"),
            appdata.join("Microsoft").join("Teams").join("GPUCache"),
        ],
        vec!["Teams.exe", "ms-teams.exe"],
        RiskLevel::Safe,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "多媒体播放器",
        "VLC 媒体缓存",
        vec![appdata.join("vlc").join("art")],
        vec!["vlc.exe"],
        RiskLevel::Medium,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "开发工具",
        "npm 缓存",
        vec![local.join("npm-cache")],
        Vec::new(),
        RiskLevel::Safe,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "多媒体播放器",
        "Spotify 缓存",
        vec![local.join("Spotify").join("Data")],
        vec!["Spotify.exe"],
        RiskLevel::Safe,
        false,
    );

    add_application_dirs(
        items,
        counter,
        "开发工具",
        "Sublime Text 缓存",
        vec![
            local.join("Sublime Text").join("Cache"),
            appdata.join("Sublime Text").join("Cache"),
        ],
        vec!["sublime_text.exe"],
        RiskLevel::Safe,
        false,
    );

    add_application_dirs(
        items,
        counter,
        "办公软件",
        "Adobe Acrobat 缓存",
        vec![
            appdata
                .join("Adobe")
                .join("Acrobat")
                .join("DC")
                .join("Cache"),
            local.join("Adobe").join("Acrobat").join("DC").join("Cache"),
        ],
        vec!["Acrobat.exe", "AcroRd32.exe"],
        RiskLevel::Safe,
        false,
    );

    add_application_dirs(
        items,
        counter,
        "Windows 附件",
        "Windows Defender 扫描日志",
        vec![env_path("PROGRAMDATA")
            .unwrap_or_default()
            .join("Microsoft")
            .join("Windows Defender")
            .join("Scans")
            .join("History")],
        Vec::new(),
        RiskLevel::Medium,
        false,
    );

    let package_dirs = package_cache_dirs(&local);
    if !package_dirs.is_empty() {
        let (size, children) = dirs_size_preview(&package_dirs, 160);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::Application,
                "Windows 商店应用",
                "Windows 商店应用缓存",
                join_paths(&package_dirs),
                "清理 UWP/商店应用的 LocalCache 与 TempState 缓存目录。",
                size,
                RiskLevel::Medium,
                false,
                Vec::new(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(package_dirs),
        );
    }

    scan_application_registry_items(items, counter);

    if let Some(temp) = env_path("TEMP") {
        let archives = collect_files_matching(vec![temp], |path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .map(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.starts_with("rar$")
                        || lower.starts_with("7z")
                        || lower.starts_with("winrar")
                })
                .unwrap_or(false)
        });
        if !archives.files.is_empty() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Application,
                    "解压缩软件",
                    "解压缩临时文件",
                    join_paths(&archives.files),
                    "清理 WinRAR、7-Zip 等工具遗留在临时目录中的文件。",
                    archives.size,
                    RiskLevel::Safe,
                    true,
                    Vec::new(),
                    archives.preview,
                ),
                CleanAction::DeletePaths(archives.files),
            );
        }
    }
}

#[cfg(windows)]
fn package_cache_dirs(local: &Path) -> Vec<PathBuf> {
    let packages = local.join("Packages");
    if !packages.is_dir() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for package in read_child_dirs(&packages) {
        result.extend(existing_dirs(vec![
            package.join("LocalCache"),
            package.join("TempState"),
            package.join("AC").join("Temp"),
        ]));
    }
    result
}

#[cfg(windows)]
fn scan_application_registry_items(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let office_versions = ["16.0", "15.0", "14.0", "12.0"];
    let office_apps = ["Word", "Excel", "PowerPoint", "Access", "Publisher"];
    for version in office_versions {
        for app_name in office_apps {
            for mru in ["File MRU", "Place MRU"] {
                let key_path = format!(
                    "HKCU\\Software\\Microsoft\\Office\\{}\\{}\\{}",
                    version, app_name, mru
                );
                if registry_key_has_content(&key_path) {
                    push_registry_cleanup_item(
                        items,
                        counter,
                        ModuleKind::Application,
                        "办公软件",
                        "Microsoft Office 最近打开列表",
                        &key_path,
                        None,
                        true,
                        "清理 Word/Excel/PowerPoint 等 Office 应用的最近文件与位置记录。",
                        RiskLevel::Medium,
                        false,
                    );
                }
            }
        }
    }

    let utility_targets = [
        (
            "7-Zip 历史记录",
            "HKCU\\Software\\7-Zip\\Compression",
            "清理 7-Zip 最近压缩/解压路径记录。",
        ),
        (
            "WinRAR 历史记录",
            "HKCU\\Software\\WinRAR\\DialogEditHistory",
            "清理 WinRAR 对话框中的历史路径和输入记录。",
        ),
        (
            "Windows Media Player 最近记录",
            "HKCU\\Software\\Microsoft\\MediaPlayer\\Player\\RecentFileList",
            "清理 Windows Media Player 最近播放列表。",
        ),
        (
            "TeamViewer 连接记录",
            "HKCU\\Software\\TeamViewer",
            "清理 TeamViewer 保存在当前用户下的连接历史缓存。",
        ),
    ];
    for (name, key_path, detail) in utility_targets {
        if registry_key_has_content(key_path) {
            push_registry_cleanup_item(
                items,
                counter,
                ModuleKind::Application,
                "常见软件 MRU",
                name,
                key_path,
                None,
                true,
                detail,
                RiskLevel::Medium,
                false,
            );
        }
    }
}

#[cfg(windows)]
fn add_chromium_browser(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    browser_name: &str,
    base: PathBuf,
    process_names: Vec<&str>,
) {
    if !base.exists() {
        return;
    }
    let processes = process_names
        .into_iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>();
    let profiles = chromium_profiles(&base);

    let mut cache_dirs = Vec::new();
    for profile in &profiles {
        cache_dirs.extend(existing_dirs(vec![
            profile.join("Cache"),
            profile.join("Code Cache"),
            profile.join("GPUCache"),
            profile.join("Service Worker").join("CacheStorage"),
        ]));
    }
    cache_dirs.extend(existing_dirs(vec![base.join("ShaderCache")]));
    if !cache_dirs.is_empty() {
        let (size, children) = dirs_size_preview(&cache_dirs, 160);
        push_item(
            items,
            counter,
            make_item(
                ModuleKind::Browser,
                browser_name,
                &format!("{} 缓存", browser_name),
                join_paths(&cache_dirs),
                "清理浏览器渲染、脚本与网络缓存。",
                size,
                RiskLevel::Safe,
                true,
                processes.clone(),
                children,
            ),
            CleanAction::DeleteDirectoryContents(cache_dirs),
        );
    }

    for profile in profiles {
        let profile_name = profile
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("Profile");
        let history = profile.join("History");
        if history.exists() {
            let size = file_size(&history);
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 历史记录 ({})", browser_name, profile_name),
                    history.display().to_string(),
                    "清理网址访问记录。",
                    size,
                    RiskLevel::Medium,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: history.clone(),
                    kind: BrowserDbKind::ChromiumHistory,
                },
            );
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 下载历史 ({})", browser_name, profile_name),
                    history.display().to_string(),
                    "清理下载记录，不删除已下载文件。",
                    size,
                    RiskLevel::Safe,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: history,
                    kind: BrowserDbKind::ChromiumDownloads,
                },
            );
        }

        let preferences = profile.join("Preferences");
        if preferences.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 最后下载位置 ({})", browser_name, profile_name),
                    preferences.display().to_string(),
                    "清理浏览器记录的上次下载保存路径。",
                    file_size(&preferences),
                    RiskLevel::Safe,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserJson {
                    path: preferences.clone(),
                    kind: BrowserJsonKind::ChromiumLastDownloadLocation,
                },
            );
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 网站偏好设置 ({})", browser_name, profile_name),
                    preferences.display().to_string(),
                    "清理针对特定网站保存的权限、缩放和内容例外设置。",
                    file_size(&preferences),
                    RiskLevel::Medium,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserJson {
                    path: preferences,
                    kind: BrowserJsonKind::ChromiumSitePreferences,
                },
            );
        }

        let cookies = [
            profile.join("Network").join("Cookies"),
            profile.join("Cookies"),
        ]
        .into_iter()
        .find(|path| path.exists());
        if let Some(cookies) = cookies.clone() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} Cookie ({})", browser_name, profile_name),
                    cookies.display().to_string(),
                    "支持按域名白名单保留 Cookie。",
                    file_size(&cookies),
                    RiskLevel::Medium,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: cookies,
                    kind: BrowserDbKind::ChromiumCookies,
                },
            );
        }

        let web_data = profile.join("Web Data");
        if web_data.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 保存的表单信息 ({})", browser_name, profile_name),
                    web_data.display().to_string(),
                    "清理自动填充保存的表单、地址和搜索输入记录。",
                    file_size(&web_data),
                    RiskLevel::Medium,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: web_data.clone(),
                    kind: BrowserDbKind::ChromiumAutofill,
                },
            );
        }

        let login_data = profile.join("Login Data");
        if login_data.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 保存的密码 ({})", browser_name, profile_name),
                    login_data.display().to_string(),
                    "清理浏览器保存的登录账号密码记录。",
                    file_size(&login_data),
                    RiskLevel::High,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: login_data.clone(),
                    kind: BrowserDbKind::ChromiumPasswords,
                },
            );
        }

        let session_dirs = existing_dirs(vec![
            profile.join("Sessions"),
            profile.join("Session Storage"),
            profile.join("Local Storage").join("leveldb"),
        ]);
        if !session_dirs.is_empty() {
            let (size, children) = dirs_size_preview(&session_dirs, 100);
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} Session 数据 ({})", browser_name, profile_name),
                    join_paths(&session_dirs),
                    "清理会话恢复与本地会话数据。",
                    size,
                    RiskLevel::High,
                    false,
                    processes.clone(),
                    children,
                ),
                CleanAction::DeleteDirectoryContents(session_dirs),
            );
        }

        let mut compact_dbs = vec![
            profile.join("History"),
            profile.join("Web Data"),
            profile.join("Login Data"),
            profile.join("Favicons"),
            profile.join("Top Sites"),
            profile.join("Network").join("Reporting and NEL"),
        ];
        if let Some(cookie_db) = cookies {
            compact_dbs.push(cookie_db);
        }
        compact_dbs.retain(|path| path.exists());
        if !compact_dbs.is_empty() {
            let size = compact_dbs.iter().map(|path| file_size(path)).sum::<u64>();
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    browser_name,
                    &format!("{} 压缩数据库 ({})", browser_name, profile_name),
                    join_paths(&compact_dbs),
                    "对浏览器 SQLite 数据库执行 VACUUM，减少碎片，不删除用户数据。",
                    size,
                    RiskLevel::Safe,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::CompactDatabases(compact_dbs),
            );
        }
    }
}

#[cfg(windows)]
fn add_firefox_browser(items: &mut Vec<ScannedItem>, counter: &mut usize) {
    let appdata = match env_path("APPDATA") {
        Some(value) => value,
        None => return,
    };
    let local = env_path("LOCALAPPDATA").unwrap_or_default();
    let roaming_profiles = appdata.join("Mozilla").join("Firefox").join("Profiles");
    if !roaming_profiles.exists() {
        return;
    }
    let processes = vec!["firefox.exe".to_string()];
    let profiles = read_child_dirs(&roaming_profiles);

    for profile in profiles {
        let profile_name = profile
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("Profile")
            .to_string();
        let local_profile = local
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles")
            .join(&profile_name);
        let cache_dirs = existing_dirs(vec![
            local_profile.join("cache2"),
            local_profile.join("startupCache"),
            local_profile.join("thumbnails"),
        ]);
        if !cache_dirs.is_empty() {
            let (size, children) = dirs_size_preview(&cache_dirs, 160);
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 缓存 ({})", profile_name),
                    join_paths(&cache_dirs),
                    "清理 Firefox 网络与启动缓存。",
                    size,
                    RiskLevel::Safe,
                    true,
                    processes.clone(),
                    children,
                ),
                CleanAction::DeleteDirectoryContents(cache_dirs),
            );
        }

        let places = profile.join("places.sqlite");
        if places.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 历史记录 ({})", profile_name),
                    places.display().to_string(),
                    "清理访问历史并保留书签。",
                    file_size(&places),
                    RiskLevel::Medium,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: places.clone(),
                    kind: BrowserDbKind::FirefoxHistory,
                },
            );
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 下载历史 ({})", profile_name),
                    places.display().to_string(),
                    "清理下载记录，不删除已下载文件。",
                    file_size(&places),
                    RiskLevel::Safe,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: places,
                    kind: BrowserDbKind::FirefoxDownloads,
                },
            );
        }

        let cookies = profile.join("cookies.sqlite");
        if cookies.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox Cookie ({})", profile_name),
                    cookies.display().to_string(),
                    "支持按域名白名单保留 Cookie。",
                    file_size(&cookies),
                    RiskLevel::Medium,
                    true,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: cookies,
                    kind: BrowserDbKind::FirefoxCookies,
                },
            );
        }

        let formhistory = profile.join("formhistory.sqlite");
        if formhistory.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 保存的表单信息 ({})", profile_name),
                    formhistory.display().to_string(),
                    "清理 Firefox 自动填充保存的表单和搜索输入记录。",
                    file_size(&formhistory),
                    RiskLevel::Medium,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserSql {
                    db_path: formhistory.clone(),
                    kind: BrowserDbKind::FirefoxFormHistory,
                },
            );
        }

        let logins = profile.join("logins.json");
        if logins.exists() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 保存的密码 ({})", profile_name),
                    logins.display().to_string(),
                    "清理 Firefox 保存的登录账号密码记录。",
                    file_size(&logins),
                    RiskLevel::High,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::BrowserJson {
                    path: logins,
                    kind: BrowserJsonKind::FirefoxPasswords,
                },
            );
        }

        let site_prefs = collect_existing_files(vec![
            profile.join("permissions.sqlite"),
            profile.join("content-prefs.sqlite"),
        ]);
        if !site_prefs.files.is_empty() {
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 网站偏好设置 ({})", profile_name),
                    join_paths(&site_prefs.files),
                    "清理网站权限、缩放和内容偏好数据库。",
                    site_prefs.size,
                    RiskLevel::Medium,
                    false,
                    processes.clone(),
                    site_prefs.preview,
                ),
                CleanAction::DeletePaths(site_prefs.files),
            );
        }

        let session_dirs = existing_dirs(vec![profile.join("sessionstore-backups")]);
        let session_files = collect_existing_files(vec![
            profile.join("recovery.jsonlz4"),
            profile.join("previous.jsonlz4"),
            profile.join("sessionstore.jsonlz4"),
        ]);
        if !session_dirs.is_empty() || !session_files.files.is_empty() {
            let (dir_size, mut children) = dirs_size_preview(&session_dirs, 80);
            children.extend(session_files.preview.clone());
            let mut paths = session_files.files;
            paths.extend(session_dirs);
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox Session 数据 ({})", profile_name),
                    join_paths(&paths),
                    "清理会话恢复数据。",
                    dir_size + session_files.size,
                    RiskLevel::High,
                    false,
                    processes.clone(),
                    children,
                ),
                CleanAction::DeletePaths(paths),
            );
        }

        let compact_dbs = [
            profile.join("places.sqlite"),
            profile.join("cookies.sqlite"),
            profile.join("formhistory.sqlite"),
            profile.join("permissions.sqlite"),
            profile.join("content-prefs.sqlite"),
            profile.join("favicons.sqlite"),
        ]
        .into_iter()
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
        if !compact_dbs.is_empty() {
            let size = compact_dbs.iter().map(|path| file_size(path)).sum::<u64>();
            push_item(
                items,
                counter,
                make_item(
                    ModuleKind::Browser,
                    "Firefox",
                    &format!("Firefox 压缩数据库 ({})", profile_name),
                    join_paths(&compact_dbs),
                    "对 Firefox SQLite 数据库执行 VACUUM，减少碎片，不删除用户数据。",
                    size,
                    RiskLevel::Safe,
                    false,
                    processes.clone(),
                    Vec::new(),
                ),
                CleanAction::CompactDatabases(compact_dbs),
            );
        }
    }
}

#[cfg(windows)]
fn add_application_dirs(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    category: &str,
    name: &str,
    paths: Vec<PathBuf>,
    process_names: Vec<&str>,
    risk: RiskLevel,
    selected_by_default: bool,
) {
    let dirs = existing_dirs(paths);
    if dirs.is_empty() {
        return;
    }
    let (size, children) = dirs_size_preview(&dirs, 140);
    push_item(
        items,
        counter,
        make_item(
            ModuleKind::Application,
            category,
            name,
            join_paths(&dirs),
            "清理应用日志、缓存与历史生成文件。",
            size,
            risk,
            selected_by_default,
            process_names
                .into_iter()
                .map(|item| item.to_string())
                .collect(),
            children,
        ),
        CleanAction::DeleteDirectoryContents(dirs),
    );
}

#[cfg(windows)]
fn scan_registry_items(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    warnings: &mut Vec<String>,
) {
    if let Err(error) = scan_registry_shared_dlls(items, counter) {
        warnings.push(format!("注册表 SharedDLLs 扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_startup(items, counter) {
        warnings.push(format!("注册表启动项扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_app_paths(items, counter) {
        warnings.push(format!("注册表 App Paths 扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_fonts(items, counter) {
        warnings.push(format!("注册表字体扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_uninstall(items, counter) {
        warnings.push(format!("注册表卸载残留扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_file_extensions(items, counter) {
        warnings.push(format!("注册表文件扩展名扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_com_classes(items, counter) {
        warnings.push(format!("注册表 ActiveX/COM 扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_type_libraries(items, counter) {
        warnings.push(format!("注册表 TypeLib 扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_mui_cache(items, counter) {
        warnings.push(format!("注册表 MUI 缓存扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_sound_events(items, counter) {
        warnings.push(format!("注册表声音事件扫描失败: {}", error));
    }
    if let Err(error) = scan_registry_services(items, counter) {
        warnings.push(format!("注册表 Windows 服务扫描失败: {}", error));
    }
}

#[cfg(windows)]
fn scan_registry_shared_dlls(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let targets = [
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs",
        ),
    ];

    for (root_label, root, subkey) in targets {
        let key = match root.open_subkey(subkey) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let key_path = format!("{}\\{}", root_label, subkey);
        for value in key.enum_values().flatten() {
            let value_name = value.0;
            let file_path = PathBuf::from(expand_env_vars(&value_name));
            if !file_path.exists() {
                add_registry_issue(
                    items,
                    counter,
                    "缺失的共享 DLL",
                    "删除指向不存在 DLL 的计数记录。",
                    &key_path,
                    Some(value_name),
                    false,
                    RiskLevel::Medium,
                    true,
                );
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_startup(items: &mut Vec<ScannedItem>, counter: &mut usize) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let targets = [
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ),
    ];

    for (root_label, root, subkey) in targets {
        let key = match root.open_subkey(subkey) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let key_path = format!("{}\\{}", root_label, subkey);
        for value in key.enum_values().flatten() {
            let value_name = value.0;
            if let Ok(command) = key.get_value::<String, _>(&value_name) {
                if registry_command_path_missing(&command) {
                    add_registry_issue(
                        items,
                        counter,
                        "失效的开机启动项",
                        "删除指向不存在程序的启动项。",
                        &key_path,
                        Some(value_name),
                        false,
                        RiskLevel::Medium,
                        true,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_app_paths(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let targets = [
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
        ),
    ];

    for (root_label, root, subkey) in targets {
        let key = match root.open_subkey(subkey) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for child in key.enum_keys().flatten() {
            if let Ok(app_key) = key.open_subkey(&child) {
                if let Ok(default_path) = app_key.get_value::<String, _>("") {
                    if registry_command_path_missing(&default_path) {
                        let key_path = format!("{}\\{}\\{}", root_label, subkey, child);
                        add_registry_issue(
                            items,
                            counter,
                            "无效的应用路径",
                            "删除 App Paths 中指向不存在程序的子键。",
                            &key_path,
                            None,
                            true,
                            RiskLevel::High,
                            false,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_fonts(items: &mut Vec<ScannedItem>, counter: &mut usize) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let windows_fonts = windows_dir().join("Fonts");
    let targets = [
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
        ),
    ];

    for (root_label, root, subkey) in targets {
        let key = match root.open_subkey(subkey) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let key_path = format!("{}\\{}", root_label, subkey);
        for value in key.enum_values().flatten() {
            let value_name = value.0;
            if let Ok(font_file) = key.get_value::<String, _>(&value_name) {
                let expanded = expand_env_vars(&font_file);
                let path = PathBuf::from(&expanded);
                let full_path = if path.is_absolute() {
                    path
                } else {
                    windows_fonts.join(path)
                };
                if !full_path.exists() {
                    add_registry_issue(
                        items,
                        counter,
                        "无效的字体记录",
                        "删除指向不存在字体文件的记录。",
                        &key_path,
                        Some(value_name),
                        false,
                        RiskLevel::Medium,
                        false,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_uninstall(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let targets = [
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            "HKLM",
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            "HKCU",
            RegKey::predef(HKEY_CURRENT_USER),
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
    ];

    for (root_label, root, subkey) in targets {
        let key = match root.open_subkey(subkey) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for child in key.enum_keys().flatten() {
            if let Ok(app_key) = key.open_subkey(&child) {
                let display_name = app_key.get_value::<String, _>("DisplayName").ok();
                if display_name.as_ref().map(|name| name.trim().is_empty()) != Some(false) {
                    continue;
                }
                let install_location = app_key.get_value::<String, _>("InstallLocation").ok();
                let uninstall = app_key.get_value::<String, _>("UninstallString").ok();
                let missing_install = install_location
                    .as_deref()
                    .map(|value| {
                        let path = PathBuf::from(expand_env_vars(value));
                        !path.as_os_str().is_empty() && !path.exists()
                    })
                    .unwrap_or(false);
                let missing_uninstall = uninstall
                    .as_deref()
                    .filter(|value| !value.to_ascii_lowercase().contains("msiexec"))
                    .map(registry_command_path_missing)
                    .unwrap_or(false);
                if missing_install && missing_uninstall {
                    let key_path = format!("{}\\{}\\{}", root_label, subkey, child);
                    add_registry_issue(
                        items,
                        counter,
                        "卸载软件残留路径",
                        "删除卸载列表中路径已失效的软件残留项。",
                        &key_path,
                        None,
                        true,
                        RiskLevel::High,
                        false,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_file_extensions(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::HKEY_CLASSES_ROOT;
    use winreg::RegKey;

    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    for extension in hkcr
        .enum_keys()
        .flatten()
        .filter(|key| key.starts_with('.'))
    {
        if let Ok(ext_key) = hkcr.open_subkey(&extension) {
            if let Ok(class_name) = ext_key.get_value::<String, _>("") {
                if class_name.trim().is_empty() {
                    continue;
                }
                if hkcr.open_subkey(&class_name).is_err() {
                    let key_path = format!("HKCR\\{}", extension);
                    add_registry_issue(
                        items,
                        counter,
                        "未使用的文件扩展名",
                        "删除指向不存在文件类型类名的扩展名记录。",
                        &key_path,
                        None,
                        true,
                        RiskLevel::High,
                        false,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_com_classes(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::HKEY_CLASSES_ROOT;
    use winreg::RegKey;

    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let clsid = match hkcr.open_subkey("CLSID") {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    for child in clsid.enum_keys().flatten() {
        for server_key in ["InprocServer32", "LocalServer32"] {
            let Ok(server) = clsid.open_subkey(format!("{}\\{}", child, server_key)) else {
                continue;
            };
            let Ok(path) = server.get_value::<String, _>("") else {
                continue;
            };
            if path.trim().is_empty() || !registry_command_path_missing(&path) {
                continue;
            }
            add_registry_issue(
                items,
                counter,
                "ActiveX 和类问题",
                "删除指向不存在组件文件的 COM/ActiveX 类注册。",
                &format!("HKCR\\CLSID\\{}", child),
                None,
                true,
                RiskLevel::High,
                false,
            );
            break;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_type_libraries(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::HKEY_CLASSES_ROOT;
    use winreg::RegKey;

    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    let typelib = match hkcr.open_subkey("TypeLib") {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    for guid in typelib.enum_keys().flatten() {
        let Ok(guid_key) = typelib.open_subkey(&guid) else {
            continue;
        };
        for version in guid_key.enum_keys().flatten() {
            let version_path = format!("{}\\{}", guid, version);
            let Ok(version_key) = guid_key.open_subkey(&version) else {
                continue;
            };
            for platform in ["0\\win32", "0\\win64"] {
                let Ok(platform_key) = version_key.open_subkey(platform) else {
                    continue;
                };
                let Ok(path) = platform_key.get_value::<String, _>("") else {
                    continue;
                };
                if path.trim().is_empty() || !registry_command_path_missing(&path) {
                    continue;
                }
                add_registry_issue(
                    items,
                    counter,
                    "类型库",
                    "删除指向不存在程序库文件的 TypeLib 注册。",
                    &format!("HKCR\\TypeLib\\{}", version_path),
                    None,
                    true,
                    RiskLevel::High,
                    false,
                );
                break;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_mui_cache(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let key_path =
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey(key_path) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let full_key = format!("HKCU\\{}", key_path);
    for (value_name, _) in key.enum_values().flatten() {
        if mui_cache_target_missing(&value_name) {
            add_registry_issue(
                items,
                counter,
                "MUI 缓存",
                "删除指向不存在程序的多语言界面缓存记录。",
                &full_key,
                Some(value_name),
                false,
                RiskLevel::Safe,
                false,
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_sound_events(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let apps_path = "AppEvents\\Schemes\\Apps";
    let apps = match hkcu.open_subkey(apps_path) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    for app in apps.enum_keys().flatten() {
        let Ok(app_key) = apps.open_subkey(&app) else {
            continue;
        };
        for event_name in app_key.enum_keys().flatten() {
            let current_path = format!("{}\\{}\\{}\\.Current", apps_path, app, event_name);
            let Ok(current_key) = hkcu.open_subkey(&current_path) else {
                continue;
            };
            let Ok(sound_path) = current_key.get_value::<String, _>("") else {
                continue;
            };
            if sound_path.trim().is_empty() {
                continue;
            }
            let expanded = PathBuf::from(expand_env_vars(&sound_path));
            if !registry_path_exists(&expanded) {
                add_registry_issue(
                    items,
                    counter,
                    "声音事件",
                    "清理指向不存在声音文件的系统事件声音关联。",
                    &format!("HKCU\\{}", current_path),
                    Some(String::new()),
                    false,
                    RiskLevel::Medium,
                    false,
                );
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn scan_registry_services(items: &mut Vec<ScannedItem>, counter: &mut usize) -> Result<(), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let services_path = "SYSTEM\\CurrentControlSet\\Services";
    let services = match hklm.open_subkey(services_path) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    for service in services.enum_keys().flatten() {
        let Ok(service_key) = services.open_subkey(&service) else {
            continue;
        };
        let Ok(image_path) = service_key.get_value::<String, _>("ImagePath") else {
            continue;
        };
        if !registry_command_path_missing(&image_path) {
            continue;
        }
        add_registry_issue(
            items,
            counter,
            "Windows 服务",
            "删除指向不存在可执行文件的后台服务注册。",
            &format!("HKLM\\{}\\{}", services_path, service),
            None,
            true,
            RiskLevel::High,
            false,
        );
    }
    Ok(())
}

#[cfg(windows)]
fn push_registry_cleanup_item(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    module: ModuleKind,
    category: &str,
    name: &str,
    key_path: &str,
    value_name: Option<String>,
    delete_key: bool,
    detail: &str,
    risk: RiskLevel,
    selected_by_default: bool,
) {
    let target = value_name
        .as_ref()
        .map(|value| format!("{}\\{}", key_path, value))
        .unwrap_or_else(|| key_path.to_string());
    push_item(
        items,
        counter,
        make_item(
            module,
            category,
            name,
            target,
            detail,
            0,
            risk,
            selected_by_default,
            Vec::new(),
            Vec::new(),
        ),
        CleanAction::RegistryDelete {
            key_path: key_path.to_string(),
            value_name,
            delete_key,
        },
    );
}

#[cfg(windows)]
fn add_registry_issue(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    name: &str,
    suggestion: &str,
    key_path: &str,
    value_name: Option<String>,
    delete_key: bool,
    risk: RiskLevel,
    selected_by_default: bool,
) {
    push_registry_cleanup_item(
        items,
        counter,
        ModuleKind::Registry,
        "注册表",
        name,
        key_path,
        value_name,
        delete_key,
        suggestion,
        risk,
        selected_by_default,
    );
}

fn execute_action(
    action: &CleanAction,
    cookie_whitelist: &[String],
) -> Result<ActionOutcome, String> {
    match action {
        CleanAction::DeleteDirectoryContents(dirs) => Ok(delete_directory_contents(dirs)),
        CleanAction::DeletePaths(paths) => Ok(delete_paths(paths)),
        CleanAction::FlushDns => flush_dns_cache().map(|_| ActionOutcome {
            freed_bytes: 0,
            errors: Vec::new(),
        }),
        CleanAction::ClearClipboard => clear_clipboard_api().map(|_| ActionOutcome {
            freed_bytes: 0,
            errors: Vec::new(),
        }),
        CleanAction::ClearRecycleBin(roots) => clear_recycle_bin(roots),
        CleanAction::CompactDatabases(paths) => compact_databases(paths),
        CleanAction::BrowserJson { path, kind } => clean_browser_json(path, kind),
        CleanAction::BrowserSql { db_path, kind } => {
            clean_browser_database(db_path, kind, cookie_whitelist)
        }
        CleanAction::RegistryDelete {
            key_path,
            value_name,
            delete_key,
        } => delete_registry_target(key_path, value_name.as_deref(), *delete_key),
    }
}

fn delete_directory_contents(dirs: &[PathBuf]) -> ActionOutcome {
    let mut freed_bytes = 0u64;
    let mut errors = Vec::new();
    for dir in dirs {
        let entries = match fs::read_dir(dir) {
            Ok(value) => value,
            Err(error) => {
                if dir.exists() {
                    errors.push(format!("{}: {}", dir.display(), error));
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let size = path_size(&path);
            match remove_path(&path) {
                Ok(()) => freed_bytes = freed_bytes.saturating_add(size),
                Err(error) => errors.push(format!("{}: {}", path.display(), error)),
            }
        }
    }
    ActionOutcome {
        freed_bytes,
        errors,
    }
}

fn delete_paths(paths: &[PathBuf]) -> ActionOutcome {
    let mut freed_bytes = 0u64;
    let mut errors = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let size = path_size(path);
        match remove_path(path) {
            Ok(()) => freed_bytes = freed_bytes.saturating_add(size),
            Err(error) => errors.push(format!("{}: {}", path.display(), error)),
        }
    }
    ActionOutcome {
        freed_bytes,
        errors,
    }
}

fn remove_path(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn clear_recycle_bin(roots: &[PathBuf]) -> Result<ActionOutcome, String> {
    let before = roots.iter().map(|path| path_size(path)).sum::<u64>();
    let result = unsafe {
        SHEmptyRecycleBinW(
            None,
            PCWSTR::null(),
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND,
        )
    };
    match result {
        Ok(()) => Ok(ActionOutcome {
            freed_bytes: before,
            errors: Vec::new(),
        }),
        Err(error) => {
            let fallback = delete_directory_contents(roots);
            if fallback.errors.is_empty() {
                Ok(fallback)
            } else {
                Err(format!("清空回收站失败: {}", error))
            }
        }
    }
}

#[cfg(windows)]
fn compact_databases(paths: &[PathBuf]) -> Result<ActionOutcome, String> {
    use rusqlite::Connection;

    let mut freed_bytes = 0u64;
    let mut errors = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let before = file_size(path);
        match Connection::open(path) {
            Ok(conn) => {
                if let Err(error) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;") {
                    errors.push(format!("{}: {}", path.display(), error));
                    continue;
                }
                drop(conn);
                remove_sqlite_sidecars(path);
                let after = file_size(path);
                freed_bytes = freed_bytes.saturating_add(before.saturating_sub(after));
            }
            Err(error) => errors.push(format!("{}: {}", path.display(), error)),
        }
    }

    Ok(ActionOutcome {
        freed_bytes,
        errors,
    })
}

#[cfg(windows)]
fn clean_browser_database(
    db_path: &Path,
    kind: &BrowserDbKind,
    cookie_whitelist: &[String],
) -> Result<ActionOutcome, String> {
    use rusqlite::Connection;

    if !db_path.exists() {
        return Ok(ActionOutcome {
            freed_bytes: 0,
            errors: Vec::new(),
        });
    }
    let before = file_size(db_path);
    let conn = Connection::open(db_path).map_err(|error| error.to_string())?;

    match kind {
        BrowserDbKind::ChromiumCookies => {
            execute_cookie_delete(&conn, "cookies", "host_key", cookie_whitelist)?;
        }
        BrowserDbKind::FirefoxCookies => {
            execute_cookie_delete(&conn, "moz_cookies", "host", cookie_whitelist)?;
        }
        BrowserDbKind::ChromiumHistory => {
            execute_optional(&conn, "DELETE FROM keyword_search_terms")?;
            execute_optional(&conn, "DELETE FROM visit_source")?;
            execute_optional(&conn, "DELETE FROM visits")?;
            execute_optional(&conn, "DELETE FROM urls")?;
        }
        BrowserDbKind::ChromiumDownloads => {
            execute_optional(&conn, "DELETE FROM downloads_url_chains")?;
            execute_optional(&conn, "DELETE FROM downloads_slices")?;
            execute_optional(&conn, "DELETE FROM downloads")?;
        }
        BrowserDbKind::ChromiumAutofill => {
            execute_optional(&conn, "DELETE FROM autofill")?;
            execute_optional(&conn, "DELETE FROM autofill_profiles")?;
            execute_optional(&conn, "DELETE FROM autofill_profile_names")?;
            execute_optional(&conn, "DELETE FROM autofill_profile_emails")?;
            execute_optional(&conn, "DELETE FROM autofill_profile_phones")?;
            execute_optional(&conn, "DELETE FROM autofill_profile_addresses")?;
            execute_optional(&conn, "DELETE FROM autofill_profile_birthdates")?;
            execute_optional(&conn, "DELETE FROM autofill_sync_metadata")?;
        }
        BrowserDbKind::ChromiumPasswords => {
            execute_optional(&conn, "DELETE FROM logins")?;
            execute_optional(&conn, "DELETE FROM stats")?;
            execute_optional(&conn, "DELETE FROM insecure_credentials")?;
            execute_optional(&conn, "DELETE FROM password_notes")?;
            execute_optional(&conn, "DELETE FROM password_issues")?;
            execute_optional(&conn, "DELETE FROM compromised_credentials")?;
        }
        BrowserDbKind::FirefoxHistory => {
            execute_optional(&conn, "DELETE FROM moz_historyvisits")?;
            execute_optional(
                &conn,
                "UPDATE moz_places SET visit_count = 0, last_visit_date = NULL",
            )?;
        }
        BrowserDbKind::FirefoxDownloads => {
            execute_optional(
                &conn,
                "DELETE FROM moz_annos WHERE anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name LIKE '%downloads%')",
            )?;
        }
        BrowserDbKind::FirefoxFormHistory => {
            execute_optional(&conn, "DELETE FROM moz_formhistory")?;
            execute_optional(&conn, "DELETE FROM moz_deleted_formhistory")?;
        }
    }

    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");
    drop(conn);
    remove_sqlite_sidecars(db_path);

    Ok(ActionOutcome {
        freed_bytes: before,
        errors: Vec::new(),
    })
}

#[cfg(windows)]
fn clean_browser_json(path: &Path, kind: &BrowserJsonKind) -> Result<ActionOutcome, String> {
    if !path.exists() {
        return Ok(ActionOutcome {
            freed_bytes: 0,
            errors: Vec::new(),
        });
    }

    let before = file_size(path);
    let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let mut changed = false;

    match kind {
        BrowserJsonKind::ChromiumLastDownloadLocation => {
            changed |= remove_json_path(&mut json, &["download", "default_directory"]);
            changed |= remove_json_path(&mut json, &["download", "savefile", "default_directory"]);
        }
        BrowserJsonKind::ChromiumSitePreferences => {
            changed |= remove_json_path(&mut json, &["profile", "content_settings", "exceptions"]);
            changed |=
                remove_json_path(&mut json, &["profile", "content_settings", "pattern_pairs"]);
            changed |= remove_json_path(&mut json, &["partition", "per_host_zoom_levels"]);
            changed |= remove_json_path(&mut json, &["partition", "per_host_content_settings"]);
        }
        BrowserJsonKind::FirefoxPasswords => {
            if let Some(object) = json.as_object_mut() {
                object.insert("logins".to_string(), serde_json::Value::Array(Vec::new()));
                object.insert(
                    "disabledHosts".to_string(),
                    serde_json::Value::Array(Vec::new()),
                );
                changed = true;
            }
        }
    }

    if changed {
        let serialized = serde_json::to_string_pretty(&json).map_err(|error| error.to_string())?;
        fs::write(path, serialized).map_err(|error| error.to_string())?;
    }

    Ok(ActionOutcome {
        freed_bytes: before.saturating_sub(file_size(path)),
        errors: Vec::new(),
    })
}

fn remove_json_path(value: &mut serde_json::Value, path: &[&str]) -> bool {
    if path.is_empty() {
        return false;
    }
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    if path.len() == 1 {
        return object.remove(path[0]).is_some();
    }
    object
        .get_mut(path[0])
        .map(|child| remove_json_path(child, &path[1..]))
        .unwrap_or(false)
}

#[cfg(windows)]
fn execute_cookie_delete(
    conn: &rusqlite::Connection,
    table: &str,
    host_column: &str,
    whitelist: &[String],
) -> Result<(), String> {
    if whitelist.is_empty() {
        execute_optional(conn, &format!("DELETE FROM {}", table))?;
        return Ok(());
    }

    let conditions = whitelist
        .iter()
        .map(|_| {
            format!(
                "LOWER({}) = ? OR LOWER({}) LIKE ?",
                host_column, host_column
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let sql = format!("DELETE FROM {} WHERE NOT ({})", table, conditions);
    let mut params = Vec::with_capacity(whitelist.len() * 2);
    for domain in whitelist.iter().map(|domain| domain.to_ascii_lowercase()) {
        params.push(domain.clone());
        params.push(format!("%.{}", domain.trim_start_matches('.')));
    }
    conn.execute(&sql, rusqlite::params_from_iter(params))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn execute_optional(conn: &rusqlite::Connection, sql: &str) -> Result<(), String> {
    match conn.execute(sql, []) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("no such table") => Ok(()),
        Err(error) if error.to_string().contains("no such column") => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn delete_registry_target(
    key_path: &str,
    value_name: Option<&str>,
    delete_key: bool,
) -> Result<ActionOutcome, String> {
    use winreg::enums::{KEY_SET_VALUE, KEY_WRITE};

    if delete_key {
        let (root, subkey, _) = split_registry_path(key_path)?;
        if subkey.trim().is_empty() {
            return Err("拒绝删除注册表根键".to_string());
        }
        root.delete_subkey_all(subkey)
            .map_err(|error| error.to_string())?;
    } else if let Some(value) = value_name {
        let (root, subkey, _) = split_registry_path(key_path)?;
        let key = root
            .open_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_WRITE)
            .map_err(|error| error.to_string())?;
        key.delete_value(value).map_err(|error| error.to_string())?;
    } else {
        return Err("注册表删除目标不完整".to_string());
    }

    Ok(ActionOutcome {
        freed_bytes: 0,
        errors: Vec::new(),
    })
}

fn backup_registry_before_delete(
    app: &tauri::AppHandle,
    items: &[ScannedItem],
) -> Result<Option<PathBuf>, String> {
    let keys = items
        .iter()
        .filter_map(|item| match &item.action {
            CleanAction::RegistryDelete { key_path, .. } => Some(key_path.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();

    if keys.is_empty() {
        return Ok(None);
    }

    let dir = backup_dir(app);
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let timestamp = unix_timestamp();
    let final_path = dir.join(format!("registry_backup_{}.reg", timestamp));
    let mut combined = String::from("Windows Registry Editor Version 5.00\r\n\r\n");

    for key in &keys {
        export_registry_key(key, &mut combined)
            .map_err(|error| format!("注册表备份失败 {}: {}", key, error))?;
    }

    write_utf16le_with_bom(&final_path, &combined).map_err(|error| error.to_string())?;
    Ok(Some(final_path))
}

fn emit_progress(app: &tauri::AppHandle, progress: CleanProgress) {
    let _ = app.emit("clean-progress", progress);
}

fn backup_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .join("Backup")
}

fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

fn running_processes(process_names: &[String]) -> Vec<String> {
    if process_names.is_empty() {
        return Vec::new();
    }

    let wanted = process_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut running = HashSet::new();
    for (name, _) in process_entries() {
        let lower = name.to_ascii_lowercase();
        if wanted.contains(&lower) {
            running.insert(name);
        }
    }
    let mut result = running.into_iter().collect::<Vec<_>>();
    result.sort();
    result
}

fn kill_process(process_name: &str) {
    let wanted = process_name.to_ascii_lowercase();
    for (name, pid) in process_entries() {
        if name.to_ascii_lowercase() == wanted {
            if let Ok(handle) = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
                let _ = unsafe { TerminateProcess(handle, 1) };
                let _ = unsafe { CloseHandle(handle) };
            }
        }
    }
}

#[cfg(windows)]
fn registry_key_has_content(key_path: &str) -> bool {
    use winreg::enums::KEY_READ;

    let Ok((root, subkey, _)) = split_registry_path(key_path) else {
        return false;
    };
    let Ok(key) = root.open_subkey_with_flags(subkey, KEY_READ) else {
        return false;
    };
    key.enum_values().next().is_some() || key.enum_keys().next().is_some()
}

#[cfg(windows)]
fn registry_value_exists(key_path: &str, value_name: &str) -> bool {
    use winreg::enums::KEY_READ;

    let Ok((root, subkey, _)) = split_registry_path(key_path) else {
        return false;
    };
    let Ok(key) = root.open_subkey_with_flags(subkey, KEY_READ) else {
        return false;
    };
    key.get_raw_value(value_name).is_ok()
}

#[cfg(windows)]
fn shell_execute(verb: &str, file: &str, parameters: Option<&str>) -> Result<(), String> {
    let verb = to_wide_null(verb);
    let file = to_wide_null(file);
    let parameters = parameters.map(to_wide_null);
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            parameters
                .as_ref()
                .map(|value| PCWSTR(value.as_ptr()))
                .unwrap_or_else(PCWSTR::null),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!(
            "ShellExecuteW 执行失败，错误码 {}",
            result.0 as isize
        ))
    }
}

#[cfg(windows)]
fn flush_dns_cache() -> Result<(), String> {
    let ok = unsafe { DnsFlushResolverCache() };
    if ok != 0 {
        Ok(())
    } else {
        Err("DNS 缓存刷新失败".to_string())
    }
}

#[cfg(windows)]
fn clear_clipboard_api() -> Result<(), String> {
    unsafe { OpenClipboard(None) }.map_err(|error| error.to_string())?;
    let result = unsafe { EmptyClipboard() }.map_err(|error| error.to_string());
    let _ = unsafe { CloseClipboard() };
    result
}

#[cfg(windows)]
fn process_entries() -> Vec<(String, u32)> {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut result = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = wide_array_to_string(&entry.szExeFile);
            if !name.is_empty() {
                result.push((name, entry.th32ProcessID));
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };
    result
}

#[cfg(windows)]
fn split_registry_path(key_path: &str) -> Result<(winreg::RegKey, String, String), String> {
    use winreg::enums::{
        HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
    };
    use winreg::RegKey;

    let normalized = key_path.trim().replace('/', "\\");
    let mut parts = normalized.splitn(2, '\\');
    let root_label = parts
        .next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "注册表路径缺少根键".to_string())?;
    let subkey = parts.next().unwrap_or("").trim_matches('\\').to_string();
    let (root, canonical) = match root_label.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => (
            RegKey::predef(HKEY_CURRENT_USER),
            "HKEY_CURRENT_USER".to_string(),
        ),
        "HKLM" | "HKEY_LOCAL_MACHINE" => (
            RegKey::predef(HKEY_LOCAL_MACHINE),
            "HKEY_LOCAL_MACHINE".to_string(),
        ),
        "HKCR" | "HKEY_CLASSES_ROOT" => (
            RegKey::predef(HKEY_CLASSES_ROOT),
            "HKEY_CLASSES_ROOT".to_string(),
        ),
        "HKU" | "HKEY_USERS" => (RegKey::predef(HKEY_USERS), "HKEY_USERS".to_string()),
        "HKCC" | "HKEY_CURRENT_CONFIG" => (
            RegKey::predef(HKEY_CURRENT_CONFIG),
            "HKEY_CURRENT_CONFIG".to_string(),
        ),
        _ => return Err(format!("不支持的注册表根键: {}", root_label)),
    };
    Ok((root, subkey, canonical))
}

#[cfg(windows)]
fn export_registry_key(key_path: &str, output: &mut String) -> Result<(), String> {
    use winreg::enums::KEY_READ;

    let (root, subkey, canonical) = split_registry_path(key_path)?;
    let key = root
        .open_subkey_with_flags(&subkey, KEY_READ)
        .map_err(|error| error.to_string())?;
    let full_path = if subkey.is_empty() {
        canonical.clone()
    } else {
        format!("{}\\{}", canonical, subkey)
    };

    output.push_str(&format!("[{}]\r\n", full_path));
    let mut values = key.enum_values().flatten().collect::<Vec<_>>();
    values.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in values {
        output.push_str(&format!(
            "{}={}\r\n",
            format_reg_value_name(&name),
            format_reg_value_data(&value)
        ));
    }
    output.push_str("\r\n");

    let mut children = key.enum_keys().flatten().collect::<Vec<_>>();
    children.sort();
    for child in children {
        let child_path = if subkey.is_empty() {
            format!("{}\\{}", canonical, child)
        } else {
            format!("{}\\{}\\{}", canonical, subkey, child)
        };
        export_registry_key(&child_path, output)?;
    }
    Ok(())
}

#[cfg(windows)]
fn format_reg_value_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", escape_reg_string(name))
    }
}

#[cfg(windows)]
fn format_reg_value_data(value: &winreg::RegValue) -> String {
    use winreg::enums::{REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ};

    match value.vtype.clone() {
        REG_SZ => format!(
            "\"{}\"",
            escape_reg_string(&utf16le_bytes_to_string(&value.bytes))
        ),
        REG_DWORD => {
            let number = value
                .bytes
                .get(0..4)
                .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .unwrap_or(0);
            format!("dword:{:08x}", number)
        }
        REG_BINARY => format!("hex:{}", format_hex_bytes(&value.bytes)),
        REG_EXPAND_SZ => format!("hex(2):{}", format_hex_bytes(&value.bytes)),
        REG_MULTI_SZ => format!("hex(7):{}", format_hex_bytes(&value.bytes)),
        REG_QWORD => format!("hex(b):{}", format_hex_bytes(&value.bytes)),
        other => format!(
            "hex({:x}):{}",
            other as isize,
            format_hex_bytes(&value.bytes)
        ),
    }
}

#[cfg(windows)]
fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(windows)]
fn escape_reg_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(windows)]
fn utf16le_bytes_to_string(bytes: &[u8]) -> String {
    let mut units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    while units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16_lossy(&units)
}

#[cfg(windows)]
fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn wide_array_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

#[cfg(windows)]
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

#[cfg(windows)]
fn windows_dir() -> PathBuf {
    env_path("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

#[cfg(windows)]
fn existing_dirs(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|path| path.is_dir()).collect()
}

#[cfg(windows)]
fn unique_existing_dirs(paths: Vec<Option<PathBuf>>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for path in paths.into_iter().flatten().filter(|path| path.is_dir()) {
        let key = path.display().to_string().to_ascii_lowercase();
        if seen.insert(key) {
            result.push(path);
        }
    }
    result
}

#[cfg(windows)]
fn read_child_dirs(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

#[cfg(windows)]
fn chromium_profiles(base: &Path) -> Vec<PathBuf> {
    let mut profiles = read_child_dirs(base)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .map(|name| {
                    name == "Default" || name.starts_with("Profile ") || name == "Guest Profile"
                })
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if profiles.is_empty() && base.join("History").exists() {
        profiles.push(base.to_path_buf());
    }
    profiles
}

#[cfg(windows)]
fn recycle_bin_roots() -> Vec<PathBuf> {
    drive_roots()
        .into_iter()
        .map(|root| root.join("$Recycle.Bin"))
        .filter(|path| path.exists())
        .collect()
}

#[cfg(windows)]
fn drive_roots() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
        .filter(|path| path.exists())
        .collect()
}

#[cfg(windows)]
fn chkdsk_fragment_paths() -> Vec<PathBuf> {
    let mut result = Vec::new();
    for root in drive_roots() {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("found.")
                || path
                    .extension()
                    .and_then(OsStr::to_str)
                    .map(|ext| ext.eq_ignore_ascii_case("chk"))
                    .unwrap_or(false)
            {
                result.push(path);
            }
        }
    }
    result
}

struct FileCollection {
    size: u64,
    preview: Vec<FilePreview>,
    files: Vec<PathBuf>,
}

fn dirs_size_preview<P: AsRef<Path>>(dirs: &[P], limit: usize) -> (u64, Vec<FilePreview>) {
    let mut size = 0u64;
    let mut preview = Vec::new();
    for dir in dirs {
        for entry in WalkDir::new(dir.as_ref())
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if path.is_file() {
                let file_size = entry.metadata().map(|value| value.len()).unwrap_or(0);
                size = size.saturating_add(file_size);
                if preview.len() < limit {
                    preview.push(FilePreview {
                        path: path.display().to_string(),
                        size_bytes: file_size,
                    });
                }
            }
        }
    }
    (size, preview)
}

#[cfg(windows)]
fn collect_existing_files(paths: Vec<PathBuf>) -> FileCollection {
    collect_files_matching(paths, |_| true)
}

#[cfg(windows)]
fn collect_files_matching<F>(paths: Vec<PathBuf>, predicate: F) -> FileCollection
where
    F: Fn(&Path) -> bool,
{
    let mut size = 0u64;
    let mut preview = Vec::new();
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() && predicate(&path) {
            let file_size = file_size(&path);
            size = size.saturating_add(file_size);
            if preview.len() < 180 {
                preview.push(FilePreview {
                    path: path.display().to_string(),
                    size_bytes: file_size,
                });
            }
            files.push(path);
        } else if path.is_dir() {
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                let path = entry.path();
                if path.is_file() && predicate(path) {
                    let file_size = entry.metadata().map(|value| value.len()).unwrap_or(0);
                    size = size.saturating_add(file_size);
                    if preview.len() < 180 {
                        preview.push(FilePreview {
                            path: path.display().to_string(),
                            size_bytes: file_size,
                        });
                    }
                    files.push(path.to_path_buf());
                }
            }
        }
    }
    FileCollection {
        size,
        preview,
        files,
    }
}

fn path_size(path: &Path) -> u64 {
    if path.is_file() {
        return file_size(path);
    }
    if path.is_dir() {
        return WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .filter_map(|entry| entry.metadata().ok().map(|metadata| metadata.len()))
            .sum();
    }
    0
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn join_paths(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .take(4)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(windows)]
fn registry_command_path_missing(command: &str) -> bool {
    executable_path_from_command(command)
        .map(|path| !registry_path_exists(&path))
        .unwrap_or(false)
}

#[cfg(windows)]
fn executable_path_from_command(command: &str) -> Option<PathBuf> {
    let expanded = expand_env_vars(command);
    let value = expanded.trim().trim_matches('\0').trim();
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("rundll32") || lower.contains("msiexec") {
        return None;
    }

    let candidate = if let Some(rest) = value.strip_prefix('"') {
        rest.find('"').map(|index| rest[..index].to_string())
    } else {
        [".exe", ".bat", ".cmd", ".com", ".dll"]
            .iter()
            .filter_map(|needle| {
                lower
                    .find(needle)
                    .map(|index| value[..index + needle.len()].to_string())
            })
            .min_by_key(|candidate| candidate.len())
            .or_else(|| value.split_whitespace().next().map(|item| item.to_string()))
    }?;

    let trimmed = candidate.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        None
    } else if trimmed.to_ascii_lowercase().starts_with("\\systemroot\\") {
        Some(windows_dir().join(&trimmed["\\SystemRoot\\".len()..]))
    } else {
        Some(PathBuf::from(trimmed))
    }
}

#[cfg(windows)]
fn registry_path_exists(path: &Path) -> bool {
    if path.exists() {
        return true;
    }
    let value = path.display().to_string();
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
        return windows_dir().join(&value).exists();
    }
    if lower.starts_with("drivers\\") {
        return windows_dir().join("System32").join(&value).exists();
    }
    false
}

#[cfg(windows)]
fn mui_cache_target_missing(value_name: &str) -> bool {
    let stripped = [
        ".friendlyappname",
        ".applicationcompany",
        ".applicationdescription",
        ".applicationicon",
    ]
    .iter()
    .find_map(|suffix| {
        value_name
            .to_ascii_lowercase()
            .rfind(suffix)
            .map(|index| value_name[..index].to_string())
    })
    .unwrap_or_else(|| value_name.to_string());
    let path = PathBuf::from(expand_env_vars(stripped.trim()));
    !path.as_os_str().is_empty() && !registry_path_exists(&path)
}

#[cfg(windows)]
fn expand_env_vars(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let mut var = String::new();
            while let Some(next) = chars.next() {
                if next == '%' {
                    break;
                }
                var.push(next);
            }
            if var.is_empty() {
                result.push('%');
            } else if let Ok(value) = std::env::var(&var) {
                result.push_str(&value);
            } else {
                result.push('%');
                result.push_str(&var);
                result.push('%');
            }
        } else {
            result.push(ch);
        }
    }
    result
}

#[cfg(windows)]
fn remove_sqlite_sidecars(db_path: &Path) {
    let base = db_path.display().to_string();
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = fs::remove_file(format!("{}{}", base, suffix));
    }
}

fn write_utf16le_with_bom(path: &Path, text: &str) -> io::Result<()> {
    let mut bytes = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(path, bytes)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn system_time_to_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
