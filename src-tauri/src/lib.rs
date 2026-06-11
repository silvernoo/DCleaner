use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};
use walkdir::WalkDir;

#[cfg(not(windows))]
compile_error!("DCleaner only supports Windows targets.");

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
    FirefoxCookies,
    FirefoxHistory,
    FirefoxDownloads,
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
    let items = selected_scanned_items(&state, &request.selected_ids)?;
    if items.is_empty() {
        return Err("没有可执行的清理项目".to_string());
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

    let output = Command::new("reg")
        .arg("import")
        .arg(&path)
        .output()
        .map_err(|error| error.to_string())?;

    if output.status.success() {
        Ok(RestoreResult {
            success: true,
            message: "注册表备份已导入。".to_string(),
        })
    } else {
        Err(command_error("reg import", &output))
    }
}

#[tauri::command]
fn relaunch_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    if is_admin() {
        return Ok(());
    }

    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let escaped = exe.display().to_string().replace('\'', "''");
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!("Start-Process -FilePath '{}' -Verb RunAs", escaped),
        ])
        .output()
        .map_err(|error| error.to_string())?;

    if output.status.success() {
        app.exit(0);
        Ok(())
    } else {
        Err(command_error("Start-Process -Verb RunAs", &output))
    }
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
    CleanerItem {
        id: String::new(),
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
            "ipconfig /flushdns".to_string(),
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
fn scan_browser_items(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
    _warnings: &mut Vec<String>,
) {
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
    }

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
        "VLC 媒体缓存",
        vec![appdata.join("vlc").join("art")],
        vec!["vlc.exe"],
        RiskLevel::Medium,
        true,
    );

    add_application_dirs(
        items,
        counter,
        "npm 缓存",
        vec![local.join("npm-cache")],
        Vec::new(),
        RiskLevel::Safe,
        true,
    );

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

        let cookies = [
            profile.join("Network").join("Cookies"),
            profile.join("Cookies"),
        ]
        .into_iter()
        .find(|path| path.exists());
        if let Some(cookies) = cookies {
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
    }
}

#[cfg(windows)]
fn add_application_dirs(
    items: &mut Vec<ScannedItem>,
    counter: &mut usize,
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
            "第三方应用",
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
    let target = value_name
        .as_ref()
        .map(|value| format!("{}\\{}", key_path, value))
        .unwrap_or_else(|| key_path.to_string());
    push_item(
        items,
        counter,
        make_item(
            ModuleKind::Registry,
            "注册表",
            name,
            target,
            suggestion,
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

fn execute_action(
    action: &CleanAction,
    cookie_whitelist: &[String],
) -> Result<ActionOutcome, String> {
    match action {
        CleanAction::DeleteDirectoryContents(dirs) => Ok(delete_directory_contents(dirs)),
        CleanAction::DeletePaths(paths) => Ok(delete_paths(paths)),
        CleanAction::FlushDns => {
            run_simple_command("ipconfig", &["/flushdns"]).map(|_| ActionOutcome {
                freed_bytes: 0,
                errors: Vec::new(),
            })
        }
        CleanAction::ClearClipboard => {
            run_simple_command("cmd", &["/C", "type nul | clip"]).map(|_| ActionOutcome {
                freed_bytes: 0,
                errors: Vec::new(),
            })
        }
        CleanAction::ClearRecycleBin(roots) => clear_recycle_bin(roots),
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
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(ActionOutcome {
            freed_bytes: before,
            errors: Vec::new(),
        })
    } else {
        let fallback = delete_directory_contents(roots);
        if fallback.errors.is_empty() {
            Ok(fallback)
        } else {
            Err(command_error("Clear-RecycleBin", &output))
        }
    }
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
    let mut command = Command::new("reg");
    command.arg("delete").arg(key_path);
    if delete_key {
        command.arg("/f");
    } else if let Some(value) = value_name {
        if value.is_empty() {
            command.arg("/ve").arg("/f");
        } else {
            command.arg("/v").arg(value).arg("/f");
        }
    }
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(ActionOutcome {
            freed_bytes: 0,
            errors: Vec::new(),
        })
    } else {
        Err(command_error("reg delete", &output))
    }
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

    for (index, key) in keys.iter().enumerate() {
        let part_path = dir.join(format!("registry_backup_{}_part_{}.reg", timestamp, index));
        let output = Command::new("reg")
            .arg("export")
            .arg(key)
            .arg(&part_path)
            .arg("/y")
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            let _ = fs::remove_file(&part_path);
            return Err(command_error("reg export", &output));
        }
        let text = read_reg_file(&part_path).map_err(|error| error.to_string())?;
        let body = text
            .lines()
            .skip_while(|line| line.trim().is_empty())
            .skip(1)
            .collect::<Vec<_>>()
            .join("\r\n");
        combined.push_str(&body);
        combined.push_str("\r\n\r\n");
        let _ = fs::remove_file(&part_path);
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
    Command::new("net")
        .arg("session")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn running_processes(process_names: &[String]) -> Vec<String> {
    if process_names.is_empty() {
        return Vec::new();
    }

    let output = match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    if !output.status.success() {
        return Vec::new();
    }
    let wanted = process_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let text = String::from_utf8_lossy(&output.stdout);
    let mut running = HashSet::new();
    for line in text.lines() {
        if let Some(name) = parse_tasklist_name(line) {
            let lower = name.to_ascii_lowercase();
            if wanted.contains(&lower) {
                running.insert(name);
            }
        }
    }
    let mut result = running.into_iter().collect::<Vec<_>>();
    result.sort();
    result
}

fn kill_process(process_name: &str) {
    let _ = Command::new("taskkill")
        .args(["/F", "/T", "/IM", process_name])
        .output();
}

fn parse_tasklist_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with('"') {
        let mut chars = trimmed.chars();
        chars.next();
        let mut name = String::new();
        for ch in chars {
            if ch == '"' {
                return Some(name);
            }
            name.push(ch);
        }
        None
    } else {
        trimmed.split(',').next().map(|value| value.to_string())
    }
}

fn run_simple_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, &output))
    }
}

fn command_error(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let message = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    if message.is_empty() {
        format!("{} 执行失败", command)
    } else {
        format!("{} 执行失败: {}", command, message)
    }
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
    (b'A'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\$Recycle.Bin", letter as char)))
        .filter(|path| path.exists())
        .collect()
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
        .map(|path| !path.exists())
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
    } else {
        Some(PathBuf::from(trimmed))
    }
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

fn read_reg_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(&[0xff, 0xfe]) {
        let mut units = Vec::new();
        for chunk in bytes[2..].chunks_exact(2) {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        Ok(String::from_utf16_lossy(&units))
    } else {
        Ok(String::from_utf8_lossy(&bytes).to_string())
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
