import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./styles.css";

const modules = [
  { id: "all", label: "总览", icon: "⌘" },
  { id: "system", label: "系统", icon: "▣" },
  { id: "browser", label: "浏览器", icon: "◎" },
  { id: "application", label: "应用", icon: "◫" },
  { id: "registry", label: "注册表", icon: "▧" },
  { id: "whitelist", label: "白名单", icon: "✓" },
  { id: "restore", label: "恢复", icon: "↺" }
];

const whitelistStorageKey = "dcleaner.itemWhitelist";
const inTauri = isTauri();
const appWindow = inTauri ? getCurrentWindow() : null;

function loadWhitelist() {
  try {
    const value = JSON.parse(window.localStorage.getItem(whitelistStorageKey) || "[]");
    return Array.isArray(value)
      ? value.filter((item) => item && typeof item.key === "string" && item.key)
      : [];
  } catch {
    return [];
  }
}

const state = {
  env: null,
  activeModule: "all",
  scanning: false,
  executing: false,
  items: [],
  selected: new Set(),
  expanded: new Set(),
  backups: [],
  page: 1,
  itemWhitelist: loadWhitelist(),
  progress: null,
  conflicts: [],
  toast: "",
  errors: [],
  contextMenu: null
};

const app = document.querySelector("#app");

document.addEventListener("contextmenu", (event) => {
  event.preventDefault();
  const itemElement = event.target.closest("[data-item-row]");
  if (itemElement) {
    state.contextMenu = {
      x: event.clientX,
      y: event.clientY,
      itemId: itemElement.dataset.itemRow
    };
    render({ preserveScroll: true });
    return;
  }
  state.contextMenu = null;
  render({ preserveScroll: true });
});

document.addEventListener("dragstart", (event) => event.preventDefault());

app.addEventListener("mousedown", async (event) => {
  const target = event.target instanceof Element ? event.target : null;
  if (event.button !== 0 || !target?.closest("[data-window-drag]")) return;
  await appWindow?.startDragging();
});

document.addEventListener(
  "wheel",
  (event) => {
    if (event.ctrlKey) event.preventDefault();
  },
  { passive: false }
);

function moduleLabel(moduleId) {
  const found = modules.find((item) => item.id === moduleId);
  return found ? found.label : moduleId;
}

function riskLabel(risk) {
  return {
    safe: "安全",
    medium: "中等",
    high: "高风险"
  }[risk] || risk;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function selectedItems() {
  return state.items.filter((item) => state.selected.has(item.id));
}

function visibleItems() {
  if (["restore", "whitelist"].includes(state.activeModule)) return [];
  if (state.activeModule === "all") return state.items;
  return state.items.filter((item) => item.module === state.activeModule);
}

function totals() {
  const selected = selectedItems();
  return {
    allCount: state.items.length,
    selectedCount: selected.length,
    totalSize: state.items.reduce((sum, item) => sum + item.sizeBytes, 0),
    selectedSize: selected.reduce((sum, item) => sum + item.sizeBytes, 0)
  };
}

function showToast(message) {
  state.toast = message;
  state.contextMenu = null;
  render({ preserveScroll: true });
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    state.toast = "";
    render({ preserveScroll: true });
  }, 3600);
}

async function nativeConfirm(message, title = "DCleaner") {
  try {
    return await callCommand("confirm_native", { title, message });
  } catch (error) {
    showToast(String(error));
    return false;
  }
}

function closeOverlays() {
  state.contextMenu = null;
}

function currentModule() {
  return modules.find((module) => module.id === state.activeModule) || modules[0];
}

function itemById(id) {
  return state.items.find((item) => item.id === id);
}

async function callCommand(command, args = {}) {
  if (inTauri) return invoke(command, args);
  if (command === "get_environment") {
    return {
      isAdmin: false,
      backupDir: "Tauri 预览模式",
      platform: browserPlatform()
    };
  }
  if (command === "list_backups") return [];
  if (command === "scan_all") {
    return {
      isAdmin: false,
      items: [],
      totalSizeBytes: 0,
      warnings: ["浏览器预览模式不会执行真实扫描。"]
    };
  }
  if (command === "confirm_native") return true;
  if (command === "detect_conflicts") return [];
  if (command === "execute_clean") {
    return {
      requestedCount: 0,
      cleanedCount: 0,
      skippedCount: 0,
      freedBytes: 0,
      backupCreated: null,
      errors: []
    };
  }
  return null;
}

function browserPlatform() {
  const value = `${navigator.userAgent} ${navigator.platform}`.toLowerCase();
  if (value.includes("mac")) return "macos";
  if (value.includes("win")) return "windows";
  return "linux";
}

function platformStyle(platform) {
  if (platform === "macos") return "macos";
  if (platform === "linux") return "linux";
  return "windows";
}

async function loadEnvironment() {
  state.env = await callCommand("get_environment");
  render({ preserveScroll: true });
}

async function loadBackups() {
  state.backups = await callCommand("list_backups");
  render({ preserveScroll: true });
}

async function runScan() {
  state.scanning = true;
  state.progress = null;
  state.errors = [];
  render();
  try {
    const result = await callCommand("scan_all", {
      options: {
        includeSystem: true,
        includeBrowsers: true,
        includeApplications: true,
        includeRegistry: true
      }
    });
    const allItems = result.items || [];
    const hiddenCount = allItems.filter((item) => isWhitelisted(item)).length;
    state.items = filterWhitelistedItems(allItems);
    state.activeModule = "all";
    state.page = 1;
    state.expanded = expandedTreeKeys();
    state.selected = new Set();
    state.errors = result.warnings || [];
    showToast(
      `扫描完成：发现 ${state.items.length} 个可处理项目${hiddenCount ? `，白名单隐藏 ${hiddenCount} 项` : ""}。`
    );
  } catch (error) {
    showToast(String(error));
  } finally {
    state.scanning = false;
    render();
  }
}

async function relaunchAdmin() {
  try {
    await callCommand("relaunch_as_admin");
  } catch (error) {
    showToast(String(error));
  }
}

function saveWhitelist() {
  window.localStorage.setItem(whitelistStorageKey, JSON.stringify(state.itemWhitelist));
}

function whitelistKeySet() {
  return new Set(state.itemWhitelist.map((item) => item.key));
}

function isWhitelisted(item) {
  return whitelistKeySet().has(item.whitelistKey);
}

function filterWhitelistedItems(items) {
  const keys = whitelistKeySet();
  return items.filter((item) => !keys.has(item.whitelistKey));
}

function whitelistEntryFromItem(item) {
  return {
    key: item.whitelistKey,
    module: item.module,
    category: item.category || "其他",
    name: item.name,
    path: item.path,
    risk: item.risk,
    sizeBytes: item.sizeBytes || 0,
    createdAt: String(Math.floor(Date.now() / 1000))
  };
}

function addItemsToWhitelist(items) {
  const addable = items.filter((item) => item?.whitelistKey);
  if (!addable.length) return;
  const merged = new Map(state.itemWhitelist.map((item) => [item.key, item]));
  for (const item of addable) {
    merged.set(item.whitelistKey, whitelistEntryFromItem(item));
    state.selected.delete(item.id);
  }
  state.itemWhitelist = [...merged.values()].sort((a, b) =>
    `${moduleLabel(a.module)}${a.category}${a.name}`.localeCompare(
      `${moduleLabel(b.module)}${b.category}${b.name}`,
      "zh-Hans-CN"
    )
  );
  state.items = filterWhitelistedItems(state.items);
  saveWhitelist();
  showToast(`已加入白名单：${addable.length} 项。`);
  render({ preserveScroll: true });
}

function removeWhitelistEntry(key) {
  state.itemWhitelist = state.itemWhitelist.filter((item) => item.key !== key);
  saveWhitelist();
  showToast("已从白名单移除，重新扫描后会再次显示。");
  render({ preserveScroll: true });
}

async function executeSelected(decisions = {}) {
  const selectedIds = selectedItems().map((item) => item.id);
  if (!selectedIds.length) {
    showToast("请先选择需要清理的项目。");
    return;
  }

  state.executing = true;
  state.progress = {
    total: selectedIds.length,
    completed: 0,
    current: "准备清理",
    status: "running",
    freedBytes: 0,
    errors: []
  };
  render();

  try {
    const summary = await callCommand("execute_clean", {
      request: {
        selectedIds,
        conflictDecisions: decisions,
        itemWhitelistKeys: [...whitelistKeySet()],
        cookieWhitelist: []
      }
    });
    state.conflicts = [];
    await loadBackups();
    await runScan();
    showToast(`清理完成：释放 ${formatBytes(summary.freedBytes)}。`);
  } catch (error) {
    const message = String(error);
    if (message.includes("PROCESS_CONFLICT")) {
      await openConflictModal();
    } else {
      showToast(message);
    }
  } finally {
    state.executing = false;
    render();
  }
}

async function openConflictModal() {
  try {
    state.conflicts = await callCommand("detect_conflicts", {
      itemIds: [...state.selected]
    });
    if (!state.conflicts.length) {
      await executeSelected({});
      return;
    }
    render();
  } catch (error) {
    showToast(String(error));
  }
}

async function restoreBackup(path) {
  if (!(await nativeConfirm("确认导入该注册表备份？", "恢复注册表备份"))) return;
  try {
    const result = await callCommand("restore_backup", { path });
    showToast(result.message);
  } catch (error) {
    showToast(String(error));
  }
}

function toggleAllVisible(checked) {
  for (const item of visibleItems()) {
    if (checked) state.selected.add(item.id);
    else state.selected.delete(item.id);
  }
  render({ preserveScroll: true });
}

function groupKey(moduleId, category) {
  return `${moduleId}:${category}`;
}

function treeGroups() {
  const modulesWithItems = modules
    .filter((module) => !["all", "restore", "whitelist"].includes(module.id))
    .filter((module) => state.activeModule === "all" || module.id === state.activeModule)
    .map((module) => {
      const moduleItems = state.items.filter((item) => item.module === module.id);
      const categories = [...new Set(moduleItems.map((item) => item.category || "其他"))].map(
        (category) => ({
          category,
          key: groupKey(module.id, category),
          items: moduleItems.filter((item) => (item.category || "其他") === category)
        })
      );
      return {
        ...module,
        items: moduleItems,
        categories
      };
    })
    .filter((module) => module.items.length);

  return modulesWithItems;
}

function expandedTreeKeys() {
  const keys = new Set();
  for (const module of treeGroups()) {
    keys.add(module.id);
  }
  return keys;
}

function groupState(items) {
  const checkedCount = items.filter((item) => state.selected.has(item.id)).length;
  return {
    checked: checkedCount === items.length && items.length > 0,
    partial: checkedCount > 0 && checkedCount < items.length,
    checkedCount
  };
}

function toggleItems(items, checked) {
  for (const item of items) {
    if (checked) state.selected.add(item.id);
    else state.selected.delete(item.id);
  }
  render({ preserveScroll: true });
}

async function runAction(action, payload = {}) {
  closeOverlays();
  if (action === "scan") await runScan();
  if (action === "execute") await executeSelected();
  if (action === "whitelist-selected") addItemsToWhitelist(selectedItems());
  if (action === "clear-whitelist") {
    if (await nativeConfirm("确认清空白名单？", "清空白名单")) {
      state.itemWhitelist = [];
      saveWhitelist();
      showToast("白名单已清空，重新扫描后恢复显示。");
      render({ preserveScroll: true });
    }
  }
  if (action === "select-visible") toggleAllVisible(true);
  if (action === "unselect-visible") toggleAllVisible(false);
  if (action === "reload-backups") await loadBackups();
  if (action === "admin") await relaunchAdmin();
  if (action === "show-all") {
    state.activeModule = "all";
    render();
  }
  if (action === "show-whitelist") {
    state.activeModule = "whitelist";
    render();
  }
  if (action === "show-restore") {
    state.activeModule = "restore";
    await loadBackups();
    render();
  }
  if (action === "whitelist-item" && payload.itemId) {
    const item = itemById(payload.itemId);
    if (item) addItemsToWhitelist([item]);
  }
  if (action === "toggle-item" && payload.itemId) {
    if (state.expanded.has(payload.itemId)) state.expanded.delete(payload.itemId);
    else state.expanded.add(payload.itemId);
    render({ preserveScroll: true });
  }
}

function renderNav() {
  return modules
    .map((module) => {
      const count =
        module.id === "restore"
          ? state.backups.length
          : module.id === "whitelist"
            ? state.itemWhitelist.length
            : module.id === "all"
              ? state.items.length
              : state.items.filter((item) => item.module === module.id).length;
      return `
        <button class="nav-item ${state.activeModule === module.id ? "active" : ""}" data-nav="${module.id}">
          <span class="nav-icon">${module.icon}</span>
          <span class="nav-label">${module.label}</span>
          <span class="count">${count}</span>
        </button>
      `;
    })
    .join("");
}

function renderSummary() {
  const data = totals();
  return `
    <div class="summary-grid">
      <div class="metric"><span>发现</span><strong>${data.allCount}</strong></div>
      <div class="metric"><span>选中</span><strong>${data.selectedCount}</strong></div>
      <div class="metric"><span>可清理</span><strong>${formatBytes(data.totalSize)}</strong></div>
      <div class="metric accent"><span>预计释放</span><strong>${formatBytes(data.selectedSize)}</strong></div>
    </div>
  `;
}

function renderToolbar() {
  const isRestore = state.activeModule === "restore";
  if (isRestore) {
    return `
      <div class="toolbar">
        <div class="toolbar-group">
          <button class="icon-button" data-action="reload-backups" title="刷新备份">↻</button>
        </div>
      </div>
    `;
  }

  if (state.activeModule === "whitelist") {
    return `
      <div class="toolbar">
        <div class="toolbar-group">
          <button class="primary command-button" data-action="scan" ${state.scanning ? "disabled" : ""}>开始扫描</button>
          <button class="danger" data-action="clear-whitelist" ${state.itemWhitelist.length ? "" : "disabled"}>清空白名单</button>
        </div>
      </div>
    `;
  }

  return `
    <div class="toolbar">
      <div class="toolbar-group">
        <button class="primary command-button" data-action="scan" ${state.scanning ? "disabled" : ""}>开始扫描</button>
        <button data-action="select-visible">全选</button>
        <button data-action="unselect-visible">取消</button>
        <button data-action="whitelist-selected" ${state.selected.size ? "" : "disabled"}>白名单</button>
        <button class="danger command-button" data-action="execute" ${state.executing || !state.selected.size ? "disabled" : ""}>清理</button>
      </div>
    </div>
  `;
}

function renderTitlebar(env) {
  const style = platformStyle(env?.platform || browserPlatform());
  const controlOrder = style === "macos" ? ["close", "minimize", "maximize"] : ["minimize", "maximize", "close"];
  const labels = {
    close: "关闭",
    minimize: "最小化",
    maximize: "最大化"
  };
  const controls = `
    <div class="window-controls ${style}" data-platform="${style}">
      ${controlOrder
        .map((action) => {
          const disabled = action === "maximize" ? " disabled" : "";
          const title = action === "maximize" ? "固定窗口大小" : labels[action];
          return `<button class="window-control ${action}" data-window="${action}" title="${title}" aria-label="${labels[action]}"${disabled}><span></span></button>`;
        })
        .join("")}
    </div>
  `;
  return `
    <header class="titlebar">
      ${style === "macos" ? controls : `<div></div>`}
      <div class="titlebar-center" data-window-drag>
        <span class="app-dot" data-window-drag></span>
        <span data-window-drag>DCleaner</span>
        <span class="titlebar-status ${env?.isAdmin ? "safe" : "warn"}" data-window-drag>${env?.isAdmin ? "管理员" : "普通权限"}</span>
      </div>
      ${style === "macos" ? `<div class="titlebar-spacer" data-window-drag></div>` : controls}
    </header>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderItems() {
  return renderTreeItems();
}

function renderTreeItems() {
  const grouped = treeGroups();
  if (!grouped.length) {
    return `<div class="panel empty-panel"><div class="empty">暂无扫描结果</div></div>`;
  }

  return `
    <div class="tree-panel">
      <div class="tree-row tree-header">
        <span></span>
        <span></span>
        <span>项目</span>
        <span class="tree-count">数量</span>
        <span class="tree-size">容量</span>
        <span>风险</span>
        <span class="tree-actions-label">操作</span>
      </div>
      ${grouped.map(renderModuleGroup).join("")}
    </div>
  `;
}

function renderModuleGroup(module) {
  const moduleState = groupState(module.items);
  const expanded = state.expanded.has(module.id);
  const totalSize = module.items.reduce((sum, item) => sum + item.sizeBytes, 0);
  return `
    <section class="tree-group">
      <div class="tree-row module-row">
        <button class="twisty ${expanded ? "expanded" : ""}" data-expand="${module.id}" title="${expanded ? "收起" : "展开"}" aria-label="${expanded ? "收起" : "展开"}"></button>
        <input type="checkbox" data-select-group="${module.id}" ${moduleState.checked ? "checked" : ""} ${moduleState.partial ? "data-partial=\"true\"" : ""} />
        <strong class="tree-name module-name">${module.label}</strong>
        <span class="tree-count">${moduleState.checkedCount} / ${module.items.length}</span>
        <span class="tree-size">${formatBytes(totalSize)}</span>
        <span></span>
        <span></span>
      </div>
      ${
        expanded
          ? `<div class="tree-children">
              ${module.categories.map((category) => renderCategoryGroup(module.id, category)).join("")}
            </div>`
          : ""
      }
    </section>
  `;
}

function renderCategoryGroup(moduleId, category) {
  const categoryState = groupState(category.items);
  const expanded = state.expanded.has(category.key);
  const totalSize = category.items.reduce((sum, item) => sum + item.sizeBytes, 0);
  return `
    <section class="tree-category">
      <div class="tree-row category-row">
        <button class="twisty ${expanded ? "expanded" : ""}" data-expand="${category.key}" title="${expanded ? "收起" : "展开"}" aria-label="${expanded ? "收起" : "展开"}"></button>
        <input type="checkbox" data-select-group="${category.key}" ${categoryState.checked ? "checked" : ""} ${categoryState.partial ? "data-partial=\"true\"" : ""} />
        <strong class="tree-name category-name">${escapeHtml(category.category)}</strong>
        <span class="tree-count">${categoryState.checkedCount} / ${category.items.length}</span>
        <span class="tree-size">${formatBytes(totalSize)}</span>
        <span></span>
        <span></span>
      </div>
      ${
        expanded
          ? `<div class="tree-items">
              ${category.items.map((item) => renderTreeItem(moduleId, category.category, item)).join("")}
            </div>`
          : ""
      }
    </section>
  `;
}

function renderTreeItem(moduleId, category, item) {
  const checked = state.selected.has(item.id) ? "checked" : "";
  const expanded = state.expanded.has(item.id);
  const detailTitle = `${item.detail}${item.path ? `\n${item.path}` : ""}`;
  const children =
    expanded && item.children.length
      ? `<div class="tree-file-list">
          ${item.children
            .map(
              (child) => `
                <div class="tree-file">
                  <span>${escapeHtml(child.path)}</span>
                  <span>${formatBytes(child.sizeBytes)}</span>
                </div>`
            )
            .join("")}
        </div>`
      : "";
  return `
    <div class="tree-item" data-item-row="${item.id}">
      <div class="tree-row leaf-row">
        <span></span>
        <input type="checkbox" data-select="${item.id}" ${checked} />
        <span class="name tree-name leaf-name">
          <strong title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</strong>
          <small title="${escapeHtml(detailTitle)}">${escapeHtml(item.detail)}</small>
        </span>
        <span class="tree-count placeholder"></span>
        <span class="tree-size">${formatBytes(item.sizeBytes)}</span>
        <span class="risk ${item.risk}">${riskLabel(item.risk)}</span>
        <span class="row-actions">
          ${
            item.children.length
              ? `<button class="subtle" data-expand="${item.id}">${expanded ? "收起" : "展开"} ${item.children.length}</button>`
              : ""
          }
          <button class="subtle" data-whitelist-item="${item.id}">白名单</button>
        </span>
      </div>
      ${children}
    </div>
  `;
}

function renderBackups() {
  if (!state.backups.length) {
    return `<div class="panel empty-panel"><div class="empty">暂无注册表备份</div></div>`;
  }

  return `
    <div class="panel restore-list">
      ${state.backups
        .map(
          (backup) => `
            <div class="backup-row">
              <strong title="${escapeHtml(backup.path)}">${escapeHtml(backup.name)}</strong>
              <span>${escapeHtml(backup.createdAt)}</span>
              <span>${formatBytes(backup.sizeBytes)}</span>
              <button data-restore="${escapeHtml(backup.path)}">恢复</button>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderWhitelistPage() {
  if (!state.itemWhitelist.length) {
    return `<div class="panel empty-panel"><div class="empty">暂无白名单项目</div></div>`;
  }

  return `
    <div class="panel whitelist-list">
      ${state.itemWhitelist
        .map(
          (entry) => `
            <div class="whitelist-row">
              <span>${moduleLabel(entry.module)}</span>
              <span>${escapeHtml(entry.category || "其他")}</span>
              <span class="name">
                <strong title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</strong>
              </span>
              <span class="risk ${entry.risk}">${riskLabel(entry.risk)}</span>
              <button data-remove-whitelist="${escapeHtml(entry.key)}">移除</button>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function renderContextMenu() {
  if (!state.contextMenu) return "";
  const item = itemById(state.contextMenu.itemId);
  if (!item) return "";
  const canExpand = item.children.length > 0;
  const expanded = state.expanded.has(item.id);
  const x = Math.min(state.contextMenu.x, window.innerWidth - 220);
  const y = Math.min(state.contextMenu.y, window.innerHeight - 146);
  return `
    <div class="context-menu" style="left:${x}px; top:${y}px">
      <button data-context-action="toggle-select" data-context-item="${item.id}">
        <span>${state.selected.has(item.id) ? "取消选择" : "选择项目"}</span>
        <kbd>Space</kbd>
      </button>
      <button data-context-action="whitelist" data-context-item="${item.id}">
        <span>加入白名单</span>
        <kbd>W</kbd>
      </button>
      <button data-context-action="expand" data-context-item="${item.id}" ${canExpand ? "" : "disabled"}>
        <span>${expanded ? "收起明细" : "展开明细"}</span>
        <kbd>Enter</kbd>
      </button>
    </div>
  `;
}

function renderModal() {
  if (state.conflicts.length) {
    return `
      <div class="modal-cover">
        <div class="modal">
          <header>
            <h3>检测到进程冲突</h3>
          </header>
          <div class="modal-body">
            <div class="conflict-list">
              ${state.conflicts
                .map(
                  (conflict) => `
                    <div class="conflict-item">
                      <strong>${escapeHtml(conflict.appName)}</strong>
                      <span>${escapeHtml(conflict.message)}</span>
                    </div>
                  `
                )
                .join("")}
            </div>
          </div>
          <footer>
            <button data-action="skip-conflicts">跳过此项</button>
            <button class="danger" data-action="kill-conflicts">结束进程并清理</button>
          </footer>
        </div>
      </div>
    `;
  }

  if (state.executing && state.progress) {
    const value = state.progress.total
      ? Math.round((state.progress.completed / state.progress.total) * 100)
      : 0;
    return `
      <div class="modal-cover">
        <div class="modal">
          <header><h3>正在清理</h3></header>
          <div class="modal-body">
            <p>${escapeHtml(state.progress.current || "处理中")}</p>
            <div class="progress-bar"><span style="width:${value}%"></span></div>
            <p>已释放 ${formatBytes(state.progress.freedBytes)}</p>
            ${
              state.progress.errors?.length
                ? `<ul class="log-list">${state.progress.errors
                    .map((item) => `<li>${escapeHtml(item)}</li>`)
                    .join("")}</ul>`
                : ""
            }
          </div>
        </div>
      </div>
    `;
  }

  return "";
}

function renderWarnings() {
  if (!state.errors.length) return "";
  return `
    <ul class="log-list">
      ${state.errors.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
    </ul>
  `;
}

function render(options = {}) {
  const previousMain = app.querySelector(".main");
  const previousScrollTop = options.preserveScroll ? previousMain?.scrollTop || 0 : 0;
  const data = totals();
  const env = state.env;
  const isRestore = state.activeModule === "restore";
  const isWhitelist = state.activeModule === "whitelist";
  const module = currentModule();
  app.innerHTML = `
    <div class="window-shell">
      ${renderTitlebar(env)}
      <div class="shell">
        <aside class="sidebar">
          <div class="brand">
            <div class="brand-mark">D</div>
            <div>
              <h1>DCleaner</h1>
              <span>Desktop Cleaner</span>
            </div>
          </div>
          <nav class="nav">${renderNav()}</nav>
        </aside>
        <main class="main">
          <div class="topbar">
            <div class="title">
              <span class="section-icon">${module.icon}</span>
              <div>
                <h2>${isRestore ? "恢复中心" : isWhitelist ? "白名单" : "扫描与清理"}</h2>
                <p>${
                  isRestore
                    ? "查看并导入历史注册表备份。"
                    : isWhitelist
                      ? "这些项目会从扫描结果中隐藏，执行清理时自动跳过。"
                      : `当前预计释放 ${formatBytes(data.selectedSize)}。`
                }</p>
              </div>
            </div>
            <div class="status-row">
              ${env && !env.isAdmin ? `<button data-action="admin">以管理员身份重启</button>` : ""}
            </div>
          </div>
          ${isRestore || isWhitelist ? "" : renderSummary()}
          ${renderToolbar()}
          ${isRestore ? renderBackups() : isWhitelist ? renderWhitelistPage() : renderItems()}
          ${renderWarnings()}
        </main>
      </div>
    </div>
    ${renderModal()}
    ${renderContextMenu()}
    ${state.toast ? `<div class="toast">${escapeHtml(state.toast)}</div>` : ""}
  `;
  syncPartialCheckboxes();
  if (options.preserveScroll) {
    const main = app.querySelector(".main");
    if (main) {
      const maxScrollTop = Math.max(0, main.scrollHeight - main.clientHeight);
      main.scrollTop = Math.min(previousScrollTop, maxScrollTop);
    }
  }
}

app.addEventListener("click", async (event) => {
  if (state.contextMenu && !event.target.closest(".context-menu")) {
    state.contextMenu = null;
    render({ preserveScroll: true });
    return;
  }

  const target = event.target.closest("button");
  const checkbox = event.target.closest("input[type='checkbox']");

  if (checkbox?.dataset.select) {
    if (checkbox.checked) state.selected.add(checkbox.dataset.select);
    else state.selected.delete(checkbox.dataset.select);
    render({ preserveScroll: true });
    return;
  }

  if (checkbox?.dataset.selectGroup) {
    const groupId = checkbox.dataset.selectGroup;
    const module = treeGroups().find((item) => item.id === groupId);
    if (module) {
      toggleItems(module.items, checkbox.checked);
      return;
    }
    for (const moduleGroup of treeGroups()) {
      const category = moduleGroup.categories.find((item) => item.key === groupId);
      if (category) {
        toggleItems(category.items, checkbox.checked);
        return;
      }
    }
  }

  if (!target) return;

  const windowAction = target.dataset.window;
  if (windowAction === "minimize") {
    await appWindow?.minimize();
    return;
  }
  if (windowAction === "close") {
    await appWindow?.close();
    return;
  }

  const contextAction = target.dataset.contextAction;
  if (contextAction) {
    const itemId = target.dataset.contextItem;
    if (contextAction === "toggle-select") {
      if (state.selected.has(itemId)) state.selected.delete(itemId);
      else state.selected.add(itemId);
      state.contextMenu = null;
      render({ preserveScroll: true });
    }
    if (contextAction === "whitelist") await runAction("whitelist-item", { itemId });
    if (contextAction === "expand") await runAction("toggle-item", { itemId });
    return;
  }

  const nav = target.dataset.nav;
  if (nav) {
    closeOverlays();
    state.activeModule = nav;
    state.page = 1;
    if (nav === "restore") await loadBackups();
    render();
    return;
  }

  const expand = target.dataset.expand;
  if (expand) {
    if (state.expanded.has(expand)) state.expanded.delete(expand);
    else state.expanded.add(expand);
    render({ preserveScroll: true });
    return;
  }

  const restore = target.dataset.restore;
  if (restore) {
    await restoreBackup(restore);
    return;
  }

  const whitelistItem = target.dataset.whitelistItem;
  if (whitelistItem) {
    const item = state.items.find((entry) => entry.id === whitelistItem);
    if (item) addItemsToWhitelist([item]);
    return;
  }

  const removeWhitelist = target.dataset.removeWhitelist;
  if (removeWhitelist) {
    removeWhitelistEntry(removeWhitelist);
    return;
  }

  const action = target.dataset.action;
  if (action) await runAction(action);
  if (action === "kill-conflicts") {
    const decisions = Object.fromEntries(state.conflicts.map((item) => [item.itemId, "kill"]));
    await executeSelected(decisions);
  }
  if (action === "skip-conflicts") {
    const decisions = Object.fromEntries(state.conflicts.map((item) => [item.itemId, "skip"]));
    await executeSelected(decisions);
  }
});

document.addEventListener("keydown", async (event) => {
  const activeTag = document.activeElement?.tagName?.toLowerCase();
  const isTextInput = ["input", "textarea"].includes(activeTag);
  if ((event.ctrlKey || event.metaKey) && ["+", "-", "=", "0"].includes(event.key)) {
    event.preventDefault();
  }
  if (event.key === "Escape") {
    if (state.contextMenu) {
      state.contextMenu = null;
      render({ preserveScroll: true });
      return;
    }
  }
  if (!isTextInput && event.key.toLowerCase() === "f5") {
    event.preventDefault();
    await runAction("scan");
  }
});

if (inTauri) {
  listen("clean-progress", (event) => {
    state.progress = event.payload;
    render({ preserveScroll: true });
  });
}

function syncPartialCheckboxes() {
  app.querySelectorAll("input[data-partial='true']").forEach((input) => {
    input.indeterminate = true;
  });
}

async function init() {
  render();
  await Promise.all([loadEnvironment(), loadBackups()]);
}

init().catch((error) => showToast(String(error)));
