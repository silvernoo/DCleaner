import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./styles.css";

const modules = [
  { id: "all", label: "全部" },
  { id: "system", label: "系统清理" },
  { id: "browser", label: "浏览器" },
  { id: "application", label: "第三方应用" },
  { id: "registry", label: "注册表" },
  { id: "restore", label: "恢复中心" }
];

const whitelistStorageKey = "dcleaner.cookieWhitelist";

function loadWhitelist() {
  try {
    const value = JSON.parse(window.localStorage.getItem(whitelistStorageKey) || "[]");
    return Array.isArray(value) ? value.filter(Boolean) : [];
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
  pageSize: 50,
  cookieWhitelist: loadWhitelist(),
  whitelistInput: "",
  progress: null,
  conflicts: [],
  toast: "",
  errors: []
};

const app = document.querySelector("#app");

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
  if (state.activeModule === "all") return state.items;
  return state.items.filter((item) => item.module === state.activeModule);
}

function pageItems() {
  const items = visibleItems();
  const start = (state.page - 1) * state.pageSize;
  return items.slice(start, start + state.pageSize);
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
  render();
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    state.toast = "";
    render();
  }, 3600);
}

async function loadEnvironment() {
  state.env = await invoke("get_environment");
  render();
}

async function loadBackups() {
  state.backups = await invoke("list_backups");
  render();
}

async function runScan() {
  state.scanning = true;
  state.progress = null;
  state.errors = [];
  render();
  try {
    const result = await invoke("scan_all", {
      options: {
        includeSystem: true,
        includeBrowsers: true,
        includeApplications: true,
        includeRegistry: true
      }
    });
    state.items = result.items;
    state.activeModule = "all";
    state.page = 1;
    state.expanded = expandedTreeKeys();
    state.selected = new Set();
    state.errors = result.warnings || [];
    showToast(`扫描完成：发现 ${result.items.length} 个可处理项目。`);
  } catch (error) {
    showToast(String(error));
  } finally {
    state.scanning = false;
    render();
  }
}

async function relaunchAdmin() {
  try {
    await invoke("relaunch_as_admin");
  } catch (error) {
    showToast(String(error));
  }
}

function whitelistDomains() {
  return state.cookieWhitelist;
}

function saveWhitelist() {
  window.localStorage.setItem(whitelistStorageKey, JSON.stringify(state.cookieWhitelist));
}

function normalizeDomain(value) {
  return value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/^\*\./, "")
    .split(/[/?#]/)[0]
    .split(":")[0]
    .replace(/^\.+|\.+$/g, "");
}

function addWhitelistEntry(value) {
  const domains = value
    .split(/[,\n;]/)
    .map(normalizeDomain)
    .filter(Boolean);
  if (!domains.length) return;
  const merged = new Set(state.cookieWhitelist);
  for (const domain of domains) {
    merged.add(domain);
  }
  state.cookieWhitelist = [...merged].sort();
  state.whitelistInput = "";
  saveWhitelist();
  render();
}

function removeWhitelistEntry(domain) {
  state.cookieWhitelist = state.cookieWhitelist.filter((item) => item !== domain);
  saveWhitelist();
  render();
}

async function executeSelected(decisions = {}) {
  const selectedIds = [...state.selected];
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
    const summary = await invoke("execute_clean", {
      request: {
        selectedIds,
        conflictDecisions: decisions,
        cookieWhitelist: whitelistDomains()
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
    state.conflicts = await invoke("detect_conflicts", {
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
  if (!window.confirm("确认导入该注册表备份？")) return;
  try {
    const result = await invoke("restore_backup", { path });
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
  render();
}

function groupKey(moduleId, category) {
  return `${moduleId}:${category}`;
}

function treeGroups() {
  const modulesWithItems = modules
    .filter((module) => !["all", "restore"].includes(module.id))
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
    for (const category of module.categories) {
      keys.add(category.key);
    }
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
  render();
}

function renderNav() {
  return modules
    .map((module) => {
      const count =
        module.id === "restore"
          ? state.backups.length
          : module.id === "all"
            ? state.items.length
            : state.items.filter((item) => item.module === module.id).length;
      return `
        <button class="${state.activeModule === module.id ? "active" : ""}" data-nav="${module.id}">
          <span>${module.label}</span>
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
      <div class="metric"><span>发现项目</span><strong>${data.allCount}</strong></div>
      <div class="metric"><span>已选择</span><strong>${data.selectedCount}</strong></div>
      <div class="metric"><span>可清理空间</span><strong>${formatBytes(data.totalSize)}</strong></div>
      <div class="metric"><span>预计释放</span><strong>${formatBytes(data.selectedSize)}</strong></div>
    </div>
  `;
}

function renderToolbar() {
  const isRestore = state.activeModule === "restore";
  if (isRestore) {
    return `
      <div class="toolbar">
        <div class="toolbar-group">
          <button data-action="reload-backups">刷新备份</button>
        </div>
      </div>
    `;
  }

  return `
    <div class="toolbar">
      <div class="toolbar-group">
        <button class="primary" data-action="scan" ${state.scanning ? "disabled" : ""}>扫描</button>
        <button data-action="select-visible">全选当前视图</button>
        <button data-action="unselect-visible">取消当前视图</button>
        <button class="danger" data-action="execute" ${state.executing || !state.selected.size ? "disabled" : ""}>执行清理</button>
      </div>
      <div class="whitelist">
        <label class="field">
          Cookie 白名单
          <input data-field="whitelistInput" value="${escapeHtml(state.whitelistInput)}" placeholder="example.com" />
        </label>
        <button data-action="add-whitelist">添加</button>
        <div class="whitelist-tags">
          ${
            state.cookieWhitelist.length
              ? state.cookieWhitelist
                  .map(
                    (domain) => `
                      <button class="tag" data-remove-whitelist="${escapeHtml(domain)}" title="移除 ${escapeHtml(domain)}">
                        ${escapeHtml(domain)} ×
                      </button>`
                  )
                  .join("")
              : `<span class="muted">未设置</span>`
          }
        </div>
      </div>
    </div>
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
  if (state.activeModule === "all") {
    return renderTreeItems();
  }

  const items = pageItems();
  const total = visibleItems().length;
  const pages = Math.max(1, Math.ceil(total / state.pageSize));

  if (!items.length) {
    return `<div class="panel"><div class="empty">暂无扫描结果</div></div>`;
  }

  const rows = items
    .map((item) => {
      const checked = state.selected.has(item.id) ? "checked" : "";
      const expanded = state.expanded.has(item.id);
      const children =
        expanded && item.children.length
          ? `<div class="children">
              ${item.children
                .map(
                  (child) => `
                    <div class="child-line">
                      <span>${escapeHtml(child.path)}</span>
                      <span>${formatBytes(child.sizeBytes)}</span>
                    </div>`
                )
                .join("")}
            </div>`
          : "";
      return `
        <div class="item-row">
          <label><input type="checkbox" data-select="${item.id}" ${checked} /></label>
          <span>${moduleLabel(item.module)}</span>
          <span class="name">
            <strong title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</strong>
            <small title="${escapeHtml(item.detail)}">${escapeHtml(item.detail)}</small>
          </span>
          <span class="path" title="${escapeHtml(item.path)}">${escapeHtml(item.path)}</span>
          <span>${formatBytes(item.sizeBytes)}</span>
          <span class="risk ${item.risk}">${riskLabel(item.risk)}</span>
          <span class="row-action">
            ${
              item.children.length
                ? `<button data-expand="${item.id}">${expanded ? "收起" : "展开"} ${item.children.length}</button>`
                : ""
            }
          </span>
          ${children}
        </div>
      `;
    })
    .join("");

  return `
    <div class="panel">
      <div class="table-head">
        <span></span>
        <span>模块</span>
        <span>项目</span>
        <span>路径 / 键值</span>
        <span>大小</span>
        <span>风险</span>
        <span>详情</span>
      </div>
      ${rows}
      <div class="pager">
        <button data-action="prev-page" ${state.page <= 1 ? "disabled" : ""}>上一页</button>
        <span>${state.page} / ${pages}</span>
        <button data-action="next-page" ${state.page >= pages ? "disabled" : ""}>下一页</button>
      </div>
    </div>
  `;
}

function renderTreeItems() {
  const grouped = treeGroups();
  if (!grouped.length) {
    return `<div class="panel"><div class="empty">暂无扫描结果</div></div>`;
  }

  return `
    <div class="tree-panel">
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
        <button class="twisty" data-expand="${module.id}" title="${expanded ? "收起" : "展开"}">${expanded ? "▾" : "▸"}</button>
        <input type="checkbox" data-select-group="${module.id}" ${moduleState.checked ? "checked" : ""} ${moduleState.partial ? "data-partial=\"true\"" : ""} />
        <strong>${module.label}</strong>
        <span>${moduleState.checkedCount} / ${module.items.length}</span>
        <span>${formatBytes(totalSize)}</span>
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
        <button class="twisty" data-expand="${category.key}" title="${expanded ? "收起" : "展开"}">${expanded ? "▾" : "▸"}</button>
        <input type="checkbox" data-select-group="${category.key}" ${categoryState.checked ? "checked" : ""} ${categoryState.partial ? "data-partial=\"true\"" : ""} />
        <strong>${escapeHtml(category.category)}</strong>
        <span>${categoryState.checkedCount} / ${category.items.length}</span>
        <span>${formatBytes(totalSize)}</span>
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
    <div class="tree-item">
      <div class="tree-row leaf-row">
        <span></span>
        <input type="checkbox" data-select="${item.id}" ${checked} />
        <span class="name">
          <strong title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</strong>
          <small title="${escapeHtml(item.detail)}">${escapeHtml(item.detail)}</small>
        </span>
        <span class="path" title="${escapeHtml(item.path)}">${escapeHtml(item.path)}</span>
        <span>${formatBytes(item.sizeBytes)}</span>
        <span class="risk ${item.risk}">${riskLabel(item.risk)}</span>
        ${
          item.children.length
            ? `<button data-expand="${item.id}">${expanded ? "收起" : "展开"} ${item.children.length}</button>`
            : "<span></span>"
        }
      </div>
      ${children}
    </div>
  `;
}

function renderBackups() {
  if (!state.backups.length) {
    return `<div class="panel"><div class="empty">暂无注册表备份</div></div>`;
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

function render() {
  const data = totals();
  const env = state.env;
  const isRestore = state.activeModule === "restore";
  app.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark">D</div>
          <h1>DCleaner</h1>
        </div>
        <nav class="nav">${renderNav()}</nav>
        <div class="sidebar-footer">
          <div>扫描后默认不勾选。</div>
          <div>注册表清理会先生成 .reg 备份。</div>
        </div>
      </aside>
      <main class="main">
        <div class="topbar">
          <div class="title">
            <h2>${isRestore ? "恢复中心" : "扫描与清理"}</h2>
            <p>${isRestore ? "查看并导入历史注册表备份。" : `当前预计释放 ${formatBytes(data.selectedSize)}。`}</p>
          </div>
          <div class="status-row">
            <span class="badge ${env?.isAdmin ? "safe" : "warn"}">${env?.isAdmin ? "管理员权限" : "普通权限"}</span>
            ${env && !env.isAdmin ? `<button data-action="admin">以管理员身份重启</button>` : ""}
          </div>
        </div>
        ${renderSummary()}
        ${renderToolbar()}
        ${isRestore ? renderBackups() : renderItems()}
        ${renderWarnings()}
      </main>
    </div>
    ${renderModal()}
    ${state.toast ? `<div class="toast">${escapeHtml(state.toast)}</div>` : ""}
  `;
  syncPartialCheckboxes();
}

app.addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  const checkbox = event.target.closest("input[type='checkbox']");

  if (checkbox?.dataset.select) {
    if (checkbox.checked) state.selected.add(checkbox.dataset.select);
    else state.selected.delete(checkbox.dataset.select);
    render();
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

  const nav = target.dataset.nav;
  if (nav) {
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
    render();
    return;
  }

  const restore = target.dataset.restore;
  if (restore) {
    await restoreBackup(restore);
    return;
  }

  const removeWhitelist = target.dataset.removeWhitelist;
  if (removeWhitelist) {
    removeWhitelistEntry(removeWhitelist);
    return;
  }

  const action = target.dataset.action;
  if (action === "scan") await runScan();
  if (action === "add-whitelist") addWhitelistEntry(state.whitelistInput);
  if (action === "execute") await executeSelected();
  if (action === "select-visible") toggleAllVisible(true);
  if (action === "unselect-visible") toggleAllVisible(false);
  if (action === "prev-page" && state.page > 1) {
    state.page -= 1;
    render();
  }
  if (action === "next-page") {
    const pages = Math.max(1, Math.ceil(visibleItems().length / state.pageSize));
    if (state.page < pages) state.page += 1;
    render();
  }
  if (action === "reload-backups") await loadBackups();
  if (action === "admin") await relaunchAdmin();
  if (action === "kill-conflicts") {
    const decisions = Object.fromEntries(state.conflicts.map((item) => [item.itemId, "kill"]));
    await executeSelected(decisions);
  }
  if (action === "skip-conflicts") {
    const decisions = Object.fromEntries(state.conflicts.map((item) => [item.itemId, "skip"]));
    await executeSelected(decisions);
  }
});

app.addEventListener("input", (event) => {
  if (event.target.dataset.field === "whitelistInput") {
    state.whitelistInput = event.target.value;
  }
});

app.addEventListener("keydown", (event) => {
  if (event.target.dataset.field === "whitelistInput" && event.key === "Enter") {
    event.preventDefault();
    addWhitelistEntry(state.whitelistInput);
  }
});

listen("clean-progress", (event) => {
  state.progress = event.payload;
  render();
});

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
