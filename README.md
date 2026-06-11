# DCleaner

DCleaner 是一个只面向 Windows 的 Tauri + Rust 清理工具，实现了 PRD 中的核心流程：

1. 只读扫描系统、浏览器、第三方应用与注册表。
2. 展示分类、路径、大小、风险等级与可展开文件预览。
3. 默认勾选安全项，高风险项默认不勾选。
4. 执行前检测浏览器/应用进程冲突，并要求选择跳过或结束进程。
5. 注册表删除前强制导出 `.reg` 备份，并在恢复中心提供导入恢复。

## 技术栈

- Tauri 2
- Rust
- Vite + 原生 JavaScript

## 本地运行

```bash
npm install
npm run tauri:dev
```

请在 Windows 上运行。应用 manifest 默认请求管理员权限，启动时会触发 UAC。

## 构建

```bash
npm run tauri:build
```

项目配置为 Windows-only，Tauri bundle 只生成 NSIS 安装包。非 Windows 目标会在构建脚本阶段直接失败。

若在其他系统上做交叉检查，请显式指定 Windows target：

```bash
cd src-tauri
cargo check --target x86_64-pc-windows-gnu
```

## 已覆盖功能

- Windows 系统清理：临时文件、回收站、剪贴板、内存转储、Windows 日志、DNS 缓存、预读文件。
- 浏览器清理：Chrome、Edge、Chromium、Brave、Firefox 的缓存、历史记录、Cookie、下载历史、Session 数据。
- Cookie 白名单：在界面中添加/移除域名并持久化保存，执行清理时保留该域名及其子域名 Cookie。
- 第三方应用清理：VS Code、Slack、Discord、Teams、VLC、npm 缓存、解压缩临时文件。
- 注册表扫描：缺失 SharedDLL、未使用扩展名、卸载残留、无效 App Paths、无效字体记录、失效启动项。
- 注册表备份与恢复：删除前导出到应用数据目录的 `Backup` 文件夹。

## 安全说明

- 前端只传递扫描结果 ID，真实路径与动作保存在 Rust 后端状态中，避免由 UI 构造任意删除路径。
- 注册表高风险项默认不勾选。
- 浏览器和第三方应用清理在执行时检测运行进程，必须由用户选择跳过或结束进程。
- 扫描结果默认不勾选；“全部”页会自动展开树形选择器，浏览器项按 Chrome、Edge、Firefox 等浏览器分组。
- 非 Windows 不是支持目标，构建配置会阻止产出其他平台版本。
