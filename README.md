# DCleaner

DCleaner 是一个只面向 Windows 的 Tauri + Rust 清理工具，实现了 PRD 中的核心流程：

1. 只读扫描系统、浏览器、第三方应用与注册表。
2. 展示分类、路径、大小、风险等级与可展开文件预览。
3. 扫描后默认不勾选，用户通过树形选择器主动选择。
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

- Windows 系统清理：临时文件、回收站、剪贴板、Explorer 历史记录、缩略图缓存、错误报告、字体缓存、Chkdsk 碎片、内存转储、Windows 日志、DNS 缓存、预读文件和高级 Explorer 缓存项。
- 浏览器清理：Chrome、Edge、Chromium、Brave、Vivaldi、Opera、Firefox 的缓存、历史记录、Cookie、下载历史、最后下载位置、Session 数据、保存的密码、表单信息、网站偏好设置和数据库压缩。
- 扫描项白名单：从扫描结果中直接加入白名单；白名单项会从当前结果移除、执行时跳过，并在下次扫描隐藏。
- 第三方应用清理：VS Code、Slack、Discord、Teams、VLC、Spotify、Sublime Text、Adobe Acrobat、npm、Windows 商店应用、Defender 日志、Office/WinRAR/7-Zip 等 MRU 和解压缩临时文件。
- 注册表扫描：缺失 SharedDLL、未使用扩展名、卸载残留、无效 App Paths、无效字体记录、失效启动项、COM/ActiveX、TypeLib、MUI 缓存、声音事件和 Windows 服务。
- 注册表备份与恢复：删除前导出到应用数据目录的 `Backup` 文件夹。

## 安全说明

- 前端只传递扫描结果 ID，真实路径与动作保存在 Rust 后端状态中，避免由 UI 构造任意删除路径。
- 注册表高风险项默认不勾选。
- 浏览器和第三方应用清理在执行时检测运行进程，必须由用户选择跳过或结束进程。
- 扫描结果默认不勾选；所有清理页都使用树形选择器，“全部”页会自动展开到第二级分类，浏览器项按 Chrome、Edge、Firefox 等浏览器分组。
- 白名单按稳定扫描项 key 保存，不依赖每次扫描生成的临时 ID。
- 后端清理动作优先使用 Win32 API、Rust 文件 API、SQLite 和 `winreg`，不再通过 `reg.exe`、`ipconfig`、`tasklist`、`taskkill`、PowerShell 或 `cmd` 执行清理。
- 非 Windows 不是支持目标，构建配置会阻止产出其他平台版本。
