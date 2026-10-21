# IDA MCP — IDA 8.0 Pro 兼容版

面向 **Windows + IDA 8.0 Pro + IDAPython** 的 MCP 兼容分支，基于 [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp) 修改。让采用 Claude Code 风格 MCP 配置的 Agent 调用 IDA，进行函数分析、反编译、交叉引用查询和数据库操作。

本仓库包含适配后的 **IDA Nexus、IDA Domain**，以及 Windows 一键安装配置脚本。部署时请使用本仓库中的完整源码和锁定依赖。

**后台加载已实现：配置控制台后端后，Agent 可直接调用 `open_database` 加载文件，无需提前在 IDA GUI 中打开。IDA 8.0 Pro 的后台模式仍待实机验收；目前已通过 IDA 9.5 控制台的端到端验证。**

## 适配能力与验证状态

- **IDA 8.0 Pro GUI 接入**：适配旧版 IDAPython 接口、插件加载和数据库注册。
- **自动后台加载**：通过 `idat64.exe` / `idat.exe` 启动控制台工作进程，完成加载、分析和 MCP 请求处理；Windows 下不显示控制台窗口。
- **数据库生命周期管理**：支持多客户端共享同一数据库、不同文件使用独立进程，以及最后一个客户端释放连接后保存并退出。
- **兼容依赖**：修复 `ea_t` 导入、`XrefsFlags.CODE`、交叉引用标志、类型和字节搜索等旧 SDK 差异。
- **一键部署**：同步依赖、更新 GUI 插件、生成 JSON 配置，并检查包版本、源码路径和 MCP 启动。

| 验证项目 | 当前状态 |
| --- | --- |
| IDA 8.0 Pro GUI 插件启动、数据库注册 | 已由目标电脑确认成功 |
| IDA 8.0 Pro 完整分析及后台加载 | 待目标电脑实测 |
| IDA 9.5 控制台加载、分析、反编译、保存和关闭 | 已通过真实 MCP 测试 |
| 控制台共享、超时中断、保存重开、丢弃修改、空闲退出 | 已通过 IDA 9.5 实测 |
| Windows 一键安装、配置备份合并、重复执行 | 已通过本机测试 |

本分支仍属于实验性适配。详细接口差异和验证报告见 [IDA 8.0 兼容说明](docs/IDA80.md)。

## 环境要求

| 组件 | 要求 |
| --- | --- |
| 操作系统 | Windows；一键脚本使用系统自带的 Windows PowerShell |
| IDA | 已安装并可运行的 **IDA 8.0 Pro**，默认目录为 `C:\Program Files\IDA Pro 8.0` |
| IDAPython | 在 IDA 内使用 Python **3.10 或更新版本** |
| 后台模式 | 安装目录中存在 `idat64.exe` 或 `idat.exe`，且能加载 IDAPython |
| 外部 MCP 服务 | Python **3.11+**；`uv` 按仓库配置准备运行环境 |
| Agent | 支持标准 stdio MCP，配置格式使用 `mcpServers` |

IDA 内嵌 Python 与外部 MCP 的 Python 是两个独立环境。安装脚本不会修改 IDA 的 Python 绑定；需要调整时，请使用对应 IDA 安装目录中的 `idapyswitch`。

本项目不为 IDA Freeware 8.0 提供其缺失的 IDAPython。默认部署要求 **Agent、MCP 服务和 IDA 位于同一台 Windows 电脑，并使用同一用户运行**。

## Windows 一键安装部署

### 1. 获取完整仓库

使用 Git 下载：

```powershell
git clone https://github.com/4B5F5F4B/ida-mcp.git
cd ida-mcp
```

也可以下载并解压完整源码 ZIP。保留 `vendor`、`scripts` 等目录，不能只复制 BAT 文件。

### 2. 运行安装脚本

保存并关闭 IDA，停止 Agent 中已有的 MCP 连接，然后双击仓库根目录中的 [install_one_click.bat](install_one_click.bat)，或在 PowerShell 中运行：

```powershell
.\install_one_click.bat
```

默认 IDA 路径为 **`C:\Program Files\IDA Pro 8.0`**。脚本会：

1. 查找 `uv`；缺失时通过 Astral 官方安装器安装到用户目录。
2. 执行 `uv sync --locked`，安装本仓库的兼容依赖。
3. 更新 GUI 插件及其依赖副本，并备份旧文件。
4. 检查包版本、源码路径及 MCP stdio 启动，确认六个工具可用。
5. 在仓库根目录生成或更新 **`.mcp.json`**，默认服务名为 **`ida80`**。

已有 JSON 配置会先备份，再更新指定服务条目；其他 MCP 服务和设置会保留。默认安装不需要管理员权限。首次下载依赖需要联网。

### 3. 接入 Agent

对于 Claude Code，在包含生成的 `.mcp.json` 的项目目录中启动客户端。对于其他采用相同 JSON 格式的 Agent，将生成的 `mcpServers.ida80` 条目合并到该 Agent 的 MCP 配置中。

也可以让安装脚本直接更新指定项目或 Agent 的配置文件：

```powershell
.\install_one_click.bat -ConfigPath 'D:\work\my-project\.mcp.json'
```

安装完成后，重启 Agent 或重新连接 MCP。生成的配置包含本机绝对路径，移动仓库后需要重新运行脚本。

### 常用安装参数

```powershell
# 指定其他 IDA 安装目录
.\install_one_click.bat -IdaDir 'D:\IDA Pro 8.0'

# 只部署后台模式，不复制 GUI 插件
.\install_one_click.bat -SkipGui

# 更新自定义位置的 GUI 插件
.\install_one_click.bat -PluginsDir 'D:\IDA-user\plugins'

# 安装后立即验证真实后台分析，使用测试程序副本
.\install_one_click.bat -TestBinary 'D:\samples\console-test.exe'

# 自动化执行，结束时不等待按 Enter
.\install_one_click.bat -NoPause
```

`-ServerName` 可修改默认的 `ida80` 服务名。脚本失败时返回非零退出码。

**未指定 `-TestBinary` 时，成功表示依赖安装和 MCP 启动检查通过；实际 IDA 加载、分析需要运行下面的实机验证。**

## 手动安装与 MCP 配置

在本仓库根目录执行：

```powershell
uv sync --locked

# 使用 GUI 接入时安装或更新插件；纯后台模式不需要此步骤
uv run --locked python scripts/install_ida80.py
```

GUI 插件默认写入：

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp_plugin.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp_deps\
```

设置了 `IDAUSR` 时使用其第一个目录下的 `plugins`。旧插件备份位于相邻的 `ida-mcp-backups` 目录。

下面是 Claude Code 风格的 JSON 配置示例。将 `D:\code\ida-mcp` 替换为实际仓库路径；若 Agent 找不到 `uv`，将 `command` 改为 `uv.exe` 的完整路径。一键脚本会自动填写这些路径。

```json
{
  "mcpServers": {
    "ida80": {
      "command": "uv",
      "args": [
        "--directory",
        "D:\\code\\ida-mcp",
        "run",
        "--locked",
        "ida-mcp",
        "stdio",
        "--agent=code-agent"
      ],
      "env": {
        "IDA_NEXUS_IDAT": "C:\\Program Files\\IDA Pro 8.0"
      }
    }
  }
}
```

`IDA_NEXUS_IDAT` 指定后台工作进程使用的 IDA 安装目录，也可设置为控制台程序的完整路径。`--agent` 是区分客户端会话的标签。

**请保留 `uv --directory ... run --locked` 这一启动方式。** `uvx ida-mcp`、上游 marketplace 或 hcli 安装方式会获取上游发行版，无法保证使用本仓库的 IDA 8.0 兼容补丁。

## 使用方式

### 直接后台分析文件

配置 `IDA_NEXUS_IDAT` 后，不必打开 IDA GUI，直接向 Agent 发送：

> 使用 ida80 MCP，调用 open_database 打开 D:\samples\program.exe，读取 reference，然后列出前 10 个函数并分析入口函数。

新建的控制台工作进程返回 **`backend: "idat"`**。如果同一目标已经在已注册的 GUI 中打开，服务会复用该数据库。

### 连接已有 GUI 数据库

安装 GUI 插件后，在 IDA 中打开文件，确认输出：

```text
[ida-mcp] Database registered successfully!
```

然后让 Agent 调用 `list_databases` 选择数据库，并用 `open_database` 连接。

| MCP 工具 | 用途 |
| --- | --- |
| `open_database` | 连接已有数据库，或自动启动配置好的后台工作进程 |
| `execute_python` | 在 IDA 内执行分析代码，使用注入的 `db` 访问 Domain API |
| `reference` | 查询 API 使用说明 |
| `list_databases` | 查看可用数据库实例 |
| `save_database` | 保存数据库 |
| `close_database` | 释放当前客户端连接；最后一个连接释放后，受管后台进程保存并退出 |

IDA 8 的后台实现使用控制台宿主和主线程请求队列。原有 IDA 9.4+ `idalib` 后端仍保留；实现说明见 [后台加载实现](docs/IDA80.md#automatic-background-loading-ida804)。

## 更新已安装版本

保存并关闭 IDA，停止已有 MCP 连接，然后在仓库目录执行：

```powershell
git pull --ff-only
.\install_one_click.bat
```

如果首次安装时指定了 `-ConfigPath` 或 `-PluginsDir`，更新时继续使用相同参数。仅 `git pull` 不会替换已经复制到 GUI 插件目录的依赖。更新完成后重新启动 Agent；需要 GUI 接入时再启动 IDA。

检查外部 MCP 环境中的兼容依赖版本：

```powershell
uv run --locked python -c "from importlib.metadata import version; print('ida-nexus:', version('ida-nexus')); print('ida-domain:', version('ida-domain'))"
```

当前兼容版本：

```text
ida-nexus: 0.13.4+ida80.4
ida-domain: 0.5.1+ida80.4
```

## IDA 8.0 实机验证

将一个小型可执行文件复制到新目录，确保没有已有数据库，保持 IDA GUI 关闭，然后执行：

```powershell
uv run --locked python scripts/verify_ida.py `
  --database 'D:\samples\console-test.exe' `
  --idat 'C:\Program Files\IDA Pro 8.0' `
  --expect-version 8.0 --headless-only `
  --output ida80-headless-report.json
```

验证会检查实际加载的兼容依赖，以及函数、反编译（可用时）、交叉引用、保存和关闭等操作。成功报告应包含 `kernel: "8.0"`、`backend: "idat"` 和 `success: true`。

进一步验证多客户端共享、进程退出和保存行为：

```powershell
uv run --locked python scripts/verify_idat_lifecycle.py `
  --binary 'D:\samples\console-test.exe' `
  --idat 'C:\Program Files\IDA Pro 8.0' `
  --expect-version 8.0 --output ida80-lifecycle-report.json
```

生命周期脚本会自动创建测试副本。失败时请提供完整错误和生成的 JSON 报告，以便定位目标机器的兼容问题。

## 日志与排查

从本仓库运行：

```powershell
uv run --locked ida-mcp dashboard --open
uv run --locked ida-mcp logs
```

- **找不到控制台程序**：检查 IDA 安装目录内的 `idat64.exe` / `idat.exe`，或通过 `-IdaDir` 指定正确目录。
- **仍加载旧依赖**：确认 Agent 的启动路径指向本仓库，重新安装 GUI 插件并重启相关进程。
- **Agent 中没有工具**：确认客户端读取的是生成的 `.mcp.json` 或指定的配置文件；它不会自动读取任意目录中的配置。
- **MCP 启动成功但分析失败**：运行实机验证脚本。安装检查不会打开数据库，无法代替 IDA 内嵌 Python 和加载器验证。

## 上游项目与兼容代码

本项目保留上游许可证，兼容修改位于本仓库及 `vendor` 目录中。

- [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp)
- [IDA Nexus](https://github.com/HexRaysSA/ida-nexus)
- [兼容依赖来源与版本](vendor/README.md)
- [适配细节、安装说明和验证记录](docs/IDA80.md)
