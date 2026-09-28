# Turb GPT Register

> 本地运行的账号注册流程管理工具，提供 CLI、WebUI 和可插拔的注册驱动。

本项目基于 [xiaoguzuiniu/gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register) 整理和扩展，支持通过本地配置连接邮箱服务、代理及浏览器运行环境。仓库包含协议注册驱动，也支持通过本地指纹浏览器执行需要浏览器交互的流程。

> **使用范围**：仅在获得授权并遵守相关服务条款、适用法律及第三方邮箱和代理服务规则的前提下使用。请勿将本项目用于未经授权的账号创建或滥用服务。本项目不提供账号、邮箱、代理或第三方服务凭据。

## 功能一览

- **CLI 与本地 WebUI**：配置运行参数并管理注册任务。
- **可插拔邮箱来源**：按需配置支持的邮箱服务。
- **多种注册运行方式**：包含协议驱动和本地指纹浏览器驱动。
- **代理与浏览器配置**：从本地配置中读取连接信息及运行选项。
- **本地数据管理**：运行状态、账号记录和导出由本机保存。

## 快速开始

建议使用 Python 3.11。在仓库根目录执行：

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python web.py
```

启动后按本地 WebUI 的提示填写自己的邮箱服务和代理配置。不要把真实凭据写入 `.env.example` 或提交到 Git。协议注册组件位于 `vendor/gpt-register-tool/协议`；独立运行该组件时，请按其目录中的说明安装对应依赖。浏览器驱动还可能需要额外安装浏览器或供应商客户端。

## 项目结构

| 路径 | 内容 |
| --- | --- |
| `config/` | 本地运行配置和环境变量读取 |
| `core/` | 注册、邮箱、浏览器、代理及数据处理模块 |
| `webui/` | 本地 WebUI 服务与页面 |
| `tools/` | 辅助命令行工具 |
| `vendor/gpt-register-tool/协议/` | 协议注册组件及其上游文件 |

## 数据与安全

凭据、邮箱池、账号数据库、浏览器配置文件、日志和导出数据属于本地运行数据，不应提交到仓库。`.gitignore` 已排除常见运行数据路径；发布前仍应检查待提交文件和 Git 历史，避免误带个人数据或密钥。

## 来源与许可

主项目按 MIT License 发布，详见 [LICENSE](LICENSE)。`vendor/gpt-register-tool/协议` 中的组件保留其上游许可证及版权说明。主项目基于 [gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register) 改造。
