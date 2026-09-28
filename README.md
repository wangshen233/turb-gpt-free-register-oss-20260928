# Turb GPT Register

本项目基于 [xiaoguzuiniu/gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register) 改造，提供本地运行的账号注册流程管理界面和可插拔注册驱动。支持通过环境配置连接邮箱服务、代理和浏览器运行环境。

## 内容

- CLI 与本地 WebUI
- 邮箱来源适配器与协议注册驱动
- 浏览器自动化驱动接口
- 本机 SOCKS 代理桥接工具

## 安装

建议使用 Python 3.11。安装依赖后复制 `.env.example` 为 `.env`，再在本地 WebUI 中配置邮箱来源与代理。凭据、邮箱池、账号数据库、日志和导出文件仅保存在本机，不要提交到代码仓库。

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python web.py
```

协议驱动位于 `vendor/gpt-register-tool/协议`，其独立依赖见该目录的 `requirements.txt`。不同驱动可能需要额外安装浏览器或供应商客户端。

请仅在获得授权并遵守相关服务条款、适用法律和第三方邮箱/代理服务规则的环境中使用。本软件不会提供邮箱、账号、代理或服务凭据。

## 数据与安全

运行配置和运行数据不应进入版本控制。`.gitignore` 已排除 `.env`、本地数据库、邮箱池、代理列表、日志、缓存、账号导出和任务状态文件。公开发布前请再次扫描所有待提交文件和 Git 历史。

## License

MIT，见 [LICENSE](LICENSE)。协议注册依赖目录另有其上游许可证。
