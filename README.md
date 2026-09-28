# Turb GPT Register

> 碰到问题欢迎开 Issue 或提 PR。把报错、运行环境和复现步骤带上，通常比一句“不能用”更容易把问题解决。

**Turb GPT Register** 是一套在本机运行的注册流程工具，基于 [gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register) 整理和扩展。它把邮箱、代理和注册流程放在同一个地方管理，既能走协议驱动，也能接本地指纹浏览器。你可以从命令行启动，也可以打开 WebUI 配置和管理任务。

这类流程牵涉的服务不少：邮箱提供商会改接口，代理可能抽风，浏览器环境也各有脾气。所以项目把这些部分拆成配置和驱动，方便按自己的环境接起来。听上去很优雅，实际碰到第三方服务变更时，该报错还是会报错；遇到问题先看日志和配置，别指望程序能隔空猜中是哪一环掉链子。

## 怎么跑起来

建议使用 Python 3.11。在仓库根目录打开 PowerShell：

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python web.py
```

启动后在本地 WebUI 里填自己的邮箱服务和代理配置。`.env.example` 只是配置样例，照着改成自己的 `.env` 就好，真实凭据别往样例文件或 Git 里塞。

协议注册组件放在 `vendor/gpt-register-tool/协议`。想单独运行它，就按那个目录里的说明装对应依赖。浏览器驱动也可能需要额外的浏览器或供应商客户端；`pip install` 不会替你把这些东西变出来。

## 里面有什么

主程序在 `core/`，配置在 `config/`，本地管理页面在 `webui/`，一些辅助脚本放在 `tools/`。协议注册组件连同它自己的文件放在 `vendor/gpt-register-tool/协议`。入口不多，按目录找通常比满仓库搜索来得快。

项目会把运行配置和结果留在本机。邮箱池、代理凭据、账号数据库、浏览器资料、日志和导出文件都属于自己的运行数据，别提交进仓库。`.gitignore` 已经挡住了常见的数据文件，但提交前扫一眼总没坏处——Git 不会因为文件名看起来无辜就替你保密。

## 来源与许可

主项目基于 [xiaoguzuiniu/gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register) 改造，按 MIT License 发布，见 [LICENSE](LICENSE)。`vendor/gpt-register-tool/协议` 里的组件保留各自上游的许可证和版权说明，使用前也记得看一眼。

请只在自己有权使用的环境里运行，并遵守相关服务、邮箱和代理提供方的规则。这个项目负责把流程接起来，不会附送账号、邮箱、代理，也不会替第三方服务承诺可用性。
