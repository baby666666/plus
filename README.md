# NativeRouting 1.0

基于 iKuai x86_64 3.7.26 的固件源码与构建仓库。功能包括域名、端口和协议分流，源地址与接入接口匹配，多出口和断线策略，WG 接入与出口，运行状态、日志时区、加密 DNS 限制及 sing-box 配置导出。

[1.0 下载](https://github.com/baby666666/plus/releases/tag/v1.0.0) · [安装与升级](docs/INSTALL.md) · [完整构建步骤](docs/BUILD.md) · [AI 接手](docs/AI_HANDOFF.md) · [测试方法](docs/TESTING.md)

## 从当前交付开始

1. 阅读 [AGENTS.md](AGENTS.md) 和 [AI 接手说明](docs/AI_HANDOFF.md)，核对 [release.json](release.json) 中的版本、文件名和摘要。
2. 按 [BUILD.md](docs/BUILD.md) 下载当前标签的源码与同版 Release 附件，安装固定依赖并校验材料。
3. 用 `tools/rebuild.py` 生成升级 BIN，`tools/cloud_from_rebuild.py` 生成安装镜像；执行宿主回归、BIOS/UEFI 启动和原生升级验证。

| 内容 | 入口 |
| --- | --- |
| 版本、交付文件和 SHA256 | [release.json](release.json)、[SHA256SUMS](SHA256SUMS) |
| 升级 BIN、安装镜像、固定构建输入和校验文件 | [1.0 Release](https://github.com/baby666666/plus/releases/tag/v1.0.0) |
| 打包运行文件 | `materials/firmware/port-3726/files/` |
| 可编辑网页、后台脚本及 C 源对应 | [代码地图](docs/AI_HANDOFF.md#代码地图) |
| 功能与交付说明 | [RELEASE.md](docs/RELEASE.md) |

重建依赖当前源码和同版 Release 的 `NativeRouting-1.0-build-inputs.tar.gz`。厂商基础系统为闭源；本仓库提供可编辑覆盖源码、固定基础输入、配套构建工具及精确 ELF，并非全系统源码编译。独立构建会生成新的签名密钥，产物哈希会变化，须按 [测试方法](docs/TESTING.md) 单独验收。
