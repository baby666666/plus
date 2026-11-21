# NativeRouting 2.0

基于 iKuai x86_64 3.7.26 的固件源码与构建仓库。功能包括域名、端口和协议分流，源地址与接入接口匹配，多出口和断线策略，WG 接入与出口，运行状态、日志时区、加密 DNS 限制及 sing-box 配置导出。

[2.0 下载](https://github.com/baby666666/plus/releases/tag/v2.0.0) · [安装与升级](docs/INSTALL.md) · [完整构建步骤](docs/BUILD.md) · [AI 接手](docs/AI_HANDOFF.md) · [测试方法](docs/TESTING.md)

## 大陆手机接入境外爱快

**NativeRouting 2.0** 在 WG 隧道编辑页提供两种连接方式。原生 WireGuard 支持手机经爱快出网、爱快借用设备网络和双向上网，手机可直接复制标准 WG 配置或完整 sing-box JSON，也可扫码。纯 Hysteria 2 供手机或另一台爱快经本路由器的 WAN 上网，可在手机上复制完整 sing-box 配置或 HY2 分享链接，每台设备使用独立的公网 UDP 端口和凭据。[设备用途](docs/WG-DEVICES.md) · [纯 HY2 扫码设置](docs/PURE-HY2.md)

旧版「Hysteria 2 承载 WG」设备在升级后停用。需要继续使用时，从中心选择支持的方式，保存并重新配置对端。已有原生 WG 和单向纯 HY2 可沿用原配置。两台爱快可以粘贴设备配置，局域网互访使用原生 WG 的互访网段。[路由器导入与组网](docs/HY2-SITE.md)

## 从当前交付开始

1. 阅读 [AGENTS.md](AGENTS.md) 和 [AI 接手说明](docs/AI_HANDOFF.md)，核对 [release.json](release.json) 中的版本、文件名和摘要。
2. 按 [BUILD.md](docs/BUILD.md) 下载当前标签的源码与同版 Release 附件，安装固定依赖并校验材料。
3. 用 `tools/rebuild.py` 生成升级 BIN，`tools/cloud_from_rebuild.py` 生成安装镜像；执行宿主回归、BIOS/UEFI 启动和原生升级验证。

| 内容 | 入口 |
| --- | --- |
| 版本、交付文件和 SHA256 | [release.json](release.json)、[SHA256SUMS](SHA256SUMS) |
| 升级 BIN、安装镜像、固定构建输入和校验文件 | [2.0 Release](https://github.com/baby666666/plus/releases/tag/v2.0.0) |
| 打包运行文件 | `materials/firmware/port-3726/files/` |
| 可编辑网页、后台脚本及 C 源对应 | [代码地图](docs/AI_HANDOFF.md#代码地图) |
| 功能与交付说明 | [RELEASE.md](docs/RELEASE.md) |

重建依赖当前源码和同版 Release 的 `NativeRouting-2.0-build-inputs.tar.gz`。厂商基础系统为闭源；本仓库提供可编辑覆盖源码、固定基础输入、配套构建工具及精确 ELF，并非全系统源码编译。独立构建会生成新的签名密钥，产物哈希会变化，须按 [测试方法](docs/TESTING.md) 单独验收。
