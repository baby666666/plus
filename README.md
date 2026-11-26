# NativeRouting 3.0

基于 iKuai x86_64 3.7.26 的固件源码与构建仓库，提供域名、端口和协议分流、多出口、原生 WireGuard 和纯 Hysteria 2 接入。

[下载 3.0](https://github.com/baby666666/plus/releases/tag/v3.0.0) · [安装与升级](docs/INSTALL.md) · [完整构建](docs/BUILD.md) · [测试方法](docs/TESTING.md)

WG 隧道页面统一配置设备用途和连接方式。原生 WG 支持设备经路由器上网、路由器借用设备网络、双向上网及指定网段互访。纯 HY2 支持认证后经路由器上网、访问路由器局域网和管理页面，并按设备使用原生分流。WAN Web 关闭时，经过认证的 HY2 仍可访问内网管理地址；打开后台仍需登录管理员账号。

手机可复制标准 WG 配置、完整 sing-box JSON 或 HY2 链接，也可扫码导入。另一台 NativeRouting 路由器可粘贴导入设备配置。按钮沿用爱快原生尺寸，手机上自动对齐和换行。

全新安装镜像已包含固定版本 HY2 核心，无需首次联网下载；eth0 默认为 WAN1/DHCP，WAN Web 默认开启。BIN 升级保留现有配置和有效核心缓存；缺少缓存时首次启用 HY2 会下载并校验核心。

## 版本选择

1.0、2.0、3.0 均保留原始源码、完整安装镜像及 BIN 升级包，3.0 为最新版本。

[1.0 发布](https://github.com/baby666666/plus/releases/tag/v1.0.0) · [2.0 发布](https://github.com/baby666666/plus/releases/tag/v2.0.0) · [3.0 发布](https://github.com/baby666666/plus/releases/tag/v3.0.0) · [各版本一键安装命令与下载](docs/VERSIONS.md)

## 一键安装

在目标 x86_64 Linux 服务器以 root 执行。此操作会清空目标系统盘；已有路由器请使用 BIN 升级。

```bash
curl -fLO https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh dd --img 'https://github.com/baby666666/plus/releases/download/v3.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0_EFI_eth0-WAN-Web.img.gz'
```

按脚本完成提示后执行 `reboot`。启动后通过 `http://服务器IP` 访问后台，默认账号和密码均为 `admin`，首次登录请修改密码。云平台安全组需允许管理端口及所配置的隧道 UDP 端口。安装镜像默认依赖 WAN DHCP，静态 IP 环境需通过控制台配置。

## 源码与交付

| 内容 | 入口 |
| --- | --- |
| 版本、文件和摘要 | [release.json](release.json)、[SHA256SUMS](SHA256SUMS) |
| 升级 BIN、安装镜像、构建输入、HY2 核心 | [3.0 Release](https://github.com/baby666666/plus/releases/tag/v3.0.0) |
| 可编辑运行覆盖 | `materials/firmware/port-3726/files/` |
| 网页源文件 | `materials/web-src/` |
| 构建和维护说明 | [AI_HANDOFF.md](docs/AI_HANDOFF.md)、[BUILD.md](docs/BUILD.md) |

厂商基础系统为闭源；仓库提供可编辑覆盖源码、固定基础输入、构建工具及配套 ELF，并非全系统源码编译。独立构建生成新的签名密钥及匹配内核，需按测试文档重新验收。
