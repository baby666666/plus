# NativeRouting 3.0 安装与升级

从 [3.0 Release](https://github.com/baby666666/plus/releases/tag/v3.0.0) 下载附件，确切摘要见根目录 [release.json](../release.json) 和 [SHA256SUMS](../SHA256SUMS)。

## BIN 升级

现有兼容 x86_64 NativeRouting 路由器：在「系统设置 → 升级备份 → 版本升级」上传 `iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0.bin`，等待安装完成并正常重启。保留现有配置、设备凭据及 WAN Web 设置。

BIN 优先使用已有有效 HY2 核心缓存。缺少缓存时，首次启用会下载并校验固定版本核心。`.img.gz` 不能上传到固件升级页面。

## 全新安装

在目标 x86_64 Linux 服务器以 root 执行以下命令。使用上游 [reinstall.sh](https://github.com/bin456789/reinstall) 的 DD 流程，整盘安装会清空目标系统盘及其配置。

```bash
curl -fLO https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh dd --img 'https://github.com/baby666666/plus/releases/download/v3.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0_EFI_eth0-WAN-Web.img.gz'
```

按脚本完成提示后运行 `reboot`。安装期间脚本询问的账号密码用于观察安装日志，不会修改镜像默认管理账号。BIOS 与 UEFI 使用同一镜像。

镜像已预置 sing-box 1.14.4 的固定核心归档，可离线启用 HY2。首次启动将 eth0 配置为 WAN1/DHCP，默认开启 WAN Web。通过 `http://服务器IP` 访问后台，默认账号和密码均为 `admin`，首次登录后修改密码。静态 IP 网络须通过控制台配置 WAN 地址、网关及 DNS。云平台安全组需放行实际管理端口及设备 UDP 端口。

## 认证后访问内网和分流

在「网络设置 → VPN客户端 → WireGuard」添加设备，选择「纯 Hysteria 2（UDP）」并保存。在手机复制完整 sing-box 配置或扫描二维码。连接后，从设备页复制后台地址，在浏览器打开并用爱快管理账号登录；局域网设备使用其 IPv4 地址和服务端口。

需要按设备选择出口时，在原生分流页使用设备显示的「分流源地址」或「分流入接口」。域名分流需要让 DNS 查询经过爱快。WAN Web 开关只控制公网直接访问管理页面，不禁止经过 HY2 认证的内网请求。[HY2 设置](PURE-HY2.md)
