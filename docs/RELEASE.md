# NativeRouting 2.0

**NativeRouting 2.0** 在 WG 隧道页提供原生 WireGuard 和纯 Hysteria 2。原生 WG 支持三种上网用途与明确网段互访，可在手机上复制标准 WG 配置和 sing-box JSON。纯 HY2 提供单向 UDP 接入、手机双格式复制、二维码与路由器导入。旧 HY2 承载 WG 的发送端和接收端在升级时停用，旧导入包需重新生成。[设备用途](WG-DEVICES.md) · [纯 HY2](PURE-HY2.md) · [路由器导入](HY2-SITE.md)

升级包、未启动安装镜像及固定构建输入的文件名和摘要，以及固件签名公钥指纹，列在 [release.json](../release.json) 中。对应发布标签为 `v2.0.0`，固件构建标签为 `V2_0`。

面向 x86_64 的固件交付，提供域名、端口及协议分流，源地址与接入接口匹配，多出口与断线策略，WG 接入、互访和出口，日志时区、DNS 请求保护、加密 DNS 限制及 sing-box 配置导出。

分流运行状态由用户点击读取，显示出口检测、WG 握手、DNS 选路和地址保护信息。简体、繁体及英文界面显示实际秒数和数量；无记录时显示“暂无记录”。页面不持续轮询或自动倒计时。

同版交付包括源码、升级 BIN、未启动安装镜像、`NativeRouting-2.0-build-inputs.tar.gz` 和 `SHA256SUMS`。文件名及摘要见 [release.json](../release.json)。新 AI 可按 [接手说明](AI_HANDOFF.md) 和 [构建步骤](BUILD.md) 从当前材料生成新固件与升级包。

基础系统包含厂商闭源组件，默认构建保留配套 ELF。独立构建生成新签名密钥，产物哈希会不同，须单独执行 [测试方法](TESTING.md)。iOS 息屏和切网转发能力、CPU 与吞吐表现须在目标环境验证；加密 DNS 限制不保证识别全部域名流量。
