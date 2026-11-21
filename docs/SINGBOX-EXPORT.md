# iPhone 作为 WG 上网出口

在 WG 隧道选择设备用途，选择原生 WG 并保存后导出。[设备用途和扫码](WG-DEVICES.md)

WG 隧道编辑页可复制或下载完整 sing-box JSON，也可通过离线 QRS 二维码导入。配置面向 iPhone sing-box MT 1.14.8，核心配置格式以 1.14.4 为基准；App 版本号与核心版本号不同。使用其他客户端或核心版本时，应先校验配置格式与导入协议。

## 配置步骤

1. 在 WG 隧道编辑页选好设备用途，填写该设备的独立密钥和 /32 地址。需要爱快借线时使用独占的 WG 服务接口。
2. 原生模式填写可从手机网络访问的爱快 Endpoint IPv4，端口取此服务接口的 WG 监听端口。通过爱快访问时填写可达的 IPv4 DNS。
3. 保存后点「复制 sing-box 配置」，在手机 sing-box 的本地配置编辑器内粘贴并保存。也可在 App 内扫码，或下载 JSON 导入。爱快侧的分流规则决定哪些业务经这台设备转发。

选择「借线」时，设备收到的 WG 连接通过本地网络访问目标，自身流量继续走本地。选择「经爱快上网」时，手机流量由 VPN 接管并送至爱快。双向用途同时启用这两条路径。普通 WireGuard .conf 仍可复制；Linux 系统使用标准 WG 客户端承接借线时，需自行配置转发与出口 NAT。

页面从已保存快照读取设备与接口数据并校验密钥、地址、端口和用途。保存／刷新后重新生成配置。独立手机出口隧道使用 /32 设备地址，站点互访网段应配置在相应的普通组网隧道。

此配置使用 iPhone 的 VPN 连接，不能与另一 VPN 同时运行。手机断网、App 停止或系统终止网络扩展时，出口不可用。蜂窝/Wi-Fi 切换、锁屏、长时间后台和 App 内扫码仍需用户的 iPhone 实测；Linux 隔离测试不能替代这些测试。该配置不承诺任意 IP 协议、完整 IPv6 或转发手机热点后面的内网。

## 离线二维码

普通 JSON 二维码不符合 Apple 客户端常规远程配置导入协议。这里使用 App 内扫描器支持的 QRS 二进制格式，将本地 BPF profile 放入一个完整块，直接编码为 Base64。二维码不是第三方网站链接，不通过外部服务生成或保存；包含私钥，须按客户端配置保管。

- BPF：消息类型 3、版本 1、gzip 内容；字符串为 UTF-8 字节长度的 uvarint 前缀，profile type 为大端 int32 的 0（本地）。
- BinaryMeta：大端 uint32 长度分别包裹 JSON 文件元数据及 BPF 数据。
- QRS：小端 degree=1、index=0、k=1、原数据长度、CRC32(data) XOR 1，随后是未压缩 BinaryMeta 数据。
- gzip 使用一个存储块，避免引入新压缩依赖。紧凑 JSON 的二维码文本限制为 2200 字节，适配既有 M 级二维码生成器。
- Apple 解码器会先尝试 zlib 解压，再按未压缩数据校验 CRC。单块无需动画或重复恢复块。

协议依据：[Apple EncodedBlock](https://github.com/SagerNet/sing-box-for-apple/blob/dev/ApplicationLibrary/LubyTransform/EncodedBlock.swift)、[Apple 扫描与导入](https://github.com/SagerNet/sing-box-for-apple/blob/dev/ApplicationLibrary/Views/Profile/NewProfileMenuView.swift)、[核心 BPF 编解码](https://github.com/SagerNet/sing-box/blob/v1.14.4/experimental/libbox/profile_import.go)。独立验证时可编译官方 Apple EncodedBlock、LubyTransformDecoder、CRC32 和 BinaryMeta 源码，还原生成的二维码；这些协议参考实现不作为固件运行依赖。

配置依据：[WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)、[Apple 客户端能力](https://sing-box.sagernet.org/clients/apple/features/)、[App Store 版本](https://apps.apple.com/us/app/sing-box-mt/id6785326793)。

## 验证入口

node materials/web-src/tests/singbox-unit.js 检查出口方向、密钥/地址校验、参数变化后的导出失效和 BPF 解码；tools/run_wg_tests.py 一并执行 WG 翻译与既有导出回归。还需对目标核心执行配置校验、TCP/UDP 转发和原生固件验证，并在实际 iPhone 上测试扫码、息屏与切网。各次产物的测试结果独立保存于 checkout 外。
