# iPhone 作为 WG 上网出口

WG 隧道编辑页提供 sing-box JSON 下载和离线 QRS 二维码。配置面向 iPhone sing-box MT 1.14.8，核心配置格式以 1.14.4 为基准；App 版本号与核心版本号不同。使用其他客户端或核心版本时，应先校验配置格式与导入协议。

## 配置步骤

1. 在公网路由器上，为出口手机单独建立一个 WG 服务接口。其他手机、电脑使用另一个接入服务接口。
2. 为出口手机建立隧道，填写独立的对端 /32 地址和匹配的密钥，勾选“用作分流出口”。客户端 Endpoint IP 填此路由器可从手机访问的 IPv4，端口取服务接口监听端口。
3. 保存隧道，重新打开编辑页，选择“生成 sing-box JSON／二维码”。在 iPhone 的 sing-box App 内扫描，或下载 JSON 后使用 App 的本地文件导入。
4. 在路由器分流设置中，为需要经手机上网的来源选择该 WG 出口。是否在手机离线时阻断，继续由该规则的线路绑定选项决定。

JSON 中的 userspace WireGuard endpoint 同时接收路由器转来的连接。唯一出口为 direct，使用手机当前网络；不能将 WG endpoint 设为最终出口，否则会把业务送回路由器。来自路由器的 IPv4 TCP/UDP 由 sing-box 建立相应连接，不依赖手机系统开启 IP 转发。

生成前通过已登录的只读接口核对保存快照、接口启用状态和双方密钥匹配。存在未保存改动、密钥请求尚未完成或服务接口信息已变化时，请保存/刷新后重新生成。服务器私钥不包含在导出响应中。

导出要求独立出口角色；不支持在同一份手机出口配置中设置 site_local/site_remote 内网互访。保留普通 WireGuard 配置、二维码与 iKuai 组网导出。密钥、地址、Endpoint、服务端口或角色变化后，旧 sing-box 二维码隐藏且下载按钮禁用。导出状态仅保留在页面内存，不增加原生配置字段或公开下载接口。

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
