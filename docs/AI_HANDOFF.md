# NativeRouting 2.0 接手说明

使用当前源码、同版 Release 的固定输入包和标准构建依赖即可生成固件与升级包。输入包只含官方基础 BIN 和最小干净 EFI 引导模板；模板不含可运行系统载荷或部署配置，镜像生成工具会写入本次构建的内核与 rootfs。版本和文件摘要以根目录 [release.json](../release.json) 为准。

纯 Hysteria 2 使用同一设备登记事务保存认证与用途。中心配置在 `wg_pure_profile.lua`，接收端在 `wg_pure_client.lua`，逻辑出口与 TUN 的映射由 `wg_pure_routing.sh` 管理。纯接入 UDP 监听由 `wg_pure_service.sh` 管理。[配置说明](PURE-HY2.md)

## 接手顺序

阅读 [维护规则](../AGENTS.md)、[构建步骤](BUILD.md) 和 [测试方法](TESTING.md)。下载并校验 Release 附件，按构建步骤依次运行材料校验、四个页面同步检查和 `python3 tools/prune_web_assets.py`，然后创建独立 Python 环境，从固定输入生成新 BIN 和安装镜像，再执行宿主回归及启动、升级测试。工具接口可用 `tools/rebuild.py --help` 和 `tools/run_host_tests.py --help` 查看。

构建会生成新的签名密钥及匹配内核，产物不保证与正式附件逐字节相同。基础系统为厂商闭源组件，默认保留配套精确 ELF；本仓库不是全系统源码编译。缺少输入、依赖或执行权限时应修复环境，不可删除签名、解包或防火墙检查来通过验收。

## 代码地图

| 功能 | 编辑位置 | 同步或验证工具 |
| --- | --- | --- |
| 域名、端口、协议及上下行分离页面 | `materials/web-src/routing/` | `tools/sync_routing.py` |
| WG 页面、导出及三语言 | `materials/web-src/src/wg-*.js`、`wg-translations.json` | `tools/sync_wg.py` |
| WG 设备连接方式与用途 | `wg_hyr_config.lua`、`wg_mobile_peer.lua`、`wg_hy_engine.sh`、`wg_hy_ctl.sh`、`wireguard.sh`、`wg-native-tunnel.js` | [设备用途](WG-DEVICES.md) |
| 时间与日志显示 | `materials/web-src/src/router-time.js`、`time/` | `tools/sync_router_time.py` |
| 软件源管理 | `materials/web-src/src/ctpanel*.js` | `tools/sync_ctpanel.py` |
| 后台与路由脚本 | `materials/firmware/port-3726/files/usr/ikuai/script/` | 宿主回归和原生虚拟机 |
| DNS 与本地 C 组件 | `materials/native-src/`、`SOURCE_MAP.json` | 固定工具链编译和对应回归 |
| 解包与签名 | `materials/base/` | `tools/rebuild.py` |
| 打包运行覆盖 | `materials/firmware/port-3726/files/` | `materials/SHA256SUMS`、`runtime-modes.json` |
| 安装镜像 | `materials/cloud/` | `tools/cloud_from_rebuild.py` |

`native_rules.sh/lua`、`native_compiler.lua`、`native_plan.lua` 和 `native_transition.lua` 负责快照及编译；`native_runtime.sh` 发射内核规则；`native_exit_health.sh` 维护出口检测；`native_ingress.sh` 适配 WG 接入；`wireguard.sh` 管理接口和对端；`native_dns_bind.sh` 处理本机 DNS 绑定。DNS 常驻程序的 C 源为 `nr_dns.c` 和 `dns_*.h`。修改 C 组件时先按 `SOURCE_MAP.json` 核对源文件与 ELF 的对应关系；默认打包不重新编译这些 ELF。

原生设备导出核对保存的用途及双方公钥。原生三种用途和纯 HY2 接入均可在对端管理页面预览并导入。旧承载 WG 记录继续绑定原身份以便升级停用；新增、启用及导出均须按已保存的连接方式校验。前端入口在 `wg-native-tunnel.js` 和 `wg-paste-import.js`。[路由器导入与组网](HY2-SITE.md)

持久化数据包括原生 `config.db`、`/etc/mnt/ikuai/native-routing.json`、`domain-iplib/`、`region-iplib/` 和 `dns-limits.conf`。`/tmp/iktmp/native-rules/` 是运行状态，临时修改不能作为固件实现。

## 关键实现要求

分流顺序、源地址、多出口与断线策略见 [ROUTING-ORDER.md](ROUTING-ORDER.md)。WG 外层、本机服务和回包不能当作客户端新流量再次兜底。明确配置的 `site_local/site_remote` 网段互访优先并保留源地址；禁止把内部 `pppwgN` 设为用户出口。

运行状态在点击后读取真实后台快照；命名占位符由页面显式替换为已校验的数字并按文本渲染。无记录不能显示为零。编辑网页后用对应同步器 `--write` 同步活动 chunk、manifest、index 和 gzip，再执行 `python3 tools/prune_web_assets.py --write` 清理已不可达的生成资源；不能只修改未被入口加载的资源。

sing-box 导出从已保存的一致快照生成，使用方式和平台限制见 [SINGBOX-EXPORT.md](SINGBOX-EXPORT.md)。实际 iOS 息屏、切网及持续转发能力须在目标设备验证。

## 继续开发

先复现问题并建立能区分正确与错误行为的测试，再修改源码、同步运行资源并清理已不可达的生成资源。随后更新材料摘要及权限清单，为候选选择新版本号、全新构建目录和新签名密钥。核对实际产物的签名、解包、启动、原生升级与配置保留，并执行与改动相关的浏览器、WG、DNS和分流场景测试。

发布只包含当前源码、当前附件和必要说明。测试输出、调试数据、部署信息和临时凭据留在 checkout 外，不加入源码交付。
