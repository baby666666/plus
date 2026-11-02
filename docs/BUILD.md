# 从零重建 NativeRouting 1.0

使用当前标签源码和同版 Release 的固定输入即可独立构建。需要私有 plus 读取权限。可直接安装 Release 的正式附件；继续开发时按下文生成新的候选产物。

## 1. 准备环境

推荐 Python 3.12、Node.js 18+、C编译器、make、tar、OpenSSL、jq、sqlite3、GNU awk、Bash及Git/GitHub CLI。新环境使用固定的 tools/requirements-host.txt；其中同时锁定构建依赖及 lupa 2.6。Linux需要Python开发头、LZO开发包；macOS需要Xcode Command Line Tools。Windows使用WSL2。

Ubuntu 24.04示例：

```bash
sudo apt-get update
sudo apt-get install -y git gh python3.12 python3.12-venv python3.12-dev build-essential liblzo2-dev nodejs openssl jq sqlite3 gawk qemu-system-x86 ovmf
```

macOS示例（已安装Homebrew）：

```bash
xcode-select --install
brew install python@3.12 node jq sqlite gawk gh qemu lzo
```

Unicorn与QEMU需要允许JIT/执行本地程序；受限环境应授予相应权限，不能绕过固件验证。建议8GiB内存、15GiB可用空间。下文所有生成目录均在checkout外；每次使用新的构建目录。

## 2. 克隆、下载和校验

```bash
gh auth login
gh repo clone baby666666/plus
cd plus
git checkout v1.0.0
gh release download v1.0.0 --repo baby666666/plus --dir ../nr-1.0-downloads
python3 tools/verify_release.py --directory ../nr-1.0-downloads
python3 tools/check_materials.py
python3 tools/sync_wg.py
python3 tools/sync_ctpanel.py
python3 tools/sync_routing.py
python3 tools/sync_router_time.py
python3 tools/prune_web_assets.py
```

也可登录GitHub后手动下载Release的四个附件到同一目录。`verify_release.py` 对照当前checkout核对三份数据文件、SHA256SUMS及镜像解压后摘要。发布包与源码必须来自同一标签。

## 3. 构建全新 BIN

```bash
python3.12 -m venv ../nr-1.0-python
../nr-1.0-python/bin/python -m pip install -r tools/requirements-host.txt
../nr-1.0-python/bin/python -u tools/rebuild.py \
  --inputs-archive ../nr-1.0-downloads/NativeRouting-1.0-build-inputs.tar.gz \
  --workdir ../nr-1.0-private-build --label V1_0-REBUILD
```

输入包只包含官方基础 BIN 和最小干净 EFI 引导模板。模板保留引导及分区结构，不含可运行系统载荷或部署配置。摘要、大小及内部文件在 materials/base/input-bundle.json、inputs.json 固定。工具编译仓库保存的 e2fsprogs 1.47.3/Lua 5.1.5，解包官方系统，生成新RSA私钥及匹配内核，应用运行覆盖，完成签名/解包/内核接受和文件系统校验。输出为 `../nr-1.0-private-build/port-3726/output/`，结论为 `rebuild-result.json`。

新签名密钥和文件系统元数据使哈希不同于发布包；这是独立衍生包，不应把它改名伪装成已验证的正式附件。默认构建保留厂商闭源组件与精确ELF，不是全系统源码编译。私钥只留在checkout外0700目录/0600文件，禁止上传整个构建目录。160MiB rootfs、200MiB RAM disk及4MiB压缩载荷增长限制必须保留。

## 4. 生成镜像并运行宿主回归

```bash
../nr-1.0-python/bin/python tools/cloud_from_rebuild.py \
  --workdir ../nr-1.0-private-build --output ../nr-1.0-cloud
../nr-1.0-python/bin/python tools/run_host_tests.py \
  --workdir ../nr-1.0-private-build --report ../nr-1.0-host-tests.json
```

镜像工具向干净模板写入本次构建的内核和 rootfs，并生成首次启动所需配置。统一回归自动从本次解出的基础文件系统读取原生校验器、导入器和真实Vue 2.4.2，使用本次编译的Lua；不会调用生产路由器。报告列出实际执行命令和结果，不把宿主模拟当内核实流验收。

## 5. 在副本上验证 BIOS/UEFI

```bash
python3 tools/smoke_cloud.py \
  --image ../nr-1.0-cloud/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0-REBUILD_EFI_eth0-WAN-Web.img \
  --out ../nr-1.0-bios
python3 tools/smoke_cloud.py \
  --image ../nr-1.0-cloud/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0-REBUILD_EFI_eth0-WAN-Web.img \
  --out ../nr-1.0-uefi --mode uefi \
  --uefi-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --uefi-vars /usr/share/OVMF/OVMF_VARS_4M.fd
```

UEFI路径示例为Ubuntu；macOS/其他Linux使用本机QEMU的匹配CODE/VARS文件（EDK2常为edk2-x86_64-code.fd及edk2-i386-vars.fd）。必要时传 `--qemu` 与 `--firmware-dir`。工具复制磁盘，仅绑定localhost管理端口，结束删除启动副本，原始镜像保持未启动。新增功能/内核更改还须测试原生升级、配置保留、实际网页和相应WG/DNS/分流故障场景，见 TESTING.md。

## 修改源码

对应同步器见 AI_HANDOFF.md。修改网页源码后，用对应同步器的 `--write` 更新活动资源，再执行 `python3 tools/prune_web_assets.py --write` 删除已不可达的生成资源，最后重新生成材料清单及运行权限清单并校验。四个同步检查之后再运行不带 `--write` 的 `python3 tools/prune_web_assets.py`，确认没有残留生成资源。C源与ELF对应见 materials/native-src/SOURCE_MAP.json；C改动需用记录的Zig0.14.1 x86_64-linux-musl或相容工具链重建并重新验收。curl/OpenSSL固定配方见 materials/native-src/curl-build/README.md。

构建失败时将日志保存在 checkout 外，使用新的输出目录复查。不要重复使用部分构建或复用签名私钥。每次生成的候选均须按 TESTING.md 独立验收。

## 原生升级与页面专项

保留当前正式版解压镜像作为测试基线，用后续候选的私有构建目录运行：

```bash
../nr-1.0-python/bin/python tools/smoke_upgrade.py \
  --baseline-image /absolute/path/to/current-release.img \
  --workdir ../nr-1.0-private-build --out ../nr-1.0-upgrade
../nr-1.0-python/bin/python materials/tests/routing-ui-dom-fixture.py \
  --rootfs ../nr-1.0-private-build/decrypted-3.7.26-enterprise/rootfs.tar.gz
```

升级工具只启动本机一次性VM，不接受生产地址；测试网络限制外网访问，并在该副本关闭自动库更新，避免占用原生升级暂存区。测试副本的配置分区临时加入诊断shell，端口仅在宿主 localhost 转发。验证原生上传/解析/安装、重启、域名/端口/协议/WG配置及全部运行文件后删除副本。第二条命令打印组件测试页地址，在浏览器点击 Run checks，验证分页、出口设置及三语言秒数。该页面采用模拟接口和简化样式，不是路由器原生界面；实际界面截图必须从启动后的完整管理页面获取。按 Ctrl-C 停止页面服务。
