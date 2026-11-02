# 1.0 下载工具构建

固件使用静态 x86_64 `curl`，同一程序通过 `--native-safe-fetch` 执行原生资源下载。`../native_safe_fetch.c` 是该入口的实际实现；`tool_main.c.modified` 负责入口分派。默认固件构建直接使用材料中已保存并校验的 ELF，修改下载器时使用本目录的完整构建入口重新生成它。

## 固定依赖

需要 Python 3.12、Perl、Make、宿主 C 编译器和 Zig 0.14.1。准备以下上游源压缩包；脚本强制验证摘要，不接受同名但内容不同的输入。源压缩包不随本目录重复保存。

| 输入 | SHA256 |
| --- | --- |
| curl 8.23.0 的 `curl-8.23.0.tar.xz` | `8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5` |
| OpenSSL 3.5.9 的 `openssl-3.5.9.tar.gz` | `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a` |

上游下载入口：[curl](https://curl.se/download/)、[OpenSSL](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9)、[Zig](https://ziglang.org/download/)。这些依赖仅在修改原生下载程序时需要；现有固件和升级包的重建不需要联网下载它们。

## 构建

在仓库根目录执行，使用实际的本地依赖路径。工作目录必须不存在，且位于仓库外：

```sh
python3 materials/native-src/curl-build/build.py \
  --curl-source /path/to/curl-8.23.0.tar.xz \
  --openssl-source /path/to/openssl-3.5.9.tar.gz \
  --zig /path/to/zig-0.14.1/zig \
  --work /path/to/new-native-build
```

脚本自动识别宿主三元组，也可通过 `--build-triplet` 指定；macOS arm64 已验证值为 `aarch64-apple-darwin`。`--jobs` 默认 4。若有可处理 ELF 的 objcopy，可传入 `--objcopy /path/to/objcopy`；默认使用 Zig 的 objcopy，在宿主链接失败时自动构建同版本 Zig 的 objcopy 实现并尝试用宿主 C 编译器链接。

完整流程包括：校验与解包固定输入、建立交叉编译包装器、构建并暂存 OpenSSL、接入入口分派、配置 curl、编译并链接 `native_safe_fetch.c`、剥离符号、核对 ELF 和输出摘要。无需事先编辑 Makefile。输出 `curl`、`curl.unstripped`、`build-report.json` 和逐步日志，仅保存在指定工作目录，脚本不会覆盖仓库材料。

编译器包装器使用 `-ffile-prefix-map` 与 `-fdebug-prefix-map`，把工作目录和工具链目录映射到固定的 `/usr/src/` 路径。OpenSSL 的目标前缀为 `/usr`，库目录为 `lib64`，配置目录为 `/etc/ssl`，安装通过 `DESTDIR` 暂存；宿主目录不会成为目标运行时目录。

## 运行约束与验证

保留静态 musl、OpenSSL、同步解析器以及当前协议和库开关。关闭动态库、线程解析、文档、手册、压缩库、IDN2、PSL、HTTP/2、HTTP/3、SSH2，以及构建脚本列出的未使用协议。OpenSSL 保留 `no-asm`、`no-module`、`no-legacy`、`no-weak-ssl-ciphers` 等固定开关。

证书文件固定为 `/etc/ssl/certs/ca-certificates.crt`，保持证书链和主机名验证；原生资源下载入口要求 HTTPS、最低 TLS 1.2，并保留公共地址、重定向、大小边界和失败保留文件的限制。构建脚本不会关闭证书验证。

构建检查保证输出为无动态解释器的 x86_64 ELF，剥离前后所有分配节、入口及程序映射一致，且包含组合入口、1.0 User-Agent 和证书路径；不会把编译成功标为运行测试通过。更换固件运行 ELF 前，还需在原生 x86_64 Linux 中验证 `curl --version`、组合入口、有效证书下载、无效证书拒绝、地址与重定向限制、大小边界、失败时目标文件保留和原生管理功能，再更新材料映射与 SHA256 清单。源文件中的第三方许可证和版权声明必须保留。
