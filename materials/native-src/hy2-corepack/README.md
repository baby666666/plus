# HY2 核心镜像制作器

固件内的 `/usr/sbin/nr-hy2-corepack` 接收固定版本上游 ELF 的标准输入，调用 `/usr/libexec/nr-mksquashfs`，将仅含 `/sing-box` 的只读 SquashFS 直接写入调用方指定的新文件。调用方先校验上游归档，再校验生成镜像的 SHA-256，校验通过才挂载。ELF 大小为 92,070,560 字节，SHA-256 为 `fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c`。

目标内核支持 SquashFS 的 XZ 解压。制作器使用 128 KiB 数据块、64 KiB 字典、单线程和受限的读写队列。构建配方把 squashfs-tools 的 XZ 编码预设从 6 调整为 0，缩短路由器首次生成镜像的时间。文件名、大小、权限、属主、目录结构及时间戳均在包装脚本中固定。维护时应使用同一版上游 ELF 验证输出，并在目标内核上挂载、比对完整 ELF 和运行版本命令。

## 离线重建

准备 Python 3.12、GNU Make 及 Zig 0.14.1，构建目录和 Zig 路径使用不带空格的绝对路径。从仓库根目录运行以下命令，指定尚不存在的构建目录。

```sh
python3 materials/native-src/hy2-corepack/build.py \
  --zig /opt/zig-0.14.1/zig --work /tmp/nr-corepack-build
```

生成的文件位于 `/tmp/nr-corepack-build/squashfs-tools-4.6.1/squashfs-tools/mksquashfs`，目标为静态链接的 x86_64 Linux musl。脚本校验目录内的两个原始上游源码包，构建结束时打印 ELF 的 SHA-256，可与 `materials/native-src/SOURCE_MAP.json` 核对。

- squashfs-tools 4.6.1 包含完整源代码和 GPLv2+ 授权文本 `COPYING`。[上游源码](https://github.com/plougher/squashfs-tools/tree/4.6.1)
- XZ Utils 5.8.4 包含完整源代码和 `COPYING.0BSD`。制作器链接其中的 liblzma。[上游发行版](https://github.com/tukaani-project/xz/releases/tag/v5.8.4)
- Zig 工具链提供的 musl 授权和署名见本目录的 `COPYRIGHT.musl`。
