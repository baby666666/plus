# NativeRouting 1.0 重建材料

firmware/port-3726/files为实际运行覆盖；native-src保存开发C源与精确ELF对应；web-src为可编辑页面及测试；base保存固定基础输入说明、解包/签名脚本、依赖版本和工具源码归档；cloud为未启动安装镜像生成器。

大型官方基础BIN和EFI模板只在当前私有Release的NativeRouting-1.0-build-inputs.tar.gz中，摘要见base/input-bundle.json、base/inputs.json。入口为根tools/rebuild.py；完整命令见docs/BUILD.md。无需旧仓库、旧Release或原电脑目录。

默认重建保留已交付ELF与厂商闭源组件，不是全系统源码编译。任何新构建必须重新验收。禁止加入私钥、生产配置或已启动磁盘。
