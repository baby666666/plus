# NativeRouting 1.0 安装与升级

从 [1.0 Release](https://github.com/baby666666/plus/releases/tag/v1.0.0) 下载附件，按 [BUILD.md](BUILD.md#2-克隆下载和校验) 校验；确切文件名和 SHA256 见根目录 `release.json`。

已有兼容 x86_64 设备：备份配置，在路由器原生升级页面上传 `.bin`，确认升级完成并正常重启。`.img.gz` 用于全新安装，不能上传到升级页面。

全新安装使用未启动的 `.img.gz`，按上游 `reinstall.sh dd --img` 流程写入目标设备。私有 GitHub 下载需要认证，先下载到自己可访问的位置，再提供镜像地址；不要把 GitHub 令牌写入公开命令。整盘安装会清空目标系统及配置，应先确认目标磁盘。

镜像首次启动将 eth0 配置为 WAN1/DHCP，并启用 WAN Web。默认管理账号和密码均为 admin，首次登录后修改密码并限制管理入口。BIOS 和 UEFI 使用同一镜像。

手机作为出口的配置方式及 iOS 限制见 [SINGBOX-EXPORT.md](SINGBOX-EXPORT.md)。
