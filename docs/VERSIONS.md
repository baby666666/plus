# 各版本下载与安装

保留 1.0、2.0、3.0 的原始源码标签和发布附件，3.0 为最新版本。每个版本的文件和摘要以该版本 Release 及标签中的 `release.json`、`SHA256SUMS` 为准。

| 版本 | 发布与源码 | BIN 升级包 | 完整安装镜像 |
| --- | --- | --- | --- |
| 3.0 | [Release](https://github.com/baby666666/plus/releases/tag/v3.0.0) · [源码](https://github.com/baby666666/plus/tree/v3.0.0) | [下载 BIN](https://github.com/baby666666/plus/releases/download/v3.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0.bin) | [下载 IMG.GZ](https://github.com/baby666666/plus/releases/download/v3.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0_EFI_eth0-WAN-Web.img.gz) |
| 2.0 | [Release](https://github.com/baby666666/plus/releases/tag/v2.0.0) · [源码](https://github.com/baby666666/plus/tree/v2.0.0) | [下载 BIN](https://github.com/baby666666/plus/releases/download/v2.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V2_0.bin) | [下载 IMG.GZ](https://github.com/baby666666/plus/releases/download/v2.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V2_0_EFI_eth0-WAN-Web.img.gz) |
| 1.0 | [Release](https://github.com/baby666666/plus/releases/tag/v1.0.0) · [源码](https://github.com/baby666666/plus/tree/v1.0.0) | [下载 BIN](https://github.com/baby666666/plus/releases/download/v1.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0.bin) | [下载 IMG.GZ](https://github.com/baby666666/plus/releases/download/v1.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0_EFI_eth0-WAN-Web.img.gz) |

## 一键全新安装

在目标 x86_64 Linux 服务器以 root 执行对应版本的命令。以下命令使用上游 `reinstall.sh dd --img` 流程，**会清空目标系统盘及配置**；按提示完成后执行 `reboot`。

### 3.0

```bash
curl -fLO https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh dd --img 'https://github.com/baby666666/plus/releases/download/v3.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V3_0_EFI_eth0-WAN-Web.img.gz'
```

### 2.0

```bash
curl -fLO https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh dd --img 'https://github.com/baby666666/plus/releases/download/v2.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V2_0_EFI_eth0-WAN-Web.img.gz'
```

### 1.0

```bash
curl -fLO https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh dd --img 'https://github.com/baby666666/plus/releases/download/v1.0.0/iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0_EFI_eth0-WAN-Web.img.gz'
```

各版本镜像默认将 eth0 配置为 WAN1/DHCP，并开启 WAN Web。通过 `http://服务器IP` 访问后台，默认账号和密码均为 `admin`，首次登录请修改。静态 IP 网络需通过控制台配置 WAN，云安全组须允许所使用端口。

## BIN 升级

已有兼容 NativeRouting x86_64 路由器，在「系统设置 → 升级备份 → 版本升级」上传对应版本的 `.bin`，按原生流程完成升级和重启。`.img.gz` 仅用于全新安装。旧版本发布文件保持原样，不代表已验证从新版本直接降级的配置兼容性。

3.0 安装镜像预置 HY2 核心；这项说明不适用于全部旧版本。各版本功能以其自身文档为准。
