# SSH Rescue Tool

这个仓库目前包含 3 个脚本：

- `ssh-rescue.sh`：SSH 紧急救援工具
- `vps-modular-init.sh`：原始 VPS 模块化初始化脚本
- `vps-unified-init.sh`：合并版一键脚本，保留原有功能，并新增 OpenClaw / SearXNG / Caddy 部署与无缝迁移菜单

以下示例默认你已经以 `root` 身份登录到全新 VPS。

## 1. SSH 紧急救援工具

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/whitzard0421/ssh-rescue-tool/main/ssh-rescue.sh)
```

## 2. 原始 VPS 模块化初始化脚本

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/whitzard0421/ssh-rescue-tool/main/vps-modular-init.sh)
```

## 3. 合并版一键脚本

适用场景：

- 新 VPS 一键基础初始化
- SSH 安全加固与紧急救援
- 部署 OpenClaw + SearXNG + Caddy
- 迁移现有 OpenClaw / SearXNG 到统一反代入口

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/whitzard0421/ssh-rescue-tool/main/vps-unified-init.sh)
```

## 其他

`SwitchNet.bat` 用于 Windows 桌面切换网络路由。
