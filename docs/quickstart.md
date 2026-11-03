# `js` 用户一页纸快速上手指南（5 分钟连上服务器）

`js` 是 JumpServer 命令行与 AI Agent 连接工具，让访问授权服务器像 `ssh 用户@IP`、`scp` 一样直接——**无需每次打开网页或进 KoKo 菜单选资产、输两次密码**。

> **权限说明**：`js` 不内置任何服务器地址或凭据。首次运行 `js init` 时输入你的 JumpServer 地址，并核对 KoKo 主机指纹；之后只能看到并连接管理员已授权给你的服务器。

---

## 1. 安装（1 分钟）

### Linux (`x86_64` / `arm64`)
```bash
mkdir -p ~/.local/bin
tar -xzf js_1.0.0_linux_amd64.tar.gz -C ~/.local/bin js
chmod +x ~/.local/bin/js
# 若 ~/.local/bin 不在 PATH 中，可执行：
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### Windows (`x86_64`，Windows Terminal / PowerShell)
1. 解压 `js_1.0.0_windows_amd64.zip`，将 `js.exe` 放到任意已在 `PATH` 中的目录（或新建 `C:\Users\<你的用户名>\bin` 并加入用户环境变量 `Path`）。
2. 若首次运行弹出 Windows SmartScreen 拦截提示，点击 **“更多信息” → “仍要运行”**，或在 PowerShell 中先解除下载标记：
   ```powershell
   Unblock-File .\js.exe
   ```

---

## 2. 首次本机初始化（每台电脑仅需一次）

在终端运行：
```bash
js init
```
按提示输入**你自己的 JumpServer 账号与密码**：
```text
JumpServer 地址：https://jumpserver.example.com
观察到 KoKo 主机指纹：SHA256:...（请与管理员提供的可信记录核对后输入 y）
JumpServer 账号：jsuser
JumpServer 密码：********
✓ 登录成功
✓ 已为本机创建个人 Access Key，保存到系统凭据库（你的密码不会被保存）
✓ KoKo 主机指纹已核验 (SHA256:0000000000000000000000000000000000000000000)
完成。试试：js hosts
```
- **纯命令行 Linux / WSL（无桌面凭据库）**：使用 `js init --store file`（以 `0600` 权限保存在 `~/.config/jsbridge/secrets.json`，请勿在多人共用同一系统账号的机器上开启）。
- **账号已启用 MFA**：在 JumpServer 网页右上角 **“个人信息 → API Key”** 手动创建一把密钥，随后运行 `js init --access-key` 粘贴 ID 和 Secret。

---

## 3. 免密码登录的四种场景（含原有 SSH 私钥免密）

| 你的目标服务器场景 | 如何实现免密直接登录 |
| --- | --- |
| **① 普通密码登录的服务器**<br>（最常见） | 直接运行 `js alice@192.0.2.16`，**首次**输入一次该服务器密码，登录成功后自动保存到系统凭据库；**第二次起零输入 1 秒直达 Shell**。 |
| **② 之前已配置 SSH 私钥免密登录**<br>（目标 `~/.ssh/authorized_keys` 已有你本机公钥，如 `root@192.0.2.105`） | 绑定本机私钥即可免密登录：<br>`js bind-key root@192.0.2.105 ~/.ssh/id_rsa --allow-key-submission`<br>之后直接运行 `js root@192.0.2.105`。<br>*(注：因经由 JumpServer KoKo 代登目标，不支持本地 SSH Agent 转发，需加 `--allow-key-submission` 明确同意连接时将私钥经 HTTPS 提交给 JumpServer)* |
| **③ JumpServer 已托管账号的服务器**<br>（管理员已在堡垒机托管目标密码或密钥） | 直接运行 `js 用户@IP`，**首次即零输入免密登录**，本机无需输入或保存任何目标密码/私钥。 |
| **④ 已使用 `gopass` 保存密码**<br>（可选，仅已在用 `gopass` 的用户） | 绑定已有条目名即可免输密码：<br>`js bind-gopass alice@192.0.2.16 servers/192.0.2.16/alice`<br>之后直接运行 `js alice@192.0.2.16`。 |

---

## 4. 日常高频命令速查（像 `ssh` / `scp` 一样用）

| 我想做什么 | 命令示例 | 说明 |
| --- | --- | --- |
| **查看我的授权服务器** | `js hosts` | 列出本人有权限的服务器 IP、名称及本地已绑定的免密方式 |
| **交互选择服务器登录** | `js` | 无参数运行，输入列表序号或关键字过滤后直接连接 |
| **直接登录某台服务器** | `js alice@192.0.2.16` | 打开远端交互终端（支持窗口缩放、Ctrl+C） |
| **设置简短别名** | `js alias s104 alice@192.0.2.16` | 之后直接运行 `js s104` 登录，或 `js s104 df -h` 执行命令 |
| **单账号 IP 简写** | `js 192.0.2.16` | 该 IP 在本机只配置过一个账号时自动使用，有多个时交互选择 |
| **远程执行单条命令** | `js s104 "uname -a"` | 不进交互终端，直接输出 `stdout`/`stderr` 并返回远端退出码 |
| **上传文件 / 目录** | `js cp ./app.tgz s104:~/app.tgz`<br>`js cp -r ./dist s104:~/dist` | 支持大文件流式传输、进度与 ETA 显示；`-f` 覆盖同名文件（`js scp` 同义） |
| **下载文件 / 目录** | `js cp s104:~/app.log ./`<br>`js cp -r s104:~/logs ./logs` | 注意：JumpServer 平台默认限制非 `root` 账号 SFTP 根目录为**登录用户家目录 `~`**（不能直接传 `/tmp`） |
| **rsync 增量同步** | `rsync -avz -e "js rsh" ./dir/ s104:~/dir/` | 用真正的 rsync，仅传差异；目标机需装 rsync，或 `--rsync-path=~/.local/bin/rsync` 指向自带二进制；需先连接过一次保存密码 |
| **修改/重设服务器凭据** | `js passwd s104`<br>`js credential s104` | 更新保存的目标密码，或交互切换密码 / 私钥 / gopass 来源 |
| **删除已保存的目标凭据** | `js forget s104` | 从本机凭据库移除该服务器的密码或私钥绑定（不会删除你磁盘上的私钥文件） |
| **环境自检 / 注销本机** | `js doctor --net` / `js logout` | 检查凭据库与网络连通性；注销并在线吊销本机 Access Key |

---

## 5. 可选配置：Tab 补全与 AI Agent (MCP)

### 开启命令行 Tab 补全（自动补全子命令、别名、`用户@IP` 及 `cp` 远端前缀）
- **Bash**：`echo 'eval "$(js completion bash)"' >> ~/.bashrc && source ~/.bashrc`
- **Zsh**：`echo 'eval "$(js completion zsh)"' >> ~/.zshrc && source ~/.zshrc`
- **PowerShell**：在 `$PROFILE` 中加入 `Invoke-Expression (& js completion powershell | Out-String)`

### 接入 AI Agent（Claude Code / Codex / Cursor 等 MCP 客户端）
只要某台服务器在本机已完成免密配置（已保存密码、已绑定无口令私钥或托管账号），AI Agent 即可直接复用，无需在配置文件里写任何秘密：
```json
{
  "mcpServers": {
    "jumpserver": {
      "command": "/绝对路径/js",
      "args": ["mcp"]
    }
  }
}
```
> Codex CLI 一键注册：`codex mcp add jumpserver -- ~/.local/bin/js mcp`
