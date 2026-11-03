# JumpServer 本地工作流工具 (`js`)

让通过 JumpServer (`jumpserver.example.com:2222`) 访问授权服务器像 `ssh 用户@IP`、`scp` 一样简单，同时为 AI Agent 提供零秘密泄露的原生 stdio MCP 服务。

- **用户 5 分钟快速上手**：请看 **[用户一页纸指南 (`docs/quickstart.md`)](docs/quickstart.md)**
- **设计说明**：[docs/design.md](docs/design.md)
- **rsync 增量同步**：[docs/rsync.md](docs/rsync.md)
- **全部文档**：[docs/](docs/README.md)

---

## 核心特性（Go 静态单文件版 `v1.0.0`）

| 场景 | 命令 | 体验 |
| --- | --- | --- |
| **首次本机初始化** | `js init` | 输入一次本人 JumpServer 账号密码，自动创建本机专属个人 Access Key 存入系统凭据库（不保存 JumpServer 密码） |
| **首次连接某台服务器** | `js alice@192.0.2.16` | 输入一次目标服务器密码，**确认远端登录成功后才自动保存**（输错密码绝不保存，防止锁号） |
| **第二次起连接** | `js alice@192.0.2.16` 或 `js s104` | **零输入、~1 秒**直达远端 PTY 交互 Shell（支持窗口大小变化、Ctrl+C） |
| **原有 SSH 私钥免密登录** | `js bind-key root@192.0.2.105 ~/.ssh/id_rsa --allow-key-submission` | 绑定本机已有私钥，之后 `js root@192.0.2.105` 直接免密进入 Shell |
| **交互式选服登录** | `js` | 无参数列出本人授权服务器，支持按序号或关键字过滤连接 |
| **远程单条命令** | `js s104 "df -h"` | 原生 SSH `exec` 通道，`stdout`/`stderr` 分离，返回远端真实退出码 |
| **文件与目录传输** | `js cp [-r] [-f] 源... 目标` | 经 KoKo SFTP 流式传输，支持大文件（已实测 >100 MiB）、`-r` 递归目录、`.js-partial` 原子落盘、实时速率与 ETA |
| **真正的 rsync 增量同步** | `rsync -avz -e "js rsh" ./dir/ s104:~/dir/` | `js rsh` 作为 rsync 的远程 shell，二进制安全透传 KoKo exec 通道；需目标机已装 rsync（否则用 `--rsync-path` 指向自带的二进制）；凭据需已保存（非交互） |
| **AI Agent 接入** | `js mcp` | 官方 Go MCP SDK 实现（`list_hosts` / `run_command` / `upload` / `download` / `close_connection`），连接池复用下命令执行仅需 **~170 ms** |

---

## 发布包与安装

预编译二进制（`CGO_ENABLED=0` 静态构建，含 Linux amd64/arm64、Windows amd64）附带 SHA-256 校验和，见 GitHub Releases。

### 从源码构建

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -buildvcs=false -trimpath -o dist/linux-amd64/js ./cmd/js
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -buildvcs=false -trimpath -o dist/linux-arm64/js ./cmd/js
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -o dist/windows-amd64/js.exe ./cmd/js
```

---

## 免密码登录场景详解

### 1. 普通密码登录服务器（首次输入后自动免密）
直接运行 `js alice@192.0.2.16`，首次输入一次目标服务器密码，程序在确认 KoKo 已成功连上目标服务器后，自动将密码保存到本机系统凭据库；第二次起直接免密登录。若目标服务器改了密码，运行 `js passwd alice@192.0.2.16` 即可更新。

### 2. 之前已配置 SSH 公钥免密登录的服务器（绑定本机私钥）
如果目标服务器的 `~/.ssh/authorized_keys` 中已经配置过你的本机公钥（例如之前直接 `ssh root@192.0.2.105` 免密登录），可将该目标绑定到你的本机私钥文件：

```bash
js bind-key root@192.0.2.105 ~/.ssh/id_rsa --allow-key-submission
js root@192.0.2.105
```

- **与直连 SSH 的区别**：在 JumpServer `@INPUT` 一次性连接令牌机制下，由服务端 KoKo 代为向目标服务器发起 SSH 连接，无法直接使用本机 `ssh-agent` 签名转发，而是需要将私钥经 HTTPS 提交给 JumpServer。
- **安全门禁**：未加 `--allow-key-submission` 时，程序只登记路径但拒绝上传私钥（返回 `KEY_SUBMISSION_REQUIRED`）；只有你明确知晓并接受该凭据流向后，才通过 `--allow-key-submission`（或 `js credential 用户@IP` 交互确认）开启。
- **带口令（passphrase）的私钥**：人工终端连接时可安全输入口令并在内存中解锁（解锁后的无口令 PEM 绝不落盘）；若需供 Agent 无人值守使用，可配合 `--passphrase-gopass-ref <条目>`。

### 3. JumpServer 托管账号（管理员 已在堡垒机录入凭据）
若 管理员 已在 JumpServer 资产中配置了同名托管账号（`has_secret: true`），直接运行 `js 用户@IP` 即可**零输入免密登录**，本机无需保存任何目标密码或私钥。

### 4. 已有 `gopass` 密码库（可选）
对于已在本机使用 `gopass` 管理服务器密码的用户，可直接绑定条目名：

```bash
js bind-gopass alice@192.0.2.16 servers/192.0.2.16/alice
js alice@192.0.2.16
```

---

## 凭据存储与安全边界

1. **所有连接均经由 JumpServer 审计**：始终先校验 KoKo 主机指纹（`SHA256:0000000000000000000000000000000000000000000`），再使用本人普通连接令牌（`is_reusable: false`）登录 `jumpserver.example.com:2222`。不回退直连、不使用超级/管理员令牌、不跨账号自动尝试其他凭据。
2. **凭据存储后端**：
   - **默认（系统凭据库）**：Linux 使用 Secret Service（GNOME Keyring / KWallet，带 D-Bus 锁定预检与超时保护），Windows 使用系统凭据管理器（Credential Manager）。
   - **无桌面 Linux / WSL 可选（`0600` 文件存储）**：通过 `js init --store file` 显式开启，保存在 `~/.config/jsbridge/secrets.json`（强制校验常规文件、拒绝软链接、校验当前用户属主与 `0600` 权限）；可用 `js store migrate --to keyring|file` 双向迁移。
3. **SFTP 根目录边界保护**：JumpServer 平台当前将非 `root` 账号的 SFTP 根目录设为登录用户家目录（如 `/home/alice`）。`js cp` 自动识别 `~/path`、相对路径及 `/home/<user>/path`，并对越界绝对路径（如 `/tmp/...`）主动拦截提示，防止被 KoKo 静默拼接到 `~/tmp`。

---

## Agent (MCP) 接入配置

MCP 客户端配置示例：

```json
{
  "mcpServers": {
    "jumpserver": {
      "command": "/home/yourname/.local/bin/js",
      "args": ["mcp"]
    }
  }
}
```

Codex CLI 注册命令（或参考 [codex.mcp.toml](codex.mcp.toml)）：

```bash
codex mcp add jumpserver -- ~/.local/bin/js mcp
```

MCP 工具一览：

| 工具名 | 参数 | 说明 |
| --- | --- | --- |
| `list_hosts` | 无 | 列出本地已配置目标、别名、凭据就绪状态 (`ready_for_agent`) 与配置代次 `generation` |
| `run_command` | `target, command, cwd?, timeout?` | 自动建连并按 `(target, "ssh")` 复用连接池；输出超 64 KiB 时按头尾各 32 KiB 截断保护上下文 |
| `upload` | `local_path, target, remote_path, overwrite?, recursive?` | 自动建连并复用 SFTP 会话流式上传文件或目录 |
| `download` | `target, remote_path, local_path, overwrite?, recursive?` | 自动建连并复用 SFTP 会话流式下载文件或目录 |
| `close_connection` | `target?, protocol?` | 主动关闭指定目标或全部缓存连接 |

---

## 开发与测试

```bash
# 运行 Go 全量单元与契约测试
go test -v ./...
```

> 配置独立存放于 `~/.config/jsbridge/config.json` 或 `%AppData%\jsbridge\config.json`。
