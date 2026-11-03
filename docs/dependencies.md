# 依赖说明

依赖选型依据为各库的公开源码和协议文档，下表为选定的版本，实际锁定以 `go.mod` / `go.sum` 为准。选型依据不代表依赖安全扫描、跨平台编译或实机验收已通过。

## 最小依赖集

| 用途 | 版本 | 代码依据与边界 |
| --- | --- | --- |
| SSH、主机密钥校验 | `golang.org/x/crypto v0.58.0`，commit `8fdf07b3114278fb3b78c1cf1814e08bd851eb4c` | `ssh` 提供协议客户端、认证与远端会话；`ssh/knownhosts` 提供 `HostKeyCallback`。无需启动本机 OpenSSH。库支持不代表 KoKo 允许对应请求。[session.go](https://github.com/golang/crypto/blob/v0.58.0/ssh/session.go)、[knownhosts.go](https://github.com/golang/crypto/blob/v0.58.0/ssh/knownhosts/knownhosts.go) |
| 本机密码输入及终端 | `golang.org/x/term v0.47.0`，commit `0851034afad912733699827b3bb94436f059797f` | Unix 后端用 `x/sys/unix`，Windows 后端用 `x/sys/windows`；提供终端模式、无回显输入及尺寸读取。Windows 的输入与输出控制台模式仍需应用适配及实机验证。[Unix](https://github.com/golang/term/blob/v0.47.0/term_unix.go)、[Windows](https://github.com/golang/term/blob/v0.47.0/term_windows.go) |
| SFTP，待服务器能力通过后开放 | `github.com/pkg/sftp v1.13.12`，commit `4b4c6a4385536ad091ae3f8d756261b35f0f860f` | 通过 SSH session 发起 SFTP subsystem；不能从 SSH shell 可用推导 SFTP 可用。采用稳定 v1，暂不引入 v2 alpha。[client.go](https://github.com/pkg/sftp/blob/v1.13.12/client.go) |
| 系统凭据库 | `github.com/zalando/go-keyring v0.2.8`，commit `a8cdfe320cc8bc0534c895a648dc9214715a9da5` | 三个平台实现不同，见下表。只按明确的 service/account 精确读写，不调用批量枚举。[go.mod](https://github.com/zalando/go-keyring/blob/v0.2.8/go.mod) |
| MCP stdio | 官方 `github.com/modelcontextprotocol/go-sdk v1.8.0`，commit `3f3b699b2b67e1ed033a63d6651671dab53c2d32` | `mcp.StdioTransport` 通过 stdin/stdout 读写逐行 JSON；不另起 HTTP 服务。[transport.go](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/transport.go) |

HTTP、TLS、JSON、配置文件与命令分发优先用标准库；先不引入 CLI 框架、本地 PTY 库、SSH 服务端或常驻后台服务。交互终端可直接请求远端 SSH PTY，再把本机终端流接入，无需为此创建本机 Unix PTY。SSH 的 PTY 与 `shell`/`exec` 请求是独立动作，必须按 KoKo 的实际能力选择。

上述 `x/crypto` 与 `x/term` 的模块要求 Go 1.26.0，MCP SDK 和 SFTP 要求 Go 1.25.0；因此组合工具链下限为 Go 1.26，发布时另固定受支持的安全补丁版本。建议在发布前执行依赖校验和漏洞检查（如 `go mod verify`、`govulncheck`）。[crypto go.mod](https://github.com/golang/crypto/blob/v0.58.0/go.mod)、[term go.mod](https://github.com/golang/term/blob/v0.47.0/go.mod)、[MCP go.mod](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/go.mod)、[SFTP go.mod](https://github.com/pkg/sftp/blob/v1.13.12/go.mod)

## `CGO_ENABLED=0` 与凭据库

| 平台 | v0.2.8 实现 | 运行条件与选择 |
| --- | --- | --- |
| Linux | Go D-Bus 客户端 `godbus/dbus/v5 v5.2.2`，调用 Secret Service；Linux build tag 不要求 cgo | 需要可访问的用户会话总线、Secret Service 服务及可解锁 collection。headless/WSL 不保证存在。缺失时明确返回不可用，可选择已配置的 gopass 或仅当前人工会话内存输入，禁止静默保存明文。[keyring_unix.go](https://github.com/zalando/go-keyring/blob/v0.2.8/keyring_unix.go)、[godbus README](https://github.com/godbus/dbus/blob/v5.2.2/README.md) |
| Windows | `wincred v1.2.3` 通过 `x/sys/windows`、`syscall.SyscallN` 调用系统 `advapi32.dll` 的 Credential Manager API，没有 cgo 调用 | 依赖当前 Windows 用户的凭据库及系统 API；不是“完全无系统依赖”。库限制 secret 不超过 2560 字节，不把完整私钥塞入该字段。[keyring_windows.go](https://github.com/zalando/go-keyring/blob/v0.2.8/keyring_windows.go)、[wincred sys.go](https://github.com/danieljoos/wincred/blob/v1.2.3/sys.go) |
| macOS | `os/exec` 调用 `/usr/bin/security`，没有 cgo 调用 | `Set` 启动参数只有 `-i`，包含 `-w secret` 的命令通过 `StdinPipe` 写入，secret **不在进程 argv**。`Get` 捕获返回值供程序内部使用；不允许透传到日志或 MCP。仍需要系统命令、Keychain 权限及解锁；建议后续实机验收再支持。[keyring_darwin.go](https://github.com/zalando/go-keyring/blob/v0.2.8/keyring_darwin.go) |

macOS 特别注意：源码在启动子进程后才检查构造命令的 4096 字节上限；适配层需在调用前限制长度并拒绝过大输入。这里的 base64 只是编码，安全存储由 Keychain 提供。当前核查版本没有把密码放进 argv，不能把这一结论无条件套用于旧版本或其他 keyring 库。

统一 `CredentialStore` 接口只存 AK secret、短期登录凭据或目标密码等短值；私钥仍为用户明确绑定的路径。gopass 是可选外部程序，不属于二进制内置能力：执行精确条目读取，内部捕获输出，限制等待时间；不可把原始 stdout/stderr 拼入错误。不要求所有平台安装 gopass，也不为此新增自建密文数据库。没有可用安全凭据来源时，人工 CLI 可提示；MCP 返回 `action_required`，由用户在独立终端完成初始化或解锁。

## MCP、SSH 返回语义和平台边界

- MCP 只是 Agent 调用本地工具的协议。其 HTTP OAuth 授权规范不适用于 stdio；JumpServer 的本人登录、MFA、普通连接令牌及审批仍由连接模块处理，不能拿 MCP 会话代替。此项目用本机凭据库读取秘密，不把秘密放在工具参数、MCP 配置、环境示例或日志中。[MCP 2025-11-25 授权规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- stdio 模式 stdout 只输出 MCP 消息，诊断走经过清理的 stderr；限长读取和分页/截断输出，避免大终端输出耗尽内存。官方 SDK v1.8.0 的 `StdioTransport.MaxLineLength` 可限制输入帧；应用仍需独立限制远端输出。[transport.go](https://github.com/modelcontextprotocol/go-sdk/blob/v1.8.0/mcp/transport.go)
- 原生 SSH exec 可分离 stdout/stderr；`Wait` 遇服务端不发送状态时返回 `ExitMissingError`，此时状态必须标记未知。PTY shell 的合并终端输出及命令内标记提取不是原生 SSH 每命令退出状态，持续会话中的超时也不证明远端进程已终止。[session.go](https://github.com/golang/crypto/blob/v0.58.0/ssh/session.go)
- `CGO_ENABLED=0` 关闭 cgo，并不消除系统服务、证书、DLL 或辅助命令依赖；设置 `GOOS/GOARCH` 只是交叉构建目标，不能作为实际运行验证证据。[Go cgo 文档](https://pkg.go.dev/cmd/cgo)

## 建议发布与验收矩阵

| 目标 | 建议 | 必须在对应环境验证 |
| --- | --- | --- |
| Linux amd64 / arm64 | 首发目标 | CGO=0 编译、二进制依赖检查；桌面 Secret Service、headless gopass 两条可选路径；SSH 主机校验、PTY 恢复、取消/超时、MCP stdio |
| Windows amd64 | 首发目标 | 原生 Windows Credential Manager；PowerShell/Windows Terminal 无回显输入、Ctrl+C、窗口尺寸、退出后终端恢复、MCP 管道模式 |
| Windows arm64 | 编译候选，暂不承诺支持 | 以上 Windows 项目在 arm64 实机重复验收 |
| macOS amd64 / arm64 | 后续候选 | Keychain 锁定/解锁/拒绝授权、security stdin 路径、无秘密日志、终端恢复及分发后的系统信任提示 |
| WSL | Linux 运行环境 | 不自动继承 Windows Credential Manager、Windows SSH agent 或原用户配置；明确凭据来源和 Linux 路径 |

每个发布资产应提供版本、对应 OS/架构、SHA-256、依赖许可清单及最小使用说明；二进制不携带个人账号、AK、目标凭据或个人配置。已编译、已启动、本机凭据库可用、JumpServer 命令执行成功和审计被管理员接受应分别验证，不能互相替代。
