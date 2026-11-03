# 通过 JumpServer 使用 rsync

JumpServer 只暴露 SSH 的 shell、exec 和 SFTP，没有 rsync 服务。`js rsh` 把 `js` 变成 rsync 的"远程 shell"（`rsync -e` 的参数），让真正的 rsync 经 KoKo 的 exec 通道运行，增量算法、`--delete`、`--exclude` 等选项都由 rsync 自身提供。

## 用法

```bash
rsync -avz -e "js rsh" ./dir/ 用户@IP:/目标目录/
rsync -avz -e "js rsh" 别名:/远端目录/ ./本地目录/
```

要求：

- `js` 在 `PATH` 中，且该目标的凭据已保存（`js rsh` 是非交互的，缺少凭据时直接报错；请先 `js 用户@IP` 连接一次）。
- 目标机器已安装 rsync。没有安装时，可把同系统版本的 rsync 二进制上传到家目录，再用 `--rsync-path` 指定：

  ```bash
  js cp /usr/bin/rsync 用户@IP:~/.local/bin/rsync
  rsync -avz --rsync-path='$HOME/.local/bin/rsync' -e "js rsh" ./dir/ 用户@IP:~/dir/
  ```

  上传的动态链接二进制要求两端的 glibc 和依赖库兼容；不确定时请使用静态编译的 rsync。

## 工作原理

rsync 会执行 `js rsh [ssh 风格选项] 目标 rsync --server ...`。`js rsh`：

1. 解析并忽略 ssh 风格选项（`-l 用户` 会并入目标）。
2. 经 JumpServer 连接目标，在**不分配 PTY** 的 exec 通道上运行命令。
3. 把本机 stdin/stdout 与远端命令原样对接，二进制安全；stdin 结束时向远端发送 EOF。
4. 诊断信息只写 stderr，不污染 rsync 协议数据；退出码为远端命令的真实退出码。

```text
本机 rsync <-- stdin/stdout --> js rsh <-- KoKo exec 通道 --> 远端 rsync --server
```

## 限制

- JumpServer 资产授权必须允许 exec；部分策略会拦截。
- 增量传输依赖 rsync 本身；`js cp` 仍是不依赖 rsync 的文件传输方式。
