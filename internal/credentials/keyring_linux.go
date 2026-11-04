//go:build linux

package credentials

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/lgcshy/js/internal/errs"
)

const (
	secretServiceName       = "org.freedesktop.secrets"
	secretCollectionIface   = "org.freedesktop.Secret.Collection"
	defaultCollectionPath   = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	loginCollectionPath     = dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
)

func checkPlatformKeyring(ctx context.Context, interactive bool) error {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := dbus.ConnectSessionBus(dbus.WithContext(checkCtx))
	if err != nil {
		return errs.Action(
			"KEYRING_UNAVAILABLE",
			"未检测到桌面会话凭据服务（D-Bus Session Bus 不可用）。",
			"无桌面 Linux 可使用 js init --store file 开启 0600 文件存储",
		)
	}
	defer conn.Close()

	// 检查默认或 login collection 是否可达及是否已锁定
	var locked bool
	var gotProp bool
	for _, path := range []dbus.ObjectPath{loginCollectionPath, defaultCollectionPath} {
		obj := conn.Object(secretServiceName, path)
		v, propErr := obj.GetProperty(secretCollectionIface + ".Locked")
		if propErr == nil {
			if b, ok := v.Value().(bool); ok {
				locked = b
				gotProp = true
				break
			}
		}
	}
	if !gotProp {
		// Secret Service 守护进程可能尚未启动或不存在默认 collection；尝试 Ping 服务
		var hasOwner bool
		err := conn.BusObject().CallWithContext(
			checkCtx,
			"org.freedesktop.DBus.NameHasOwner",
			0,
			secretServiceName,
		).Store(&hasOwner)
		if err != nil {
			return errs.Action(
				"KEYRING_UNAVAILABLE",
				"系统凭据服务（Secret Service）不可访问。",
				"无桌面 Linux 可使用 js init --store file 开启 0600 文件存储",
			)
		}
		if !hasOwner {
			// 检查是否可按需激活
			var activatable []string
			if listErr := conn.BusObject().CallWithContext(
				checkCtx,
				"org.freedesktop.DBus.ListActivatableNames",
				0,
			).Store(&activatable); listErr == nil {
				found := false
				for _, name := range activatable {
					if name == secretServiceName {
						found = true
						break
					}
				}
				if !found {
					return errs.Action(
						"KEYRING_UNAVAILABLE",
						"本机未安装 Secret Service（如 gnome-keyring）。",
						"无桌面 Linux 可使用 js init --store file 开启 0600 文件存储",
					)
				}
			}
		}
		return nil
	}

	if locked && !interactive {
		return errs.Action(
			"KEYRING_LOCKED",
			"系统凭据库当前处于锁定状态，非交互模式无法弹窗解锁。",
			"请先在桌面终端解锁凭据库并运行一次 js hosts",
		)
	}
	return nil
}
