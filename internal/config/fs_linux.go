//go:build linux

package config

import "syscall"

const (
	nfsSuperMagic  = 0x6969
	smbSuperMagic  = 0x517b
	cifsMagic      = 0xff534d42
	smb2Magic      = 0xfe534d42
)

// IsNetworkFilesystem 检测配置目录是否位于 NFS/SMB/CIFS 等网络文件系统。
func IsNetworkFilesystem(dir string) (bool, string) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, ""
	}
	switch uint64(st.Type) {
	case nfsSuperMagic:
		return true, "NFS"
	case smbSuperMagic, cifsMagic, smb2Magic:
		return true, "SMB/CIFS"
	default:
		return false, ""
	}
}
