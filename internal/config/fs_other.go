//go:build !linux

package config

func IsNetworkFilesystem(_ string) (bool, string) {
	return false, ""
}
