//go:build !linux

package credentials

import "context"

func checkPlatformKeyring(_ context.Context, _ bool) error {
	return nil
}
