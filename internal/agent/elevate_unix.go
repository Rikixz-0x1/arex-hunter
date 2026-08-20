//go:build !windows

package agent

import "os"

func currentUserIsRoot() bool {
	return os.Geteuid() == 0
}