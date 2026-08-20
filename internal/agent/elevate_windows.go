//go:build windows

package agent

func currentUserIsRoot() bool {
	return false
}