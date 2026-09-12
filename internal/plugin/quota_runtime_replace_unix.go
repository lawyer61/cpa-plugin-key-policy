//go:build !windows

package plugin

import "os"

func replaceQuotaRuntimeFile(source, destination string) error {
	return os.Rename(source, destination)
}
