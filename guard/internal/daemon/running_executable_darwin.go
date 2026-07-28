// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"os"
	"path/filepath"
)

func runningExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func inspectRunningExecutable(path string) (executableIdentity, error) {
	return inspectExecutable(path)
}
