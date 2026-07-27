// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"context"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func (m *Manager) launchCommand(
	ctx context.Context,
	logFile *os.File,
) (*exec.Cmd, func(), error) {
	executable, err := os.Open(m.cfg.Executable)
	if err != nil {
		return nil, nil, ErrUnsafeExecutable
	}
	identity, err := inspectExecutableFile(executable)
	if err != nil || identity != m.launch {
		_ = executable.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	command := exec.CommandContext(context.WithoutCancel(ctx), "/proc/self/fd/3")
	command.Args = append([]string{m.cfg.Executable}, m.cfg.Arguments...)
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append(safeBaseEnvironment(), m.cfg.ChildEnv...)
	command.ExtraFiles = []*os.File{executable}
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	return command, func() { _ = executable.Close() }, nil
}
