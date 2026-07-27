// SPDX-License-Identifier: MIT
//go:build darwin

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
	opened, err := inspectExecutableFile(executable)
	if err != nil || opened != m.launch {
		_ = executable.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	// Darwin has no Go-level fexecve. Hold the proven descriptor and require
	// an identical pathname snapshot immediately before posix_spawn; readiness
	// later verifies the child's independently measured content digest.
	current, err := inspectExecutable(m.cfg.Executable)
	if err != nil || current != opened {
		_ = executable.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	command := exec.CommandContext(
		context.WithoutCancel(ctx), m.cfg.Executable, m.cfg.Arguments...,
	)
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append(safeBaseEnvironment(), m.cfg.ChildEnv...)
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	return command, func() { _ = executable.Close() }, nil
}
