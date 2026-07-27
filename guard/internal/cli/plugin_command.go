// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/plugin"
)

var (
	pluginUserHome   = os.UserHomeDir
	pluginExecutable = os.Executable
)

func runPluginCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		return invalidArguments(stderr, "plugin")
	}
	target, ok := parsePluginTarget(args[1])
	if !ok {
		return invalidArguments(stderr, "plugin")
	}
	home, err := pluginUserHome()
	if err != nil {
		_, _ = io.WriteString(stderr, "palonexus: plugin: home unavailable\n")
		return 1
	}
	switch args[0] {
	case "install":
		if len(args) != 4 || args[2] != "--source" {
			return invalidArguments(stderr, "plugin")
		}
		executable, err := pluginExecutable()
		if err != nil {
			_, _ = io.WriteString(stderr, "palonexus: plugin: guard unavailable\n")
			return 1
		}
		result, err := plugin.Install(context.Background(), target, plugin.Options{
			Home: home, SourceDir: args[3], GuardPath: executable, Version: Version,
		})
		if err != nil {
			_, _ = io.WriteString(stderr, "palonexus: plugin: install failed\n")
			return 1
		}
		status := "installed"
		if !result.Changed {
			status = "already installed"
		}
		_, _ = fmt.Fprintf(stdout, "palonexus: plugin %s %s\n", target, status)
		return 0
	case "uninstall":
		if len(args) != 2 {
			return invalidArguments(stderr, "plugin")
		}
		result, err := plugin.Uninstall(context.Background(), target, plugin.Options{Home: home})
		if err != nil {
			_, _ = io.WriteString(stderr, "palonexus: plugin: uninstall failed\n")
			return 1
		}
		status := "uninstalled"
		if !result.Changed {
			status = "not installed"
		}
		_, _ = fmt.Fprintf(stdout, "palonexus: plugin %s %s\n", target, status)
		return 0
	default:
		return invalidArguments(stderr, "plugin")
	}
}

func parsePluginTarget(raw string) (plugin.Target, bool) {
	switch raw {
	case string(plugin.ClaudeCode):
		return plugin.ClaudeCode, true
	case string(plugin.Codex):
		return plugin.Codex, true
	default:
		return "", false
	}
}
