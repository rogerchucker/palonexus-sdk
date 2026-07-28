// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/plugin"
)

var (
	pluginUserHome   = os.UserHomeDir
	pluginExecutable = os.Executable
	pluginLookPath   = exec.LookPath
	pluginRunner     plugin.NativeRunner
)

func runPluginCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		_, _ = io.WriteString(stdout, pluginHelp)
		return 0
	}
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
		if len(args) != 2 && (len(args) != 4 || args[2] != "--source") {
			return invalidArguments(stderr, "plugin")
		}
		executable, err := pluginExecutable()
		if err != nil {
			_, _ = io.WriteString(stderr, "palonexus: plugin: guard unavailable\n")
			return 1
		}
		hostName := "claude"
		if target == plugin.Codex {
			hostName = "codex"
		}
		hostPath, err := pluginLookPath(hostName)
		if err != nil || !filepath.IsAbs(hostPath) {
			_, _ = io.WriteString(stderr, "palonexus: plugin: supported host unavailable\n")
			return 1
		}
		hostPath, err = filepath.EvalSymlinks(hostPath)
		if err != nil || !filepath.IsAbs(hostPath) {
			_, _ = io.WriteString(stderr, "palonexus: plugin: supported host unavailable\n")
			return 1
		}
		source := ""
		if len(args) == 4 {
			source = args[3]
		} else {
			source, err = packagedPluginSource(executable, target)
			if err != nil {
				_, _ = io.WriteString(stderr, "palonexus: plugin: packaged artifact unavailable\n")
				return 1
			}
		}
		result, err := plugin.Install(context.Background(), target, plugin.Options{
			Home: home, SourceDir: source, GuardPath: executable, HostPath: hostPath, Version: Version,
			Runner: pluginRunner,
		})
		if err != nil {
			_, _ = io.WriteString(stderr, "palonexus: plugin: install failed\n")
			return 1
		}
		status := "installed"
		if !result.Changed {
			status = "already installed"
		}
		authMessage := "authentication status unavailable; run `palonexus status` and `palonexus login` if required"
		if result.AuthenticationStatus == "login-required" {
			authMessage = "login required; run `palonexus login`"
		} else if result.AuthenticationStatus == "authenticated" {
			authMessage = "guard authenticated and ready"
		}
		_, _ = fmt.Fprintf(stdout, "palonexus: plugin %s %s; %s\n", target, status, authMessage)
		return 0
	case "uninstall":
		if len(args) != 2 {
			return invalidArguments(stderr, "plugin")
		}
		hostName := "claude"
		if target == plugin.Codex {
			hostName = "codex"
		}
		hostPath, lookupErr := pluginLookPath(hostName)
		if lookupErr != nil || !filepath.IsAbs(hostPath) {
			_, _ = io.WriteString(stderr, "palonexus: plugin: supported host unavailable\n")
			return 1
		}
		hostPath, lookupErr = filepath.EvalSymlinks(hostPath)
		if lookupErr != nil || !filepath.IsAbs(hostPath) {
			_, _ = io.WriteString(stderr, "palonexus: plugin: supported host unavailable\n")
			return 1
		}
		result, err := plugin.Uninstall(context.Background(), target, plugin.Options{
			Home: home, HostPath: hostPath,
			Runner: pluginRunner,
		})
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

const pluginHelp = `Usage:
  palonexus plugin install <claude-code|codex> [--source <absolute-marketplace-path>]
  palonexus plugin uninstall <claude-code|codex>

Install uses the marketplace bundled beside the palonexus executable. --source
is a development-only override. Installation validates the native host and
marketplace, registers palonexus@palonexus-sdk, and preserves unrelated host
configuration.
`

func packagedPluginSource(executable string, target plugin.Target) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", fmt.Errorf("executable path is not absolute")
	}
	base := filepath.Dir(filepath.Clean(executable))
	candidates := []string{
		filepath.Join(base, "plugins", string(target)),
		filepath.Clean(filepath.Join(base, "..", "share", "palonexus", "plugins", string(target))),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("packaged plugin not found")
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
