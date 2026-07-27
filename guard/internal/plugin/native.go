// SPDX-License-Identifier: MIT

//go:build darwin || linux

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxNativeOutput = 1 << 20

// NativeCommand is an argv-only host invocation. Environment variables are
// explicitly bounded and do not inherit credentials or shell startup state.
type NativeCommand struct {
	Path string
	Args []string
	Env  []string
}

// NativeRunner executes one host command.
type NativeRunner interface {
	Run(context.Context, NativeCommand) ([]byte, error)
}

type execNativeRunner struct{}

func (execNativeRunner) Run(ctx context.Context, invocation NativeCommand) ([]byte, error) {
	command := exec.CommandContext(ctx, invocation.Path, invocation.Args...) //nolint:gosec
	command.Env = append([]string(nil), invocation.Env...)
	command.Stdin = nil
	var output bytes.Buffer
	command.Stdout = &limitedWriter{writer: &output, remaining: maxNativeOutput}
	command.Stderr = &limitedWriter{writer: &output, remaining: maxNativeOutput}
	err := command.Run()
	if errors.Is(err, errOutputLimit) {
		return nil, errors.New("native host output exceeded limit")
	}
	if err != nil {
		return nil, errors.New("native host command failed")
	}
	return output.Bytes(), nil
}

var errOutputLimit = errors.New("output limit")

type limitedWriter struct {
	writer    *bytes.Buffer
	remaining int
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, errOutputLimit
	}
	w.remaining -= len(data)
	return w.writer.Write(data)
}

func nativeEnvironment(home, hostPath string, target Target) ([]string, error) {
	if !safeAbsolute(home) || !safeAbsolute(hostPath) {
		return nil, errors.New("unsafe native host environment")
	}
	path := filepath.Dir(hostPath) + string(os.PathListSeparator) + "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"
	if len(path) > 4096 || strings.ContainsAny(path, "\r\n\x00") {
		return nil, errors.New("unsafe native host path")
	}
	environment := []string{
		"HOME=" + home,
		"PATH=" + path,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	if target == Codex {
		environment = append(environment, "CODEX_HOME="+filepath.Join(home, ".codex"))
	}
	return environment, nil
}

func probeNative(ctx context.Context, target Target, options Options) error {
	output, err := runNative(ctx, target, options, "--version")
	if err != nil {
		return err
	}
	version, err := parseHostVersion(target, string(output))
	if err != nil {
		return err
	}
	minimum := [3]int{2, 1, 219}
	if target == Codex {
		minimum = [3]int{0, 145, 0}
	}
	if compareVersion(version, minimum) < 0 {
		return errors.New("unsupported native host version")
	}
	return nil
}

func probeGuard(ctx context.Context, target Target, options Options) error {
	runner := options.Runner
	if runner == nil {
		runner = execNativeRunner{}
	}
	environment, err := nativeEnvironment(options.Home, options.GuardPath, target)
	if err != nil {
		return err
	}
	output, err := runner.Run(ctx, NativeCommand{
		Path: options.GuardPath, Args: []string{"--version", "--json"}, Env: environment,
	})
	if err != nil {
		return errors.New("guard capability probe failed")
	}
	var identity struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocolVersion"`
	}
	if decodeStrictDocument(output, &identity) != nil || identity.Name != "palonexus" ||
		identity.Version != options.Version || identity.ProtocolVersion != "1.0" {
		return errors.New("unexpected guard identity or protocol")
	}
	return nil
}

func guardAuthenticationStatus(ctx context.Context, target Target, options Options) string {
	runner := options.Runner
	if runner == nil {
		runner = execNativeRunner{}
	}
	environment, err := nativeEnvironment(options.Home, options.GuardPath, target)
	if err != nil {
		return "unknown"
	}
	commandContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := runner.Run(commandContext, NativeCommand{
		Path: options.GuardPath, Args: []string{"status", "--json"}, Env: environment,
	})
	if err != nil {
		return "unknown"
	}
	var status struct {
		Authenticated bool `json:"authenticated"`
		Ready         bool `json:"ready"`
	}
	if decodeStrictDocument(output, &status) != nil {
		return "unknown"
	}
	if status.Authenticated && status.Ready {
		return "authenticated"
	}
	return "login-required"
}

var semanticVersion = regexp.MustCompile(`(?:^|[^0-9])([0-9]+)\.([0-9]+)\.([0-9]+)(?:[^0-9]|$)`)

func parseHostVersion(target Target, output string) ([3]int, error) {
	if len(output) == 0 || len(output) > 4096 || strings.ContainsRune(output, '\x00') {
		return [3]int{}, errors.New("invalid native host version")
	}
	if target == Codex && !strings.Contains(output, "codex-cli") {
		return [3]int{}, errors.New("unexpected native host identity")
	}
	if target == ClaudeCode && !strings.Contains(output, "Claude Code") {
		return [3]int{}, errors.New("unexpected native host identity")
	}
	match := semanticVersion.FindStringSubmatch(output)
	if len(match) != 4 {
		return [3]int{}, errors.New("invalid native host version")
	}
	var result [3]int
	for index := range result {
		value, err := strconv.Atoi(match[index+1])
		if err != nil || value > 1_000_000 {
			return [3]int{}, errors.New("invalid native host version")
		}
		result[index] = value
	}
	return result, nil
}

func compareVersion(left, right [3]int) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func runNative(ctx context.Context, target Target, options Options, args ...string) ([]byte, error) {
	runner := options.Runner
	if runner == nil {
		runner = execNativeRunner{}
	}
	environment, err := nativeEnvironment(options.Home, options.HostPath, target)
	if err != nil {
		return nil, err
	}
	commandContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return runner.Run(commandContext, NativeCommand{
		Path: options.HostPath,
		Args: append([]string(nil), args...),
		Env:  environment,
	})
}

func nativeValidate(ctx context.Context, target Target, options Options, marketplacePath string) error {
	if target == ClaudeCode {
		_, err := runNative(ctx, target, options, "plugin", "validate", "--strict", marketplacePath)
		return err
	}
	// Codex 0.145 validates a local marketplace as part of the native
	// marketplace-add operation; there is no standalone validate subcommand.
	if _, err := runNative(ctx, target, options, "plugin", "marketplace", "add", "--json", marketplacePath); err != nil {
		return err
	}
	if _, err := runNative(ctx, target, options, "plugin", "marketplace", "remove", "palonexus-sdk"); err != nil {
		return errors.New("Codex marketplace validation cleanup failed")
	}
	return nil
}

func nativeReplace(ctx context.Context, target Target, options Options, marketplacePath, version string) error {
	if err := nativeRemove(ctx, target, options, false); err != nil {
		return err
	}
	var err error
	if target == ClaudeCode {
		_, err = runNative(ctx, target, options, "plugin", "marketplace", "add", "--scope", "user", marketplacePath)
		if err == nil {
			_, err = runNative(ctx, target, options, "plugin", "install", "--scope", "user", "palonexus@palonexus-sdk")
		}
	} else {
		_, err = runNative(ctx, target, options, "plugin", "marketplace", "add", "--json", marketplacePath)
		if err == nil {
			_, err = runNative(ctx, target, options, "plugin", "add", "--json", "palonexus@palonexus-sdk")
		}
	}
	if err != nil {
		return err
	}
	return verifyNativeInstalled(ctx, target, options, marketplacePath, version, true)
}

func nativeRemove(ctx context.Context, target Target, options Options, verify bool) error {
	var pluginErr, marketplaceErr error
	if target == ClaudeCode {
		_, pluginErr = runNative(ctx, target, options, "plugin", "uninstall", "--scope", "user", "palonexus@palonexus-sdk")
		_, marketplaceErr = runNative(ctx, target, options, "plugin", "marketplace", "remove", "palonexus-sdk")
	} else {
		_, pluginErr = runNative(ctx, target, options, "plugin", "remove", "--json", "palonexus@palonexus-sdk")
		_, marketplaceErr = runNative(ctx, target, options, "plugin", "marketplace", "remove", "palonexus-sdk")
	}
	if pluginErr != nil {
		if err := verifyNativeInstalled(ctx, target, options, "", "", false); err != nil {
			return pluginErr
		}
	}
	if marketplaceErr != nil {
		absent, err := nativeMarketplaceAbsent(ctx, target, options)
		if err != nil || !absent {
			return marketplaceErr
		}
	}
	if verify {
		return verifyNativeInstalled(ctx, target, options, "", "", false)
	}
	return nil
}

func nativeMarketplaceAbsent(ctx context.Context, target Target, options Options) (bool, error) {
	output, err := runNative(ctx, target, options, "plugin", "marketplace", "list", "--json")
	if err != nil {
		return false, err
	}
	if target == ClaudeCode {
		var records []struct {
			Name string `json:"name"`
		}
		if err := decodeExactJSON(output, &records); err != nil || len(records) > 4096 {
			return false, errors.New("invalid Claude marketplace list")
		}
		for _, record := range records {
			if record.Name == "palonexus-sdk" {
				return false, nil
			}
		}
		return true, nil
	}
	var document struct {
		Marketplaces []struct {
			Name string `json:"name"`
		} `json:"marketplaces"`
	}
	if err := decodeExactJSON(output, &document); err != nil || len(document.Marketplaces) > 4096 {
		return false, errors.New("invalid Codex marketplace list")
	}
	for _, record := range document.Marketplaces {
		if record.Name == "palonexus-sdk" {
			return false, nil
		}
	}
	return true, nil
}

func verifyNativeInstalled(
	ctx context.Context,
	target Target,
	options Options,
	marketplacePath, version string,
	wantInstalled bool,
) error {
	output, err := runNative(ctx, target, options, "plugin", "list", "--json")
	if err != nil {
		return err
	}
	found := false
	if target == ClaudeCode {
		var records []struct {
			ID          string `json:"id"`
			Version     string `json:"version"`
			InstallPath string `json:"installPath"`
			Scope       string `json:"scope"`
		}
		if err := decodeExactJSON(output, &records); err != nil || len(records) > 4096 {
			return errors.New("invalid Claude plugin list")
		}
		for _, record := range records {
			if record.ID == "palonexus@palonexus-sdk" {
				if found || record.Version != version || record.Scope != "user" ||
					!pathWithinMarketplace(record.InstallPath,
						filepath.Join(options.Home, ".claude", "plugins", "cache", "palonexus-sdk")) {
					return errors.New("unexpected Claude plugin registration")
				}
				found = true
			}
		}
	} else {
		var document struct {
			Installed []struct {
				PluginID        string `json:"pluginId"`
				Version         string `json:"version"`
				Installed       bool   `json:"installed"`
				MarketplaceName string `json:"marketplaceName"`
				Source          struct {
					Source string `json:"source"`
					Path   string `json:"path"`
				} `json:"source"`
				MarketplaceSource struct {
					SourceType string `json:"sourceType"`
					Source     string `json:"source"`
				} `json:"marketplaceSource"`
			} `json:"installed"`
			Available []json.RawMessage `json:"available"`
		}
		if err := decodeExactJSON(output, &document); err != nil || len(document.Installed) > 4096 {
			return errors.New("invalid Codex plugin list")
		}
		for _, record := range document.Installed {
			if record.PluginID == "palonexus@palonexus-sdk" {
				if found || !record.Installed || record.Version != version ||
					record.MarketplaceName != "palonexus-sdk" ||
					record.MarketplaceSource.SourceType != "local" ||
					!sameCanonicalPath(record.MarketplaceSource.Source, marketplacePath) ||
					!pathWithinMarketplace(record.Source.Path, marketplacePath) {
					return errors.New("unexpected Codex plugin registration")
				}
				found = true
			}
		}
	}
	if found != wantInstalled {
		return fmt.Errorf("native plugin registration mismatch")
	}
	return nil
}

func pathWithinMarketplace(path, marketplace string) bool {
	if !safeAbsolute(path) || !safeAbsolute(marketplace) {
		return false
	}
	canonicalPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		canonicalPath = filepath.Clean(path)
	}
	canonicalMarketplace, err := filepath.EvalSymlinks(marketplace)
	if err != nil {
		canonicalMarketplace = filepath.Clean(marketplace)
	}
	relative, err := filepath.Rel(canonicalMarketplace, canonicalPath)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func sameCanonicalPath(left, right string) bool {
	if !safeAbsolute(left) || !safeAbsolute(right) {
		return false
	}
	leftCanonical, leftErr := filepath.EvalSymlinks(left)
	rightCanonical, rightErr := filepath.EvalSymlinks(right)
	if leftErr != nil {
		leftCanonical = filepath.Clean(left)
	}
	if rightErr != nil {
		rightCanonical = filepath.Clean(right)
	}
	return leftCanonical == rightCanonical
}

func decodeExactJSON(data []byte, destination any) error {
	if len(data) == 0 || len(data) > maxNativeOutput || rejectDuplicateJSONKeys(data) != nil {
		return errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}
