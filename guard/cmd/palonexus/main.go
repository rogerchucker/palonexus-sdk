// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/cli"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/config"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/daemon"
	guardcore "github.com/rogerchucker/palonexus-sdk/guard/internal/guard"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/normalize"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/routing"
	guardsocket "github.com/rogerchucker/palonexus-sdk/guard/internal/socket"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

const internalServeCommand = "__daemon-serve"

func main() {
	if len(os.Args) > 1 && os.Args[1] == internalServeCommand {
		os.Exit(runInternalDaemon(os.Args[2:]))
	}
	if len(os.Args) <= 1 || os.Args[1] == "--help" || os.Args[1] == "-h" ||
		os.Args[1] == "--version" {
		os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
	}
	manager, err := productionManager()
	if err != nil {
		_, _ = os.Stderr.WriteString("palonexus: guard: unavailable\n")
		os.Exit(1)
	}
	os.Exit(cli.RunWithDaemonIO(
		context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, manager,
	))
}

func productionManager() (*daemon.Manager, error) {
	configPath := os.Getenv("PALONEXUS_CONFIG")
	runtimeDir := os.Getenv("PALONEXUS_RUNTIME_DIR")
	if configPath == "" || runtimeDir == "" ||
		!filepath.IsAbs(configPath) || !filepath.IsAbs(runtimeDir) {
		return nil, errors.New("production configuration unavailable")
	}
	allowLocal := os.Getenv("PALONEXUS_ALLOW_LOCAL_TEST_MODE") == "1"
	configuration, err := config.Load(
		configPath, config.Options{AllowLocalTestMode: allowLocal},
	)
	if err != nil {
		return nil, err
	}
	handler, err := checkerHandler(configuration)
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	arguments := []string{
		internalServeCommand,
		"--config", configPath,
		"--runtime", runtimeDir,
		"--config-digest", configuration.Digest(),
	}
	childEnvironment := []string{
		"PALONEXUS_CONFIG_DIGEST=" + configuration.Digest(),
		"PALONEXUS_ALLOW_LOCAL_TEST_MODE=0",
	}
	if allowLocal {
		childEnvironment[1] = "PALONEXUS_ALLOW_LOCAL_TEST_MODE=1"
	}
	return daemon.New(daemon.Config{
		RuntimeDir: runtimeDir, Handler: handler, Executable: executable,
		Arguments: arguments, ChildEnv: childEnvironment,
		ConfigurationDigest: configuration.Digest(),
	})
}

func runInternalDaemon(arguments []string) int {
	if len(arguments) != 6 || arguments[0] != "--config" ||
		arguments[2] != "--runtime" || arguments[4] != "--config-digest" {
		_, _ = os.Stderr.WriteString("palonexus: internal daemon arguments invalid\n")
		return 2
	}
	configPath, runtimeDir, expectedDigest := arguments[1], arguments[3], arguments[5]
	if expectedDigest == "" || os.Getenv("PALONEXUS_CONFIG_DIGEST") != expectedDigest {
		_, _ = os.Stderr.WriteString("palonexus: internal daemon identity unavailable\n")
		return 1
	}
	allowLocal := os.Getenv("PALONEXUS_ALLOW_LOCAL_TEST_MODE") == "1"
	configuration, err := config.Load(
		configPath, config.Options{AllowLocalTestMode: allowLocal},
	)
	if err != nil || configuration.Digest() != expectedDigest {
		_, _ = os.Stderr.WriteString("palonexus: internal daemon configuration unavailable\n")
		return 1
	}
	handler, err := checkerHandler(configuration)
	if err != nil {
		_, _ = os.Stderr.WriteString("palonexus: internal daemon composition unavailable\n")
		return 1
	}
	childEnvironment := []string{
		"PALONEXUS_CONFIG_DIGEST=" + expectedDigest,
		"PALONEXUS_ALLOW_LOCAL_TEST_MODE=0",
	}
	if allowLocal {
		childEnvironment[1] = "PALONEXUS_ALLOW_LOCAL_TEST_MODE=1"
	}
	manager, err := daemon.New(daemon.Config{
		RuntimeDir: runtimeDir, Handler: handler,
		Arguments: append([]string{internalServeCommand}, arguments...),
		ChildEnv:  childEnvironment, ConfigurationDigest: expectedDigest,
	})
	if err != nil {
		_, _ = os.Stderr.WriteString("palonexus: internal daemon runtime unavailable\n")
		return 1
	}
	if err := manager.Run(context.Background()); err != nil {
		if errors.Is(err, guardsocket.ErrRecoveryAmbiguous) {
			return 93
		}
		_, _ = os.Stderr.WriteString("palonexus: internal daemon serve unavailable\n")
		return 1
	}
	return 0
}

type safeResourceNormalizer struct{}

func (safeResourceNormalizer) Normalize(
	ctx context.Context,
	request guardcore.NormalizationRequest,
) (normalize.Prepared, error) {
	if err := ctx.Err(); err != nil {
		return normalize.Prepared{}, err
	}
	resource, ok := request.Opaque.(protocol.SafeText)
	if !ok {
		return normalize.Prepared{}, errors.New("invalid local action resource")
	}
	return normalize.FromSafeResource(resource)
}

type missingSessionSource struct{}

func (missingSessionSource) Current(context.Context) (guardcore.AuthenticatedSession, error) {
	return guardcore.AuthenticatedSession{}, guardcore.ErrNoSession
}

type unavailableDecider struct{}

func (unavailableDecider) Decide(
	context.Context,
	guardcore.DecisionRequest,
) (protocol.AuthorizationDecision, error) {
	return protocol.AuthorizationDecision{}, errors.New("authorization unavailable")
}

func checkerHandler(configuration *config.Config) (guardsocket.Handler, error) {
	routes := configuration.Routes()
	compiled := make([]routing.Route, 0, len(routes))
	for _, route := range routes {
		compiled = append(compiled, routing.Route{
			Target: route.Target, Destination: route.DecisionEndpoint,
		})
	}
	table, err := routing.New(compiled)
	if err != nil {
		return nil, err
	}
	checker := guardcore.New(
		safeResourceNormalizer{}, missingSessionSource{},
		guardcore.NewTableRouteResolver(table), unavailableDecider{},
	)
	if checker == nil {
		return nil, errors.New("guard composition unavailable")
	}
	return func(ctx context.Context, document []byte) ([]byte, error) {
		action, err := protocol.ParseActionRequest(document)
		if err != nil {
			return protocolFailure(
				protocol.ProtocolErrorCodeInvalidRequest, "The request is invalid.", false,
			), nil
		}
		result := checker.Check(ctx, guardcore.Input{
			Normalization: guardcore.NormalizationRequest{
				Kind: action.Target.Kind, Service: action.Target.Service,
				Opaque: action.Target.Resource,
			},
			RouteTarget: action.Target.Service,
			Action:      action,
		})
		code := protocol.ProtocolErrorCodeAuthorizationUnavailable
		message := protocol.SafeText("Authorization is temporarily unavailable.")
		retryable := true
		switch result.Code {
		case guardcore.CodeInvalidRequest:
			code, message, retryable = protocol.ProtocolErrorCodeInvalidRequest,
				"The request is invalid.", false
		case guardcore.CodeMissingIdentity:
			code, message, retryable = protocol.ProtocolErrorCodeAuthenticationFailed,
				"Authentication failed.", false
		case guardcore.CodeInvalidDecision:
			code, message, retryable = protocol.ProtocolErrorCodeInvalidDecision,
				"The authorization decision is invalid.", false
		}
		return protocolFailure(code, message, retryable), nil
	}, nil
}

func protocolFailure(
	code protocol.ProtocolErrorCode,
	message protocol.SafeText,
	retryable bool,
) []byte {
	document, _ := json.Marshal(protocol.ProtocolError{
		SchemaVersion: "1", Code: code, SafeMessage: message, Retryable: retryable,
	})
	return document
}
