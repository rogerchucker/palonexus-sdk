// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func FuzzFrame(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"1"}` + "\n"))
	f.Add([]byte(`{"schemaVersion":"999"}` + "\n"))
	f.Add([]byte("{\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		response := processFrame(context.Background(), input, 4096, echoHandler)
		if len(response) == 0 || response[len(response)-1] != '\n' {
			t.Fatal("response is not one NDJSON frame")
		}
		var value any
		if err := json.Unmarshal(response[:len(response)-1], &value); err != nil {
			t.Fatal(err)
		}
		if len(input) == 0 || len(input) > 4097 || input[len(input)-1] != '\n' {
			var failure protocol.ProtocolError
			if json.Unmarshal(response, &failure) != nil || failure.Code == "" {
				t.Fatal("invalid framing did not fail closed")
			}
		}
	})
}
