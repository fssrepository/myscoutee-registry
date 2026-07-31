package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/buildinfo"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestVersionCommandDoesNotLoadConfiguration(t *testing.T) {
	t.Setenv("REGISTRY_SCOPE", "this value would fail configuration validation")
	var output bytes.Buffer
	if err := runVersion(&output); err != nil {
		t.Fatalf("run version: %v", err)
	}
	var result struct {
		Service         string `json:"service"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocol_version"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode version output: %v", err)
	}
	if result.Service != buildinfo.Service ||
		result.Version != buildinfo.Version ||
		result.ProtocolVersion != protocol.Version {
		t.Fatalf("unexpected version output: %+v", result)
	}
}
