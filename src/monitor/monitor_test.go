package monitor

import (
	"encoding/json"
	"testing"
)

func TestResultEnvelopeMarshalUnmarshal(t *testing.T) {
	sr := &SiteResult{Name: "example", URL: "https://example.com", TCPTimeMs: 10}
	env := wrapRoot(sr)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var dec ResultEnvelope
	if err := json.Unmarshal(b, &dec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dec.Meta == nil || dec.SiteResult == nil {
		t.Fatalf("decoded envelope missing parts")
	}
	if dec.Meta.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version mismatch: got %d want %d", dec.Meta.SchemaVersion, SchemaVersion)
	}
	if dec.SiteResult.Name != "example" {
		t.Fatalf("site_result name mismatch: %s", dec.SiteResult.Name)
	}
}
