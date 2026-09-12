package plugin

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestCodexCredentialFingerprintTracksAccountNotTokenGeneration(t *testing.T) {
	first := codexCredentials{AccessToken: "access-a", AccountID: "acct-stable"}
	refreshed := codexCredentials{AccessToken: "access-b", AccountID: "acct-stable"}
	replaced := codexCredentials{AccessToken: "access-b", AccountID: "acct-other"}
	if codexCredentialFingerprint(first) != codexCredentialFingerprint(refreshed) {
		t.Fatal("normal OAuth token rotation changed the real-account fingerprint")
	}
	if codexCredentialFingerprint(first) == codexCredentialFingerprint(replaced) {
		t.Fatal("different real accounts shared a fingerprint")
	}
}

func TestCodexAuthAttributesReadsPlanTypeFromIDToken(t *testing.T) {
	claims, _ := json.Marshal(map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_plan_type": "Team"},
	})
	token := "header." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	raw, _ := json.Marshal(map[string]any{"type": "codex", "id_token": token})
	attributes := codexAuthAttributes(raw)
	if attributes["plan_type"] != "team" {
		t.Fatalf("plan_type = %q", attributes["plan_type"])
	}
}
