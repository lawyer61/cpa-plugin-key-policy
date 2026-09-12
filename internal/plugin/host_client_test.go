package plugin

import (
	"encoding/json"
	"testing"
)

func TestHostHTTPResponseMatchesCurrentCPAWireFieldNames(t *testing.T) {
	var response HostHTTPResponse
	if err := json.Unmarshal([]byte(`{"StatusCode":200,"Headers":{"X-Test":["ok"]},"Body":"e30="}`), &response); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || response.Headers.Get("X-Test") != "ok" || string(response.Body) != "{}" {
		t.Fatalf("response = %#v", response)
	}
}
