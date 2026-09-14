package plugin

import (
	"strings"
	"testing"
)

func TestParseActivationResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body, outcome, code string
		rejected, output          bool
		tokens                    int64
	}{
		{name: "completed", body: `{"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}`, outcome: "completed", tokens: 3},
		{name: "completed_without_usage", body: `{"type":"response.completed","response":{"status":"completed"}}`, outcome: "completed"},
		{name: "raw_usage", body: `{"usage":{"input_tokens":1,"total_tokens":1}}`, outcome: "unknown", tokens: 1},
		{name: "failed", body: `{"type":"response.failed","response":{"error":{"code":"model_not_found","message":"SECRET-ACCESS-TOKEN"}}}`, outcome: "failed", code: "model_not_found", rejected: true},
		{name: "json_error", body: `{"error":{"type":"invalid_request_error","message":"SECRET"}}`, outcome: "failed", code: "invalid_request_error", rejected: true},
		{name: "event_fallback", body: "event: error\r\ndata: {\"error\":{\"code\":\"permission_denied\"}}\r\n\r\n", outcome: "failed", code: "permission_denied", rejected: true},
		{name: "unknown_code", body: `{"type":"error","error":{"code":"SECRET_TOKEN","type":"invalid_request_error","message":"SECRET_MESSAGE"}}`, outcome: "failed", code: "unrecognized_error"},
		{name: "server_error", body: `{"type":"response.failed","response":{"error":{"code":"server_error"}}}`, outcome: "failed", code: "server_error"},
		{name: "failed_with_usage", body: `{"type":"response.failed","response":{"error":{"code":"model_not_found"},"usage":{"output_tokens":1,"total_tokens":1}}}`, outcome: "failed", code: "model_not_found", tokens: 1},
		{name: "failed_with_output", body: `{"type":"response.failed","response":{"output":[{"text":"secret output"}],"error":{"code":"invalid_request_error"}}}`, outcome: "failed", code: "invalid_request_error", output: true},
		{name: "partial_stream", body: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n", outcome: "unknown", output: true},
		{name: "incomplete", body: `{"type":"response.incomplete","response":{"usage":{"output_tokens":0}}}`, outcome: "incomplete"},
		{name: "missing_terminal", body: "data: {\"type\":\"response.created\"}\n\ndata: [DONE]\n\n", outcome: "unknown"},
		{name: "truncated", body: "data: {\"type\":\"response.completed\"\n\n", outcome: "unknown", code: "invalid_response"},
		{name: "multiline", body: "event: response.completed\ndata: {\ndata: \"response\":{\"usage\":{\"total_tokens\":2}}}\n\n", outcome: "completed", tokens: 2},
		{name: "large_event", body: `data: {"type":"response.completed","padding":"` + strings.Repeat("x", 70000) + `","response":{"usage":{"total_tokens":2}}}` + "\n\n", outcome: "completed", tokens: 2},
		{name: "conflicting", body: "data: {\"type\":\"response.completed\"}\n\ndata: {\"type\":\"error\",\"error\":{\"code\":\"model_not_found\"}}\n\n", outcome: "unknown", code: "invalid_response"},
		{name: "malformed_then_rejection", body: "data: broken\n\ndata: {\"type\":\"error\",\"error\":{\"code\":\"model_not_found\"}}\n\n", outcome: "unknown", code: "invalid_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := parseActivationResponse([]byte(tc.body))
			if e.Outcome != tc.outcome || e.ErrorCode != tc.code || e.definitelyRejected() != tc.rejected || e.HasOutput != tc.output || e.TotalTokens != tc.tokens {
				t.Fatalf("evidence=%+v rejected=%t; want outcome=%s code=%s rejected=%t output=%t tokens=%d", e, e.definitelyRejected(), tc.outcome, tc.code, tc.rejected, tc.output, tc.tokens)
			}
			if strings.Contains(e.ErrorCode, "SECRET") {
				t.Fatal("upstream secret leaked")
			}
		})
	}
}
