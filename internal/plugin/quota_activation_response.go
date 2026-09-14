package plugin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// HTTP success is not a Responses terminal result. Never retain response text
// or arbitrary upstream error messages/codes in the persisted diagnostics.
type activationResponseEvidence struct {
	Outcome, ErrorCode                     string
	HasOutput                              bool
	InputTokens, OutputTokens, TotalTokens int64
}

func parseActivationResponse(raw []byte) activationResponseEvidence {
	e := activationResponseEvidence{Outcome: "unknown"}
	malformed, conflicting := false, false
	consume := func(payload []byte, event string) {
		var doc map[string]any
		if json.Unmarshal(payload, &doc) != nil || doc == nil {
			malformed = true
			return
		}
		var usage quotaActivationState
		readActivationUsageJSON(payload, &usage)
		e.InputTokens = max(e.InputTokens, usage.InputTokens)
		e.OutputTokens = max(e.OutputTokens, usage.OutputTokens)
		e.TotalTokens = max(e.TotalTokens, usage.TotalTokens)
		kind, _ := doc["type"].(string)
		if kind == "" {
			kind = event
		}
		response, nested := mapChild(doc, "response")
		if !nested {
			response = doc
		}
		if output, ok := response["output"].([]any); ok && len(output) > 0 {
			e.HasOutput = true
		}
		if delta, ok := doc["delta"].(string); ok && delta != "" {
			e.HasOutput = true
		}
		if kind == "response.output_item.added" || kind == "response.output_item.done" {
			e.HasOutput = true
		}
		outcome := ""
		switch kind {
		case "response.completed", "response.done":
			outcome = "completed"
		case "response.failed", "error":
			outcome = "failed"
		case "response.incomplete":
			outcome = "incomplete"
		}
		if outcome == "" {
			status, _ := response["status"].(string)
			switch status {
			case "completed", "failed", "incomplete":
				outcome = status
			}
			if _, ok := mapChild(doc, "error"); ok {
				outcome = "failed"
			}
		}
		if outcome != "" {
			if e.Outcome != "unknown" && e.Outcome != outcome {
				conflicting = true
			}
			e.Outcome = outcome
		}
		if outcome == "failed" {
			errorDoc, ok := mapChild(response, "error")
			if !ok {
				errorDoc, ok = mapChild(doc, "error")
			}
			if !ok {
				errorDoc = doc
			}
			code, exists := errorDoc["code"]
			if !exists || code == nil {
				code = errorDoc["type"]
			}
			value, _ := code.(string)
			if knownActivationErrorCode(value) {
				e.ErrorCode = value
			} else {
				e.ErrorCode = "unrecognized_error"
			}
		}
	}
	if json.Valid(raw) {
		consume(raw, "")
	} else {
		// Reader (not Scanner's 64 KiB token limit) handles full terminal events.
		reader := bufio.NewReader(bytes.NewReader(raw))
		var data []string
		event := ""
		flush := func() {
			if len(data) > 0 {
				payload := strings.Join(data, "\n")
				if strings.TrimSpace(payload) != "[DONE]" {
					consume([]byte(payload), event)
				}
			}
			data, event = nil, ""
		}
		for {
			line, err := reader.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				flush()
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, ":"), strings.HasPrefix(line, "id:"), strings.HasPrefix(line, "retry:"):
			default:
				malformed = true
			}
			if err == io.EOF {
				flush()
				break
			}
			if err != nil {
				malformed = true
				break
			}
		}
	}
	if malformed || conflicting {
		e.Outcome, e.ErrorCode = "unknown", "invalid_response"
	}
	return e
}

func knownActivationErrorCode(code string) bool {
	return activationErrorDefinitelyRejected(code) || code == "server_error" || code == "internal_error" || code == "overloaded"
}

func activationErrorDefinitelyRejected(code string) bool {
	switch code {
	case "model_not_found", "unsupported_model", "model_not_supported", "invalid_model",
		"invalid_request_error", "invalid_request", "unsupported_parameter", "invalid_value", "unsupported_value",
		"missing_required_parameter", "invalid_api_key", "authentication_error", "permission_denied",
		"insufficient_permissions", "account_deactivated", "rate_limit_exceeded", "usage_limit_reached", "insufficient_quota":
		return true
	}
	return false
}

func (e activationResponseEvidence) definitelyRejected() bool {
	return e.Outcome == "failed" && !e.HasOutput && e.InputTokens == 0 && e.OutputTokens == 0 && e.TotalTokens == 0 && activationErrorDefinitelyRejected(e.ErrorCode)
}
