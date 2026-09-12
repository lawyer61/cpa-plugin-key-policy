package plugin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type codexCredentials struct {
	AccessToken string
	AccountID   string
	ExpiresAt   time.Time
}

func extractCodexCredentials(raw json.RawMessage) (codexCredentials, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return codexCredentials{}, err
	}
	accessToken, ok := lookupStringDeep(doc, "access_token")
	if !ok || strings.TrimSpace(accessToken) == "" {
		return codexCredentials{}, errors.New("missing access_token")
	}
	idToken, _ := lookupStringDeep(doc, "id_token")
	accountID, _ := lookupStringDeep(doc, "account_id")
	if accountID == "" {
		accountID, _ = lookupStringDeep(doc, "chatgpt_account_id")
	}
	if accountID == "" && idToken != "" {
		accountID, _ = accountIDFromJWT(idToken)
	}
	if strings.TrimSpace(accountID) == "" {
		return codexCredentials{}, errors.New("missing chatgpt_account_id")
	}
	expiresAt, _ := lookupTimeDeep(doc, "expired", "expire", "expires_at", "expiresAt")
	return codexCredentials{
		AccessToken: strings.TrimSpace(accessToken),
		AccountID:   strings.TrimSpace(accountID),
		ExpiresAt:   expiresAt,
	}, nil
}

// codexCredentialFingerprint identifies the real upstream account, not one
// particular OAuth token generation. Access, refresh, and ID tokens can all
// rotate for the same account and therefore must not reset window baselines or
// activation de-duplication state.
func codexCredentialFingerprint(credentials codexCredentials) string {
	sum := sha256.Sum256([]byte("codex\x00" + strings.TrimSpace(credentials.AccountID)))
	return hex.EncodeToString(sum[:])
}

// codexAuthAttributes reconstructs the small attribute projection used by the
// existing group classifier. CPA's host.auth.list payload does not expose the
// auth Attributes map, so maintenance must confirm the physical auth document
// before deciding whether a binding's route/group can actually use it.
func codexAuthAttributes(raw json.RawMessage) map[string]string {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	attributes := make(map[string]string)
	for key, value := range doc {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			continue
		}
		switch typed := value.(type) {
		case string:
			if text := strings.TrimSpace(typed); text != "" {
				attributes[key] = text
			}
		case json.Number:
			attributes[key] = typed.String()
		case float64, bool:
			attributes[key] = strings.TrimSpace(strings.ToLower(fmt.Sprint(typed)))
		}
	}
	if strings.TrimSpace(attributes["plan_type"]) == "" {
		if idToken, ok := lookupStringDeep(doc, "id_token"); ok {
			if planType, ok := planTypeFromJWT(idToken); ok {
				attributes["plan_type"] = planType
			}
		}
	}
	return attributes
}

func codexCredentialsExpired(credentials codexCredentials, now time.Time) bool {
	return !credentials.ExpiresAt.IsZero() && !now.Add(2*time.Minute).Before(credentials.ExpiresAt)
}

func accountIDFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	for _, key := range []string{"https://api.openai.com/auth.chatgpt_account_id", "chatgpt_account_id"} {
		if value, ok := lookupStringDeep(claims, key); ok && value != "" {
			return value, true
		}
	}
	if root, ok := claims.(map[string]any); ok {
		if auth, ok := root["https://api.openai.com/auth"].(map[string]any); ok {
			if value, ok := auth["chatgpt_account_id"].(string); ok && strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value), true
			}
		}
	}
	return "", false
}

func planTypeFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	if root, ok := claims.(map[string]any); ok {
		if auth, ok := root["https://api.openai.com/auth"].(map[string]any); ok {
			if value, ok := auth["chatgpt_plan_type"].(string); ok && strings.TrimSpace(value) != "" {
				return strings.ToLower(strings.TrimSpace(value)), true
			}
		}
	}
	return "", false
}

func decodeJWTClaims(token string) (any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

func lookupStringDeep(value any, key string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if found, ok := typed[key].(string); ok {
			return strings.TrimSpace(found), true
		}
		for _, child := range typed {
			if found, ok := lookupStringDeep(child, key); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range typed {
			if found, ok := lookupStringDeep(child, key); ok {
				return found, true
			}
		}
	}
	return "", false
}

func lookupTimeDeep(value any, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		if raw, ok := lookupStringDeep(value, key); ok {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				if parsed, err := time.Parse(layout, raw); err == nil {
					return parsed, true
				}
			}
		}
	}
	return time.Time{}, false
}

func codexAuthUsesUnsupportedProxy(raw json.RawMessage) bool {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return false
	}
	for _, key := range []string{"proxy", "proxy_url", "proxy-url"} {
		if value, ok := lookupStringDeep(doc, key); ok && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
