package policy

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const HashPrefix = "sha256:"

var ErrUnknownKey = errors.New("unknown key")
var ErrNativeKeyUsageReset = errors.New("native CPA keys do not own a resettable derived-key usage ledger")

func GenerateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "cpa_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New("key is required")
	}
	sum := sha256.Sum256([]byte(key))
	return HashPrefix + hex.EncodeToString(sum[:]), nil
}

func MatchHash(key, hash string) bool {
	key = strings.TrimSpace(key)
	hash = strings.TrimSpace(hash)
	if key == "" || hash == "" || !strings.HasPrefix(hash, HashPrefix) {
		return false
	}
	got, err := HashKey(key)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}

func PreviewKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 12 {
		return key
	}
	return fmt.Sprintf("%s...%s", key[:7], key[len(key)-5:])
}

func ExtractAPIKey(headers http.Header, query map[string][]string) string {
	for _, name := range []string{"Authorization", "X-API-Key", "api-key", "x-api-key", "x-goog-api-key"} {
		value := strings.TrimSpace(headerValue(headers, name))
		if value == "" {
			continue
		}
		if strings.EqualFold(name, "Authorization") {
			if token := bearerToken(value); token != "" {
				return token
			}
			continue
		}
		return value
	}
	if query != nil {
		for _, name := range []string{"api_key", "key"} {
			values := query[name]
			if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
				return strings.TrimSpace(values[0])
			}
		}
	}
	return ""
}

func headerValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	if value := headers.Get(name); value != "" {
		return value
	}
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func bearerToken(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
