package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const quotaRuntimeVersion = 1

type quotaWindowBaseline struct {
	Kind          quotaWindowKind `json:"kind"`
	ResetAt       time.Time       `json:"reset_at"`
	UsedPercent   float64         `json:"used_percent"`
	WindowSeconds int64           `json:"window_seconds"`
	ObservedAt    time.Time       `json:"observed_at"`
}

type quotaActivationState struct {
	Protocol             string                                  `json:"protocol,omitempty"`
	Model                string                                  `json:"model,omitempty"`
	Status               string                                  `json:"status,omitempty"`
	CycleID              string                                  `json:"cycle_id,omitempty"`
	Windows              []quotaWindowKind                       `json:"windows,omitempty"`
	Attempts             int                                     `json:"attempts,omitempty"`
	LastAttemptAt        time.Time                               `json:"last_attempt_at,omitempty"`
	NextCheckAt          time.Time                               `json:"next_check_at,omitempty"`
	SendIntent           bool                                    `json:"send_intent,omitempty"`
	RetryAllowed         bool                                    `json:"retry_allowed,omitempty"`
	LastResult           string                                  `json:"last_result,omitempty"`
	LastError            string                                  `json:"last_error,omitempty"`
	InputTokens          int64                                   `json:"input_tokens,omitempty"`
	OutputTokens         int64                                   `json:"output_tokens,omitempty"`
	TotalTokens          int64                                   `json:"total_tokens,omitempty"`
	ResponseOutcome      string                                  `json:"response_outcome,omitempty"`
	ResponseErrorCode    string                                  `json:"response_error_code,omitempty"`
	OutputObserved       bool                                    `json:"output_observed,omitempty"`
	RecoveryObservations map[quotaWindowKind]quotaWindowBaseline `json:"recovery_observations,omitempty"`
}

type quotaAuthRuntime struct {
	AuthID                string                                  `json:"auth_id"`
	AuthIndex             string                                  `json:"auth_index,omitempty"`
	CredentialFingerprint string                                  `json:"credential_fingerprint,omitempty"`
	Provider              string                                  `json:"provider,omitempty"`
	PlanType              string                                  `json:"plan_type,omitempty"`
	Groups                []string                                `json:"groups,omitempty"`
	RosterConfirmed       bool                                    `json:"roster_confirmed,omitempty"`
	QueryEligible         bool                                    `json:"query_eligible,omitempty"`
	QuotaBackoffUntil     time.Time                               `json:"quota_backoff_until,omitempty"`
	Status                string                                  `json:"status,omitempty"`
	InManagedPool         bool                                    `json:"in_managed_pool,omitempty"`
	InMaintenanceScope    bool                                    `json:"in_maintenance_scope,omitempty"`
	InActivationScope     bool                                    `json:"in_activation_scope,omitempty"`
	ExclusionReason       string                                  `json:"exclusion_reason,omitempty"`
	LastRosterSeenAt      time.Time                               `json:"last_roster_seen_at,omitempty"`
	OutOfScopeAt          time.Time                               `json:"out_of_scope_at,omitempty"`
	LastCheckAt           time.Time                               `json:"last_check_at,omitempty"`
	NextCheckAt           time.Time                               `json:"next_check_at,omitempty"`
	LastResult            string                                  `json:"last_result,omitempty"`
	LastError             string                                  `json:"last_error,omitempty"`
	Baselines             map[quotaWindowKind]quotaWindowBaseline `json:"baselines,omitempty"`
	Activation            quotaActivationState                    `json:"activation,omitempty"`
}

type quotaRuntimeDocument struct {
	Version        int                         `json:"version"`
	UpdatedAt      time.Time                   `json:"updated_at"`
	AuthRefSecret  string                      `json:"auth_ref_secret,omitempty"`
	LastRosterSync time.Time                   `json:"last_roster_sync,omitempty"`
	LastRoundAt    time.Time                   `json:"last_round_at,omitempty"`
	RoundCursor    string                      `json:"round_cursor,omitempty"`
	Observations   map[string]quotaObservation `json:"observations,omitempty"`
	Auths          map[string]quotaAuthRuntime `json:"auths,omitempty"`
}

type quotaRuntimeStore struct {
	mu   sync.Mutex
	path string
}

func newQuotaRuntimeStore(path string) *quotaRuntimeStore {
	return &quotaRuntimeStore{path: path}
}

func quotaRuntimePath(statePath string) string {
	if statePath == "" {
		return ""
	}
	return statePath + ".quota-runtime.json"
}

func (s *quotaRuntimeStore) load() (quotaRuntimeDocument, error) {
	if s == nil || s.path == "" {
		return quotaRuntimeDocument{}, errors.New("quota runtime path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return quotaRuntimeDocument{}, err
	}
	var doc quotaRuntimeDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return quotaRuntimeDocument{}, fmt.Errorf("decode quota runtime state: %w", err)
	}
	if doc.Version != quotaRuntimeVersion {
		return quotaRuntimeDocument{}, fmt.Errorf("unsupported quota runtime state version %d", doc.Version)
	}
	if doc.Auths == nil {
		doc.Auths = make(map[string]quotaAuthRuntime)
	}
	if doc.Observations == nil {
		doc.Observations = make(map[string]quotaObservation)
	}
	return doc, nil
}

func (s *quotaRuntimeStore) save(doc quotaRuntimeDocument) error {
	if s == nil || s.path == "" {
		return errors.New("quota runtime path is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc.Version = quotaRuntimeVersion
	doc.UpdatedAt = time.Now().UTC()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return replaceQuotaRuntimeFile(tempName, s.path)
}
