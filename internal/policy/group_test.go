package policy

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

// ModelRule.Group is an optional field: legacy state/config without it must
// round-trip as an empty string (no tier narrowing), and a config that sets it
// must normalize it (trim + lowercase) and survive YAML decode + state JSON
// save/load.
func TestModelRuleGroupRoundTrip(t *testing.T) {
	yaml := []byte(`
enabled: true
state_file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "state.json")) + `"
keys:
  - id: k
    enabled: true
    key_hash: x
    models:
      - alias: fast
        provider: Codex
        target_model: gpt-5-codex
        group: TEAM
      - alias: any
        provider: codex
        target_model: gpt-5-codex
`)
	cfg, err := DecodeConfig(yaml)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Migration: per-key Models are promoted to the global alias table.
	// The key now references aliases by name (Models is empty, Aliases has refs).
	if len(cfg.Keys) != 1 || len(cfg.Keys[0].Aliases) != 2 {
		t.Fatalf("unexpected decode: %+v", cfg)
	}
	if len(cfg.Aliases) != 2 {
		t.Fatalf("expected 2 global aliases, got %d", len(cfg.Aliases))
	}
	// Find the "fast" alias and check its target's group was normalized.
	var fastAlias *AliasMapping
	for i := range cfg.Aliases {
		if cfg.Aliases[i].Alias == "fast" {
			fastAlias = &cfg.Aliases[i]
		}
	}
	if fastAlias == nil || len(fastAlias.Targets) != 1 {
		t.Fatalf("fast alias not found or wrong targets: %+v", cfg.Aliases)
	}
	if fastAlias.Targets[0].Group != "team" {
		t.Fatalf("expected normalized group 'team', got %q", fastAlias.Targets[0].Group)
	}
	// The "any" alias should have empty group.
	var anyAlias *AliasMapping
	for i := range cfg.Aliases {
		if cfg.Aliases[i].Alias == "any" {
			anyAlias = &cfg.Aliases[i]
		}
	}
	if anyAlias == nil || anyAlias.Targets[0].Group != "" {
		t.Fatalf("expected empty group for 'any' alias, got: %+v", cfg.Aliases)
	}

	// State JSON serialization must keep group and omit empty.
	// Serialize the global alias table (the migrated form).
	out, err := json.Marshal(cfg.Aliases)
	if err != nil {
		t.Fatal(err)
	}
	var back []AliasMapping
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back[0].Targets[0].Group != "team" && back[1].Targets[0].Group != "" {
		t.Fatalf("json round-trip lost group: %+v", back)
	}
}

// Group is surfaced via Authenticate's decision.Rule so the plugin can stamp it
// into request metadata for the scheduler.
func TestAuthenticateSurfacesGroup(t *testing.T) {
	store := NewStore()
	hash, _ := HashKey("k1")
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Keys: []KeyConfig{{
			ID:      "k",
			Enabled: true,
			KeyHash: hash,
			Models: []ModelRule{
				{Alias: "fast", Provider: "codex", TargetModel: "gpt-5-codex", Group: "team"},
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	dec := store.Authenticate("POST", "/v1/chat/completions", http.Header{"Authorization": {"Bearer k1"}}, nil, []byte(`{"model":"fast"}`))
	if !dec.Allowed {
		t.Fatalf("expected allowed, got %+v", dec)
	}
	if dec.Rule.Group != "team" {
		t.Fatalf("expected group surfaced on decision, got %q", dec.Rule.Group)
	}
}

// Multi-target aliases with different groups must surface the SAME group on
// Authenticate and Route for one request. Previously Authenticate used
// ModelForAlias (always first match) while Route advanced round-robin, so the
// scheduler could filter by free while the router forwarded the team target.
func TestAuthenticateAndRouteShareMultiTargetGroup(t *testing.T) {
	store := NewStore()
	plain := "multi-group-key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{{
			Alias:    "mixed",
			Dispatch: "round-robin",
			Targets: []AliasTarget{
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "free"},
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "team"},
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "plus"},
			},
			BillingMode: "tokens",
		}},
		Keys: []KeyConfig{{
			ID: "k", Enabled: true, KeyHash: hash,
			Aliases: []KeyAliasRef{{Alias: "mixed"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	hdr := http.Header{"Authorization": {"Bearer " + plain}}
	body := []byte(`{"model":"mixed"}`)

	seenGroups := map[string]int{}
	for i := 0; i < 6; i++ {
		dec := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, body)
		if !dec.Allowed {
			t.Fatalf("auth %d: expected allowed, got %+v", i, dec)
		}
		rule, keyID, ok := store.Route(hdr, nil, "mixed")
		if !ok || keyID != "k" {
			t.Fatalf("route %d: expected ok key=k, got ok=%v key=%q", i, ok, keyID)
		}
		if rule.Group != dec.Rule.Group {
			t.Fatalf("call %d: auth group %q != route group %q (provider=%s model=%s)",
				i, dec.Rule.Group, rule.Group, rule.Provider, rule.TargetModel)
		}
		if rule.Provider != dec.Rule.Provider || rule.TargetModel != dec.Rule.TargetModel {
			t.Fatalf("call %d: auth target %+v != route target %+v", i, dec.Rule, rule)
		}
		seenGroups[rule.Group]++
	}
	// Round-robin across 3 groups × 2 cycles should hit every group.
	for _, g := range []string{"free", "team", "plus"} {
		if seenGroups[g] == 0 {
			t.Fatalf("expected round-robin to hit group %q, got %v", g, seenGroups)
		}
	}
}

// Explicit account bindings make the credential allow-list the complete
// account boundary. Targets that differ only by group collapse to one route,
// while genuinely different provider/model routes keep their dispatch order.
func TestBoundAuthenticateAndRouteIgnoreAndDeduplicateGroups(t *testing.T) {
	store := NewStore()
	plain := "bound-multi-group-key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	multiplier := 1.5
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{{
			Alias:    "mixed",
			Dispatch: "round-robin",
			Targets: []AliasTarget{
				{Provider: "codex", TargetModel: "gpt-5.6-luna", Group: "team"},
				{Provider: "codex", TargetModel: "gpt-5.6-luna", Group: "plus"},
				{Provider: "codex", TargetModel: "gpt-5.6-luna", Group: "pro"},
				{Provider: "codex", TargetModel: "gpt-5.6-terra", Group: "classify:custom"},
			},
			InputPricePerMillion: 2.5,
			BillingMultiplier:    &multiplier,
		}},
		Keys: []KeyConfig{{
			ID: "k", Enabled: true, KeyHash: hash,
			AccountBinding: &AccountBinding{Allow: []string{"account-*"}, Strategy: BindingStrategyRoundRobin},
			Aliases:        []KeyAliasRef{{Alias: "mixed"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	hdr := http.Header{"Authorization": {"Bearer " + plain}}
	body := []byte(`{"model":"mixed"}`)
	wantModels := []string{"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-terra"}
	for i, wantModel := range wantModels {
		dec := store.Authenticate("POST", "/v1/responses", hdr, nil, body)
		if !dec.Allowed {
			t.Fatalf("auth %d: expected allowed, got %+v", i, dec)
		}
		rule, keyID, ok := store.Route(hdr, nil, "mixed")
		if !ok || keyID != "k" {
			t.Fatalf("route %d: expected ok key=k, got ok=%v key=%q", i, ok, keyID)
		}
		if dec.Rule.Group != "" || rule.Group != "" {
			t.Fatalf("call %d retained group: auth=%q route=%q", i, dec.Rule.Group, rule.Group)
		}
		if dec.Rule.TargetModel != wantModel || rule.TargetModel != wantModel {
			t.Fatalf("call %d target auth=%q route=%q, want %q", i, dec.Rule.TargetModel, rule.TargetModel, wantModel)
		}
		if rule.InputPricePerMillion != 2.5 || rule.BillingMultiplier == nil || *rule.BillingMultiplier != multiplier {
			t.Fatalf("call %d lost pricing: %+v", i, rule)
		}
	}
	if group, err := SchedulerGroupForKey(store.FindByID("k"), "mixed", "codex", "gpt-5.6-luna"); err != nil || group != "" {
		t.Fatalf("bound scheduler group = %q, err=%v", group, err)
	}
}

// Priority multi-target always pins the first target's group on both auth and route.
func TestAuthenticateAndRoutePriorityKeepsFirstGroup(t *testing.T) {
	store := NewStore()
	plain := "prio-group-key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{{
			Alias:    "prio",
			Dispatch: "priority",
			Targets: []AliasTarget{
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "team"},
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "free"},
			},
			BillingMode: "tokens",
		}},
		Keys: []KeyConfig{{
			ID: "k", Enabled: true, KeyHash: hash,
			Aliases: []KeyAliasRef{{Alias: "prio"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{"Authorization": {"Bearer " + plain}}
	for i := 0; i < 3; i++ {
		dec := store.Authenticate("POST", "/v1/chat/completions", hdr, nil, []byte(`{"model":"prio"}`))
		if !dec.Allowed || dec.Rule.Group != "team" {
			t.Fatalf("auth %d: want team, got %+v", i, dec)
		}
		rule, _, ok := store.Route(hdr, nil, "prio")
		if !ok || rule.Group != "team" {
			t.Fatalf("route %d: want team, got %+v", i, rule)
		}
	}
}

// Route-only callers (no prior Authenticate) still resolve multi-target aliases.
func TestRouteWithoutAuthenticateStillResolves(t *testing.T) {
	store := NewStore()
	plain := "route-only-key"
	hash, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(Config{
		Enabled:   true,
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Aliases: []AliasMapping{{
			Alias:    "solo",
			Dispatch: "round-robin",
			Targets: []AliasTarget{
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "free"},
				{Provider: "codex", TargetModel: "gpt-5.4-mini", Group: "team"},
			},
		}},
		Keys: []KeyConfig{{
			ID: "k", Enabled: true, KeyHash: hash,
			Aliases: []KeyAliasRef{{Alias: "solo"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{"Authorization": {"Bearer " + plain}}
	rule, _, ok := store.Route(hdr, nil, "solo")
	if !ok || rule.Group == "" {
		t.Fatalf("expected route-only multi-target resolve, got ok=%v rule=%+v", ok, rule)
	}
}
