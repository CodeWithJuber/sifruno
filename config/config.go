package config

import (
	"embed"
	"encoding/json"
)

//go:embed baseline.json obligations.json
var files embed.FS

type Reference struct {
	Family               string `json:"family"`
	DocumentationVersion string `json:"documentation_version"`
	ExactBuild           string `json:"exact_build"`
	OS                   string `json:"os"`
	ArtifactSHA256       string `json:"artifact_sha256"`
	Licensed             bool   `json:"licensed_reference_verified"`
}
type Baseline struct {
	SchemaVersion        int       `json:"schema_version"`
	Product              string    `json:"product"`
	Reference            Reference `json:"reference"`
	Targets              []string  `json:"targets"`
	ControlPlaneTargets  []string  `json:"control_plane_targets"`
	LegacyOSRequirement  string    `json:"legacy_os_requirement"`
	InventoryComplete    bool      `json:"inventory_complete"`
	PilotAccounts        int       `json:"pilot_accounts"`
	AIMonthlyCap         int64     `json:"ai_monthly_cap_usd_micros"`
	AIExecution          string    `json:"ai_execution"`
	InstallationContract string    `json:"installation_contract"`
	Vendors              []string  `json:"vendors"`
}
type Obligation struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Vendor   string `json:"vendor,omitempty"`
	Source   string `json:"source"`
}

func Load() (Baseline, []Obligation, error) {
	var b Baseline
	var o []Obligation
	raw, err := files.ReadFile("baseline.json")
	if err != nil {
		return b, o, err
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		return b, o, err
	}
	raw, err = files.ReadFile("obligations.json")
	if err != nil {
		return b, o, err
	}
	err = json.Unmarshal(raw, &o)
	return b, o, err
}
