package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
)

type CaseComparison struct {
	ID           string   `json:"id"`
	ObligationID string   `json:"obligation_id"`
	Matches      bool     `json:"matches"`
	Differences  []string `json:"differences"`
}

type Comparison struct {
	SchemaVersion          int              `json:"schema_version"`
	ReferenceID            string           `json:"reference_id"`
	CandidateID            string           `json:"candidate_id"`
	Kind                   string           `json:"kind"`
	Total                  int              `json:"total"`
	Matching               int              `json:"matching"`
	Different              int              `json:"different"`
	ContextMatches         bool             `json:"context_matches"`
	ContextDifferences     []string         `json:"context_differences"`
	CertifiesCompatibility bool             `json:"certifies_compatibility"`
	Limitations            []string         `json:"limitations"`
	Cases                  []CaseComparison `json:"cases"`
}

// Compare never runs commands and never rewrites observations. Nothing is
// filtered as "volatile": differing defaults, errors, exit codes, JSON fields,
// array ordering and missing cases remain visible to the compatibility review.
func Compare(reference, candidate Bundle) (Comparison, error) {
	if err := Verify(reference); err != nil {
		return Comparison{}, err
	}
	if err := Verify(candidate); err != nil {
		return Comparison{}, err
	}
	if reference.Role != "reference" || candidate.Role != "candidate" {
		return Comparison{}, errors.New("comparison requires reference then candidate roles")
	}
	r := Comparison{SchemaVersion: SchemaVersion, ReferenceID: reference.ID, CandidateID: candidate.ID, Kind: "synthetic", ContextMatches: true, ContextDifferences: []string{}, Cases: []CaseComparison{}, Limitations: []string{"Matching cases do not certify full WHM/cPanel compatibility.", "SHA256 verifies contents, not provenance authenticity or licensing.", "Operator attestations and each scenario require independent review; runtime, vendor and exhaustive-inventory gates remain."}}
	if reference.Kind == "observed" && candidate.Kind == "observed" {
		r.Kind = "observed_differential"
	} else {
		r.Limitations = append(r.Limitations, "At least one input is synthetic; this comparison cannot count as observed parity evidence.")
	}
	if reference.Provenance.OS != candidate.Provenance.OS {
		r.ContextDifferences = append(r.ContextDifferences, "os")
	}
	if reference.Provenance.Arch != candidate.Provenance.Arch {
		r.ContextDifferences = append(r.ContextDifferences, "arch")
	}
	if !reflect.DeepEqual(reference.Provenance.Features, candidate.Provenance.Features) {
		r.ContextDifferences = append(r.ContextDifferences, "enabled_features")
	}
	r.ContextMatches = len(r.ContextDifferences) == 0
	refs, cands := map[string]Case{}, map[string]Case{}
	ids := map[string]bool{}
	for _, c := range reference.Cases {
		refs[c.Operation.ID] = c
		ids[c.Operation.ID] = true
	}
	for _, c := range candidate.Cases {
		cands[c.Operation.ID] = c
		ids[c.Operation.ID] = true
	}
	ordered := []string{}
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		a, aok := refs[id]
		b, bok := cands[id]
		c := CaseComparison{ID: id, ObligationID: a.Operation.ObligationID, Differences: []string{}}
		if !aok {
			c.ObligationID = b.Operation.ObligationID
			c.Differences = append(c.Differences, "unexpected_candidate_case")
		} else if !bok {
			c.Differences = append(c.Differences, "missing_candidate_case")
		} else {
			if !reflect.DeepEqual(a.Operation, b.Operation) {
				c.Differences = append(c.Differences, "operation_definition")
			}
			if a.Outcome.Format != b.Outcome.Format {
				c.Differences = append(c.Differences, "output_format")
			}
			if a.Outcome.HTTPStatus != b.Outcome.HTTPStatus {
				c.Differences = append(c.Differences, "http_status")
			}
			if !reflect.DeepEqual(a.Outcome.ExitCode, b.Outcome.ExitCode) {
				c.Differences = append(c.Differences, "cli_exit_code")
			}
			if a.Outcome.Stderr != b.Outcome.Stderr {
				c.Differences = append(c.Differences, "stderr")
			}
			if a.Outcome.Format == "json" && b.Outcome.Format == "json" {
				x, _ := CanonicalJSON([]byte(a.Outcome.Stdout))
				y, _ := CanonicalJSON([]byte(b.Outcome.Stdout))
				if !bytes.Equal(x, y) {
					c.Differences = append(c.Differences, "json_body")
				}
			} else if a.Outcome.Stdout != b.Outcome.Stdout {
				c.Differences = append(c.Differences, "stdout")
			}
		}
		c.Matches = len(c.Differences) == 0
		if c.Matches {
			r.Matching++
		} else {
			r.Different++
		}
		r.Cases = append(r.Cases, c)
	}
	r.Total = len(r.Cases)
	return r, nil
}

// MarshalComparison emits a stable report containing difference categories,
// not captured response contents or credentials.
func MarshalComparison(c Comparison) ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
