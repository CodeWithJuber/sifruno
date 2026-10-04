package compat

import (
 "fmt"
 "regexp"
 "sifruno/config"
)

type Entry struct {
 config.Obligation
 Status string `json:"status"`
 Reason string `json:"reason"`
}
type Report struct {
 Product string `json:"product"`
 Stage string `json:"stage"`
 Ready bool `json:"ready"`
 Reference config.Reference `json:"reference"`
 InventoryComplete bool `json:"inventory_complete"`
 Total int `json:"total"`
 Passed int `json:"passed"`
 Untested int `json:"untested"`
 Blockers []string `json:"blockers"`
 Entries []Entry `json:"entries"`
 AIMonthlyCap int64 `json:"ai_monthly_cap_usd_micros"`
 PilotAccounts int `json:"pilot_accounts"`
}

// Report is deliberately fail-closed. No endpoint accepts a self-reported
// passed flag. A certification importer requires independently reviewed,
// authentic reference evidence and is outside the current phase.
func Evaluate(b config.Baseline, obligations []config.Obligation) Report {
 r:=Report{Product:b.Product,Stage:"Phase 0 · reference access required",Reference:b.Reference,InventoryComplete:b.InventoryComplete,Total:len(obligations),Untested:len(obligations),Entries:[]Entry{},Blockers:[]string{},AIMonthlyCap:b.AIMonthlyCap,PilotAccounts:b.PilotAccounts}
 if b.Reference.ExactBuild=="" || b.Reference.OS=="" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(b.Reference.ArtifactSHA256) { r.Blockers=append(r.Blockers,"Exact licensed cPanel build, OS and reference artifact digest are not frozen.") }
 if !b.Reference.Licensed {r.Blockers=append(r.Blockers,"Licensed reference access has not been verified.")}
 if !b.InventoryComplete {r.Blockers=append(r.Blockers,"The exhaustive API, CLI, runtime and plugin inventory has not been captured.")}
 if len(obligations)==0 {r.Blockers=append(r.Blockers,"An empty inventory cannot establish compatibility.")}
 for _,o:=range obligations {
  r.Entries=append(r.Entries,Entry{Obligation:o,Status:"untested",Reason:"Original reference and unmodified replacement scenario have not been executed."})
 }
 r.Blockers=append(r.Blockers,fmt.Sprintf("%d bootstrap obligations have no independently reviewed differential evidence.",len(obligations)))
 r.Blockers=append(r.Blockers,"Original WHMCS cPanel module license requirements and JetBackup custom-panel support remain launch gates.")
 return r
}
