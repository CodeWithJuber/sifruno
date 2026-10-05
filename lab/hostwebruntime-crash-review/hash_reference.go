// Pure Windows-compatible typed hash reference. No native operations or state.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"sifruno/internal/hostweb"
	"sifruno/internal/hostwebgeneration"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if err != nil || len(raw) > 65536 { os.Exit(2) }
	var in struct {
		Crash struct { Boundary struct { Native hostwebgeneration.RecoveryInspection `json:"native"` } `json:"boundary"` } `json:"crash"`
		History []hostwebgeneration.Event `json:"history"`
	}
	if json.Unmarshal(raw,&in)!=nil || in.Crash.Boundary.Native.CompletedApply==nil || len(in.History)<7 || in.History[6].Repair==nil { os.Exit(2) }
	// Event.Repair is intentionally private; marshal its public JSON then decode
	// the binding through the published DeniedRepairRequest/RecoveryIntentSHA seam.
	repairRaw,_:=json.Marshal(in.History[6])
	var repair struct { Repair struct { Binding hostwebgeneration.RecoveryBinding `json:"binding"` } `json:"repair"` }
	if json.Unmarshal(repairRaw,&repair)!=nil { os.Exit(2) };b:=repair.Repair.Binding
	gen:=func(x hostwebgeneration.Identity)hostwebgeneration.Generation{return hostwebgeneration.Generation{ID:x.GenerationID,ProfileSHA256:x.ProfileSHA256,SnapshotSHA256:x.SnapshotSHA256,Denied:x.Denied,Bundle:hostweb.Bundle{SHA256:x.BundleSHA256}}}
	q:=hostwebgeneration.DeniedRepairRequest{AttemptID:b.AttemptID,Original:hostwebgeneration.Transition{OperationID:b.OperationID,Revision:b.OriginalRevision,Before:gen(b.Before),After:gen(b.After)},BaseRevision:b.BaseRevision,Source:b.Source,Target:gen(b.Target)}
	events:=[]string{}
	for _,e:=range in.History { e.SHA="";bytes,_:=json.Marshal(e);sum:=sha256.Sum256(bytes);events=append(events,hex.EncodeToString(sum[:])) }
	out:=map[string]any{"apply_intent_sha256":hostwebgeneration.ApplyIntentSHA(in.Crash.Boundary.Native.CompletedApply.Binding),"repair_intent_sha256":hostwebgeneration.RecoveryIntentSHA(q),"event_sha256":events}
	result,_:=json.Marshal(out);fmt.Println(string(result))
}
