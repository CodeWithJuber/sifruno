package serviceaccountsreview
import (
 "context"
 "encoding/json"
 "strings"
 "testing"
 "sifruno/internal/hostaccounts"
)
func TestPublicPolicyContextBoundary(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 for _,c:=range []context.Context{nil,ctx} {
  report:=hostaccounts.CheckHostPolicy(c)
  raw,err:=json.Marshal(report);if err!=nil {t.Fatal(err)}
  var shape map[string]json.RawMessage;if json.Unmarshal(raw,&shape)!=nil||len(shape)!=7||report.Supported||!report.ReadOnly {t.Fatal("fixed unavailable report")}
  if len(report.Checks)!=3||len(report.Restrictions)!=3||strings.Contains(string(raw),"/etc/") {t.Fatal("unbounded/redaction contract")}
  for _,check:=range report.Checks {if check.Status!="not_checked"||check.Reason!="probe_context_unavailable" {t.Fatal("unavailable context accessed host")}}
 }
}
