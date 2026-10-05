package compat

import (
 "testing"
 "sifruno/config"
)
func TestNeverCertifyBootstrapOrEmptyInventory(t *testing.T){
 b,o,err:=config.Load();if err!=nil{t.Fatal(err)}
 for _,inventory:=range [][]config.Obligation{o,{}}{
  r:=Evaluate(b,inventory)
  if r.Ready || r.Passed!=0 || len(r.Blockers)==0 {t.Fatal("unverified inventory was certified")}
 }
 b.Reference.Licensed=true;b.Reference.ExactBuild="138.fake";b.Reference.OS="AlmaLinux9";b.Reference.ArtifactSHA256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";b.InventoryComplete=true
 if Evaluate(b,o).Ready {t.Fatal("self-attested metadata bypassed reference tests")}
}
