//go:build linux

package main

import (
 "archive/tar"
 "bytes"
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "sifruno/internal/cpmove"
)

func scratch(t *testing.T) string { t.Helper(); p,e:=filepath.EvalSymlinks(t.TempDir()); if e!=nil {t.Fatal("temporary directory unavailable")}; return p }
func put(t *testing.T,p string,b []byte) {t.Helper();if os.MkdirAll(filepath.Dir(p),0700)!=nil || os.WriteFile(p,b,0600)!=nil {t.Fatal("synthetic file creation failed")}}
func TestReviewerArgumentAdmission(t *testing.T) {
 valid:=[]string{"--guest-qualification","--bundle","/review/bundle","--fixtures","/review/fixtures","--run-parent","/review/tmp","--run-id","test-1","--manifest-sha256",strings.Repeat("a",64),"--expected-sha256",strings.Repeat("b",64)}
 if _,e:=parse(valid);e!=nil {t.Fatal("valid scoped arguments refused")}
 cases:=[]struct{name string;replace int;value string}{
  {"nested-parent",6,"/review/bundle/scratch"},
  {"path-alias",2,"/review/./bundle"},
  {"unsafe-id",8,"../escape"},
  {"hash",10,"invalid"},
 }
 for _,c:=range cases {t.Run(c.name,func(t *testing.T){a:=append([]string{},valid...);a[c.replace]=c.value;if _,e:=parse(a);e==nil {t.Fatal("unsafe arguments accepted")}})}
 for _,s:=range []string{"../file","a/../file","a//b","/abs","a\\b","a/./b",""} {if localPath(s) {t.Fatal("unsafe manifest path accepted")}}
 if _,e:=parse(append(append([]string{},valid...),"--timeout","11m"));e==nil {t.Fatal("unbounded duration accepted")}
 if _,e:=parse(valid[1:]);e==nil {t.Fatal("missing acknowledgement accepted")}
}
func TestReviewerReadAndHashBounds(t *testing.T) {
 p:=scratch(t); f:=filepath.Join(p,"input");put(t,f,[]byte("synthetic"));
 if _,e:=readFile(context.Background(),f,8);e==nil {t.Fatal("read limit ignored")}
 if _,e:=hashFile(context.Background(),f,8);e==nil {t.Fatal("hash limit ignored")}
 ctx,cancel:=context.WithCancel(context.Background());cancel();if _,e:=readFile(ctx,f,32);e==nil {t.Fatal("cancelled read accepted")}
 if _,e:=hashFile(ctx,f,32);e==nil {t.Fatal("cancelled hash accepted")}
 link:=filepath.Join(p,"link");if os.Symlink(f,link)!=nil {t.Fatal("real Linux file symlink creation failed")}
 if _,e:=readFile(context.Background(),link,32);e==nil {t.Fatal("file symlink accepted")}
 if _,e:=hashFile(context.Background(),link,32);e==nil {t.Fatal("hashed through symlink")}
 dl:=filepath.Join(p,"dir-link");if os.Symlink(p,dl)!=nil || safeDirectory(dl)==nil {t.Fatal("directory symlink admitted")}
}
func TestReviewerManifestCoverage(t *testing.T) {
 p:=scratch(t); payload:=[]byte("harmless nonexecutable fixture");
 names:=[]string{"bin/panelctl","bin/sifruno","web/dist/index.html"}
 m:=manifest{SchemaVersion:1,Target:"linux-amd64",InputFingerprint:strings.Repeat("c",64)}
 for _,n:=range names {put(t,filepath.Join(p,n),payload);m.Files=append(m.Files,hashRecord{Path:n,Bytes:int64(len(payload)),SHA256:digest(payload)})}
 write:=func(x manifest)string{b,e:=json.Marshal(x);if e!=nil {t.Fatal("manifest encoding failed")};put(t,filepath.Join(p,"manifest.json"),b);return digest(b)}
 pin:=write(m);if _,_,e:=loadManifest(context.Background(),p,pin);e!=nil {t.Fatal("valid pinned manifest refused")}
 if verifyBinary(filepath.Join(p,"bin/sifruno"))==nil {t.Fatal("nonexecutable fake ELF admitted")}
 put(t,filepath.Join(p,"extra"),[]byte("extra"));if _,_,e:=loadManifest(context.Background(),p,pin);e==nil {t.Fatal("unmanifested file admitted")};os.Remove(filepath.Join(p,"extra"))
 m.Files=append(m.Files,m.Files[0]);pin=write(m);if _,_,e:=loadManifest(context.Background(),p,pin);e==nil {t.Fatal("duplicate manifest entry admitted")}
 m.Files=m.Files[:3];m.Files[0].Path="../escape";pin=write(m);if _,_,e:=loadManifest(context.Background(),p,pin);e==nil {t.Fatal("manifest traversal admitted")}
}
func TestReviewerExclusiveRunAndReport(t *testing.T) {
 p:=scratch(t);o:=options{bundle:filepath.Join(p,"bundle"),fixtures:filepath.Join(p,"fixtures"),parent:filepath.Join(p,"scratch"),id:"owned",manifestHash:strings.Repeat("a",64),expectedHash:strings.Repeat("b",64),guest:true,timeout:time.Minute}
 for _,d:=range []string{o.bundle,o.fixtures,o.parent}{if os.Mkdir(d,0700)!=nil {t.Fatal("run staging failed")}}
 ctx,cancel:=context.WithCancel(context.Background());cancel();if run(ctx,o)==nil {t.Fatal("cancelled run passed")}
 rp:=filepath.Join(o.parent,o.id,"report.json");b,e:=os.ReadFile(rp);if e!=nil {t.Fatal("failure report missing")}
 var r report;if json.Unmarshal(b,&r)!=nil || r.Passed || r.ReferenceObserved || r.CompatibilityCertified || r.ProductionMutated {t.Fatal("failure evidence overstated")}
 info,e:=os.Stat(rp);if e!=nil || info.Mode().Perm()!=0600 {t.Fatal("report permissions invalid")}
 if run(context.Background(),o)==nil {t.Fatal("existing run directory reused")};after,e:=os.ReadFile(rp);if e!=nil || !bytes.Equal(b,after){t.Fatal("prior report changed")}
}
func TestReviewerPrivateModesAndLinks(t *testing.T) {
 p:=scratch(t);f:=filepath.Join(p,"data");put(t,f,[]byte("synthetic nonsecret"));if checkPrivatePermissions(p)!=nil {t.Fatal("valid private mode fixture refused")}
 if os.Chmod(f,0644)!=nil || checkPrivatePermissions(p)==nil {t.Fatal("public file permissions admitted")};os.Chmod(f,0600)
 hard:=filepath.Join(p,"linked");if os.Link(f,hard)!=nil || checkPrivatePermissions(p)==nil {t.Fatal("actual Linux hardlink admitted")};os.Remove(hard)
 if os.Symlink(f,filepath.Join(p,"symlink"))!=nil || checkPrivatePermissions(p)==nil {t.Fatal("actual Linux symlink admitted")}
}
func TestReviewerCatalogIntegrityAndExclusion(t *testing.T) {
 p:=scratch(t);secret:=[]byte("SYNTHETIC-PRIVATE-SENTINEL-ONLY");
 var input bytes.Buffer;tw:=tar.NewWriter(&input)
 names:=[]string{"account/custom","account/custom2"}
 for i,n:=range names {h:=&tar.Header{Name:n,Typeflag:tar.TypeReg,Size:int64(len(secret)),Mode:0640,Uid:1234,Gid:2345,ModTime:time.Unix(1700000000,0)}
 if i==1 {h.Format=tar.FormatPAX;h.PAXRecords=map[string]string{"vendor.synthetic":string(secret)}}
 if tw.WriteHeader(h)!=nil {t.Fatal("synthetic TAR header failed")};if _,e:=tw.Write(secret);e!=nil {t.Fatal("synthetic TAR payload failed")}}
 if tw.Close()!=nil {t.Fatal("synthetic TAR close failed")}
 file:=filepath.Join(p,"synthetic.tar");put(t,file,input.Bytes())
 want:=expectation{Entries:2,Files:[]expectedFile{{Name:names[0],SHA256:digest(secret),Bytes:int64(len(secret))},{Name:names[1],SHA256:digest(secret),Bytes:int64(len(secret))}},ForbiddenPayloadSHA256:digest(secret)}
 refs,forbidden,e:=referenceEntries(context.Background(),file,want);if e!=nil {t.Fatal("independent metadata expectations failed")}
 var out bytes.Buffer;sum,e:=cpmove.WriteCatalog(context.Background(),bytes.NewReader(input.Bytes()),&out,cpmove.DefaultLimits())
 if e!=nil || verifyCatalog(out.Bytes(),sum,refs,forbidden)!=nil {t.Fatal("valid sealed synthetic catalog refused")}
 bad:=sum;bad.CatalogSHA256=strings.Repeat("0",64);if verifyCatalog(out.Bytes(),bad,refs,forbidden)==nil {t.Fatal("invalid digest admitted")}
 if verifyCatalog(append(out.Bytes(),secret...),sum,refs,forbidden)==nil {t.Fatal("payload leak admitted")}
 lines:=bytes.Split(bytes.TrimSuffix(out.Bytes(),[]byte{'\n'}),[]byte{'\n'});if verifyCatalog(bytes.Join(lines[:len(lines)-1],[]byte{'\n'}),sum,refs,forbidden)==nil {t.Fatal("missing footer admitted")}
}
func TestReviewerOutputAndNegativeClassification(t *testing.T) {
 b:=&boundedBuffer{};if n,e:=b.Write(make([]byte,maxJSON+1));e==nil || n!=0 || !b.exceeded || b.Len()!=0 {t.Fatal("output bound bypass")}
 cases:=[]commandResult{{ExitCode:-1,OutputBounded:true},{ExitCode:2,OutputBounded:true},{ExitCode:1,TimedOut:true,OutputBounded:true},{ExitCode:1,OutputBounded:false}}
 for _,c:=range cases {if expectedFailure(report{Commands:[]commandResult{c}}) {t.Fatal("abnormal command failure accepted as expected rejection")}}
 if !expectedFailure(report{Commands:[]commandResult{{ExitCode:1,OutputBounded:true}}}){t.Fatal("ordinary rejection refused")}
}
func TestReviewerActualCommandTermination(t *testing.T) {
 exe,e:=os.Executable();if e!=nil {t.Fatal("test executable unavailable")};p:=scratch(t);env:=[]string{"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C"}
 helper:=func(c string)[]string{return []string{"-test.run=^TestReviewerHelper$","--","review-helper",c}}
 r:=report{};_,ok:=command(context.Background(),exe,helper("reject"),[]string{"synthetic-helper","reject"},p,env,&r)
 if ok || !expectedFailure(r) {t.Fatal("actual normal rejection not classified")}
 r=report{};_,ok=command(context.Background(),exe,helper("abnormal"),[]string{"synthetic-helper","abnormal"},p,env,&r)
 if ok || expectedFailure(r) {t.Fatal("actual abnormal exit treated as valid rejection")}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel();r=report{}
 started:=time.Now();_,ok=command(ctx,exe,helper("hold"),[]string{"synthetic-helper","hold"},p,env,&r)
 if ok || expectedFailure(r) || time.Since(started)>3*time.Second || len(r.Commands)!=1 || !r.Commands[0].TimedOut {t.Fatal("owned helper deadline failed")}
 if _,e:=os.Stat(filepath.Join(p,"helper-started"));e!=nil {t.Fatal("deadline helper did not actually start")}
}
func TestReviewerHelper(t *testing.T) {
 n:=len(os.Args);if n<3 || os.Args[n-2]!="review-helper" {return}
 switch os.Args[n-1] {case "reject":os.Exit(1);case "abnormal":os.Exit(2);case "hold":if os.WriteFile("helper-started",[]byte("synthetic marker"),0600)!=nil {os.Exit(3)};time.Sleep(20*time.Second);os.Exit(0);default:os.Exit(3)}
}
