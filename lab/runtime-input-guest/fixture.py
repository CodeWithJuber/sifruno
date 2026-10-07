"""Input-only observations in one explicitly admitted disposable guest."""
import base64, hashlib, json, os, platform, re, shutil, stat, sys
from pathlib import Path
import startup_helpers as helpers

PHASE = 'admission'
MODULES = ['mpm_event','unixd','authz_core','authz_host','dir','log_config','proxy','proxy_http','proxy_fcgi','ssl','mime']
FILES = ['/usr/sbin/httpd','/usr/sbin/php-fpm'] + ['/usr/lib64/httpd/modules/mod_'+n+'.so' for n in MODULES]
CA = b'Sifruno input-only CA fixture; not a certificate.\n'
def require(v, code):
    if not v: raise AssertionError(code)
def sha(b): return hashlib.sha256(b).hexdigest()
def compact(v): return json.dumps(v,separators=(',',':'),ensure_ascii=True)
def capture(raw): return {'base64':base64.b64encode(raw).decode('ascii'),'sha256':sha(raw),'bytes':len(raw)}
def metadata(p, name):
    st=p.lstat()
    require(stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode),'snapshot_kind')
    b=helpers.bounded_bytes(p,64*1024*1024) if stat.S_ISREG(st.st_mode) else None
    return {'path':name,'kind':'file' if b is not None else 'directory','mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid,'inode':st.st_ino,'bytes':len(b) if b is not None else 0,'sha256':sha(b) if b is not None else None}
def tree(root):
    if not root.exists(): return []
    paths=[root,*sorted(root.rglob('*'))]
    require(len(paths)<=16,'tree_bound')
    return [metadata(p,'.' if p==root else str(p.relative_to(root))) for p in paths]
def installed():
    result=[metadata(Path(p),p) for p in FILES]
    for i, row in enumerate(result):
        require(row['kind']=='file' and row['uid']==0 and row['mode']&0o022==0 and row['bytes']>1000,'installed_metadata')
        if i<2: require(helpers.bounded_bytes(FILES[i],64*1024*1024)[:4]==b'\x7fELF','installed_elf')
    return result
def daemons():
    pids=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try: exe=os.readlink(entry/'exe')
        except FileNotFoundError: continue
        if exe in FILES[:2]: pids.append(int(entry.name))
    return sorted(pids)
def child(argv, timeout=20, test_temp=None):
    r=helpers.run_child(argv,timeout=timeout,limit=65536,test_temp=test_temp)
    require(r['owned_child_exited'],'child_cleanup')
    return {'exit_code':r['exit_code'],'stdout':capture(r['stdout']),'stderr':capture(r['stderr']),'owned_child_exited':True}
def observe(nonce, expected_file):
    global PHASE
    require(sys.platform=='linux' and os.geteuid()==0 and re.fullmatch('[a-f0-9]{32}',nonce),'platform_nonce')
    marker=Path('/run/sifruno-runtime-input-admission');st=marker.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and helpers.bounded_bytes(marker,100)==(nonce+'\n').encode(),'marker')
    release=Path('/etc/os-release').read_text();require('ID="almalinux"' in release and 'VERSION_ID="9.8"' in release and platform.machine()=='x86_64','distribution')
    here=Path(__file__).parent
    expected=helpers.strict_json(helpers.bounded_bytes(expected_file,8192).decode())
    require(set(expected)=={'hostsetup','runtime.test','fixture.py','startup_helpers.py'},'expected_set')
    def inputs(): return {n:sha(helpers.bounded_bytes(here/n,64*1024*1024)) for n in expected}
    require(inputs()==expected,'input_pins')
    baseline=installed(); daemons_before=daemons();require(not daemons_before,'existing_daemon')
    root=Path('/run/ri'+nonce[:6]);tmp=Path('/run/c'+nonce[:6]);require(not root.exists() and not root.is_symlink() and not tmp.exists() and not tmp.is_symlink(),'owned_paths_absent')
    cases=[];created=[]
    try:
        PHASE='targeted_tests';tmp.mkdir(mode=0o700);created.append(tmp)
        tests=child([str(here/'runtime.test'),'-test.v','-test.count=1','-test.timeout=60s','-test.run=^TestInstallation'],90,tmp)
        require(tests['exit_code']==0,'test_exit')
        def check(name):
            global PHASE
            PHASE=name
            before=tree(root); external_before=installed()
            result=child([str(here/'hostsetup'),'--check-web-runtime','--root',str(root),'--controller-uid','65534'])
            after=tree(root);external_after=installed()
            require(before==after and external_before==external_after,'diagnostic_mutation')
            cases.append({'id':name,**result,'before':before,'after':after})
        check('missing_layout')
        root.mkdir(mode=0o700);created.append(root)
        for name in ['managed','homes','front-jail','backend-jails','run','tls']: (root/name).mkdir(mode=0o700)
        ca=root/'tls/ca.pem';ca.write_bytes(CA);ca.chmod(0o600)
        check('ready')
        (root/'managed').chmod(0o755);check('managed_mode');(root/'managed').chmod(0o700)
        ca.chmod(0o666);check('ca_mode');ca.chmod(0o600)
        check('restored')
        require(inputs()==expected and installed()==baseline and daemons()==daemons_before,'final_drift')
    finally:
        PHASE='cleanup'
        for p in reversed(created):
            require(p in (root,tmp) and p.parent==Path('/run') and not p.is_symlink(),'cleanup_scope')
            shutil.rmtree(p)
    require(not root.exists() and not tmp.exists(),'cleanup_absence')
    return {'schema_version':1,'scope':'native_runtime_installation_inputs','nonce':nonce,'passed':True,'profile':{'distribution':'almalinux','version':'9.8','machine':'x86_64'},'inputs':expected,'installed_before':baseline,'installed_after':installed(),'daemons_before':daemons_before,'daemons_after':daemons(),'ca_fixture':{'bytes':len(CA),'sha256':sha(CA),'certificate_validity':False},'tests':tests,'cases':cases,'owned_cleanup':True}
if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'arguments')
        print(compact(observe(sys.argv[1],sys.argv[2])))
    except Exception:
        print('RUNTIME_INPUT_FAILURE_PHASE='+PHASE,file=sys.stderr)
        sys.exit(1)
