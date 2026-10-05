import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';

const root=process.cwd(), sha=b=>createHash('sha256').update(b).digest('hex');
assert.equal(process.argv.length,2,'This qualification accepts only its fixed staged inputs');
function input(relative,max=64*1024*1024){
 assert(!path.isAbsolute(relative)&&!relative.split(/[\\/]/).some(x=>x==='..'||x===''));
 const p=path.join(root,relative),s=fs.lstatSync(p);assert(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=max&&fs.realpathSync(p)===p);return p;
}
const sourceFiles=['scripts/alma-account-qualify.mjs','scripts/alma-account-iso.py','cmd/hostbroker/main.go',...fs.readdirSync(path.join(root,'internal/hostaccounts')).filter(name=>/\.(go|md)$/.test(name)).map(name=>'internal/hostaccounts/'+name)];
const sourcePins=sourceFiles.map(source=>({source,sha256:sha(fs.readFileSync(input(source)))}));
const imageName='.tools/linuxguest/alma9/AlmaLinux-9-GenericCloud-9.8-20260810.x86_64.qcow2';
const imageSHA='6bdab6376d46d42e4203ace3733efafc7c5d37c7cb443a6cc74750097002d74b';
const image=input(imageName,700*1024*1024);assert.equal(sha(fs.readFileSync(image)),imageSHA);
const verification=JSON.parse(fs.readFileSync(input('.tools/linuxguest/alma9/verified.json'),'utf8'));assert(verification.checksum_signature_verified&&verification.signer_fingerprint==='BF18AC2876178908D6E71267D36CB86CB86B3716'&&verification.sha256===imageSHA);
const prepared=JSON.parse(fs.readFileSync(input('.tools/linuxguest/prepared.json'),'utf8'));for(const file of prepared.files)assert.equal(sha(fs.readFileSync(input(file.path))),file.sha256);
const qdir=path.join(root,'.tools/linuxguest/qemu-20260811'),img=input('.tools/linuxguest/qemu-20260811/qemu-img.exe');assert.equal(sha(fs.readFileSync(img)),'9d930582d0d574bb106d89982c547688e10b8f356192d302cc3d0ae4e8674534');
const run=`accounts-${Date.now()}-${randomBytes(4).toString('hex')}`,relative=`.cache/alma9-qualification/${run}`,work=path.join(root,relative);fs.mkdirSync(work,{recursive:true});assert.equal(fs.realpathSync(work),work);
const env={};for(const name of ['SYSTEMROOT','SystemRoot','WINDIR','TEMP','TMP','LOCALAPPDATA'])if(process.env[name]!==undefined)env[name]=process.env[name];env.PATH=qdir+';'+path.join(env.SystemRoot??env.SYSTEMROOT,'System32');
const overlay=path.join(work,'guest.qcow2'),made=spawnSync(img,['create','-f','qcow2','-F','qcow2','-b',image,overlay],{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:65536});assert.equal(made.status,0);
const script=`#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
trap '/sbin/poweroff' EXIT
mkdir -p /mnt/sifruno-payload /opt/sifruno-account-qualification
mount -t iso9660 -o ro,nosuid,nodev /dev/disk/by-label/CIDATA /mnt/sifruno-payload
cp /mnt/sifruno-payload/payload/* /opt/sifruno-account-qualification/
chmod 0555 /opt/sifruno-account-qualification/sifruno /opt/sifruno-account-qualification/panelctl /opt/sifruno-account-qualification/hostbroker /opt/sifruno-account-qualification/*.test
mkdir /opt/sifruno-account-qualification/ui
printf '<!doctype html><html><head><title>Isolated fixture</title></head><body>Isolated account qualification</body></html>' > /opt/sifruno-account-qualification/ui/index.html
printf 'trusted-disposable-alma9\n' >/run/sifruno-qualification-admission
chmod 0600 /run/sifruno-qualification-admission
set +e
echo SIFRUNO_ACCOUNT_REPORT_BEGIN_${run}
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 /opt/sifruno-account-qualification/qualifier.py --disposable-alma-guest --qualification-files-only-nss --qualification-no-mail-spool-default --report /opt/sifruno-account-qualification/account-report.json
fixture_status=$?
echo SIFRUNO_ACCOUNT_REPORT_END_${run}
echo SIFRUNO_ACCOUNT_FIXTURE_EXIT_$fixture_status
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /opt/sifruno-account-qualification/core.test -test.v -test.timeout=90s
echo SIFRUNO_ACCOUNT_CORE_EXIT_$?
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C SIFRUNO_HOSTACCOUNTS_REVIEW_GUEST=1 /opt/sifruno-account-qualification/socket.test -test.v -test.timeout=60s
echo SIFRUNO_ACCOUNT_SOCKET_EXIT_$?
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C SIFRUNO_HOSTACCOUNTS_REVIEW_GUEST=1 /opt/sifruno-account-qualification/authority.test -test.v -test.run='^TestReviewerNativePathAuthority$' -test.timeout=20s
echo SIFRUNO_ACCOUNT_AUTHORITY_EXIT_$?
`;
fs.writeFileSync(path.join(work,'meta-data'),`instance-id: ${run}\nlocal-hostname: sifruno-qualification\n`,{flag:'wx'});
fs.writeFileSync(path.join(work,'network-config'),'version: 2\nethernets: {}\n',{flag:'wx'});
fs.writeFileSync(path.join(work,'user-data'),'#cloud-config\nusers: []\nssh_pwauth: false\ndisable_root: true\nwrite_files:\n  - path: /root/sifruno-account-proof.sh\n    owner: root:root\n    permissions: "0700"\n    content: |\n'+script.split('\n').map(line=>'      '+line).join('\n')+'\nruncmd:\n  - ["/bin/sh", "/root/sifruno-account-proof.sh"]\n',{flag:'wx'});
const entries=[];function entry(source,destination,expected){const p=input(source),bytes=fs.readFileSync(p),digest=sha(bytes);if(expected)assert.equal(digest,expected);entries.push({source,destination,bytes:bytes.length,sha256:digest});}
for(const name of ['user-data','meta-data','network-config'])entry(`${relative}/${name}`,name);
const binaryPins={sifruno:'d75426f7e1358b175e544c60667ef3b028bba2c75996d50b59684a03e7db01ad',panelctl:'18a4b4e45c24e0045d5c4a86a7f99d19544a4f2d8cbd515c86ec0f319d34e07b',hostbroker:'eb19376976893b9cd2b948176c874b692d8541a82d377c906c7ade6432e94760'};
for(const name of ['sifruno','panelctl','hostbroker'])entry(`.cache/alma9-account-payload-policy-v4/${name}`,`payload/${name}`,binaryPins[name]);
entry('lab/hosting_account_fixture.py','payload/qualifier.py');
entry('.worktrees/native-transfer-cli/.cache/hostaccounts-linux-tests-policy-v4','payload/core.test','03ef91996c3a716e2a5897f02eb8e4fc4efa0a72a49efbc2a749724bb0efe217');
entry('.worktrees/native-transfer-review/.cache/hostaccounts-review-build/v4-useradd-policy/socket-review-linux-amd64.test','payload/socket.test','002796e1cc34eb3bf3a629e42bc97baf49ef1350f106d3a83f0cae27e7c9a68e');
entry('.worktrees/native-transfer-review/.cache/hostaccounts-review-build/v4-useradd-policy/authority-review-linux-amd64.test','payload/authority.test','6571ce31acedccd8c4d6d2d50e5601ff2465065e7054ecc324e02cc4c6fe6287');
fs.writeFileSync(path.join(work,'payload-plan.json'),JSON.stringify({schema_version:1,entries},null,2)+'\n',{flag:'wx'});
const planSource=`${relative}/payload-plan.json`,planSHA=sha(fs.readFileSync(input(planSource)));
const python=path.join(env.LOCALAPPDATA,'Programs/Python/Python312/python.exe');const iso=spawnSync(python,['-I',input('scripts/alma-account-iso.py'),'--plan',`${relative}/payload-plan.json`],{cwd:root,env,encoding:'utf8',windowsHide:true,timeout:90000,maxBuffer:65536});assert.equal(iso.status,0,iso.stderr);const isoResult=JSON.parse(iso.stdout);
const args=['-L',path.join(qdir,'share'),'-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','1','-m','1536','-nodefaults','-no-user-config','-nic','none','-display','none','-vga','none','-monitor','none','-serial','stdio','-no-reboot','-object','rng-builtin,id=rng0','-device','virtio-rng-pci,rng=rng0','-drive',`file=${overlay},if=virtio,format=qcow2,index=0`,'-drive',`file=${path.join(work,'payload.iso')},media=cdrom,format=raw,readonly=on,index=2`];
const started=new Date().toISOString(),child=spawn(input('.tools/linuxguest/qemu-20260811/qemu-system-x86_64.exe'),args,{cwd:qdir,env,windowsHide:true,stdio:['ignore','pipe','pipe']});const fd=fs.openSync(path.join(work,'serial.log'),'wx');let serial='',count=0,limit=false,timedout=false;const timer=setTimeout(()=>{timedout=true;child.kill()},600000);
const capture=bytes=>{if(limit)return;if(count+bytes.length>2*1024*1024){limit=true;child.kill();return};count+=bytes.length;serial+=bytes.toString('utf8');fs.writeSync(fd,bytes);if(serial.includes('Kernel panic - not syncing')||serial.includes('Fatal glibc error'))child.kill()};child.stdout.on('data',capture);child.stderr.on('data',capture);
console.log(JSON.stringify({started:true,run_id:run,pid:child.pid,inputs:entries.length,external_nic:false,guest_loopback:true,host_shares:false}));
const result=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}))});clearTimeout(timer);fs.closeSync(fd);
const clean=serial.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\r/g,'');const begin=`SIFRUNO_ACCOUNT_REPORT_BEGIN_${run}\n`,end=`\nSIFRUNO_ACCOUNT_REPORT_END_${run}`;const a=clean.indexOf(begin),b=clean.indexOf(end,a+begin.length);let guest=null;
let guestReportError=null;
if(a>=0&&b>a){try{guest=JSON.parse(clean.slice(a+begin.length,b));}catch{guestReportError='invalid_guest_json';}}
else guestReportError='missing_guest_report';
const codes=['FIXTURE','CORE','SOCKET','AUTHORITY'].map(name=>({name,passed:new RegExp(`^SIFRUNO_ACCOUNT_${name}_EXIT_0$`,'m').test(clean)}));
let stable=false;
try{stable=entries.every(e=>sha(fs.readFileSync(input(e.source)))===e.sha256)&&sourcePins.every(e=>sha(fs.readFileSync(input(e.source)))===e.sha256)&&sha(fs.readFileSync(input(planSource)))===planSHA&&sha(fs.readFileSync(image))===imageSHA;}catch{}
const passed=result.code===0&&!limit&&!timedout&&stable&&guest?.passed===true&&codes.every(x=>x.passed);
const report={run_id:run,passed,started_at:started,checked_at:new Date().toISOString(),...result,timedout,output_limit:limit,serial_bytes:count,input_stable:stable,guest_report_error:guestReportError,image_sha256:imageSHA,image_checksum_signature_verified:true,payload_sha256:isoResult.sha256,payload_plan_sha256:planSHA,source_pins:sourcePins,entries,results:codes,qemu_args:args,host_shares:false,external_nic:false,guest_loopback:true,hostile_guest_isolation_certified:false,global_install:false,production_mutated:false,cpanel_compatibility_certified:false};
const destination=path.join(root,'artifacts/runtime/alma-account-runs',run);fs.mkdirSync(destination,{recursive:true});for(const [name,value]of [['host-report.json',report],['native-accounts.json',guest]])if(value)fs.writeFileSync(path.join(destination,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({passed,run_id:run,guest_passed:guest?.passed??false,guest_failure:guest?.failure??null,results:codes,evidence:path.relative(root,destination)}));if(!passed)process.exitCode=1;
