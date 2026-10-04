import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash,randomBytes } from 'node:crypto';
import { spawn,spawnSync } from 'node:child_process';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const valid=name=>typeof name==='string'&&name.length<4096&&!/[\\:\r\n\0]/.test(name)&&!name.startsWith('/')&&name.split('/').every(p=>p&&p!=='.'&&p!=='..');
function input(name,directory=false){assert(valid(name),'Invalid workspace input');let current=root;for(const part of name.split('/')){current=path.join(current,part);assert(!fs.lstatSync(current).isSymbolicLink(),'Linked workspace input');}assert.equal(fs.realpathSync(current),current,'Linked workspace input');const s=fs.lstatSync(current);assert(directory?s.isDirectory():s.isFile()&&s.nlink===1,'Independent input required');return current;}
const read=name=>fs.readFileSync(input(name));
const json=name=>JSON.parse(read(name));
const privateValues=Object.entries(process.env).filter(([key,value])=>/key|token|secret|password/i.test(key)&&value?.length>=12).map(([,value])=>Buffer.from(value));
function safeBytes(bytes){assert(!privateValues.some(value=>bytes.includes(value)),'Inherited credential value present; stopped without disclosure');}
const args=process.argv.slice(2);assert(args.length===4&&args[0]==='--runner'&&args[2]==='--review-binary','Usage: node scripts/linux-guest-qualify.mjs --runner WORKSPACE_ELF --review-binary WORKSPACE_TEST_ELF');
const runner=args[1],review=args[3];for(const p of [runner,review])assert(valid(p)&&(p.startsWith('.cache/')||p.startsWith('.worktrees/')),'Qualification binary must be a workspace artifact');
const latest=json('deliverables/runtime-builds/latest.json'),indexName=`${latest.directory}/index.json`;
assert.equal(sha(read(indexName)),latest.index_sha256,'Runtime index changed');const index=json(indexName);
const archive=index.archives.find(a=>a.file.endsWith('linux-amd64.zip'));assert(archive,'Linux archive required');assert.equal(sha(read(archive.file)),archive.sha256,'Runtime archive changed');
const bundle=`.cache/runtime-builds/${latest.run_id}/linux-amd64`,manifestBytes=read(`${bundle}/manifest.json`),manifest=JSON.parse(manifestBytes);
assert.equal(sha(manifestBytes),archive.manifest_sha256);assert.equal(manifest.target,'linux-amd64');
const fixtures='.cache/cpanel-backup-qualification/producer-smoke-20261004-2119',expectedBytes=read(`${fixtures}/expected.json`),expected=JSON.parse(expectedBytes);
assert.equal(expected.kind,'synthetic');assert.equal(expected.compatibility_certified,false);
const runID='linux-'+new Date().toISOString().replace(/[-:.TZ]/g,'')+'-'+randomBytes(4).toString('hex'),work=`.cache/linux-qualification/${runID}`;
for(const dir of ['.cache','.cache/linux-qualification']){fs.mkdirSync(path.join(root,dir),{recursive:true});input(dir,true);}fs.mkdirSync(path.join(root,work));
const entries=[];
function entry(source,destination,executable=false){assert(valid(destination));const bytes=read(source);assert(bytes.length<=128*1024*1024,'Payload file too large');safeBytes(bytes);entries.push({source,destination,bytes:bytes.length,sha256:sha(bytes),executable});}
for(const record of manifest.files){assert(valid(record.path));const source=`${bundle}/${record.path}`;assert.equal(sha(read(source)),record.sha256,'Runtime staging checksum mismatch');entry(source,`bundle/${record.path}`,record.path.startsWith('bin/')||record.path.endsWith('.sh'));}
entry(`${bundle}/manifest.json`,'bundle/manifest.json');
for(const name of ['synthetic.tar','synthetic.tar.gz','bad-crc.tar.gz','truncated.tar','trailing.tar']){assert.equal(sha(read(`${fixtures}/${name}`)),expected.source_sha256[name]);entry(`${fixtures}/${name}`,`fixtures/${name}`);}
entry(`${fixtures}/expected.json`,'fixtures/expected.json');entry(runner,'probe/linuxruntime',true);entry(review,'review/reviewer.test',true);
const runnerSHA=sha(read(runner)),reviewSHA=sha(read(review));
const script=`#!/bin/sh\nset -eu\numask 077\ntrap 'poweroff' EXIT\nmkdir -p /root/sifruno-qualification /root/reviewer-tmp\nip link set lo up\nset +e\nenv -i PATH=/usr/bin:/bin HOME=/root/reviewer-tmp TMPDIR=/root/reviewer-tmp /mnt/sifruno-data/review/reviewer.test -test.v -test.timeout=60s -test.run='^TestReviewer'\nreview_status=$?\necho SIFRUNO_REVIEW_EXIT_$review_status\nenv -i PATH=/usr/bin:/bin HOME=/root TMPDIR=/tmp /mnt/sifruno-data/probe/linuxruntime --guest-qualification --bundle /mnt/sifruno-data/bundle --fixtures /mnt/sifruno-data/fixtures --run-parent /root/sifruno-qualification --run-id ${runID} --manifest-sha256 ${sha(manifestBytes)} --expected-sha256 ${sha(expectedBytes)} --timeout 8m\nprobe_status=$?\necho SIFRUNO_PROBE_EXIT_$probe_status\necho SIFRUNO_REPORT_BEGIN_${runID}\ncat /root/sifruno-qualification/${runID}/report.json\necho SIFRUNO_REPORT_END_${runID}\n`;
fs.writeFileSync(path.join(root,work,'BOOT.SH'),script,{flag:'wx'});entry(`${work}/BOOT.SH`,'BOOT.SH');
assert(entries.reduce((n,e)=>n+e.bytes,0)<=2*1024*1024*1024,'Payload limit exceeded');
fs.writeFileSync(path.join(root,work,'payload-plan.json'),JSON.stringify({schema_version:1,entries,output:`${work}/payload.iso`},null,2)+'\n',{flag:'wx'});
const environment={};for(const key of ['SYSTEMROOT','SystemRoot','WINDIR','TEMP','TMP','LOCALAPPDATA'])if(process.env[key]!==undefined)environment[key]=process.env[key];
const python=path.join(process.env.LOCALAPPDATA??'','Programs/Python/Python312/python.exe');
const isoBuild=spawnSync(python,['-I',path.join(root,'scripts/linux-guest-iso.py'),'--plan',`${work}/payload-plan.json`],{cwd:root,env:environment,encoding:'utf8',windowsHide:true,timeout:120000,maxBuffer:1024*1024});
assert.equal(isoBuild.status,0,'Qualification ISO preparation failed');const isoResult=JSON.parse(isoBuild.stdout);assert.equal(sha(read(`${work}/payload.iso`)),isoResult.iso_sha256);
const tools='.tools/linuxguest',qemu=`${tools}/qemu-20260811/qemu-system-x86_64.exe`,kernel=`${tools}/alpine-3.24.2-boot/boot/vmlinuz-virt`,initrd=`${tools}/alpine-3.24.2-boot/boot/initramfs-virt`,alpine=`${tools}/downloads/alpine-virt-3.24.2-x86_64.iso`;
const prepared=json(`${tools}/prepared.json`);assert.equal(prepared.signatures_verified,false);for(const record of prepared.files)assert.equal(sha(read(record.path)),record.sha256,'Guest tool changed');
assert.equal(sha(read(alpine)),'3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b');
const qemuDir=path.dirname(input(qemu));environment.PATH=qemuDir+';'+path.join(process.env.SystemRoot??process.env.SYSTEMROOT,'System32');
const qemuArgs=['-L',path.join(qemuDir,'share'),'-machine','pc','-accel','tcg,thread=single','-smp','1','-m','768','-nodefaults','-no-user-config','-nic','none','-display','none','-vga','none','-monitor','none','-serial','stdio','-no-reboot','-kernel',input(kernel),'-initrd',input(initrd),'-append','console=ttyS0,115200 modules=loop,squashfs,sd-mod,usb-storage quiet','-drive',`file=${input(alpine)},media=cdrom,format=raw,readonly=on,index=0`,'-drive',`file=${input(`${work}/payload.iso`)},media=cdrom,format=raw,readonly=on,index=1`];
const startedAt=new Date().toISOString(),child=spawn(input(qemu),qemuArgs,{cwd:qemuDir,env:environment,windowsHide:true,stdio:['pipe','pipe','pipe']});
let serial='',serialBytes=0,login=false,invoked=false,timedOut=false,overflow=false,sendFailure=false;
async function typeLine(line){try{for(const ch of line){if(child.exitCode!==null)return;child.stdin.write(ch);await new Promise(resolve=>setTimeout(resolve,25));}}catch{sendFailure=true;child.kill();}}
child.stdin.on('error',()=>{sendFailure=true;child.kill();});
const timer=setTimeout(()=>{timedOut=true;child.kill();},600000);
function collect(bytes){if(overflow)return;const piece=bytes.toString('utf8'),size=Buffer.byteLength(piece);if(serialBytes+size>2*1024*1024){overflow=true;child.kill();return;}serial+=piece;serialBytes+=size;
 const clean=serial.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');if(!login&&/login:\s*$/.test(clean)){login=true;void typeLine('root\n');}
 else if(login&&!invoked&&/localhost:[^\r\n]*#\s*$/.test(clean)){invoked=true;void typeLine('mkdir -p /mnt/sifruno-data; mount -t iso9660 -o ro,nosuid,nodev /dev/sr1 /mnt/sifruno-data; sh /mnt/sifruno-data/BOOT.SH\n');}
}
child.stdout.on('data',collect);child.stderr.on('data',collect);
let result;try{result=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});}finally{clearTimeout(timer);}
fs.writeFileSync(path.join(root,work,'serial.log'),serial,{flag:'wx'});
const clean=serial.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\r/g,'');
const begin=`\nSIFRUNO_REPORT_BEGIN_${runID}\n`,end=`\nSIFRUNO_REPORT_END_${runID}\n`,at=clean.indexOf(begin),to=clean.indexOf(end,at+begin.length);
let guest=null;if(at>=0&&to>at){const raw=clean.slice(at+begin.length,to);assert(raw.length<2*1024*1024);guest=JSON.parse(raw);safeBytes(Buffer.from(raw));fs.writeFileSync(path.join(root,work,'native-linux.json'),JSON.stringify(guest,null,2)+'\n',{flag:'wx'});}
const passed=!timedOut&&!overflow&&!sendFailure&&result.code===0&&guest?.passed===true&&guest.complete===true&&guest.runner_sha256===runnerSHA&&guest.manifest_sha256===sha(manifestBytes)&&guest.expected_sha256===sha(expectedBytes)&&guest.reference_observed===false&&guest.compatibility_certified===false&&guest.restore_implemented===false&&/^SIFRUNO_REVIEW_EXIT_0$/m.test(clean)&&/^SIFRUNO_PROBE_EXIT_0$/m.test(clean);
const report={checked_at:new Date().toISOString(),started_at:startedAt,passed,run_id:runID,runtime_run:latest.run_id,archive_sha256:archive.sha256,payload_iso_sha256:isoResult.iso_sha256,payload_plan_sha256:sha(read(`${work}/payload-plan.json`)),payload_entries:entries.length,inherited_credential_values_excluded:true,host_coordinator_sha256:sha(read('scripts/linux-guest-qualify.mjs')),iso_helper_sha256:sha(read('scripts/linux-guest-iso.py')),runner_sha256:runnerSHA,runner_source_sha256:sha(read('lab/linuxruntime/main.go')),review_binary_sha256:reviewSHA,emulator_sha256:sha(read(qemu)),boot_iso_sha256:sha(read(alpine)),kernel_sha256:sha(read(kernel)),initrd_sha256:sha(read(initrd)),prepared_manifest_sha256:sha(read(`${tools}/prepared.json`)),qemu_args:qemuArgs,signatures_verified:false,mode:'trusted software-emulated generic Linux runtime',cpu_count:1,memory_mib:768,host_wall_clock_limit_seconds:600,serial_limit_bytes:2*1024*1024,serial_bytes:serialBytes,network_enabled:false,host_directory_shares:false,host_inbound_forwarding:false,hostile_guest_isolation_certified:false,global_install:false,production_mutated:false,timed_out:timedOut,output_limit_exceeded:overflow,send_failure:sendFailure,login,invoked,...result,reference_observed:false,compatibility_certified:false,other_linux_families_verified:false,macos_verified:false};
fs.writeFileSync(path.join(root,work,'host-report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
const destination=`artifacts/runtime/linux-runs/${runID}`;for(const directory of ['artifacts','artifacts/runtime','artifacts/runtime/linux-runs',destination]){fs.mkdirSync(path.join(root,directory),{recursive:true});input(directory,true);}
for(const name of ['host-report.json',...(guest?['native-linux.json']:[])])fs.copyFileSync(input(`${work}/${name}`),path.join(root,destination,name),fs.constants.COPYFILE_EXCL);
console.log(JSON.stringify({passed,run_id:runID,runtime_run:latest.run_id,evidence:destination,guest_phase:guest?.phase??null,guest_passed:guest?.passed??false,timed_out:timedOut,reference_observed:false,compatibility_certified:false}));if(!passed)process.exitCode=1;
