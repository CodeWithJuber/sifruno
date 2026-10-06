"""Pure path/data and mocked producer checks. No native child or system reads."""
import importlib.util, io, json
from pathlib import Path, PurePosixPath
from unittest.mock import patch
guest=Path(__file__).resolve().parents[3]/'startup-preflight-guest-sol'
spec=importlib.util.spec_from_file_location('reviewed_fixture',guest/'lab/startup-preflight-guest/fixture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
checks=0
def check(value):
    global checks
    assert value;checks+=1
def refused(action):
    global checks
    try: action()
    except AssertionError as e: checks+=1;return e
    raise AssertionError('unexpected_admission')
labels=['missing_uid','root_uid','state_file','homes_file','homes_symlink','homes_dangling_symlink','ancestor_untrusted_nontraversable','setgid_parent','socket_file','socket_bound','socket_dangling_symlink','nonempty_state','unknown_private_argument']
nonce='b'*32;owned=PurePosixPath('/run/sp-cases-'+nonce)
planned=f.planned_socket_paths(nonce)
check(f.CASE_LABELS==labels)
check(list(planned)==['stock','adapted',*labels,'broker_smoke'])
check(len(planned)==16 and len(set(planned.values()))==16)
lengths={}
for label,endpoint in planned.items():
    f.admit_socket_path(endpoint)
    lengths[label]=len(str(endpoint).encode('utf-8'))
    check(lengths[label]<=100)
for i,label in enumerate(labels):
    check(planned[label]==owned/('c%02d'%i)/'socket-parent/broker.sock')
    check(f.case_parent(owned,i).name=='c%02d'%i)
for index in [True,-1,13,1.0,'1']: refused(lambda:f.case_parent(owned,index))
old=owned/'ancestor_untrusted_nontraversable'
check(len(str(f.startup_paths(old)[3]).encode())==106)
for operation in [lambda:f.OwnedBroker(PurePosixPath('/synthetic'),old),lambda:f.startup_observation(PurePosixPath('/synthetic'),old)]:
    with patch.object(f.subprocess,'Popen') as spawned,patch.object(f,'owned_snapshot',return_value='a'*64),patch.object(f,'run_child') as run:
        error=refused(operation)
        check(str(error)=='socket_path_admission' and not spawned.called and not run.called)
f.admit_socket_path(PurePosixPath('/'+'x'*99));check(True)
for value in ['/'+'x'*100,'/'+'é'*50,'relative/socket','//run/socket','/run/../socket','/run/bad\0value','/run/bad\rvalue','/run/bad\nvalue']:
    refused(lambda:f.admit_socket_path(PurePosixPath(value)))
# Planned overlength refusal precedes all guest input reads or subprocesses.
with patch.object(f,'admitted_guest'),patch.object(f,'planned_socket_paths',return_value={'stock':f.startup_paths(old)[3]}),patch.object(f,'bounded_bytes') as reads,patch.object(f.subprocess,'Popen') as spawned:
    refused(lambda:f.observe(type('Args',(),{'nonce':nonce})()))
    check(not reads.called and not spawned.called)
def report():
    return dict(schema_version=1,scope='native_linux_broker_startup_admission',platform='linux',supported=True,read_only=True,checks=[dict(id=name,status='pass',reason='satisfied') for name in f.IDS],restrictions=list(f.RESTRICTIONS))
for i in range(9):
    value=report();value['checks'][i].update(status='PRIVATE/status',reason='PRIVATE/secret')
    error=refused(lambda:f.run_phase(labels[i],lambda:f.validate_startup(value)))
    check(error.diagnostic==dict(phase=labels[i],check_index=i,status='unknown',reason='unknown'))
    check('PRIVATE' not in json.dumps(error.diagnostic))
for error in [ValueError('PRIVATE/secret'),AssertionError('private_code'),AssertionError('/private/path')]:
    failure=refused(lambda:f.run_phase('core_tests',lambda:(_ for _ in ()).throw(error)))
    check(str(failure)=='fixture_observation_failed' and failure.diagnostic==dict(phase='core_tests',check_index=None,status=None,reason=None))
refused(lambda:f.run_phase('/private/phase',lambda:None))
argv=['fixture.py','--disposable-startup-preflight','--nonce',nonce]
for name in ['baseline','candidate','fixture','core-test','review-test']:argv+=['--'+name+'-sha','a'*64]
argv+=['--core-test-names','TestCore','--review-test-names','TestReview']
for error in [AssertionError('PRIVATE'),ValueError('PRIVATE'),f.PhaseFailure('startup_order_reason','stock',0,'refused',f.REASONS[0])]:
    output=io.StringIO()
    with patch.object(f.sys,'argv',argv),patch.object(f.sys,'stdout',output),patch.object(f,'observe',side_effect=error):check(f.main()==1)
    result=json.loads(output.getvalue());check(not result['passed'] and 'PRIVATE' not in output.getvalue())
    check(set(result)=={'schema_version','scope','nonce','passed','failure'}|({'diagnostic'} if isinstance(error,f.PhaseFailure) else set()))
print(json.dumps(dict(passed=True,checks=checks,planned_socket_bytes=lengths,synthetic=True,native_observation=False)))
