"""Exact preview ISO payload adapter; shared admission/library routines pinned."""
import hashlib, importlib.util, io, json, os, stat, sys
from pathlib import Path, PurePosixPath
sys.dont_write_bytecode = True
OWN = Path(__file__).resolve().parents[2]
PRIMARY = OWN.parents[1]
helper = OWN / 'lab/controller-layout-guest/make_iso.py'
assert hashlib.sha256(helper.read_bytes()).hexdigest() == 'cd4e867d8adc7026735b35b2e86dfbd257bff1c3028d2164d3a20024eb082db9'
spec = importlib.util.spec_from_file_location('reviewed_iso_helpers', helper)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
admitted, sha, WHEEL_SHA = shared.admitted, shared.sha, shared.WHEEL_SHA

def main():
    assert len(sys.argv) == 2
    plan_file = admitted(OWN, sys.argv[1])
    assert plan_file.is_relative_to(OWN / '.cache/native-web-preview') and plan_file.name == 'payload-plan.json'
    plan = json.loads(plan_file.read_bytes())
    assert set(plan) == {'schema_version', 'entries'} and plan['schema_version'] == 1
    wheel = admitted(PRIMARY, PRIMARY / '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl')
    assert sha(wheel.read_bytes()) == WHEEL_SHA
    sys.path.insert(0, str(wheel))
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge='1.09', vol_ident='CIDATA')
    iso.add_directory(iso_path='/PAYLOAD', rr_name='payload', file_mode=0o40555)
    expected = {'user-data', 'meta-data', 'network-config', 'payload/hostsetup', 'payload/hostbroker', 'payload/sifruno', 'payload/panelctl', 'payload/fixture.py', 'payload/startup_helpers.py', 'payload/expected.json'}
    assert len(plan['entries']) == len(expected) and {e['destination'] for e in plan['entries']} == expected
    total = 0
    for index, entry in enumerate(plan['entries']):
        assert set(entry) == {'source', 'destination', 'bytes', 'sha256'}
        name = entry['destination']
        source = admitted(OWN, entry['source'])
        data = source.read_bytes()
        assert len(data) == entry['bytes'] and sha(data) == entry['sha256']
        total += len(data)
        assert total <= 256 * 1024 * 1024
        iso.add_file(str(source), iso_path=('/PAYLOAD' if name.startswith('payload/') else '') + '/F%02d.BIN;1' % index, rr_name=PurePosixPath(name).name, file_mode=0o100444)
    output = plan_file.parent / 'payload.iso'
    with output.open('xb') as target:
        iso.write_fp(target)
    iso.close()
    iso = pycdlib.PyCdlib()
    iso.open(str(output))
    records = []
    try:
        actual = []
        for folder, dirs, files in iso.walk(rr_path='/'):
            actual.extend((folder.rstrip('/') + '/' + name).lstrip('/') for name in files)
        assert set(actual) == expected and len(actual) == len(expected)
        for entry in plan['entries']:
            stream = io.BytesIO()
            iso.get_file_from_iso_fp(stream, rr_path='/' + entry['destination'])
            data = stream.getvalue()
            assert len(data) == entry['bytes'] and sha(data) == entry['sha256'] and data == admitted(OWN, entry['source']).read_bytes()
            record = iso.get_record(rr_path='/' + entry['destination']).rock_ridge.dr_entries.px_record
            assert record.posix_file_mode == 0o100444 and record.posix_file_links == 1
            records.append({'destination': entry['destination'], 'bytes': len(data), 'sha256': sha(data)})
    finally:
        iso.close()
    result = {'schema_version': 1, 'passed': True, 'iso_sha256': sha(output.read_bytes()), 'plan_sha256': sha(plan_file.read_bytes()), 'entries': records, 'wheel_sha256': WHEEL_SHA, 'independent_review': False}
    with (plan_file.parent / 'iso-readback.json').open('x', encoding='utf-8') as target:
        json.dump(result, target, indent=2)
        target.write('\n')
    print(json.dumps({'passed': True, 'entries': len(records), 'iso_sha256': result['iso_sha256']}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Native preview ISO admission failed', file=sys.stderr)
        sys.exit(1)
