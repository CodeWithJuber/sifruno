"""Reuse the pinned ISO library; build and immediately read back owned payloads."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

OWN = Path(__file__).resolve().parents[2]
PRIMARY = OWN.parents[1]
WHEEL_SHA = "1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e"


def admitted(root, target):
    target = Path(target).absolute()
    assert target.is_relative_to(root) and target != root
    for current in [target, *target.parents]:
        assert not current.is_symlink() and current.resolve(strict=True) == current and not (getattr(current.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        if current == root:
            break
    info = target.stat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 256 * 1024 * 1024
    return target


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    assert len(sys.argv) == 2
    plan_file = admitted(OWN, sys.argv[1])
    assert plan_file.is_relative_to(OWN / '.cache/controller-layout') and plan_file.name == 'payload-plan.json'
    plan = json.loads(plan_file.read_bytes())
    assert set(plan) == {'schema_version', 'entries'} and plan['schema_version'] == 1
    wheel = admitted(PRIMARY, PRIMARY / '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl')
    assert sha(wheel.read_bytes()) == WHEEL_SHA
    sys.path.insert(0, str(wheel))
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge='1.09', vol_ident='CIDATA')
    iso.add_directory(iso_path='/PAYLOAD', rr_name='payload', file_mode=0o40555)
    expected = {'user-data', 'meta-data', 'network-config', 'payload/hostsetup', 'payload/core.test', 'payload/fixture.py', 'payload/startup_helpers.py', 'payload/expected.json'}
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
        print('Controller layout ISO admission failed', file=sys.stderr)
        sys.exit(1)
