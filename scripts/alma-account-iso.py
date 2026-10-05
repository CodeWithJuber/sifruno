"""Build the admitted static AlmaLinux account fixture plan."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import os
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
WHEEL = ROOT / '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'


def digest(p):
    with p.open('rb') as source:
        h = hashlib.file_digest(source, 'sha256')
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--plan', required=True)
    args = p.parse_args()
    plan_name = PurePosixPath(args.plan)
    assert args.plan.startswith('.cache/alma9-qualification/') and args.plan.endswith('/payload-plan.json') and '..' not in plan_name.parts
    plan_path = ROOT.joinpath(*plan_name.parts)
    assert plan_path.resolve() == plan_path and plan_path.stat().st_size < 65536
    plan = json.loads(plan_path.read_text())
    assert set(plan) == {'schema_version', 'entries'} and plan['schema_version'] == 1 and 4 <= len(plan['entries']) <= 16
    assert digest(WHEEL) == '1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e'
    sys.path.insert(0, str(WHEEL))
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge='1.09', vol_ident='CIDATA')
    iso.add_directory(iso_path='/PAYLOAD', rr_name='payload', file_mode=0o40555)
    seen = set()
    admitted = []
    total = 0
    for index, entry in enumerate(plan['entries']):
        assert set(entry) == {'source', 'destination', 'bytes', 'sha256'}
        source_name, name = entry['source'], entry['destination']
        assert source_name.startswith(('.cache/alma9-qualification/', '.cache/alma9-account-payload/', '.cache/alma9-account-payload-gecos-v2/', '.cache/alma9-account-payload-policy-v4/', '.worktrees/native-transfer-cli/.cache/', '.worktrees/native-transfer-review/.cache/')) or source_name == 'lab/hosting_account_fixture.py'
        parts = PurePosixPath(source_name)
        assert not parts.is_absolute() and not any(v in ('', '.', '..') for v in source_name.split('/')) and '\\' not in source_name
        source = ROOT.joinpath(*parts.parts)
        assert os.path.normcase(str(source.resolve())) == os.path.normcase(str(source))
        for parent in [source, *source.parents]:
            if parent == ROOT.parent: break
            assert not parent.is_symlink() and not (getattr(parent.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        info = source.stat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == entry['bytes'] and info.st_size <= 64*1024*1024 and digest(source) == entry['sha256']
        assert name in {'user-data', 'meta-data', 'network-config', 'payload/sifruno', 'payload/panelctl', 'payload/hostbroker', 'payload/qualifier.py', 'payload/core.test', 'payload/socket.test', 'payload/authority.test'} and name not in seen
        seen.add(name)
        total += info.st_size
        assert total <= 256*1024*1024
        if name.startswith('payload/'):
            iso_name = '/PAYLOAD/F%02d.BIN;1' % index
        else:
            iso_name = '/F%02d.TXT;1' % index
        iso.add_file(str(source), iso_path=iso_name, rr_name=PurePosixPath(name).name, file_mode=0o100444)
        admitted.append((source, entry['sha256']))
    assert {'user-data', 'meta-data', 'network-config'}.issubset(seen)
    with (plan_path.parent/'payload.iso').open('xb') as target: iso.write_fp(target)
    iso.close()
    for source, expected in admitted: assert digest(source) == expected
    print(json.dumps({'entries': len(seen), 'bytes': total, 'sha256': digest(plan_path.parent/'payload.iso')}))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Account qualification ISO admission failed', file=sys.stderr)
        raise SystemExit(1)
