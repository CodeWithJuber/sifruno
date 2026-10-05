"""Build a bounded, read-only CIDATA payload for trusted offline web guests.

This reuses the pinned pycdlib/runtime admission used by alma-account-iso.py.
It does not mount disks, install packages or execute payloads on Windows.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
WHEEL = ROOT / '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl'
PREFIXES = ('.cache/alma-web-runtime/', '.cache/alma-web-repositories/',
            '.cache/alma-web-packages/', '.cache/alma-web-payload/',
            '.cache/alma9-account-payload-policy-v4/')
LAB = {'lab/web_package_prepare.py', 'lab/web_runtime_fixture.py'}
FIXED = {'user-data', 'meta-data', 'network-config', 'payload/prepare.py',
         'payload/qualifier.py', 'payload/repository-manifest.json',
         'payload/package-manifest.json', 'payload/resolve-report.json',
         'payload/sifruno', 'payload/panelctl', 'payload/hostbroker',
         'payload/web-render'}


def digest(p):
    with p.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def regular(p, maximum):
    assert os.path.normcase(str(p.resolve())) == os.path.normcase(str(p))
    for part in [p, *p.parents]:
        if part == ROOT.parent:
            break
        info = part.lstat()
        assert not part.is_symlink()
        assert not (getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    info = p.stat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum
    return info


def relative(name):
    assert isinstance(name, str) and len(name) <= 512
    assert not PurePosixPath(name).is_absolute() and '\\' not in name
    assert all(v not in ('', '.', '..') for v in name.split('/'))
    assert re.fullmatch(r'[A-Za-z0-9_.+/-]+', name)
    return PurePosixPath(name)


def destination(name):
    relative(name)
    return (name in FIXED or
            bool(re.fullmatch(r'repositories/(?:BaseOS|AppStream)/repodata/[A-Za-z0-9_.+-]+', name)) or
            bool(re.fullmatch(r'packages/[A-Za-z0-9_.+-]+\.rpm', name)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    args = parser.parse_args()
    relative(args.plan)
    assert args.plan.startswith('.cache/alma-web-runtime/') and args.plan.endswith('/payload-plan.json')
    plan_path = ROOT.joinpath(*PurePosixPath(args.plan).parts)
    regular(plan_path, 256 * 1024)
    plan = json.loads(plan_path.read_text())
    assert set(plan) == {'schema_version', 'phase', 'entries'} and plan['schema_version'] == 1
    assert plan['phase'] in ('resolve', 'install', 'qualify') and 4 <= len(plan['entries']) <= 300
    regular(WHEEL, 2 * 1024 * 1024)
    assert digest(WHEEL) == '1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e'
    sys.path.insert(0, str(WHEEL))
    import pycdlib
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge='1.09', vol_ident='CIDATA')
    seen, directories, admitted = set(), {'': ''}, []
    total = 0
    for index, entry in enumerate(plan['entries']):
        assert set(entry) == {'source', 'destination', 'bytes', 'sha256'}
        source_name, name = entry['source'], entry['destination']
        relative(source_name)
        assert source_name.startswith(PREFIXES) or source_name in LAB
        assert destination(name) and name not in seen
        assert re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])
        source = ROOT.joinpath(*PurePosixPath(source_name).parts)
        info = regular(source, 64 * 1024 * 1024)
        assert info.st_size == entry['bytes'] and digest(source) == entry['sha256']
        total += info.st_size
        assert total <= 512 * 1024 * 1024
        parent = ''
        for component in PurePosixPath(name).parts[:-1]:
            child = parent + '/' + component if parent else component
            if child not in directories:
                iso_path = directories[parent] + '/D%06d' % len(directories)
                iso.add_directory(iso_path=iso_path, rr_name=component, file_mode=0o40555)
                directories[child] = iso_path
            parent = child
        iso.add_file(str(source), iso_path=directories[parent] + '/F%06d.BIN;1' % index,
                     rr_name=PurePosixPath(name).name, file_mode=0o100444)
        seen.add(name)
        admitted.append((source, entry['sha256']))
    assert {'user-data', 'meta-data', 'network-config'}.issubset(seen)
    target = plan_path.parent / 'payload.iso'
    with target.open('xb') as output:
        iso.write_fp(output)
    iso.close()
    for source, expected in admitted:
        assert digest(source) == expected
    print(json.dumps({'entries': len(seen), 'bytes': total, 'sha256': digest(target)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Web qualification ISO admission failed', file=sys.stderr)
        raise SystemExit(1)
