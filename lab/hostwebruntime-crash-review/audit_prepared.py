"""Read-only source/payload/actual-ISO audit; never launches guest or processes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            assert k not in result
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))


def below(root, relative):
    assert isinstance(relative, str) and '\\' not in relative
    p = root.joinpath(*relative.split('/'))
    assert p.is_absolute() and root in p.parents and p.resolve() == p
    assert not any(x.is_symlink() for x in [p, *p.parents])
    return p


def main():
    assert len(sys.argv) == 4
    primary, candidate, work = [Path(x).absolute() for x in sys.argv[1:]]
    assert candidate == primary / '.worktrees/web-crash-integration'
    assert work.parent == candidate / '.cache/hostwebruntime-crash-host'
    assert re.fullmatch(r'crash-[0-9]+-[a-f0-9]{24}', work.name)
    raw = (work / 'report.json').read_bytes()
    report = strict(raw)
    assert report['schema_version'] == 2 and report['run'] == work.name
    assert report['production_activated'] is False and report['original_compatibility_certified'] is False
    assert report['qemu_launched'] is False and report['evidence_kind'] == 'preparation-only'
    assert report['passed'] is False and report['native_controller_death_qualified'] is False
    for entry in report['source_inputs']:
        assert entry['root'] in ['source', 'primary']
        p = below(candidate if entry['root'] == 'source' else primary, entry['path'])
        b = p.read_bytes()
        assert len(b) == entry['bytes'] and digest(b) == entry['sha256'], entry['path']
    for entry in report['runner_sources']:
        b = below(candidate, entry['path']).read_bytes()
        assert len(b) == entry['bytes'] and digest(b) == entry['sha256'], entry['path']
    for entry in report['payload']:
        b = below(work, entry['name']).read_bytes()
        assert len(b) == entry['bytes'] and digest(b) == entry['sha256'], entry['name']
    assert len(report['payload']) == 30 and len(report['iso_readback']) == 30
    assert len({x['name'] for x in report['payload']}) == 30
    iso = below(work, 'payload.iso')
    assert digest(iso.read_bytes()) == report['iso_sha256']
    wheel = below(primary, '.tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl')
    assert digest(wheel.read_bytes()) == '1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e'
    sys.path.insert(0, str(wheel))
    import pycdlib
    source = below(candidate, 'lab/hostwebruntime-crash-host/make_iso.py')
    spec = importlib.util.spec_from_file_location('sifruno_readonly_crash_iso', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.verify_iso(pycdlib, iso, report['payload'])
    assert actual == report['iso_readback']
    admission = strict((work / 'admission.json').read_bytes())
    assert admission == report['admission'] and admission['nonce'] == report['nonce']
    assert digest((work / 'source_catalog.json').read_bytes()) == admission['source_catalog_sha256']
    assert digest((work / 'qualification-driver').read_bytes()) == admission['driver_sha256']
    assert digest((work / 'serving-linux.test').read_bytes()) == admission['test_sha256']
    assert digest((work / 'reaping-linux.test').read_bytes()) == admission['reaping_test_sha256']
    catalog = strict((work / 'source_catalog.json').read_bytes())
    assert catalog['required_reaping_tests'] == ['TestNamespaceReopenedHandlesReapOriginalChild']
    print(json.dumps({'kind': 'independent-prepared-crash-payload-audit', 'passed': True,
                      'native_execution_performed': False, 'prepared_run': work.name,
                      'prepared_report_sha256': digest(raw), 'source_inputs': len(report['source_inputs']),
                      'runner_sources': len(report['runner_sources']), 'payloads': len(actual),
                      'iso_sha256': report['iso_sha256'], 'catalog_sha256': admission['source_catalog_sha256']}, separators=(',', ':')))


if __name__ == '__main__':
    main()
