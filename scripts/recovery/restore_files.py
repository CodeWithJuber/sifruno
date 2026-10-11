"""Restore the file snapshot to a NEW directory; never follows archived paths blindly."""
import argparse,hashlib,json,zipfile
from pathlib import Path,PurePosixPath

def restore(archive,destination,prefix=''):
    destination=Path(destination)
    if destination.exists():raise ValueError('Destination must not exist; use a new empty location.')
    with zipfile.ZipFile(archive) as z:
        m=json.loads(z.read('manifest.json'))
        if m.get('format')!='sifruno-file-snapshot-v1':raise ValueError('Unsupported snapshot format')
        entries=[e for e in m['files'] if not prefix or e['path']==prefix or e['path'].startswith(prefix.rstrip('/')+'/')]
        paths=set();objects=set()
        for e in entries:
            raw=e['path'];p=PurePosixPath(raw)
            if p.is_absolute() or any(x in ('','..','.') for x in raw.split('/')) or '\\' in raw or ':' in raw:raise ValueError('Unsafe snapshot path')
            if any(part.casefold()=='.git' for part in p.parts):raise ValueError('Git metadata must be recovered from the Git bundle')
            if raw.casefold() in paths:raise ValueError('Duplicate snapshot path')
            paths.add(raw.casefold())
            sha=e['sha256']
            if len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):raise ValueError('Invalid object ID')
            if m['unique_objects'].get(sha)!=e['size']:raise ValueError('Invalid object size')
            objects.add(sha)
        # Verify everything requested before writing any restored files.
        for sha in objects:
            data=z.read('objects/'+sha)
            if hashlib.sha256(data).hexdigest()!=sha or len(data)!=m['unique_objects'][sha]:raise ValueError('Object integrity mismatch')
        destination.mkdir(parents=True,exist_ok=False)
        root=destination.resolve()
        for e in entries:
            p=destination.joinpath(*PurePosixPath(e['path']).parts)
            if not p.resolve().is_relative_to(root):raise ValueError('Path escaped destination')
            p.parent.mkdir(parents=True,exist_ok=True)
            with p.open('xb') as out:out.write(z.read('objects/'+e['sha256']))
        return {'restored_files':len(entries),'verified_objects':len(objects)}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive');parser.add_argument('destination');parser.add_argument('--prefix',default='')
    args=parser.parse_args()
    print(json.dumps(restore(args.archive,args.destination,args.prefix)))
