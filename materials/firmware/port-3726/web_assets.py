"""Find unreachable generated management assets while preserving vendor resources."""
import gzip
import re
from pathlib import PurePosixPath

NAME = r'(?:[0-9]+|app(?:\.featureport)?|manifest(?:\.featureport)?|vendor|wg-[a-z0-9-]+|router-time|ctpanel-sources)\.[a-f0-9]{8,}\.(?:js|css)'
GENERATED = re.compile(r'^' + NAME + r'(?:\.gz)?$')
REFERENCES = re.compile(NAME)


def asset_inventory(files):
    """Accept relative web path -> bytes and return unused generated paths.

    Non-generated files remain roots. The active webpack manifest names lazy
    chunks by numeric id and hash; scripts can name further helper resources.
    Gzip twins share the same reachability as the uncompressed resource.
    """
    by_name = {}
    roots = []
    generated = []
    for path, data in files.items():
        name = PurePosixPath(path).name
        plain = name[:-3] if name.endswith('.gz') else name
        if GENERATED.fullmatch(name):
            generated.append(path)
            if not name.endswith('.gz'):
                by_name[plain] = data
            elif plain not in by_name:
                by_name[plain] = gzip.decompress(data)
        elif not name.endswith('.gz') and PurePosixPath(path).suffix in {'.html', '.js', '.css', '.json'}:
            roots.append(data)
    needed = set()
    queue = list(roots)
    while queue:
        text = queue.pop().decode('utf-8', errors='replace')
        names = set(REFERENCES.findall(text))
        # Only the selected manifest is traversed, so obsolete manifests cannot
        # keep earlier chunk generations alive.
        if 'webpackJsonp' in text and 'script' in text:
            aliases = dict(re.findall(r'(?<=[{,])(\d+):"(vendor|app(?:\.featureport)?)"', text))
            names.update(aliases.get(chunk, chunk) + '.' + digest + '.js'
                         for chunk, digest in re.findall(r'(?<=[{,])(\d+):"([a-f0-9]{8,})"', text))
        for name in names - needed:
            needed.add(name)
            if name in by_name:
                queue.append(by_name[name])
    return needed, generated


def obsolete_assets(files):
    needed, generated = asset_inventory(files)
    return sorted(path for path in generated
                  if PurePosixPath(path).name.removesuffix('.gz') not in needed)
