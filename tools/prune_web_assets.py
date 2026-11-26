#!/usr/bin/env python3
"""Check/remove unreachable generated web assets after running source sync tools."""
from pathlib import Path
import argparse,importlib.util
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('web_assets',ROOT/'materials/firmware/port-3726/web_assets.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
web=ROOT/'materials/firmware/port-3726/files/usr/ikuai/www'
files={str(x.relative_to(web)):x.read_bytes() for x in web.rglob('*') if x.is_file()}
obsolete=mod.obsolete_assets(files)
if a.write:
 for name in obsolete:(web/name).unlink()
 print('Removed unreachable generated web assets:',len(obsolete))
else:
 assert not obsolete,'Run tools/prune_web_assets.py --write after source sync: '+', '.join(obsolete)
 print('Only current generated web assets remain.')
