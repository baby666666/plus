#!/usr/bin/env python3
"""Explicitly update or verify the embedded control-panel source; no firmware build."""
from pathlib import Path
import argparse,json,re
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
page=ROOT/'materials/firmware/port-3726/files/usr/ikuai/www/plugins/01.ctpanel/index.html'
text=page.read_text();pattern=r'(readyScript\.textContent=)("(?:[^"\\]|\\.)*")(;)'
matches=list(re.finditer(pattern,text));assert len(matches)==1
source=(ROOT/'materials/web-src/src/ctpanel.js').read_text()
if a.write:
 text=re.sub(pattern,lambda m:m[1]+json.dumps(source,ensure_ascii=False)+m[3],text);page.write_text(text)
else:assert json.loads(matches[0][2])==source,'Embedded control-panel source differs; run with --write then review changes'
print('Control-panel source and runtime page match')
