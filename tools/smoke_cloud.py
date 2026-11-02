#!/usr/bin/env python3
"""Boot a disposable copy with QEMU. Never changes a physical disk or production router."""
from pathlib import Path
import argparse,hashlib,http.cookiejar,json,shutil,socket,subprocess,time,urllib.request
p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
p.add_argument('--qemu',default='qemu-system-x86_64');p.add_argument('--firmware-dir',type=Path)
p.add_argument('--mode',choices=['bios','uefi'],default='bios');p.add_argument('--uefi-code',type=Path);p.add_argument('--uefi-vars',type=Path)
a=p.parse_args();image=a.image.resolve();out=a.out.resolve();assert image.suffix=='.img' and image.is_file();assert not out.exists();out.mkdir(parents=True)
original=hashlib.sha256(image.read_bytes()).hexdigest();disk=out/'test-copy.img';shutil.copyfile(image,disk)
s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
args=[a.qemu,'-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','1','-m','1024',
 '-drive','file='+str(disk)+',format=raw,if=ide','-netdev','user,id=wan,hostfwd=tcp:127.0.0.1:'+str(port)+'-:80',
 '-device','e1000,netdev=wan','-serial','file:'+str(out/'serial.log'),'-display','none','-no-reboot']
if a.firmware_dir:args+=['-L',str(a.firmware_dir.resolve())]
if a.mode=='uefi':
 assert a.uefi_code and a.uefi_vars,'Provide matching OVMF/EDK2 CODE and VARS files'
 vars=out/'uefi-vars.fd';shutil.copyfile(a.uefi_vars,vars)
 varformat='qcow2' if vars.read_bytes()[:4]==b'QFI\xfb' else 'raw'
 args+=['-drive','if=pflash,format=raw,readonly=on,file='+str(a.uefi_code.resolve()),'-drive','if=pflash,format='+varformat+',file='+str(vars)]
log=open(out/'qemu.log','wb');proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));base='http://127.0.0.1:'+str(port)
def post(path,obj):
 with op.open(urllib.request.Request(base+path,json.dumps(obj).encode(),{'Content-Type':'application/json'}),timeout=10)as r:return json.load(r)
def call(func,action,param=None):
 payload={'func_name':func,'action':action,'param':param or {}}
 r=post('/Action/call',payload)
 # First-boot config initialization can invalidate an early login session.
 if r.get('Result')==10014:
  assert post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()}).get('Result')==10000
  r=post('/Action/call',payload)
 assert r.get('Result')==30000,(func,action,r.get('Result'));return r
try:
 start=time.monotonic();last='waiting'
 while time.monotonic()-start<600:
  assert proc.poll()is None,'QEMU exited before API became ready'
  try:
   if post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()}).get('Result')==10000:break
  except (OSError,ValueError):pass
  time.sleep(2)
 else:raise RuntimeError('Local QEMU management API did not become ready')
 # Wait for early startup/time initialization before the functional checks.
 while int(call('sysstat','show',{'TYPE':'uptime'})['Data']['uptime'])<90:
  time.sleep(2)
 assert post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()}).get('Result')==10000
 for func,typ in [('stream_domain','data'),('stream_ipport','data'),('stream_layer7','data'),('wireguard','iface_data')]:
  assert not call(func,'show',{'TYPE':typ})['Data'][typ],'Unexpected preconfigured rule/interface'
 defaults=call('wireguard','show',{'TYPE':'defaults'})['Data']['iface_defaults']
 assert defaults['name']=='wg1' and defaults['local_address']=='10.100.1.1/24'
 sources=call('plugin_ctpanel','show',{'TYPE':'data'})['Data']['sources'];exports={}
 for fmt in ['csv','txt']:
  name='software_sources.'+fmt;r=call('plugin_ctpanel','EXPORT',{'format':fmt});assert r.get('Filename')==name
  for attempt in range(2):
   with op.open(base+'/Action/download?filename='+name,timeout=10)as h:
    b=h.read();disposition=h.headers.get('Content-Disposition');login_redirect='/login'in h.geturl()
   if login_redirect and attempt==0:
    assert post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()}).get('Result')==10000
    continue
   assert disposition=='attachment; filename="'+name+'"','Unexpected download header: '+str(disposition)
   assert b;break
  exports[fmt]={'filename':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
 report={'passed':True,'mode':a.mode,'image_sha256':original,'management_and_default_login':True,'empty_routing_and_WG':True,'first_WG_default':'10.100.1.1/24',
   'software_source_exports':exports,'source_count':len(sources),'test_copy_only':True,'seconds_until_checked':round(time.monotonic()-start,1)}
 try:call('reboots','shutdown')
 except OSError:pass
 try:proc.wait(timeout=45)
 except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=10)
 assert hashlib.sha256(image.read_bytes()).hexdigest()==original
 (out/'smoke-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
finally:
 if proc.poll()is None:proc.terminate();proc.wait(timeout=15)
 log.close();disk.unlink(missing_ok=True)
 (out/'uefi-vars.fd').unlink(missing_ok=True)
