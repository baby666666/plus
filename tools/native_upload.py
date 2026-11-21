"""Native UI-equivalent firmware upload/parse/install, usable by isolated tests.

No work occurs on import. Caller owns authentication, final-artifact checks,
configuration backups, the destination authorization, and any reboot.
"""
from pathlib import Path
import hashlib, json, time, urllib.request, uuid

def upload_and_install(opener, base, package, expected_sha256, report_path):
    package=Path(package)
    data=package.read_bytes()
    assert hashlib.sha256(data).hexdigest()==expected_sha256
    report={'package_sha256':expected_sha256,'package_name':package.name,'upload_complete':False,'parse_complete':False,'install_complete':False}
    def save():Path(report_path).write_text(json.dumps(report,indent=2)+'\n')
    def call(action,param=None,timeout=180):
        body={'func_name':'upgrade','action':action,'param':param or {}}
        request=urllib.request.Request(base+'/Action/call',json.dumps(body).encode(),{'Content-Type':'application/json'})
        with opener.open(request,timeout=timeout) as response:result=json.load(response)
        assert result.get('Result')==30000,('upgrade',action,result.get('Result'))
        return result
    pending=call('show',{'TYPE':'fileinfo'}).get('Data',{}).get('fileinfo',{})
    assert not pending or not pending.get('firmwarename'), 'A staged firmware already exists; refusing to overwrite it'
    # Follow the native page: clean own staging, multipart upload, parse, verify,
    # and one update_file call. Do not retry a write after an ambiguous response.
    call('clean_file')
    field='upgrade-'+str(int(time.time()))+'-'+uuid.uuid4().hex[:8]+'.bin'
    boundary='----NativeRoutingUpload'+uuid.uuid4().hex
    assert package.name.isascii() and '\"' not in package.name and '\n' not in package.name
    prefix=(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{package.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()
    body=prefix+data+f'\r\n--{boundary}--\r\n'.encode()
    request=urllib.request.Request(base+'/Action/upload',body,{'Content-Type':'multipart/form-data; boundary='+boundary})
    save()
    with opener.open(request,timeout=180) as response:
        raw=response.read()
        assert response.status==200,'Native upload HTTP failure'
    try:
        reply=json.loads(raw)
    except ValueError:
        reply={}
    if isinstance(reply,dict) and 'Result' in reply:
        assert int(reply['Result'])%10000==0,('upload',reply['Result'])
    report['upload_complete']=True;save()
    call('parse_file',{'filename':field})
    info=call('show',{'TYPE':'fileinfo'})['Data']['fileinfo']
    report['parsed_fileinfo']={k:info.get(k) for k in ['firmware_type','firmwarename','version','length','sha256sum']}
    save()
    assert info['sha256sum']==expected_sha256,'Server-uploaded SHA256 differs'
    assert int(info['length'])==len(data),'Server-uploaded size differs'
    assert int(info['firmware_type'])==1,'Not system firmware'
    assert info['firmwarename']==package.name,'Native firmware header name differs'
    report['parsed_fileinfo']={k:info[k] for k in ['firmware_type','firmwarename','version','length','sha256sum']}
    report['parse_complete']=True;save()
    call('update_file')
    report['install_complete']=True;save()
    return report
