/* Device transport and role are committed with the native WG add/edit transaction. */
(function (root) {
    'use strict';
    function tr(s) { return root.WGI18n ? root.WGI18n.text(s) : s; }
    var validId = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
    var pinPattern=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
    function isPure(method) { return method==='pure_hy2'; }
    function managementURL(value) {
        if(typeof value!=='string')return '';
        var parts=/^(https?):\/\/([0-9]+(?:\.[0-9]+){3})(?::([1-9][0-9]{0,4}))?\/$/.exec(value);
        if(!parts || parts[3] && Number(parts[3])>65535)return '';
        try {root.WGClientConfig.endpointIP(parts[2]);}catch(e){return '';}
        return value;
    }
    var validName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;
    function reverseConfig(value){return root.WGPasteImport.validateReverse(value);}
    function reverseDraft(value){
        var saved=reverseConfig(value);
        return {enabled:saved.enabled,mappings:saved.mappings.map(function(row){
            return {id:row.id,protocol:row.protocol,listen_port:String(row.listen_port),target_ip:row.target_ip,
                target_port:String(row.target_port),sources_text:row.sources.join(', ')};
        })};
    }
    function reverseParameters(draft){
        if(!draft || !draft.enabled)return {enabled:false,mappings:[]};
        return reverseConfig({enabled:true,mappings:draft.mappings.map(function(row){
            function port(value){return /^(?:[1-9][0-9]{0,4})$/.test(String(value))?Number(value):NaN;}
            return {id:row.id,protocol:row.protocol,listen_port:port(row.listen_port),target_ip:row.target_ip.trim(),
                target_port:port(row.target_port),sources:row.sources_text.split(/[,\s]+/).filter(Boolean)};
        })});
    }
    function sameReverse(first,second){return JSON.stringify(first)===JSON.stringify(second);}
    // Keep only saved, non-secret fields in the editor. Old registrations used shared defaults.
    function snapshot(status) {
        if (!status || typeof status.enabled!=='boolean' || !Array.isArray(status.members)) throw Error();
        return {
            public_ip:status.public_ip || '', core_storage:status.core_storage, core_format:status.core_format,
            members:status.members.map(function (m) {
                if (!m || !/^[1-9][0-9]*$/.test(String(m.peer_id)) || !validId.test(m.id) ||
                    !validName.test(m.name) || typeof m.interface!=='string' || typeof m.address!=='string') throw Error();
                var transport=m.transport || 'hysteria2';
                if (transport!=='hysteria2' && !isPure(transport)) throw Error();
                var mode=m.mode || (m.exit ? 'both' : 'access'), addressMode=m.addr_mode || 'shared', portMode=m.port_mode || 'shared';
                if (['access','lend','both','site'].indexOf(mode)<0 || ['auto','manual','shared'].indexOf(addressMode)<0 ||
                    ['wg','shared'].indexOf(portMode)<0) throw Error();
                return {peer_id:String(m.peer_id), id:m.id, name:m.name, interface:m.interface, address:m.address,
                    peer_publickey:m.peer_publickey, mode:mode, addr_mode:addressMode, port_mode:portMode,
                    management_url:isPure(transport)?managementURL(m.management_url):'',
                    reverse:isPure(transport)?reverseConfig(m.reverse):{enabled:false,mappings:[]},
                    transport:transport, public_ip:m.public_ip || '', public_port:m.public_port, retired:!isPure(transport) || m.retired===true,
                    active:isPure(transport) && m.active!==false, paused:!isPure(transport) || m.paused===true || !status.enabled};
            })
        };
    }
    function download(profile, name) {
        var url = URL.createObjectURL(new Blob([JSON.stringify(profile, null, 2) + '\n'], {type: 'application/json'}));
        var link = document.createElement('a');
        link.href = url;
        link.download = name + '.json';
        document.body.appendChild(link);
        try { link.click(); }
        finally {
            document.body.removeChild(link);
            setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
        }
    }

    function methods() {
        return [
            ['native',tr('原生 WireGuard（UDP）')],
            ['pure_hy2',tr('纯 Hysteria 2（UDP）')]
        ];
    }
    function roles() {
        return [
            ['lend',tr('让路由器借用这台设备的网络')],
            ['access',tr('让这台设备连接路由器上网')],
            ['both',tr('双向使用')]
        ];
    }
    var fields=['interface','allowips','peer_publickey','peer_privatekey','presharedkey','client_dns',
        'keepalive','exit_peer','site_local','site_remote','enabled'];
    var editable=fields.concat(['native_role','client_endpoint','endpoint','endpoint_port','out_mode','out_wans','out_balance']);
    function editInputs(form){return JSON.stringify(editable.map(function(k){return form[k];}));}
    function nativeMode(form) {
        return form.native_role || (form.exit_peer==='yes' ? 'both' : 'access');
    }
    function sitePeer(form) {
        var allowed=String(form.allowips||'').trim();
        return !!(form.site_local || form.site_remote || (allowed && !/^\d+\.\d+\.\d+\.\d+(?:\/32)?$/.test(allowed)));
    }
    function networks(value) {
        return String(value || '').trim().split(/[,\s]+/).map(function(net) {
            return net.replace(/^(\d+\.\d+\.\d+\.\d+)\/32$/,'$1');
        }).join(',');
    }
    function sameDevice(row,opened) {
        return row && row.interface===opened.interface && row.peer_publickey===opened.peer_publickey &&
            networks(row.allowips)===networks(opened.allowips);
    }
    function matchesSavedPeer(row,opened) {
        return sameDevice(row,opened) && String(row.id)===String(opened.id) &&
            networks(row.site_local)===networks(opened.site_local) && networks(row.site_remote)===networks(opened.site_remote) &&
            (row.native_role||'')===opened.native_role && (row.exit_peer==='yes'?'yes':'no')===opened.exit_peer;
    }
    function matchesMember(member,opened) {
        return member.interface===opened.interface && member.peer_publickey===opened.peer_publickey &&
            networks(member.address)===networks(opened.allowips);
    }
    function matchesNativeExport(v,w,t){
        var f=v.peerForm;
        if(w.address.split('/')[0]!==String(f.allowips || '').trim().split('/')[0] || w.keepalive!==Number(f.keepalive || 0))return false;
        var psk=f.presharedkey || '';
        if(psk==='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')psk='';
        if((w.preshared_key || '')!==psk)return false;
        var endpoint=String(f.client_endpoint || '').trim().split(':');
        var host=endpoint[0],port=endpoint[1] || v.listenPort;
        return w.public_key===v.serverKey && (!host || host.toLowerCase()===t.server.toLowerCase()) &&
            (!port || Number(port)===t.server_port);
    }
    function matchesPureEndpoint(view,server,port) {
        return server===view.draft.public_ip && port===Number(view.listenPort || view.member.public_port);
    }
    function matchesPurePhone(view,profile) {
        if (!profile || (profile.endpoints && (!Array.isArray(profile.endpoints) || profile.endpoints.length)) ||
            !Array.isArray(profile.outbounds) || !Array.isArray(profile.inbounds) ||
            profile.inbounds.length!==1 || !profile.inbounds[0] || profile.inbounds[0].type!=='tun') return false;
        var hy=profile.outbounds.filter(function(o){return o && o.type==='hysteria2';});
        if (hy.length!==1 || profile.outbounds.some(function(o){return !o || (o.type!=='hysteria2' && o.type!=='direct');})) return false;
        var tls=hy[0].tls || {}, pins=tls.certificate_public_key_sha256;
        return view.mode==='access' && matchesPureEndpoint(view,hy[0].server,hy[0].server_port) &&
            !hy[0].realm && typeof hy[0].password==='string' && !!hy[0].password && tls.enabled===true && !tls.insecure &&
            Array.isArray(pins) && pins.length===1 && pinPattern.test(pins[0]);
    }
    function matchesPureUri(view,profile) {
        if(!profile || typeof profile.uri!=='string' || profile.uri.length>1024 ||
            !matchesPureEndpoint(view,profile.server,profile.server_port))return false;
        var parts=/^hysteria2:\/\/((?:[a-zA-Z0-9._~-]|%[0-9a-fA-F]{2})+)@([0-9.]+):([1-9][0-9]{0,4})\/\?sni=([0-9.]+)&insecure=1&pinSHA256=[0-9a-f]{64}#([a-zA-Z0-9._-]+)$/.exec(profile.uri);
        return !!(parts && parts[0]===profile.uri && parts[2]===profile.server && parts[3]===String(profile.server_port) &&
            parts[4]===profile.server && parts[5]===view.member.name);
    }
    function copyPhoneText(view,text,current) {
        var clipboard=root.navigator && root.navigator.clipboard;
        return root.WGClientConfig.copyDeferred(text,current,clipboard,function(label,value){
            view._phoneCurrent=current;view.phoneText=value;
        },function(msg){view.notice=msg;},tr('复制配置'),root);
    }
    function staleMessage(){return tr('设备已被删除或更改，请返回列表并重新打开。');}
    root.WGNativeTunnel={
        name:'WgNativeTunnel',
        props:{apiUrl:{type:String,required:true},makeQrSvg:{type:Function,required:true},peerForm:{type:Object,required:true},listenPort:{type:[String,Number],default:''},serverKey:{type:String,default:''},autoEndpoint:{type:String,default:''}},
        data:function () {
            return {transport:'native',mode:'access',portMode:'wg',addrMode:'auto',service:null,member:null,draft:null,qr:null,phoneKind:'',phoneText:'',playing:false,busy:false,serial:0,error:'',notice:'',
                selected:false,discovering:false,discoveryError:'',reading:false,saving:false,committed:false,revision:0,
                resume:false,settingsOpen:false,stale:false,reverseDraft:reverseDraft(),reverseRuntime:null,
                reverseServiceRunning:null,reverseReading:false,reverseReadError:''};
        },
        computed:{
            selectedInterface:function(){return this.peerForm.interface;},
            unchanged:function () {
                var v=this;
                return v.revision>0 && fields.every(function(k,i){return v._initialFields[i]===v.peerForm[k];});
            },
            managementAddress:function(){return this.exportReady?this.member.management_url:'';},
            reverseUnchanged:function(){
                try{return !!this.member && sameReverse(reverseParameters(this.reverseDraft),this.member.reverse);}
                catch(e){return false;}
            },
            pureRouterReady:function(){return this.exportReady && this.reverseUnchanged;},
            nativeRouterReady:function () {
                var f=this.peerForm, origin=this._origin;
                return !!(this.transport==='native' && this.service && !this.member && this.unchanged && !this.stale &&
                    !this.reading && !this.saving && !this.committed && this.serverKey && origin && origin.id &&
                    ['access','lend','both'].indexOf(f.native_role)>=0 && origin.native_role===f.native_role &&
                    this.mode===f.native_role && f.enabled==='yes' && !sitePeer(f) &&
                    ((f.client_endpoint || '')===origin.client_endpoint || (!origin.client_endpoint && f.client_endpoint===this.autoEndpoint)));
            },
            exportReady:function () {
                var m=this.member;
                return !!(isPure(this.transport) && m && m.transport===this.transport && m.active && !m.paused && !m.retired &&
                    m.mode==='access' && this.mode==='access' && m.port_mode==='wg' && m.addr_mode===this.addrMode &&
                    (!m.public_port || !this.listenPort || Number(m.public_port)===Number(this.listenPort)) &&
                    m.public_ip===this.draft.public_ip && this.unchanged &&
                    !this.stale && !this.discovering && !this.reading && !this.saving && !this.committed);
            }
        },
        watch:{
            exportReady:function (ready) { if (!ready) this.closeQr(); },
            selectedInterface:function() {
                if(isPure(this.transport) && this.addrMode==='auto') this.discoverAddress();
            },
            peerForm:function (next,previous) {
                if (next!==previous) { this.committed=false;this.loadTunnel(); }
            }
        },
        mounted:function () {
            document.addEventListener('visibilitychange',this.onVisibility);
            window.addEventListener('pagehide',this.closeQr);
            this.loadTunnel();
        },
        deactivated:function () { this.closeQr(); },
        beforeDestroy:function () {
            this.closeQr(); this.serial++;
            document.removeEventListener('visibilitychange',this.onVisibility);
            window.removeEventListener('pagehide',this.closeQr);
            this._initialFields=null;this.$emit('transport',false);
        },
        methods:{
            addReverseMapping:function(){
                if(this.reverseDraft.mappings.length>=32)return false;
                var used={};this.reverseDraft.mappings.forEach(function(row){used[row.id]=true;});
                var id=1;while(used[String(id)] && id<=32)id++;
                if(id>32)return false;
                this.reverseDraft.mappings.push({id:String(id),protocol:'tcp',listen_port:'',target_ip:'',target_port:'',sources_text:''});
                return true;
            },
            removeReverseMapping:function(id){
                this.reverseDraft.mappings=this.reverseDraft.mappings.filter(function(row){return row.id!==id;});
            },
            readReverseStatus:function(){
                var v=this,m=v.member,f=v.peerForm;
                if(v.reverseReading || !m || !isPure(v.transport) || m.transport!=='pure_hy2' || !m.reverse.enabled)return false;
                var request=v._reverseRequest={};
                v.reverseReading=true;v.reverseReadError='';
                function current(){return !v._isDestroyed && v._reverseRequest===request && v.member===m && v.peerForm===f && isPure(v.transport);}
                return v.request('show',{TYPE:'hyr_status',peer_id:m.peer_id,id:m.id}).then(function(data){
                    if(!current())return false;
                    var status=data && data.hyr_status,rows=status && Array.isArray(status.members) && status.members.filter(function(row){
                        return String(row.peer_id)===m.peer_id && row.id===m.id && row.interface===m.interface;
                    });
                    if(!rows || rows.length!==1)throw Error();
                    v.reverseRuntime=root.WGPasteImport.reverseState(rows[0].reverse_status);
                    v.reverseServiceRunning=typeof rows[0].running==='boolean'?rows[0].running:null;
                    return true;
                }).catch(function(){
                    if(current()){
                        v.reverseRuntime=null;v.reverseServiceRunning=null;
                        v.reverseReadError=tr('无法读取反向连接状态，请重试。');
                    }
                    return false;
                }).then(function(ok){if(current())v.reverseReading=false;return ok;});
            },
            onVisibility: function () { if (document.hidden) this.closeQr(); },
            stopFrames: function () {
                clearInterval(this._qrTimer); this._qrTimer = null; this.playing = false;
            },
            closeQr: function () {
                if (this._exportPending) {
                    this.serial++; this._exportPending = false; this.busy = false;
                }
                this.stopFrames(); this.qr = null; this.phoneKind=''; this.phoneText=''; this._phoneCurrent=null;
            },
            copyManagementAddress:function(){
                var v=this,address=v.managementAddress,serial=v.serial,member=v.member;
                function current(){return !!address && v.serial===serial && v.member===member && v.managementAddress===address;}
                v.notice='';
                return root.WGClientConfig.copyText(address,current,root.navigator && root.navigator.clipboard,function(){
                    if(current()) {v.selectManagementAddress();v.notice=tr('请全选后台地址，再使用手机的复制菜单。');}
                },function(msg){v.notice=msg;},tr('复制后台地址'));
            },
            selectManagementAddress:function(){
                return !!this.managementAddress && !!this.$refs.managementAddress && root.WGClientConfig.selectPhoneText(this.$refs.managementAddress);
            },
            selectPhoneText:function(){
                var input=this.$refs.phoneText;
                if(!input || !this._phoneCurrent || !this._phoneCurrent())return false;
                return root.WGClientConfig.selectPhoneText(input);
            },
            copyShownPhone:function(){
                var v=this,text=v.phoneText,bound=v._phoneCurrent;
                function current(){return !!(bound && v._phoneCurrent===bound && v.phoneText===text && bound());}
                if(!current())return false;
                v.notice='';
                var clipboard=root.navigator && root.navigator.clipboard;
                if(!clipboard || typeof clipboard.writeText!=='function'){
                    if(v.selectPhoneText() && typeof document.execCommand==='function'){
                        try{if(document.execCommand('copy')){v.notice=tr('已复制');return true;}}catch(e){}
                    }
                    return false;
                }
                return root.WGClientConfig.copyText(text,current,clipboard,v.selectPhoneText,function(msg){v.notice=msg;},tr('复制配置'));
            },
            nextFrame: function () {
                if (this.qr) this.qr.index = (this.qr.index + 1) % this.qr.frames.length;
            },
            playFrames: function () {
                this.stopFrames();
                if (this.qr && this.qr.frames.length > 1) {
                    this.playing = true; this._qrTimer = setInterval(this.nextFrame, 650);
                }
            },
            request:function (action,param) {
                function failure(response) {
                    var msg=response && (response.ErrMsg || (response.data && response.data.ErrMsg));
                    throw {userMessage:root.WGI18n && root.WGI18n.knownText(msg)};
                }
                return this.$http.post(this.apiUrl,{func_name:'wireguard',action:action,param:param},
                    {timeout:60000}).then(function(response){
                    if (!response || !response.data || response.data.Result!==30000) return failure(response);
                    return response.data.Data;
                },failure);
            },
            notifyMethod:function () {
                var native=this.transport==='native';
                this.$emit('transport',!native,native && !this.member,false,!native);
            },
            discoverAddress:function(force) {
                var v=this,f=v.peerForm,iface=f.interface,draft=v.draft;
                var token=v._addressRequest={};v.discovering=false;v.discoveryError='';
                if(!isPure(v.transport) || !iface || !draft || !v.service || v.addrMode!=='auto') return;
                var request={TYPE:'client_endpoint',interface:iface};
                if(force) request.force='1';
                v.discovering=true;
                function current(){return !v._isDestroyed && v._addressRequest===token && v.peerForm===f &&
                    isPure(v.transport) && v.addrMode==='auto' && f.interface===iface && v.draft===draft;}
                return v.request('show',request).then(function(data){
                    if(!current())return;
                    var ep=data.client_endpoint,ip=ep && ep.ip;
                    if(!ep || ['public','wan'].indexOf(ep.source)<0 || !root.WGClientConfig.publicIPv4(ip)) throw Error();
                    draft.public_ip=ip;
                }).catch(function(){
                    if(current()) {
                        draft.public_ip='';
                        v.settingsOpen=true;
                        v.discoveryError=tr('未取得公网 IPv4，请重新获取或选择手动填写。');
                    }
                }).then(function(){if(current())v.discovering=false;});
            },
            loadTunnel:function (afterSave) {
                var v=this,f=v.peerForm,identity=afterSave ? v._submitted : f;
                if (v._openedForm!==f || afterSave===true || String(f.id||'')!==String(v._origin.id||'')) {
                    v._openedForm=f;
                    v._origin={id:identity.id,interface:identity.interface,peer_publickey:identity.peer_publickey || '',
                        site_local:identity.site_local,site_remote:identity.site_remote,
                        client_endpoint:identity.client_endpoint || '',allowips:identity.allowips,native_role:identity.native_role||'',exit_peer:identity.exit_peer==='yes'?'yes':'no'};
                    v._openedInputs=afterSave?v._submitted.inputs:editInputs(f);
                    v._openedComment=afterSave?v._submitted.comment:(f.comment||'');
                    v._initialFields=afterSave?v._savedFields:fields.map(function(k){return f[k];});
                }
                v.closeQr();var token=++v.serial;
                v.busy=false;v.reading=true;v.service=null;v.member=null;v.revision=0;
                v._reverseRequest=null;v.reverseReading=false;v.reverseRuntime=null;v.reverseServiceRunning=null;v.reverseReadError='';
                v.reverseDraft=reverseDraft();
                v.resume=false;v.settingsOpen=false;
                v.selected=false;v.stale=false;v.error='';v.notice='';
                v.$emit('transport',v.transport!=='native',false,false,isPure(v.transport));
                v._addressRequest=null;v.discovering=false;v.discoveryError='';
                function current(){return !v._isDestroyed && v.serial===token && v.peerForm===f;}
                var opened=v._origin, request={TYPE:'hyr_settings'};
                if(opened.id) request.peer_id=String(opened.id);
                return v.request('show',request).then(function(data){
                    if (!current()) return false;
                    var raw=data.hyr_settings, hy=snapshot(raw), id=request.peer_id;
                    var matches=hy.members.filter(function(m){
                        if(id) return m.peer_id===id;
                        return afterSave && matchesMember(m,opened);
                    });
                    var member=matches.length===1 ? matches[0] : null;
                    v.reading=false;
                    if(id && (!matchesSavedPeer(raw.peer,opened) || (member && !matchesMember(member,opened)))) {
                        v.stale=true;v.error=staleMessage();return false;
                    }
                    if(afterSave && (!member || member.transport!==identity.method || member.mode!==identity.mode || member.port_mode!==identity.portMode ||
                        member.addr_mode!==identity.addrMode || !sameReverse(member.reverse,identity.reverse) ||
                        (identity.resume && member.paused) || (identity.addrMode!=='shared' && member.public_ip!==identity.publicIP))) return false;
                    v.member=member;
                    v.service={public_ip:hy.public_ip,core_storage:hy.core_storage,core_format:hy.core_format};
                    v.draft={public_ip:''};
                    v.reverseDraft=reverseDraft(member?member.reverse:undefined);
                    v.portMode=member ? member.port_mode : 'wg';
                    v.addrMode=member ? member.addr_mode : 'auto';
                    v.draft.public_ip=member ? (member.addr_mode==='shared'?hy.public_ip:member.public_ip) : '';
                    v.transport=member?member.transport:'native';v.mode=member?member.mode:nativeMode(f);
                    if(afterSave) opened.id=member.peer_id;
                    v.revision++;v.notifyMethod();return true;
                }).catch(function(err){
                    if(current()){v.reading=false;v.error=err && err.userMessage || tr('无法读取隧道连接方式，请刷新状态。');}
                    return false;
                });
            },
            selectTransport:function (method) {
                if(method!=='native' && !isPure(method))return;
                this.closeQr();this.error='';this.notice='';this.selected=true;
                var existing=this.member && this.member.transport===method ? this.member : null;
                this._addressRequest=null;this.discovering=false;this.discoveryError='';this.transport=method;
                this._reverseRequest=null;this.reverseReading=false;this.reverseRuntime=null;this.reverseServiceRunning=null;this.reverseReadError='';
                if(method==='native') this.resume=false;
                if(existing) {
                    this.mode=existing.mode;this.portMode=existing.port_mode;this.addrMode=existing.addr_mode;
                    this.draft.public_ip=existing.addr_mode==='shared'?this.service.public_ip:existing.public_ip;
                    if(isPure(method))this.reverseDraft=reverseDraft(existing.reverse);
                } else if(isPure(method)) {
                    this.portMode='wg';
                    if(this.addrMode==='shared')this.addrMode='auto';
                    this.mode='access';
                    this.resume=!!(this.member && this.member.retired);
                }
                else if(method==='native' && this.mode==='site') {
                    this.$set(this.peerForm,'native_role','');this.mode=nativeMode(this.peerForm);this.selected=false;
                }
                this.applyRole();
                if(method!=='native' && this.addrMode==='auto' && (!existing || !this.draft.public_ip))return this.discoverAddress();
            },
            selectAddressMode:function (mode) {
                if(!isPure(this.transport) || (mode!=='auto' && mode!=='manual'))return;
                this.closeQr();this._addressRequest=null;this.discovering=false;this.discoveryError='';
                this.addrMode=mode;
                if(mode==='auto')return this.discoverAddress();
            },
            selectMode:function (mode) {
                if(this.transport==='native' ? ['access','lend','both'].indexOf(mode)<0 : !isPure(this.transport) || mode!=='access')return;
                this.closeQr();this.error='';this.notice='';this.selected=true;this.mode=mode;
                if(isPure(this.transport) && this.member && this.member.retired)this.resume=true;
                this.applyRole();
            },
            applyRole:function () {
                var f=this.peerForm;
                this.$set(f,'exit_peer',this.mode==='access'?'no':'yes');
                if(this.transport==='native') this.$set(f,'native_role',sitePeer(f) && !this.selected?'':this.mode);
                if(this.transport==='native' && this.mode==='lend' && (f.keepalive==='' || f.keepalive==null)) this.$set(f,'keepalive',25);
                this.$set(f,'client_config','');this.$set(f,'client_qr_svg','');
                this.notifyMethod();
            },
            parameters:function () {
                if(this.stale) throw Error(staleMessage());
                if(this.committed) throw Error(tr('隧道已保存。请点击“刷新状态”读取此设备的配置。'));
                if(this.saving || this.reading || this.busy || this.discovering) throw Error(tr('请等待隧道状态读取或保存完成'));
                var method=this.transport,f=this.peerForm,send={};
                if(method!=='native' && !isPure(method))throw Error(tr('此设备原用 HY2 承载 WG，已停用。请选择新的连接方式并保存。'));
                if(isPure(method) && this.member && this.member.retired && this.mode!=='access')throw Error(tr('原纯 HY2 借线用途已停用。请选择上网用途或其他连接方式，再保存。'));
                if(!this.service && (f.id || method!=='native')) throw Error(tr('无法读取隧道连接方式，请刷新状态。'));
                if(f.id) {
                    // Even ordinary edits of a legacy registration must compare the entire saved identity.
                    send.hyr_id=this.member ? this.member.id : '';
                    send.hyr_origin_key=this._origin.peer_publickey;send.hyr_origin_iface=this._origin.interface;
                    send.native_origin_role=this._origin.native_role;send.native_origin_exit=this._origin.exit_peer;
                }
                send.wg_transport=method;
                // Opening a pre-role peer for an ordinary edit preserves its existing routing policy.
                send.wg_role=(method==='native' && (f.id || sitePeer(f)) && !f.native_role && !this.selected) ? 'off' : this.mode;
                if(!isPure(method) && send.wg_role==='lend' && !(Number(f.keepalive)>0)) throw Error(tr('借用设备网络需要非零 WG 心跳，可设置为 25 秒'));
                if(method==='native') return send;
                if(this.mode!=='access' || this.portMode!=='wg' || ['auto','manual'].indexOf(this.addrMode)<0) throw Error(tr('请核对纯 HY2 的设备用途和公网入口。'));
                if(f.site_local || f.site_remote)throw Error(tr('纯 HY2 仅支持设备上网，请清空互访网段。'));
                send.hyr_port_mode='wg';
                send.hyr_addr_mode=this.addrMode;
                var address;
                try {address=root.WGClientConfig.endpointIP(this.draft.public_ip);} catch(e) {throw Error(tr('请填写有效的 IPv4 地址'));}
                if(this.member && this.member.paused && this.resume) send.hyr_resume='yes';
                send.hyr_public_ip=address;
                send.hyr_reverse_hex=root.WGPasteImport.reverseHex(reverseParameters(this.reverseDraft));
                try {root.WGClientConfig.endpointIP(f.client_endpoint);} catch(e) {this.$set(f,'client_endpoint',address);}
                send.exit_peer=this.mode==='access'?'no':'yes';
                return send;
            },
            commentEdit:function (payload) {
                var f=this.peerForm,m=this.member;
                if(!f.id || this.selected || this.resume || (f.comment||'')===this._openedComment || editInputs(f)!==this._openedInputs) return null;
                if(m && (m.port_mode!==this.portMode || m.addr_mode!==this.addrMode ||
                    (this.addrMode!=='shared' && m.public_ip!==payload.hyr_public_ip))) return null;
                if(isPure(this.transport) && !this.reverseUnchanged)return null;
                return {id:f.id,comment:f.comment||'',comment_only:'yes',hyr_origin_key:payload.hyr_origin_key,
                    hyr_origin_iface:payload.hyr_origin_iface,hyr_id:payload.hyr_id,
                    native_origin_role:payload.native_origin_role,native_origin_exit:payload.native_origin_exit};
            },
            saved:function (submitted) {
                var v=this,f=v.peerForm;
                if(!v.committed) {
                    var row=submitted || f;
                    v._submitted={id:row.id,interface:row.interface,allowips:row.allowips,peer_publickey:row.peer_publickey,
                        site_local:row.site_local,site_remote:row.site_remote,method:row.wg_transport || v.transport,mode:row.wg_role || v.mode,portMode:row.hyr_port_mode || v.portMode,
                        resume:row.hyr_resume==='yes' || v.resume,addrMode:row.hyr_addr_mode || v.addrMode,publicIP:row.hyr_public_ip || v.draft.public_ip,
                        reverse:row.hyr_reverse_hex?root.WGPasteImport.reverseFromHex(row.hyr_reverse_hex):reverseParameters(v.reverseDraft),
                        native_role:'',exit_peer:row.exit_peer,inputs:editInputs(row),comment:row.comment||''};
                    v._savedFields=fields.map(function(k){return row[k];});
                }
                v.committed=true;
                function bind(ok) {
                    if(v._isDestroyed || v.peerForm!==f) return false;
                    if(v.stale) return false;
                    if(!ok) { v.error=tr('隧道已保存。请点击“刷新状态”读取此设备的配置。');return false; }
                    v.committed=false;v._submitted=null;v._savedFields=null;v.notice='';
                    v.$emit('bound',v.member.peer_id);return true;
                }
                return v.loadTunnel(true).then(function(ok){
                    if(ok || v.stale || v._isDestroyed || v.peerForm!==f) return bind(ok);
                    return v.loadTunnel(true).then(bind);
                });
            },
            exportMember:function (qrRequested) {
                var v=this,member=v.member,form=v.peerForm;
                var native=qrRequested==='router' && v.transport==='native',router=qrRequested==='router';
                var copying=qrRequested==='json' || qrRequested==='uri';
                var serverKey=v.serverKey,listenPort=v.listenPort;
                if(!(native?v.nativeRouterReady:router?v.pureRouterReady:v.exportReady) || (v.busy && !(copying && v.phoneKind && v.phoneKind!==qrRequested)))return false;
                if(copying && v.phoneKind===qrRequested && v.phoneText)return v.copyShownPhone();
                v.closeQr();
                if(copying)v.phoneKind=qrRequested;
                var pure=isPure(v.transport);
                var name=native?'':'HY2-'+member.name, token=++v.serial;
                v.busy=true;v._exportPending=true;v.error='';v.notice='';
                function current(){return !v._isDestroyed && !document.hidden && v.serial===token && v.peerForm===form &&
                    v.member===member && (native?v.nativeRouterReady && v.serverKey===serverKey && v.listenPort===listenPort:router?v.pureRouterReady:v.exportReady);}
                var type=native?'native_router_profile':router?'hyr_site_profile':qrRequested==='uri'?'hyr_uri':'hyr_profile';
                var request=native?{TYPE:type,peer_id:String(v._origin.id),hyr_origin_iface:v._origin.interface,
                    hyr_origin_key:v._origin.peer_publickey,expected_server_key:serverKey}:{TYPE:type,peer_id:member.peer_id,id:member.id};
                request.expected_role=v.mode;
                var verified=v.request('show',request).then(function(data){
                    if(!current())return false;
                    var profile=data[type];
                    var agrees;
                    if(router){
                        var preview=root.WGPasteImport.validateSite(profile);
                        agrees=preview.purpose===v.mode && preview.transport===v.transport &&
                            (pure?matchesPureEndpoint(v,preview.server,preview.port) && sameReverse(reverseConfig(preview.reverse),member.reverse):
                            matchesNativeExport(v,profile.wireguard,profile.transport));
                    }else if(qrRequested==='uri'){
                        agrees=matchesPureUri(v,profile);
                    }else{
                        agrees=matchesPurePhone(v,profile);
                    }
                    if(!agrees){
                        v.error=staleMessage();v.stale=true;v.$emit('transport',!native,false,false,pure);
                        throw {userMessage:v.error};
                    }
                    return profile;
                });
                var result=copying ? copyPhoneText(v,verified.then(function(profile){
                    if(!profile)return null;
                    return qrRequested==='uri'?profile.uri:JSON.stringify(profile,null,2)+'\n';
                }),current) : verified.then(function(profile){
                    if(!profile || !current())return false;
                    if(router){
                        return root.WGClientConfig.copyText(JSON.stringify(profile,null,2)+'\n',current,
                            root.navigator && root.navigator.clipboard,function(label,text){root.prompt(label,text);},
                            function(msg){v.notice=msg;},tr('复制到路由器'));
                    }
                    if(!qrRequested) {download(profile,name);return true;}
                    return root.WGSingBox.qrsFrames(profile,name).then(function(frames){
                        if(!current() || document.hidden)return false;
                        var images=frames.map(function(frame){return v.makeQrSvg(frame);});
                        if(!images.length || images.some(function(svg){return !svg;}))throw Error();
                        v.qr={name:name,frames:images,index:0};
                        v.playFrames();
                        v.$nextTick(function(){if(v.$refs.qrBox)v.$refs.qrBox.scrollIntoView({block:'nearest'});});
                        return true;
                    });
                });
                return result.then(function(done){
                    if(v.serial!==token)return false;
                    v._exportPending=false;v.busy=false;return done;
                },function(err){
                    if(v.serial!==token)return false;
                    v.closeQr();
                    v.error=err && err.userMessage || (qrRequested===true ? tr('二维码生成失败，可重试或下载设备 JSON。') :
                        tr('无法读取隧道连接方式，请刷新状态。'));
                    return false;
                });
            }
        },
        render:function(h) {
            var v=this,method=v.transport,pure=isPure(method),source=pure && v.service,locked=v.busy || v.reading || v.saving || v.committed;
            function button(label,click,disabled,primary,copyKind) {
                var busy=v.busy && !(copyKind && v.phoneKind && copyKind!==v.phoneKind);
                return h('button',{staticClass:primary?'btn btn_blue':'btn',attrs:{type:'button',disabled:!!disabled || v.reading || v.saving || busy},on:{click:click}},[label]);
            }
            function radios(name,title,values,value,select,disabled) {
                return h('fieldset',{staticClass:'wg-hyr-roles'},[h('legend',[title])].concat(values.map(function(option){
                    return h('label',{key:option[0]},[h('input',{
                        attrs:{type:'radio',name:name,value:option[0],disabled:disabled || locked},
                        domProps:{checked:value===option[0]},on:{change:function(){return select(option[0]);}}
                    }),option[1]]);
                })));
            }
            function field(label,key,name,len) {
                return h('label',{staticClass:'wg-tunnel-field'},[label,h('input',{staticClass:'inptText',
                    attrs:{name:name,type:'text',disabled:locked || (key==='public_ip' && v.addrMode!=='manual'),maxlength:len,placeholder:key==='public_ip'?'203.0.113.10':''},
                    domProps:{value:v.draft[key]},on:{input:function(e){if(key==='public_ip'){v._addressRequest=null;v.discovering=false;v.discoveryError='';} v.draft[key]=e.target.value.trim();}}})]);
            }
            function controls(children){return h('div',{staticClass:'wg-tunnel-controls'},children);}
            function renderReverseEditor(){
                var saved=v.member && v.member.reverse;
                function reverseInput(row,key,label,placeholder,maxlength){
                    return h('label',{staticClass:'wg-tunnel-field'},[label,h('input',{staticClass:'inptText',
                        attrs:{type:'text',disabled:locked || !v.reverseDraft.enabled,
                            inputmode:key.indexOf('port')>=0?'numeric':'text',maxlength:maxlength,
                            placeholder:placeholder,'aria-label':label+' '+row.id},
                        domProps:{value:row[key]},on:{input:function(event){row[key]=event.target.value;}}
                    })]);
                }
                var items=[h('h4',[tr('反向端口映射')]),h('label',[
                    h('input',{attrs:{type:'checkbox',name:'hyr_reverse_enabled',disabled:locked},domProps:{checked:v.reverseDraft.enabled},
                        on:{change:function(event){v.reverseDraft.enabled=event.target.checked;if(event.target.checked && !v.reverseDraft.mappings.length)v.addReverseMapping();}}}),
                    tr('允许通过服务端端口访问这台路由器的指定服务')
                ]),h('p',{staticClass:'note'},[tr('仅支持兼容的 NativeRouting 路由器；手机配置不包含反向映射。')])];
                if(v.reverseDraft.enabled){
                    items.push(h('p',{staticClass:'note'},[tr('填写客户端本机或局域网的目标 IPv4 和端口。每条映射单独设置允许访问的来源网段。')]));
                    v.reverseDraft.mappings.forEach(function(row){
                        items.push(h('fieldset',{key:row.id,staticClass:'wg-reverse-mapping'},[
                            h('legend',[tr('映射'),' ',row.id]),
                            h('div',{staticClass:'wg-reverse-fields'},[
                                h('label',{staticClass:'wg-tunnel-field'},[tr('协议'),h('select',{staticClass:'inptText',attrs:{disabled:locked,'aria-label':tr('协议')+' '+row.id},
                                    domProps:{value:row.protocol},on:{change:function(event){row.protocol=event.target.value;}}},[
                                    h('option',{attrs:{value:'tcp'}},['TCP']),h('option',{attrs:{value:'udp'}},['UDP'])
                                ])]),
                                reverseInput(row,'listen_port',tr('服务端映射端口'),'18080',5),
                                reverseInput(row,'target_ip',tr('客户端目标 IPv4'),'192.168.62.1',15),
                                reverseInput(row,'target_port',tr('客户端目标端口'),'80',5),
                                reverseInput(row,'sources_text',tr('允许访问的来源网段'),'203.0.113.0/24',512)
                            ]),button(tr('移除映射'),function(){v.removeReverseMapping(row.id);},locked)
                        ]));
                    });
                    items.push(button(tr('新增映射'),v.addReverseMapping,locked || v.reverseDraft.mappings.length>=32),
                        h('p',{staticClass:'note'},[tr('多个网段用逗号分隔；0.0.0.0/0 表示允许所有来源。')]),
                        h('p',{staticClass:'note'},[tr('保存映射变更后，请重新复制到客户端路由器并导入。')])
                    );
                }
                if(saved && saved.enabled){
                    items.push(h('h4',[tr('已保存映射的连接状态')]),
                        controls([button(v.reverseReading?tr('正在读取…'):tr('读取连接状态'),v.readReverseStatus,locked || v.reverseReading)]),
                        h('p',[tr('HY2 服务状态'),' · ',v.reverseServiceRunning===true?tr('服务运行中'):v.reverseServiceRunning===false?tr('服务未运行'):tr('无记录')]),
                        root.WGPasteImport.renderReverseStatus(h,v.reverseRuntime,saved.mappings)
                    );
                    if(v.reverseReadError)items.push(h('p',{staticClass:'error_tip',attrs:{role:'status'}},[v.reverseReadError]));
                }
                if(!v.reverseUnchanged && v.member)items.push(h('p',{staticClass:'note'},[tr('反向映射有未保存的更改，保存后才能复制路由器配置。')]));
                return h('section',{staticClass:'wg-reverse-editor'},items);
            }
            function renderQr(){
                var qr=v.qr;
                return h('section',{ref:'qrBox',staticClass:'wg-tunnel-qr'},[
                    controls([h('strong',[qr.name]),button(tr('关闭二维码'),v.closeQr)]),
                    h('p',{staticClass:'note'},[tr('用此设备的 sing-box 扫码。二维码含本设备的连接凭据。')]),
                    qr.frames.length>1 ? controls([
                        h('span',[tr('持续对准屏幕，直到所有帧读完。')+' '+(qr.index+1)+' / '+qr.frames.length]),
                        button(v.playing?tr('暂停轮播'):tr('继续轮播'),v.playing?v.stopFrames:v.playFrames),
                        v.playing?null:button(tr('下一帧'),v.nextFrame)
                    ]) : null,
                    h('div',{staticClass:'wg-tunnel-qr-image',attrs:{role:'img','aria-label':tr('设备配置二维码')},
                        domProps:{innerHTML:qr.frames[qr.index]}})
                ]);
            }
            var links=methods(),body=[radios('wg_transport',tr('连接方式'),links,v.service?method:'',v.selectTransport,!v.service)];
            if(method==='native' && v.service && v.member) {
                body.push(h('p',{staticClass:'note'},[tr('保存连接方式后可使用原生 WG 配置。')]));
            }
            var purposes=pure?[['access',tr('让这台设备连接路由器上网')]]:roles();
            if(method==='hysteria2' && v.service)body.push(h('p',{staticClass:'note',attrs:{role:'status'}},[
                tr('此设备原用 HY2 承载 WG，已停用。请选择新的连接方式并保存。')]));
            if(v.service && (method==='native' || pure)) body.push(radios('wg_role',tr('设备用途'),purposes,method==='native' && (v.peerForm.id || sitePeer(v.peerForm)) && !v.peerForm.native_role && !v.selected?'':v.mode,v.selectMode,false));
            if(method==='native' && v.service && v.peerForm.id && !v.peerForm.native_role && !v.selected) {
                body.push(h('p',{staticClass:'note'},[tr('旧隧道沿用原配置。选择用途并保存后，才会应用新的设备用途。')]));
            }
            if(method==='native' && !v.peerForm.id && !v.selected && sitePeer(v.peerForm)) {
                body.push(h('p',{staticClass:'note'},[tr('站点互访沿用 WG 的原生路由设置。')]));
            }
            if(method==='native' && v.mode!=='access') body.push(h('p',{staticClass:'note'},[
                tr('手机借线请用 sing-box 扫出口配置；使用原生 WireGuard 配置的对端路由器需开启转发和出口 NAT。')]));
            if(v.nativeRouterReady)body.push(controls([button(tr('复制到路由器'),function(){return v.exportMember('router');})]));
            if(source) {
                if(pure){
                    body.push(h('p',{staticClass:'note'},[tr('手机连上 HY2 后，可用内网 IP 访问局域网设备。打开爱快后台仍需管理账号。')]));
                    if(v.exportReady)body.push(h('p',{staticClass:'note'},[
                        tr('分流入接口'), ' ', h('code',[v.member.interface]), ' · ',
                        tr('分流源地址'), ' ', h('code',[v.member.address])
                    ]));
                    if(v.managementAddress)body.push(controls([
                        h('label',[tr('路由器后台地址'),h('input',{ref:'managementAddress',staticClass:'inptText',attrs:{type:'text',readonly:true,'aria-label':tr('路由器后台地址')},domProps:{value:v.managementAddress}})]),
                        button(tr('复制后台地址'),v.copyManagementAddress),button(tr('全选后台地址'),v.selectManagementAddress)
                    ]));
                }
                if(pure && v.member && v.member.retired && v.mode!=='access')body.push(h('p',{staticClass:'note'},[
                    tr('原纯 HY2 借线用途已停用。请选择上网用途或其他连接方式，再保存。')]));
                var options=[];
                var addressModes=[['auto',tr('自动获取本设备 WAN 的地址')],['manual',tr('手动填写')]];
                options.push(radios('hyr_addr_mode',tr('公网入口 IPv4'),addressModes,v.addrMode,v.selectAddressMode,false));
                var inputs=[field(tr('本设备公网 IPv4'),'public_ip','hyr_public_ip',15)];
                if(v.addrMode==='auto')inputs.push(button(v.discovering?tr('获取中…'):tr('重新获取'),function(){return v.discoverAddress(true);},v.discovering));
                options.push(h('div',{staticClass:'wg-tunnel-fields'},inputs));
                var ip=v.draft.public_ip,port=v.listenPort;
                options.push(h('p',[tr('需放行的公网端口')+' · '+(port?port+'/UDP':tr('与本设备的 WG 接口相同'))]));
                if(source.core_storage==='memory')options.push(h('p',{staticClass:'note'},[tr('HY2 核心存放在内存盘，约占 88 MiB，由所有设备共用。')]));
                else if(source.core_storage==='disk' && source.core_format==='squashfs')options.push(h('p',{staticClass:'note'},[tr('HY2 核心从压缩磁盘按需读取。')]));
                var title=tr('连接设置');
                if(ip && port)title+=' · '+ip+':'+port+'/UDP';
                body.push(h('details',{staticClass:'wg-hyr-options',attrs:{open:v.settingsOpen},
                    on:{toggle:function(e){v.settingsOpen=e.target.open;}}},[h('summary',[title])].concat(options)));
                if(v.discoveryError)body.push(h('p',{staticClass:'error_tip'},[v.discoveryError]));
                if(pure)body.push(renderReverseEditor());
                if(v.member && v.member.paused && !v.member.retired)body.push(h('label',[
                    h('input',{attrs:{type:'checkbox',name:'hyr_resume',disabled:locked},
                        domProps:{checked:v.resume},on:{change:function(e){v.resume=e.target.checked;}}}),
                    tr('启用此设备')
                ]));
                if(v.exportReady){
                    body.push(controls([
                        button(tr('扫码导入'),function(){return v.exportMember(true);},false,true),
                        button(tr('复制 sing-box 配置'),function(){return v.exportMember('json');},false,false,'json'),
                        button(tr('复制 HY2 链接'),function(){return v.exportMember('uri');},false,false,'uri'),
                        button(tr('下载设备 JSON'),function(){return v.exportMember(false);}),
                        button(tr('复制到路由器'),function(){return v.exportMember('router');},!v.pureRouterReady)
                    ]));
                    body.push(h('p',{staticClass:'note'},[tr('在手机 sing-box 新建本地配置，打开编辑器，粘贴完整 JSON 并保存。')]));
                    body.push(h('p',{staticClass:'note'},[tr('HY2 链接适用于支持证书指纹校验（pinSHA256）的客户端。')]));
                    if(v.phoneText){
                        body.push(h('div',{staticClass:'wg-phone-copy'},[
                            h('p',{staticClass:'note',attrs:{role:'status'}},[tr('请点“全选配置”，再使用手机的复制菜单。')]),
                            h('textarea',{ref:'phoneText',staticClass:'inptText',attrs:{rows:v.phoneKind==='uri'?3:8,readonly:true,spellcheck:'false','aria-label':v.phoneKind==='uri'?'HY2 URI':'sing-box JSON'},domProps:{value:v.phoneText}}),
                            controls([button(tr('全选配置'),v.selectPhoneText),button(tr('关闭'),v.closeQr)])
                        ]));
                    }
                } else if(!v.member || !v.member.paused || v.resume) {
                    body.push(h('p',{staticClass:'note'},[tr('保存后可复制手机配置、扫码，或复制配置到另一台 NativeRouting 路由器。')]));
                }
                if(v.qr && v.exportReady)body.push(renderQr());
            }
            if(v.stale) body.push(button(tr('返回并刷新列表'),function(){v.$emit('reload-list');}));
            else if((!v.service || v.committed) && !v.reading && !v.saving)
                body.push(button(tr('刷新状态'),function(){return v.committed?v.saved():v.loadTunnel();}));
            if(v.reading || v.busy || v.saving || v.error || v.notice) body.push(h('p',{staticClass:v.error?'error_tip':'note',
                attrs:{role:'status','aria-live':'polite'}},[v.reading || v.busy || v.saving ? tr('处理中…') : v.error || v.notice]));
            return h('div',{staticClass:'line_edit wg-hyr-tunnel'},[
                h('div',{staticClass:'input_tit'},[tr('设备隧道')]),h('div',{staticClass:'input_group wg-hyr-editor'},body)]);
        }
    };
}(this));

/* Add identity checks to mutations from the two WireGuard lists. The native table supplies their rendering, filtering and pagination. */
(function(root){
    'use strict';
    var base, guarded;
    function tr(s){return root.WGI18n?root.WGI18n.text(s):s;}
    function stale(){return tr('设备已被删除或更改，请返回列表并重新打开。');}
    function identity(row,iface){
        var r={id:String(row.id),interface:iface?row.name:row.interface,public_key:iface?row.local_publickey:row.peer_publickey};
        var key=/^[A-Za-z0-9+/]{43}=$/;
        if(!/^[1-9]\d{0,9}$/.test(r.id) || !/^wg\d{1,10}$/.test(r.interface) || !key.test(r.public_key))return null;
        if(!iface){
            r.iface_id=String(row.iface_id);r.server_key=row.server_key;
            if(!(r.iface_id==='0' && r.server_key==='') && !(/^[1-9]\d{0,9}$/.test(r.iface_id) && key.test(r.server_key)))return null;
        }
        return r;
    }
    function snapshot(table,row){
        return identity(row,table.opt.requests.delRowAction==='iface_del');
    }
    function hex(rows){
        var text=JSON.stringify(rows),out='';
        for(var i=0;i<text.length;i++)out+=('0'+text.charCodeAt(i).toString(16)).slice(-2);
        return out;
    }
    function valid(table,rows){
        if(!rows.length){root.customError(table.$t('firewall.arp.checkTip'));return false;}
        if(rows.some(function(r){return !r;})){root.customError(stale());return false;}
        return true;
    }
    function selected(table){
        return table.rowChecking.map(function(id){return table._wgChecked[id] || null;});
    }
    function mutate(table,action,rows,event,state){
        if(table._isDestroyed || !valid(table,rows))return false;
        var req=table.opt.requests,ids=rows.map(function(r){return r.id;}).join(',');
        return table.$http.post(req.url,{func_name:'wireguard',action:action,param:{id:ids,expected_rows:hex(rows)}}).then(function(reply){
            if(!reply || !reply.data || reply.data.Result!==30000)throw (reply && reply.data || {});
            if(table._isDestroyed)return true;
            var affected={};rows.forEach(function(r){affected[r.id]=JSON.stringify(r);});
            // A newer list can arrive before the response. Never update a replacement row in its place.
            table.listData=table.listData.filter(function(row){
                if(affected[row.id]!==JSON.stringify(snapshot(table,row)))return true;
                if(state){row.enabled=state;return true;}
                return false;
            });
            table.toggleCheckAll(true);
            if(state)table.$emit(event,state==='yes');else table.$emit(event);
            if(!state)table.paginationOptions.currentPage=1;
            table.reload(!state);
            return true;
        }).catch(function(error){
            if(!table._isDestroyed){
                var body=error && (error.data || error),known=root.WGI18n && root.WGI18n.knownText(body && body.ErrMsg);
                root.customError(known || tr('请求失败，请检查连接并刷新接口列表确认结果后重试。'));
                table.toggleCheckAll(true);table.reload();
            }
            return false;
        });
    }
    function toggle(table,state,rows){
        return mutate(table,state==='yes'?table.opt.requests.enableRowAction:table.opt.requests.disableRowAction,
            rows,'toggleRowComplete',state);
    }
    function remove(table,rows,message,batch){
        if(!valid(table,rows))return false;
        table.editingRow=null;
        return root.customConfirm(message||table.$t(batch?'firewall.arp.delAllConfirm':'firewall.arp.delRowConfirm')).then(function(){
            return mutate(table,table.opt.requests.delRowAction,rows,batch?'batchDeleteRowSuccess':'deleteRowSuccess');
        },function(){return false;});
    }
    root.WGIdentityTable=function(view){
        var parent=view.$options.components.DTable;
        if(!parent || typeof parent.extend!=='function')return 'wg-table-unavailable';
        if(base===parent)return guarded;
        base=parent;
        var native=parent.options.methods;
        guarded=parent.extend({
            name:'WGIdentityTable',
            created:function(){this._wgChecked={};},
            methods:{
                toggleCheckRow:function(row,event){
                    native.toggleCheckRow.call(this,row,event);
                    if(event.target.checked)this._wgChecked[row.id]=snapshot(this,row);else delete this._wgChecked[row.id];
                },
                toggleCheckAll:function(clear){
                    native.toggleCheckAll.call(this,clear);
                    var t=this;t._wgChecked={};
                    t.listData.forEach(function(row){if(t.rowChecking.indexOf(row.id)>=0)t._wgChecked[row.id]=snapshot(t,row);});
                },
                toggleRowsState:function(state,row){return toggle(this,state,[snapshot(this,row)]);},
                batchEnableRows:function(){return toggle(this,'yes',selected(this));},
                batchDisableRows:function(){return toggle(this,'no',selected(this));},
                deleteRow:function(row,message){return remove(this,[snapshot(this,row)],message,false);},
                batchDeleteRows:function(message){return remove(this,selected(this),message,true);}
            }
        });
        return guarded;
    };
    root.WGIdentityTable.interfaceTarget=function(row){
        var original=identity(row,true);
        return original?hex([original]):'';
    };
}(this));

(function(showError){function tr(s){return typeof window!=='undefined'&&window.WGI18n?window.WGI18n.text(s):s;}var customError=function(s){return showError(tr(s));};
webpackJsonp([34],{"935":function(e,t,a){a(12040);var i=a(23)(a(11749),a(12282),"data-v-6a1474b8",null);e.exports=i.exports},"11048":function(e,t,a){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.default={props:["data"],data:function(){return{oemSign:2}},created:function(){var e=this;window.getHeaders(function(){e.oemSign=window.headers.oemSign})},methods:{}}},"11053":function(e,t,a){var s=a(23)(a(11048),a(11054),null,null);e.exports=s.exports},"11054":function(e,t){e.exports={render:function(){var e=this,t=e.$createElement,a=e._self._c||t;return 1==e.oemSign?a("div",[a("div",{staticClass:"readme"},[a("span",{staticClass:"note"},[e._v(e._s(e.$t("vpn_ad.help_tip"))+"：")]),e._v(" "),a("div",[e._v(e._s(e.$t("vpn_ad.tip1")))]),e._v(" "),a("div",[e._v(e._s(e.$t("vpn_ad.tip2")))]),e._v(" "),a("div",[e._v(e._s(e.$t("vpn_ad.tip3")))]),e._v(" "),a("div",[e._v(e._s(e.$t("vpn_ad.tip4")))]),e._v(" "),a("div",{domProps:{innerHTML:e._s(e.$t("vpn_ad.tip5"))}})])]):e._e()},staticRenderFns:[]}},"11114":function(t,e,s){t.exports={default:s(11186),__esModule:!0}},"11186":function(t,e,s){s(10134),s(11190),t.exports=s(16).Array.from},"11188":function(t,e,s){"use strict";var a=s(8),i=s(61);t.exports=function(t,e,s){e in t?a.f(t,e,i(0,s)):t[e]=s}},"11190":function(t,e,s){"use strict";var a=s(34),i=s(32),n=s(12),r=s(245),o=s(364),d=s(9),c=s(11188),l=s(221);i(i.S+i.F*!s(366)(function(t){Array.from(t)}),"Array",{from:function(t){var e,s,i,_,v=n(t),p="function"==typeof this?this:Array,m=arguments.length,u=m>1?arguments[1]:void 0,h=void 0!==u,f=0,b=l(v);if(h&&(u=a(u,m>2?arguments[2]:void 0,2)),void 0==b||p==Array&&o(b))for(e=d(v.length),s=new p(e);e>f;f++)c(s,f,h?u(v[f],f):v[f]);else for(_=b.call(v),s=new p;!(i=_.next()).done;f++)c(s,f,h?r(_,u,[i.value,f],!0):i.value);return s.length=f,s}})},"11525":function(t,e,a){"use strict";e.__esModule=!0;var s=a(350),i=function(t){return t&&t.__esModule?t:{default:t}}(s);e.default=i.default||function(t){for(var e=1;e<arguments.length;e++){var a=arguments[e];for(var s in a)Object.prototype.hasOwnProperty.call(a,s)&&(t[s]=a[s])}return t}},"11526":function(t,e,s){"use strict";e.__esModule=!0;var a=s(11114),i=function(t){return t&&t.__esModule?t:{default:t}}(a);e.default=function(t){if(Array.isArray(t)){for(var e=0,s=Array(t.length);e<t.length;e++)s[e]=t[e];return s}return(0,i.default)(t)}},"11749":function(e,t,a){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var i=a(10360),s=a.n(i),r=a(11526),l=a.n(r),o=a(80),n=a.n(o),d=a(11525),c=a.n(d),p=a(78),u=a(79),v=a.n(u),_=a(11053),m=a.n(_);t.default={components:{VpnAdPartial:m.a},
computed:{wgConfInputs:function(){return this.tableRowEditing1?window.WGClientConfig.exportInputs(this):''}},
watch:{wgConfInputs:function(){if(this._wgPhoneCurrent&&!this._wgPhoneCurrent())window.WGClientConfig.closePhoneCopy(this);if(this.tableForm.client_config&&!window.WGClientConfig.exportMatches(this))window.WGClientConfig.invalidate(this)}},
mounted:function(){
    var view=this;
    view._wgCopyHidden=function(){if(document.hidden)window.WGClientConfig.closePhoneCopy(view)};
    view._wgCopyLeave=function(){window.WGClientConfig.closePhoneCopy(view)};
    document.addEventListener('visibilitychange',view._wgCopyHidden);
    window.addEventListener('pagehide',view._wgCopyLeave);
},
deactivated:function(){window.WGClientConfig.closePhoneCopy(this)},
beforeDestroy:function(){
    if(this._wgCopyHidden)document.removeEventListener('visibilitychange',this._wgCopyHidden);
    if(this._wgCopyLeave)window.removeEventListener('pagehide',this._wgCopyLeave);
    window.WGClientConfig.cancel(this);
},data:function(){var e=this;return{wgIfaceBusy:false,wgIfaceNotice:"",wgTunnelOn:!1,wgPureMode:!1,wgShowNative:!1,wgSiteMode:!1,wgListRevision:0,wgListError:!1,wgImportSavedWarning:!1,wgManagedSite:null,wgSitePreview:null,wgManualCopy:null,wgSingbox:null,wgSingboxToken:0,wgSingboxBusy:!1,wgKeyRequests:{},wgEndpointToken:0,wgEndpointBusy:!1,wgEndpointError:"",wgEndpointNote:"",wgEndpointAuto:"",wgEndpointManual:!1,wgEndpointForm:null,wgPlanToken:0,wgPlanBusy:!1,wgPlanError:"",wgPlanNetwork:"",wgAutoAddress:"",wgAutoDns:"",wgImportOpen:!1,wgImportText:"",wgImportError:"",wgImportNote:"",wgImportBusy:!1,wgImportFromPeer:!1,wgImportPending:null,PWDis_show:!1,shouHint:!1,tableOptions:{clickToEdit:!1,rowEditFormat:"tableForm",tableClass:"table table_w checkbox_checked",customMethods:{},pagination:{paginateable:!0},tableOperation:[{type:"addRow",disable:!1},{type:"importFile",disable:!1},{type:"exportFile",disable:!1},{type:"batchEnableRows",disable:!1},{type:"batchDisableRows",disable:!1},{type:"batchDeleteRows",disable:!1},{type:"reorderRows",disable:!1},{type:"autoRefresh",disable:!1}],requests:{param:{TYPE:"iface_total,iface_data"},returnFieldAlias:{total:"iface_total",data:"iface_data"},url:p.a.apiUrl,funcName:"wireguard",listAction:"show",delRowAction:"iface_del",enableRowAction:"iface_up",disableRowAction:"iface_down",addRowAction:"iface_add",editRowAction:"iface_edit"},fixColumns:["id","buttons","checkbox","enabled"],columns:[{name:"name",display:"text",headerLabel:"wire_guard.name",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"local_address",display:"text",headerLabel:"wire_guard.localIP",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"local_listenport",display:"text",headerLabel:"wire_guard.listeningPort",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"interface",display:"customFunction",headerLabel:"wire_guard.Circuit",cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(t){return"auto"===t?e.$t("vpn.openVpnClient.auto"):t}},{name:"enabled",headerLabel:"wire_guard.Status",display:"customHtmlFunction",cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(t){return"yes"===t?"<span class='colorG'>"+e.$t("common.state_enabled")+"</span>":"<span class='colorR'>"+e.$t("common.state_disabled")+"</span>"}},{name:"buttons",headerLabel:"common.operation",display:"buttons",cls:{headerClass:"",cellClass:"td_opear"}},{name:"checkbox",headerLabel:"",display:"checkbox",cls:{headerClass:"td_check tc tm",cellClass:"tc tm"}}]},tableOptionsTunnel:{clickToEdit:!1,rowEditFormat:"tableForm",tableClass:"table table_w checkbox_checked",customMethods:{},pagination:{paginateable:!0},tableOperation:[{type:"addRow",disable:!1},{type:"customButton",disable:!1,label:"wire_guard.pasteImportConfig",emitEvent:"pasteImportConfig",cls:"wg-paste-import"},{type:"importFile",disable:!1},{type:"exportFile",disable:!1},{type:"batchEnableRows",disable:!1},{type:"batchDisableRows",disable:!1},{type:"batchDeleteRows",disable:!1},{type:"reorderRows",disable:!1},{type:"autoRefresh",disable:!1}],requests:{param:{TYPE:"total,data"},url:p.a.apiUrl,funcName:"wireguard",listAction:"show",delRowAction:"del",enableRowAction:"up",disableRowAction:"down",addRowAction:"add",editRowAction:"edit",export:"EXPORT_EXTEND",import:"IMPORT_EXTEND"},fixColumns:["id","buttons","checkbox","enabled"],columns:[{name:"endpoint",display:"text",headerLabel:"wire_guard.oppositeIP",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"endpoint_port",display:"text",headerLabel:"wire_guard.OppositePort",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"interface",display:"text",headerLabel:"wire_guard.name",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"keepalive",display:"text",headerLabel:"wire_guard.heartbeatInterval",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"upload",display:"text",headerLabel:"wire_guard.upstream",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(e,t){return v.a.formatBytes(e)}},{name:"download",display:"text",headerLabel:"wire_guard.downloadstream",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(e,t){return v.a.formatBytes(e)}},{name:"comment",display:"text",headerLabel:"common.comment",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"enabled",headerLabel:"wire_guard.Status",display:"customHtmlFunction",cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(t){return"yes"===t?"<span class='colorG'>"+e.$t("common.state_enabled")+"</span>":"<span class='colorR'>"+e.$t("common.state_disabled")+"</span>"}},{name:"buttons",headerLabel:"common.operation",display:"buttons",cls:{headerClass:"",cellClass:"td_opear"}},{name:"checkbox",headerLabel:"",display:"checkbox",cls:{headerClass:"td_check tc tm",cellClass:"tc tm"}}]},tableRowEditing:!1,tableRowEditing1:!1,tableForm:{name:"",local_publickey:"",peer_publickey:"",peer_privatekey:"",presharedkey:"",local_address:"",interface:"",keepalive:"",local_listenport:"",local_privatekey:"",allowips:"",endpoint:"",endpoint_port:"",enabled:"yes",out_mode:"auto",out_wans:"",out_balance:"failover",client_dns:"",client_config:"",client_qr_svg:""},interfaces:[],interfaces1:[],ifaceRows:[],ifaceDefaults:{},peerDefaults:{},wanEndpoint:{},centerForm:{enable:"0",client_src:"10.100.10.0/24",china_iface:"wg_to_A",oversea_iface:"wg_to_C",route_non_china:"1",china_url:"https://ispip.clang.cn/all_cn.txt",nat_enable:"0",nat_src:"10.100.10.0/24",nat_wan:"wan1",last_update:"",last_apply:""},xEnterprise:0,oemSign:0}},created:function(){var e=this;window.getHeaders(function(){e.xEnterprise=window.headers.xEnterprise,e.oemSign=window.headers.oemSign,(e.xEnterprise||2==e.oemSign)&&e.getInterfaceAndServiceStatus()})},methods:{getPrivateKey:function(){if(this.wgIfaceBusy)return false;var e=this;return window.WGClientConfig.generateKey(this,"private",function(t){return e.$http.post(p.a.apiUrl,t)},customError)},getShareKey:function(){var e=this;return window.WGClientConfig.generateKey(this,"shared",function(t){return e.$http.post(p.a.apiUrl,t)},customError)},getPeerKey:function(){var e=this;return window.WGClientConfig.generateKey(this,"peer",function(t){return e.$http.post(p.a.apiUrl,t)},customError)},getInterfaceAndServiceStatus:function(){
    var view=this,token=view._ifaceRead={};
    return view.$http.post(view.tableOptions.requests.url,{func_name:"wireguard",action:"show",param:{TYPE:"interface,wg_iface,iface_data,wan_endpoint,defaults,center_config"}}).then(function(reply){
        var data=reply && reply.data && reply.data.Result===30000 && reply.data.Data;
        if(!data || !Array.isArray(data.iface_data) || !Array.isArray(data.wg_iface))return null;
        if(view._isDestroyed || view._ifaceRead!==token)return null;
        view.interfaces=copyAry("decode",data.interface || []);
        view.interfaces1=copyAry("decode",data.wg_iface);
        view.ifaceRows=data.iface_data;
        view.ifaceDefaults=data.iface_defaults || {};
        view.peerDefaults=data.peer_defaults || {};
        view.centerForm=data.center_config || view.centerForm;
        view.wanEndpoint={};
        (data.wan_endpoint || []).forEach(function(row){view.wanEndpoint[row[0]]=row[1];});
        return data.iface_data;
    },function(){return null;});
},saveCenterConfig:function(){var e=this,t=c()({},JSON.parse(n()(this.centerForm)));this.$http.post(p.a.apiUrl,{func_name:"wireguard",action:"center_save",param:copyObj("encode",t)}).then(function(t){customSuccess(tr("中心分流配置已保存")),e.getInterfaceAndServiceStatus()})},updateCenterConfig:function(){var e=this,t=c()({},JSON.parse(n()(this.centerForm)));this.$http.post(p.a.apiUrl,{func_name:"wireguard",action:"center_save",param:copyObj("encode",t)}).then(function(){e.$http.post(p.a.apiUrl,{func_name:"wireguard",action:"center_update_apply",param:{}}).then(function(t){customSuccess(tr("已开始更新IP库并应用")),setTimeout(function(){e.getInterfaceAndServiceStatus()},1500)})})},deleteRowSuccess:function(){this.getInterfaceAndServiceStatus()},nextIndexedValue:function(e,t,a){for(var i={},s=0;s<e.length;s++){var r=(e[s][t]||"").match(a);r&&(i[1*r[1]]=!0)}for(var l=1;i[l];)l++;return l},nextIfaceDefaults:function(){return this.ifaceDefaults||{}},nextPeerDefaults:function(){return this.peerDefaults||{}},getIfaceRow:function(){for(var e=0;e<this.ifaceRows.length;e++)if(this.ifaceRows[e].name==this.tableForm.interface)return this.ifaceRows[e];return{}},getInterfaceDns:function(e){for(var t=0;t<this.ifaceRows.length;t++)if(this.ifaceRows[t].name==e)return(this.ifaceRows[t].local_address||"").split("/")[0];return""},syncClientDnsFromInterface:function(){var e=this,t=function(t){return e.$http.post(p.a.apiUrl,t)},a=function(t){return copyObj("encode",t)};return Promise.all([window.WGAddressPlan.changed(this,t,a),window.WGClientConfig.changed(this,t,a)])},openClientEndpoint:function(){var e=this;return window.WGClientConfig.open(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)})},refreshClientEndpoint:function(){var e=this;return window.WGClientConfig.request(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)},true)},makeQrSvg:function(e){try{window.__wgQrLib||(window.__wgQrLib=(new Function("module","exports","//---------------------------------------------------------------------\n//\n// QR Code Generator for JavaScript\n//\n// Copyright (c) 2009 Kazuhiko Arase\n//\n// URL: http://www.d-project.com/\n//\n// Licensed under the MIT license:\n//  http://www.opensource.org/licenses/mit-license.php\n//\n// The word 'QR Code' is registered trademark of\n// DENSO WAVE INCORPORATED\n//  http://www.denso-wave.com/qrcode/faqpatent-e.html\n//\n//---------------------------------------------------------------------\n\nvar qrcode = function() {\n\n  //---------------------------------------------------------------------\n  // qrcode\n  //---------------------------------------------------------------------\n\n  /**\n   * qrcode\n   * @param typeNumber 1 to 40\n   * @param errorCorrectionLevel 'L','M','Q','H'\n   */\n  var qrcode = function(typeNumber, errorCorrectionLevel) {\n\n    var PAD0 = 0xEC;\n    var PAD1 = 0x11;\n\n    var _typeNumber = typeNumber;\n    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];\n    var _modules = null;\n    var _moduleCount = 0;\n    var _dataCache = null;\n    var _dataList = [];\n\n    var _this = {};\n\n    var makeImpl = function(test, maskPattern) {\n\n      _moduleCount = _typeNumber * 4 + 17;\n      _modules = function(moduleCount) {\n        var modules = new Array(moduleCount);\n        for (var row = 0; row < moduleCount; row += 1) {\n          modules[row] = new Array(moduleCount);\n          for (var col = 0; col < moduleCount; col += 1) {\n            modules[row][col] = null;\n          }\n        }\n        return modules;\n      }(_moduleCount);\n\n      setupPositionProbePattern(0, 0);\n      setupPositionProbePattern(_moduleCount - 7, 0);\n      setupPositionProbePattern(0, _moduleCount - 7);\n      setupPositionAdjustPattern();\n      setupTimingPattern();\n      setupTypeInfo(test, maskPattern);\n\n      if (_typeNumber >= 7) {\n        setupTypeNumber(test);\n      }\n\n      if (_dataCache == null) {\n        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);\n      }\n\n      mapData(_dataCache, maskPattern);\n    };\n\n    var setupPositionProbePattern = function(row, col) {\n\n      for (var r = -1; r <= 7; r += 1) {\n\n        if (row + r <= -1 || _moduleCount <= row + r) continue;\n\n        for (var c = -1; c <= 7; c += 1) {\n\n          if (col + c <= -1 || _moduleCount <= col + c) continue;\n\n          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )\n              || (0 <= c && c <= 6 && (r == 0 || r == 6) )\n              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {\n            _modules[row + r][col + c] = true;\n          } else {\n            _modules[row + r][col + c] = false;\n          }\n        }\n      }\n    };\n\n    var getBestMaskPattern = function() {\n\n      var minLostPoint = 0;\n      var pattern = 0;\n\n      for (var i = 0; i < 8; i += 1) {\n\n        makeImpl(true, i);\n\n        var lostPoint = QRUtil.getLostPoint(_this);\n\n        if (i == 0 || minLostPoint > lostPoint) {\n          minLostPoint = lostPoint;\n          pattern = i;\n        }\n      }\n\n      return pattern;\n    };\n\n    var setupTimingPattern = function() {\n\n      for (var r = 8; r < _moduleCount - 8; r += 1) {\n        if (_modules[r][6] != null) {\n          continue;\n        }\n        _modules[r][6] = (r % 2 == 0);\n      }\n\n      for (var c = 8; c < _moduleCount - 8; c += 1) {\n        if (_modules[6][c] != null) {\n          continue;\n        }\n        _modules[6][c] = (c % 2 == 0);\n      }\n    };\n\n    var setupPositionAdjustPattern = function() {\n\n      var pos = QRUtil.getPatternPosition(_typeNumber);\n\n      for (var i = 0; i < pos.length; i += 1) {\n\n        for (var j = 0; j < pos.length; j += 1) {\n\n          var row = pos[i];\n          var col = pos[j];\n\n          if (_modules[row][col] != null) {\n            continue;\n          }\n\n          for (var r = -2; r <= 2; r += 1) {\n\n            for (var c = -2; c <= 2; c += 1) {\n\n              if (r == -2 || r == 2 || c == -2 || c == 2\n                  || (r == 0 && c == 0) ) {\n                _modules[row + r][col + c] = true;\n              } else {\n                _modules[row + r][col + c] = false;\n              }\n            }\n          }\n        }\n      }\n    };\n\n    var setupTypeNumber = function(test) {\n\n      var bits = QRUtil.getBCHTypeNumber(_typeNumber);\n\n      for (var i = 0; i < 18; i += 1) {\n        var mod = (!test && ( (bits >> i) & 1) == 1);\n        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;\n      }\n\n      for (var i = 0; i < 18; i += 1) {\n        var mod = (!test && ( (bits >> i) & 1) == 1);\n        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;\n      }\n    };\n\n    var setupTypeInfo = function(test, maskPattern) {\n\n      var data = (_errorCorrectionLevel << 3) | maskPattern;\n      var bits = QRUtil.getBCHTypeInfo(data);\n\n      // vertical\n      for (var i = 0; i < 15; i += 1) {\n\n        var mod = (!test && ( (bits >> i) & 1) == 1);\n\n        if (i < 6) {\n          _modules[i][8] = mod;\n        } else if (i < 8) {\n          _modules[i + 1][8] = mod;\n        } else {\n          _modules[_moduleCount - 15 + i][8] = mod;\n        }\n      }\n\n      // horizontal\n      for (var i = 0; i < 15; i += 1) {\n\n        var mod = (!test && ( (bits >> i) & 1) == 1);\n\n        if (i < 8) {\n          _modules[8][_moduleCount - i - 1] = mod;\n        } else if (i < 9) {\n          _modules[8][15 - i - 1 + 1] = mod;\n        } else {\n          _modules[8][15 - i - 1] = mod;\n        }\n      }\n\n      // fixed module\n      _modules[_moduleCount - 8][8] = (!test);\n    };\n\n    var mapData = function(data, maskPattern) {\n\n      var inc = -1;\n      var row = _moduleCount - 1;\n      var bitIndex = 7;\n      var byteIndex = 0;\n      var maskFunc = QRUtil.getMaskFunction(maskPattern);\n\n      for (var col = _moduleCount - 1; col > 0; col -= 2) {\n\n        if (col == 6) col -= 1;\n\n        while (true) {\n\n          for (var c = 0; c < 2; c += 1) {\n\n            if (_modules[row][col - c] == null) {\n\n              var dark = false;\n\n              if (byteIndex < data.length) {\n                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);\n              }\n\n              var mask = maskFunc(row, col - c);\n\n              if (mask) {\n                dark = !dark;\n              }\n\n              _modules[row][col - c] = dark;\n              bitIndex -= 1;\n\n              if (bitIndex == -1) {\n                byteIndex += 1;\n                bitIndex = 7;\n              }\n            }\n          }\n\n          row += inc;\n\n          if (row < 0 || _moduleCount <= row) {\n            row -= inc;\n            inc = -inc;\n            break;\n          }\n        }\n      }\n    };\n\n    var createBytes = function(buffer, rsBlocks) {\n\n      var offset = 0;\n\n      var maxDcCount = 0;\n      var maxEcCount = 0;\n\n      var dcdata = new Array(rsBlocks.length);\n      var ecdata = new Array(rsBlocks.length);\n\n      for (var r = 0; r < rsBlocks.length; r += 1) {\n\n        var dcCount = rsBlocks[r].dataCount;\n        var ecCount = rsBlocks[r].totalCount - dcCount;\n\n        maxDcCount = Math.max(maxDcCount, dcCount);\n        maxEcCount = Math.max(maxEcCount, ecCount);\n\n        dcdata[r] = new Array(dcCount);\n\n        for (var i = 0; i < dcdata[r].length; i += 1) {\n          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];\n        }\n        offset += dcCount;\n\n        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);\n        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);\n\n        var modPoly = rawPoly.mod(rsPoly);\n        ecdata[r] = new Array(rsPoly.getLength() - 1);\n        for (var i = 0; i < ecdata[r].length; i += 1) {\n          var modIndex = i + modPoly.getLength() - ecdata[r].length;\n          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;\n        }\n      }\n\n      var totalCodeCount = 0;\n      for (var i = 0; i < rsBlocks.length; i += 1) {\n        totalCodeCount += rsBlocks[i].totalCount;\n      }\n\n      var data = new Array(totalCodeCount);\n      var index = 0;\n\n      for (var i = 0; i < maxDcCount; i += 1) {\n        for (var r = 0; r < rsBlocks.length; r += 1) {\n          if (i < dcdata[r].length) {\n            data[index] = dcdata[r][i];\n            index += 1;\n          }\n        }\n      }\n\n      for (var i = 0; i < maxEcCount; i += 1) {\n        for (var r = 0; r < rsBlocks.length; r += 1) {\n          if (i < ecdata[r].length) {\n            data[index] = ecdata[r][i];\n            index += 1;\n          }\n        }\n      }\n\n      return data;\n    };\n\n    var createData = function(typeNumber, errorCorrectionLevel, dataList) {\n\n      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);\n\n      var buffer = qrBitBuffer();\n\n      for (var i = 0; i < dataList.length; i += 1) {\n        var data = dataList[i];\n        buffer.put(data.getMode(), 4);\n        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );\n        data.write(buffer);\n      }\n\n      // calc num max data.\n      var totalDataCount = 0;\n      for (var i = 0; i < rsBlocks.length; i += 1) {\n        totalDataCount += rsBlocks[i].dataCount;\n      }\n\n      if (buffer.getLengthInBits() > totalDataCount * 8) {\n        throw 'code length overflow. ('\n          + buffer.getLengthInBits()\n          + '>'\n          + totalDataCount * 8\n          + ')';\n      }\n\n      // end code\n      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {\n        buffer.put(0, 4);\n      }\n\n      // padding\n      while (buffer.getLengthInBits() % 8 != 0) {\n        buffer.putBit(false);\n      }\n\n      // padding\n      while (true) {\n\n        if (buffer.getLengthInBits() >= totalDataCount * 8) {\n          break;\n        }\n        buffer.put(PAD0, 8);\n\n        if (buffer.getLengthInBits() >= totalDataCount * 8) {\n          break;\n        }\n        buffer.put(PAD1, 8);\n      }\n\n      return createBytes(buffer, rsBlocks);\n    };\n\n    _this.addData = function(data, mode) {\n\n      mode = mode || 'Byte';\n\n      var newData = null;\n\n      switch(mode) {\n      case 'Numeric' :\n        newData = qrNumber(data);\n        break;\n      case 'Alphanumeric' :\n        newData = qrAlphaNum(data);\n        break;\n      case 'Byte' :\n        newData = qr8BitByte(data);\n        break;\n      case 'Kanji' :\n        newData = qrKanji(data);\n        break;\n      default :\n        throw 'mode:' + mode;\n      }\n\n      _dataList.push(newData);\n      _dataCache = null;\n    };\n\n    _this.isDark = function(row, col) {\n      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {\n        throw row + ',' + col;\n      }\n      return _modules[row][col];\n    };\n\n    _this.getModuleCount = function() {\n      return _moduleCount;\n    };\n\n    _this.make = function() {\n      if (_typeNumber < 1) {\n        var typeNumber = 1;\n\n        for (; typeNumber < 40; typeNumber++) {\n          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);\n          var buffer = qrBitBuffer();\n\n          for (var i = 0; i < _dataList.length; i++) {\n            var data = _dataList[i];\n            buffer.put(data.getMode(), 4);\n            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );\n            data.write(buffer);\n          }\n\n          var totalDataCount = 0;\n          for (var i = 0; i < rsBlocks.length; i++) {\n            totalDataCount += rsBlocks[i].dataCount;\n          }\n\n          if (buffer.getLengthInBits() <= totalDataCount * 8) {\n            break;\n          }\n        }\n\n        _typeNumber = typeNumber;\n      }\n\n      makeImpl(false, getBestMaskPattern() );\n    };\n\n    _this.createTableTag = function(cellSize, margin) {\n\n      cellSize = cellSize || 2;\n      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;\n\n      var qrHtml = '';\n\n      qrHtml += '<table style=\"';\n      qrHtml += ' border-width: 0px; border-style: none;';\n      qrHtml += ' border-collapse: collapse;';\n      qrHtml += ' padding: 0px; margin: ' + margin + 'px;';\n      qrHtml += '\">';\n      qrHtml += '<tbody>';\n\n      for (var r = 0; r < _this.getModuleCount(); r += 1) {\n\n        qrHtml += '<tr>';\n\n        for (var c = 0; c < _this.getModuleCount(); c += 1) {\n          qrHtml += '<td style=\"';\n          qrHtml += ' border-width: 0px; border-style: none;';\n          qrHtml += ' border-collapse: collapse;';\n          qrHtml += ' padding: 0px; margin: 0px;';\n          qrHtml += ' width: ' + cellSize + 'px;';\n          qrHtml += ' height: ' + cellSize + 'px;';\n          qrHtml += ' background-color: ';\n          qrHtml += _this.isDark(r, c)? '#000000' : '#ffffff';\n          qrHtml += ';';\n          qrHtml += '\"/>';\n        }\n\n        qrHtml += '</tr>';\n      }\n\n      qrHtml += '</tbody>';\n      qrHtml += '</table>';\n\n      return qrHtml;\n    };\n\n    _this.createSvgTag = function(cellSize, margin, alt, title) {\n\n      var opts = {};\n      if (typeof arguments[0] == 'object') {\n        // Called by options.\n        opts = arguments[0];\n        // overwrite cellSize and margin.\n        cellSize = opts.cellSize;\n        margin = opts.margin;\n        alt = opts.alt;\n        title = opts.title;\n      }\n\n      cellSize = cellSize || 2;\n      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;\n\n      // Compose alt property surrogate\n      alt = (typeof alt === 'string') ? {text: alt} : alt || {};\n      alt.text = alt.text || null;\n      alt.id = (alt.text) ? alt.id || 'qrcode-description' : null;\n\n      // Compose title property surrogate\n      title = (typeof title === 'string') ? {text: title} : title || {};\n      title.text = title.text || null;\n      title.id = (title.text) ? title.id || 'qrcode-title' : null;\n\n      var size = _this.getModuleCount() * cellSize + margin * 2;\n      var c, mc, r, mr, qrSvg='', rect;\n\n      rect = 'l' + cellSize + ',0 0,' + cellSize +\n        ' -' + cellSize + ',0 0,-' + cellSize + 'z ';\n\n      qrSvg += '<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\"';\n      qrSvg += !opts.scalable ? ' width=\"' + size + 'px\" height=\"' + size + 'px\"' : '';\n      qrSvg += ' viewBox=\"0 0 ' + size + ' ' + size + '\" ';\n      qrSvg += ' preserveAspectRatio=\"xMinYMin meet\"';\n      qrSvg += (title.text || alt.text) ? ' role=\"img\" aria-labelledby=\"' +\n          escapeXml([title.id, alt.id].join(' ').trim() ) + '\"' : '';\n      qrSvg += '>';\n      qrSvg += (title.text) ? '<title id=\"' + escapeXml(title.id) + '\">' +\n          escapeXml(title.text) + '</title>' : '';\n      qrSvg += (alt.text) ? '<description id=\"' + escapeXml(alt.id) + '\">' +\n          escapeXml(alt.text) + '</description>' : '';\n      qrSvg += '<rect width=\"100%\" height=\"100%\" fill=\"white\" cx=\"0\" cy=\"0\"/>';\n      qrSvg += '<path d=\"';\n\n      for (r = 0; r < _this.getModuleCount(); r += 1) {\n        mr = r * cellSize + margin;\n        for (c = 0; c < _this.getModuleCount(); c += 1) {\n          if (_this.isDark(r, c) ) {\n            mc = c*cellSize+margin;\n            qrSvg += 'M' + mc + ',' + mr + rect;\n          }\n        }\n      }\n\n      qrSvg += '\" stroke=\"transparent\" fill=\"black\"/>';\n      qrSvg += '</svg>';\n\n      return qrSvg;\n    };\n\n    _this.createDataURL = function(cellSize, margin) {\n\n      cellSize = cellSize || 2;\n      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;\n\n      var size = _this.getModuleCount() * cellSize + margin * 2;\n      var min = margin;\n      var max = size - margin;\n\n      return createDataURL(size, size, function(x, y) {\n        if (min <= x && x < max && min <= y && y < max) {\n          var c = Math.floor( (x - min) / cellSize);\n          var r = Math.floor( (y - min) / cellSize);\n          return _this.isDark(r, c)? 0 : 1;\n        } else {\n          return 1;\n        }\n      } );\n    };\n\n    _this.createImgTag = function(cellSize, margin, alt) {\n\n      cellSize = cellSize || 2;\n      margin = (typeof margin == 'undefined')? cellSize * 4 : margin;\n\n      var size = _this.getModuleCount() * cellSize + margin * 2;\n\n      var img = '';\n      img += '<img';\n      img += '\\u0020src=\"';\n      img += _this.createDataURL(cellSize, margin);\n      img += '\"';\n      img += '\\u0020width=\"';\n      img += size;\n      img += '\"';\n      img += '\\u0020height=\"';\n      img += size;\n      img += '\"';\n      if (alt) {\n        img += '\\u0020alt=\"';\n        img += escapeXml(alt);\n        img += '\"';\n      }\n      img += '/>';\n\n      return img;\n    };\n\n    var escapeXml = function(s) {\n      var escaped = '';\n      for (var i = 0; i < s.length; i += 1) {\n        var c = s.charAt(i);\n        switch(c) {\n        case '<': escaped += '&lt;'; break;\n        case '>': escaped += '&gt;'; break;\n        case '&': escaped += '&amp;'; break;\n        case '\"': escaped += '&quot;'; break;\n        default : escaped += c; break;\n        }\n      }\n      return escaped;\n    };\n\n    var _createHalfASCII = function(margin) {\n      var cellSize = 1;\n      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;\n\n      var size = _this.getModuleCount() * cellSize + margin * 2;\n      var min = margin;\n      var max = size - margin;\n\n      var y, x, r1, r2, p;\n\n      var blocks = {\n        '██': '█',\n        '█ ': '▀',\n        ' █': '▄',\n        '  ': ' '\n      };\n\n      var blocksLastLineNoMargin = {\n        '██': '▀',\n        '█ ': '▀',\n        ' █': ' ',\n        '  ': ' '\n      };\n\n      var ascii = '';\n      for (y = 0; y < size; y += 2) {\n        r1 = Math.floor((y - min) / cellSize);\n        r2 = Math.floor((y + 1 - min) / cellSize);\n        for (x = 0; x < size; x += 1) {\n          p = '█';\n\n          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {\n            p = ' ';\n          }\n\n          if (min <= x && x < max && min <= y+1 && y+1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {\n            p += ' ';\n          }\n          else {\n            p += '█';\n          }\n\n          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.\n          ascii += (margin < 1 && y+1 >= max) ? blocksLastLineNoMargin[p] : blocks[p];\n        }\n\n        ascii += '\\n';\n      }\n\n      if (size % 2 && margin > 0) {\n        return ascii.substring(0, ascii.length - size - 1) + Array(size+1).join('▀');\n      }\n\n      return ascii.substring(0, ascii.length-1);\n    };\n\n    _this.createASCII = function(cellSize, margin) {\n      cellSize = cellSize || 1;\n\n      if (cellSize < 2) {\n        return _createHalfASCII(margin);\n      }\n\n      cellSize -= 1;\n      margin = (typeof margin == 'undefined')? cellSize * 2 : margin;\n\n      var size = _this.getModuleCount() * cellSize + margin * 2;\n      var min = margin;\n      var max = size - margin;\n\n      var y, x, r, p;\n\n      var white = Array(cellSize+1).join('██');\n      var black = Array(cellSize+1).join('  ');\n\n      var ascii = '';\n      var line = '';\n      for (y = 0; y < size; y += 1) {\n        r = Math.floor( (y - min) / cellSize);\n        line = '';\n        for (x = 0; x < size; x += 1) {\n          p = 1;\n\n          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {\n            p = 0;\n          }\n\n          // Output 2 characters per pixel, to create full square. 1 character per pixels gives only half width of square.\n          line += p ? white : black;\n        }\n\n        for (r = 0; r < cellSize; r += 1) {\n          ascii += line + '\\n';\n        }\n      }\n\n      return ascii.substring(0, ascii.length-1);\n    };\n\n    _this.renderTo2dContext = function(context, cellSize) {\n      cellSize = cellSize || 2;\n      var length = _this.getModuleCount();\n      for (var row = 0; row < length; row++) {\n        for (var col = 0; col < length; col++) {\n          context.fillStyle = _this.isDark(row, col) ? 'black' : 'white';\n          context.fillRect(row * cellSize, col * cellSize, cellSize, cellSize);\n        }\n      }\n    }\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // qrcode.stringToBytes\n  //---------------------------------------------------------------------\n\n  qrcode.stringToBytesFuncs = {\n    'default' : function(s) {\n      var bytes = [];\n      for (var i = 0; i < s.length; i += 1) {\n        var c = s.charCodeAt(i);\n        bytes.push(c & 0xff);\n      }\n      return bytes;\n    }\n  };\n\n  qrcode.stringToBytes = qrcode.stringToBytesFuncs['default'];\n\n  //---------------------------------------------------------------------\n  // qrcode.createStringToBytes\n  //---------------------------------------------------------------------\n\n  /**\n   * @param unicodeData base64 string of byte array.\n   * [16bit Unicode],[16bit Bytes], ...\n   * @param numChars\n   */\n  qrcode.createStringToBytes = function(unicodeData, numChars) {\n\n    // create conversion map.\n\n    var unicodeMap = function() {\n\n      var bin = base64DecodeInputStream(unicodeData);\n      var read = function() {\n        var b = bin.read();\n        if (b == -1) throw 'eof';\n        return b;\n      };\n\n      var count = 0;\n      var unicodeMap = {};\n      while (true) {\n        var b0 = bin.read();\n        if (b0 == -1) break;\n        var b1 = read();\n        var b2 = read();\n        var b3 = read();\n        var k = String.fromCharCode( (b0 << 8) | b1);\n        var v = (b2 << 8) | b3;\n        unicodeMap[k] = v;\n        count += 1;\n      }\n      if (count != numChars) {\n        throw count + ' != ' + numChars;\n      }\n\n      return unicodeMap;\n    }();\n\n    var unknownChar = '?'.charCodeAt(0);\n\n    return function(s) {\n      var bytes = [];\n      for (var i = 0; i < s.length; i += 1) {\n        var c = s.charCodeAt(i);\n        if (c < 128) {\n          bytes.push(c);\n        } else {\n          var b = unicodeMap[s.charAt(i)];\n          if (typeof b == 'number') {\n            if ( (b & 0xff) == b) {\n              // 1byte\n              bytes.push(b);\n            } else {\n              // 2bytes\n              bytes.push(b >>> 8);\n              bytes.push(b & 0xff);\n            }\n          } else {\n            bytes.push(unknownChar);\n          }\n        }\n      }\n      return bytes;\n    };\n  };\n\n  //---------------------------------------------------------------------\n  // QRMode\n  //---------------------------------------------------------------------\n\n  var QRMode = {\n    MODE_NUMBER :    1 << 0,\n    MODE_ALPHA_NUM : 1 << 1,\n    MODE_8BIT_BYTE : 1 << 2,\n    MODE_KANJI :     1 << 3\n  };\n\n  //---------------------------------------------------------------------\n  // QRErrorCorrectionLevel\n  //---------------------------------------------------------------------\n\n  var QRErrorCorrectionLevel = {\n    L : 1,\n    M : 0,\n    Q : 3,\n    H : 2\n  };\n\n  //---------------------------------------------------------------------\n  // QRMaskPattern\n  //---------------------------------------------------------------------\n\n  var QRMaskPattern = {\n    PATTERN000 : 0,\n    PATTERN001 : 1,\n    PATTERN010 : 2,\n    PATTERN011 : 3,\n    PATTERN100 : 4,\n    PATTERN101 : 5,\n    PATTERN110 : 6,\n    PATTERN111 : 7\n  };\n\n  //---------------------------------------------------------------------\n  // QRUtil\n  //---------------------------------------------------------------------\n\n  var QRUtil = function() {\n\n    var PATTERN_POSITION_TABLE = [\n      [],\n      [6, 18],\n      [6, 22],\n      [6, 26],\n      [6, 30],\n      [6, 34],\n      [6, 22, 38],\n      [6, 24, 42],\n      [6, 26, 46],\n      [6, 28, 50],\n      [6, 30, 54],\n      [6, 32, 58],\n      [6, 34, 62],\n      [6, 26, 46, 66],\n      [6, 26, 48, 70],\n      [6, 26, 50, 74],\n      [6, 30, 54, 78],\n      [6, 30, 56, 82],\n      [6, 30, 58, 86],\n      [6, 34, 62, 90],\n      [6, 28, 50, 72, 94],\n      [6, 26, 50, 74, 98],\n      [6, 30, 54, 78, 102],\n      [6, 28, 54, 80, 106],\n      [6, 32, 58, 84, 110],\n      [6, 30, 58, 86, 114],\n      [6, 34, 62, 90, 118],\n      [6, 26, 50, 74, 98, 122],\n      [6, 30, 54, 78, 102, 126],\n      [6, 26, 52, 78, 104, 130],\n      [6, 30, 56, 82, 108, 134],\n      [6, 34, 60, 86, 112, 138],\n      [6, 30, 58, 86, 114, 142],\n      [6, 34, 62, 90, 118, 146],\n      [6, 30, 54, 78, 102, 126, 150],\n      [6, 24, 50, 76, 102, 128, 154],\n      [6, 28, 54, 80, 106, 132, 158],\n      [6, 32, 58, 84, 110, 136, 162],\n      [6, 26, 54, 82, 110, 138, 166],\n      [6, 30, 58, 86, 114, 142, 170]\n    ];\n    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);\n    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);\n    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);\n\n    var _this = {};\n\n    var getBCHDigit = function(data) {\n      var digit = 0;\n      while (data != 0) {\n        digit += 1;\n        data >>>= 1;\n      }\n      return digit;\n    };\n\n    _this.getBCHTypeInfo = function(data) {\n      var d = data << 10;\n      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {\n        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );\n      }\n      return ( (data << 10) | d) ^ G15_MASK;\n    };\n\n    _this.getBCHTypeNumber = function(data) {\n      var d = data << 12;\n      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {\n        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );\n      }\n      return (data << 12) | d;\n    };\n\n    _this.getPatternPosition = function(typeNumber) {\n      return PATTERN_POSITION_TABLE[typeNumber - 1];\n    };\n\n    _this.getMaskFunction = function(maskPattern) {\n\n      switch (maskPattern) {\n\n      case QRMaskPattern.PATTERN000 :\n        return function(i, j) { return (i + j) % 2 == 0; };\n      case QRMaskPattern.PATTERN001 :\n        return function(i, j) { return i % 2 == 0; };\n      case QRMaskPattern.PATTERN010 :\n        return function(i, j) { return j % 3 == 0; };\n      case QRMaskPattern.PATTERN011 :\n        return function(i, j) { return (i + j) % 3 == 0; };\n      case QRMaskPattern.PATTERN100 :\n        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };\n      case QRMaskPattern.PATTERN101 :\n        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };\n      case QRMaskPattern.PATTERN110 :\n        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };\n      case QRMaskPattern.PATTERN111 :\n        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };\n\n      default :\n        throw 'bad maskPattern:' + maskPattern;\n      }\n    };\n\n    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {\n      var a = qrPolynomial([1], 0);\n      for (var i = 0; i < errorCorrectLength; i += 1) {\n        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );\n      }\n      return a;\n    };\n\n    _this.getLengthInBits = function(mode, type) {\n\n      if (1 <= type && type < 10) {\n\n        // 1 - 9\n\n        switch(mode) {\n        case QRMode.MODE_NUMBER    : return 10;\n        case QRMode.MODE_ALPHA_NUM : return 9;\n        case QRMode.MODE_8BIT_BYTE : return 8;\n        case QRMode.MODE_KANJI     : return 8;\n        default :\n          throw 'mode:' + mode;\n        }\n\n      } else if (type < 27) {\n\n        // 10 - 26\n\n        switch(mode) {\n        case QRMode.MODE_NUMBER    : return 12;\n        case QRMode.MODE_ALPHA_NUM : return 11;\n        case QRMode.MODE_8BIT_BYTE : return 16;\n        case QRMode.MODE_KANJI     : return 10;\n        default :\n          throw 'mode:' + mode;\n        }\n\n      } else if (type < 41) {\n\n        // 27 - 40\n\n        switch(mode) {\n        case QRMode.MODE_NUMBER    : return 14;\n        case QRMode.MODE_ALPHA_NUM : return 13;\n        case QRMode.MODE_8BIT_BYTE : return 16;\n        case QRMode.MODE_KANJI     : return 12;\n        default :\n          throw 'mode:' + mode;\n        }\n\n      } else {\n        throw 'type:' + type;\n      }\n    };\n\n    _this.getLostPoint = function(qrcode) {\n\n      var moduleCount = qrcode.getModuleCount();\n\n      var lostPoint = 0;\n\n      // LEVEL1\n\n      for (var row = 0; row < moduleCount; row += 1) {\n        for (var col = 0; col < moduleCount; col += 1) {\n\n          var sameCount = 0;\n          var dark = qrcode.isDark(row, col);\n\n          for (var r = -1; r <= 1; r += 1) {\n\n            if (row + r < 0 || moduleCount <= row + r) {\n              continue;\n            }\n\n            for (var c = -1; c <= 1; c += 1) {\n\n              if (col + c < 0 || moduleCount <= col + c) {\n                continue;\n              }\n\n              if (r == 0 && c == 0) {\n                continue;\n              }\n\n              if (dark == qrcode.isDark(row + r, col + c) ) {\n                sameCount += 1;\n              }\n            }\n          }\n\n          if (sameCount > 5) {\n            lostPoint += (3 + sameCount - 5);\n          }\n        }\n      };\n\n      // LEVEL2\n\n      for (var row = 0; row < moduleCount - 1; row += 1) {\n        for (var col = 0; col < moduleCount - 1; col += 1) {\n          var count = 0;\n          if (qrcode.isDark(row, col) ) count += 1;\n          if (qrcode.isDark(row + 1, col) ) count += 1;\n          if (qrcode.isDark(row, col + 1) ) count += 1;\n          if (qrcode.isDark(row + 1, col + 1) ) count += 1;\n          if (count == 0 || count == 4) {\n            lostPoint += 3;\n          }\n        }\n      }\n\n      // LEVEL3\n\n      for (var row = 0; row < moduleCount; row += 1) {\n        for (var col = 0; col < moduleCount - 6; col += 1) {\n          if (qrcode.isDark(row, col)\n              && !qrcode.isDark(row, col + 1)\n              &&  qrcode.isDark(row, col + 2)\n              &&  qrcode.isDark(row, col + 3)\n              &&  qrcode.isDark(row, col + 4)\n              && !qrcode.isDark(row, col + 5)\n              &&  qrcode.isDark(row, col + 6) ) {\n            lostPoint += 40;\n          }\n        }\n      }\n\n      for (var col = 0; col < moduleCount; col += 1) {\n        for (var row = 0; row < moduleCount - 6; row += 1) {\n          if (qrcode.isDark(row, col)\n              && !qrcode.isDark(row + 1, col)\n              &&  qrcode.isDark(row + 2, col)\n              &&  qrcode.isDark(row + 3, col)\n              &&  qrcode.isDark(row + 4, col)\n              && !qrcode.isDark(row + 5, col)\n              &&  qrcode.isDark(row + 6, col) ) {\n            lostPoint += 40;\n          }\n        }\n      }\n\n      // LEVEL4\n\n      var darkCount = 0;\n\n      for (var col = 0; col < moduleCount; col += 1) {\n        for (var row = 0; row < moduleCount; row += 1) {\n          if (qrcode.isDark(row, col) ) {\n            darkCount += 1;\n          }\n        }\n      }\n\n      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;\n      lostPoint += ratio * 10;\n\n      return lostPoint;\n    };\n\n    return _this;\n  }();\n\n  //---------------------------------------------------------------------\n  // QRMath\n  //---------------------------------------------------------------------\n\n  var QRMath = function() {\n\n    var EXP_TABLE = new Array(256);\n    var LOG_TABLE = new Array(256);\n\n    // initialize tables\n    for (var i = 0; i < 8; i += 1) {\n      EXP_TABLE[i] = 1 << i;\n    }\n    for (var i = 8; i < 256; i += 1) {\n      EXP_TABLE[i] = EXP_TABLE[i - 4]\n        ^ EXP_TABLE[i - 5]\n        ^ EXP_TABLE[i - 6]\n        ^ EXP_TABLE[i - 8];\n    }\n    for (var i = 0; i < 255; i += 1) {\n      LOG_TABLE[EXP_TABLE[i] ] = i;\n    }\n\n    var _this = {};\n\n    _this.glog = function(n) {\n\n      if (n < 1) {\n        throw 'glog(' + n + ')';\n      }\n\n      return LOG_TABLE[n];\n    };\n\n    _this.gexp = function(n) {\n\n      while (n < 0) {\n        n += 255;\n      }\n\n      while (n >= 256) {\n        n -= 255;\n      }\n\n      return EXP_TABLE[n];\n    };\n\n    return _this;\n  }();\n\n  //---------------------------------------------------------------------\n  // qrPolynomial\n  //---------------------------------------------------------------------\n\n  function qrPolynomial(num, shift) {\n\n    if (typeof num.length == 'undefined') {\n      throw num.length + '/' + shift;\n    }\n\n    var _num = function() {\n      var offset = 0;\n      while (offset < num.length && num[offset] == 0) {\n        offset += 1;\n      }\n      var _num = new Array(num.length - offset + shift);\n      for (var i = 0; i < num.length - offset; i += 1) {\n        _num[i] = num[i + offset];\n      }\n      return _num;\n    }();\n\n    var _this = {};\n\n    _this.getAt = function(index) {\n      return _num[index];\n    };\n\n    _this.getLength = function() {\n      return _num.length;\n    };\n\n    _this.multiply = function(e) {\n\n      var num = new Array(_this.getLength() + e.getLength() - 1);\n\n      for (var i = 0; i < _this.getLength(); i += 1) {\n        for (var j = 0; j < e.getLength(); j += 1) {\n          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );\n        }\n      }\n\n      return qrPolynomial(num, 0);\n    };\n\n    _this.mod = function(e) {\n\n      if (_this.getLength() - e.getLength() < 0) {\n        return _this;\n      }\n\n      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );\n\n      var num = new Array(_this.getLength() );\n      for (var i = 0; i < _this.getLength(); i += 1) {\n        num[i] = _this.getAt(i);\n      }\n\n      for (var i = 0; i < e.getLength(); i += 1) {\n        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);\n      }\n\n      // recursive call\n      return qrPolynomial(num, 0).mod(e);\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // QRRSBlock\n  //---------------------------------------------------------------------\n\n  var QRRSBlock = function() {\n\n    var RS_BLOCK_TABLE = [\n\n      // L\n      // M\n      // Q\n      // H\n\n      // 1\n      [1, 26, 19],\n      [1, 26, 16],\n      [1, 26, 13],\n      [1, 26, 9],\n\n      // 2\n      [1, 44, 34],\n      [1, 44, 28],\n      [1, 44, 22],\n      [1, 44, 16],\n\n      // 3\n      [1, 70, 55],\n      [1, 70, 44],\n      [2, 35, 17],\n      [2, 35, 13],\n\n      // 4\n      [1, 100, 80],\n      [2, 50, 32],\n      [2, 50, 24],\n      [4, 25, 9],\n\n      // 5\n      [1, 134, 108],\n      [2, 67, 43],\n      [2, 33, 15, 2, 34, 16],\n      [2, 33, 11, 2, 34, 12],\n\n      // 6\n      [2, 86, 68],\n      [4, 43, 27],\n      [4, 43, 19],\n      [4, 43, 15],\n\n      // 7\n      [2, 98, 78],\n      [4, 49, 31],\n      [2, 32, 14, 4, 33, 15],\n      [4, 39, 13, 1, 40, 14],\n\n      // 8\n      [2, 121, 97],\n      [2, 60, 38, 2, 61, 39],\n      [4, 40, 18, 2, 41, 19],\n      [4, 40, 14, 2, 41, 15],\n\n      // 9\n      [2, 146, 116],\n      [3, 58, 36, 2, 59, 37],\n      [4, 36, 16, 4, 37, 17],\n      [4, 36, 12, 4, 37, 13],\n\n      // 10\n      [2, 86, 68, 2, 87, 69],\n      [4, 69, 43, 1, 70, 44],\n      [6, 43, 19, 2, 44, 20],\n      [6, 43, 15, 2, 44, 16],\n\n      // 11\n      [4, 101, 81],\n      [1, 80, 50, 4, 81, 51],\n      [4, 50, 22, 4, 51, 23],\n      [3, 36, 12, 8, 37, 13],\n\n      // 12\n      [2, 116, 92, 2, 117, 93],\n      [6, 58, 36, 2, 59, 37],\n      [4, 46, 20, 6, 47, 21],\n      [7, 42, 14, 4, 43, 15],\n\n      // 13\n      [4, 133, 107],\n      [8, 59, 37, 1, 60, 38],\n      [8, 44, 20, 4, 45, 21],\n      [12, 33, 11, 4, 34, 12],\n\n      // 14\n      [3, 145, 115, 1, 146, 116],\n      [4, 64, 40, 5, 65, 41],\n      [11, 36, 16, 5, 37, 17],\n      [11, 36, 12, 5, 37, 13],\n\n      // 15\n      [5, 109, 87, 1, 110, 88],\n      [5, 65, 41, 5, 66, 42],\n      [5, 54, 24, 7, 55, 25],\n      [11, 36, 12, 7, 37, 13],\n\n      // 16\n      [5, 122, 98, 1, 123, 99],\n      [7, 73, 45, 3, 74, 46],\n      [15, 43, 19, 2, 44, 20],\n      [3, 45, 15, 13, 46, 16],\n\n      // 17\n      [1, 135, 107, 5, 136, 108],\n      [10, 74, 46, 1, 75, 47],\n      [1, 50, 22, 15, 51, 23],\n      [2, 42, 14, 17, 43, 15],\n\n      // 18\n      [5, 150, 120, 1, 151, 121],\n      [9, 69, 43, 4, 70, 44],\n      [17, 50, 22, 1, 51, 23],\n      [2, 42, 14, 19, 43, 15],\n\n      // 19\n      [3, 141, 113, 4, 142, 114],\n      [3, 70, 44, 11, 71, 45],\n      [17, 47, 21, 4, 48, 22],\n      [9, 39, 13, 16, 40, 14],\n\n      // 20\n      [3, 135, 107, 5, 136, 108],\n      [3, 67, 41, 13, 68, 42],\n      [15, 54, 24, 5, 55, 25],\n      [15, 43, 15, 10, 44, 16],\n\n      // 21\n      [4, 144, 116, 4, 145, 117],\n      [17, 68, 42],\n      [17, 50, 22, 6, 51, 23],\n      [19, 46, 16, 6, 47, 17],\n\n      // 22\n      [2, 139, 111, 7, 140, 112],\n      [17, 74, 46],\n      [7, 54, 24, 16, 55, 25],\n      [34, 37, 13],\n\n      // 23\n      [4, 151, 121, 5, 152, 122],\n      [4, 75, 47, 14, 76, 48],\n      [11, 54, 24, 14, 55, 25],\n      [16, 45, 15, 14, 46, 16],\n\n      // 24\n      [6, 147, 117, 4, 148, 118],\n      [6, 73, 45, 14, 74, 46],\n      [11, 54, 24, 16, 55, 25],\n      [30, 46, 16, 2, 47, 17],\n\n      // 25\n      [8, 132, 106, 4, 133, 107],\n      [8, 75, 47, 13, 76, 48],\n      [7, 54, 24, 22, 55, 25],\n      [22, 45, 15, 13, 46, 16],\n\n      // 26\n      [10, 142, 114, 2, 143, 115],\n      [19, 74, 46, 4, 75, 47],\n      [28, 50, 22, 6, 51, 23],\n      [33, 46, 16, 4, 47, 17],\n\n      // 27\n      [8, 152, 122, 4, 153, 123],\n      [22, 73, 45, 3, 74, 46],\n      [8, 53, 23, 26, 54, 24],\n      [12, 45, 15, 28, 46, 16],\n\n      // 28\n      [3, 147, 117, 10, 148, 118],\n      [3, 73, 45, 23, 74, 46],\n      [4, 54, 24, 31, 55, 25],\n      [11, 45, 15, 31, 46, 16],\n\n      // 29\n      [7, 146, 116, 7, 147, 117],\n      [21, 73, 45, 7, 74, 46],\n      [1, 53, 23, 37, 54, 24],\n      [19, 45, 15, 26, 46, 16],\n\n      // 30\n      [5, 145, 115, 10, 146, 116],\n      [19, 75, 47, 10, 76, 48],\n      [15, 54, 24, 25, 55, 25],\n      [23, 45, 15, 25, 46, 16],\n\n      // 31\n      [13, 145, 115, 3, 146, 116],\n      [2, 74, 46, 29, 75, 47],\n      [42, 54, 24, 1, 55, 25],\n      [23, 45, 15, 28, 46, 16],\n\n      // 32\n      [17, 145, 115],\n      [10, 74, 46, 23, 75, 47],\n      [10, 54, 24, 35, 55, 25],\n      [19, 45, 15, 35, 46, 16],\n\n      // 33\n      [17, 145, 115, 1, 146, 116],\n      [14, 74, 46, 21, 75, 47],\n      [29, 54, 24, 19, 55, 25],\n      [11, 45, 15, 46, 46, 16],\n\n      // 34\n      [13, 145, 115, 6, 146, 116],\n      [14, 74, 46, 23, 75, 47],\n      [44, 54, 24, 7, 55, 25],\n      [59, 46, 16, 1, 47, 17],\n\n      // 35\n      [12, 151, 121, 7, 152, 122],\n      [12, 75, 47, 26, 76, 48],\n      [39, 54, 24, 14, 55, 25],\n      [22, 45, 15, 41, 46, 16],\n\n      // 36\n      [6, 151, 121, 14, 152, 122],\n      [6, 75, 47, 34, 76, 48],\n      [46, 54, 24, 10, 55, 25],\n      [2, 45, 15, 64, 46, 16],\n\n      // 37\n      [17, 152, 122, 4, 153, 123],\n      [29, 74, 46, 14, 75, 47],\n      [49, 54, 24, 10, 55, 25],\n      [24, 45, 15, 46, 46, 16],\n\n      // 38\n      [4, 152, 122, 18, 153, 123],\n      [13, 74, 46, 32, 75, 47],\n      [48, 54, 24, 14, 55, 25],\n      [42, 45, 15, 32, 46, 16],\n\n      // 39\n      [20, 147, 117, 4, 148, 118],\n      [40, 75, 47, 7, 76, 48],\n      [43, 54, 24, 22, 55, 25],\n      [10, 45, 15, 67, 46, 16],\n\n      // 40\n      [19, 148, 118, 6, 149, 119],\n      [18, 75, 47, 31, 76, 48],\n      [34, 54, 24, 34, 55, 25],\n      [20, 45, 15, 61, 46, 16]\n    ];\n\n    var qrRSBlock = function(totalCount, dataCount) {\n      var _this = {};\n      _this.totalCount = totalCount;\n      _this.dataCount = dataCount;\n      return _this;\n    };\n\n    var _this = {};\n\n    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {\n\n      switch(errorCorrectionLevel) {\n      case QRErrorCorrectionLevel.L :\n        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];\n      case QRErrorCorrectionLevel.M :\n        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];\n      case QRErrorCorrectionLevel.Q :\n        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];\n      case QRErrorCorrectionLevel.H :\n        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];\n      default :\n        return undefined;\n      }\n    };\n\n    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {\n\n      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);\n\n      if (typeof rsBlock == 'undefined') {\n        throw 'bad rs block @ typeNumber:' + typeNumber +\n            '/errorCorrectionLevel:' + errorCorrectionLevel;\n      }\n\n      var length = rsBlock.length / 3;\n\n      var list = [];\n\n      for (var i = 0; i < length; i += 1) {\n\n        var count = rsBlock[i * 3 + 0];\n        var totalCount = rsBlock[i * 3 + 1];\n        var dataCount = rsBlock[i * 3 + 2];\n\n        for (var j = 0; j < count; j += 1) {\n          list.push(qrRSBlock(totalCount, dataCount) );\n        }\n      }\n\n      return list;\n    };\n\n    return _this;\n  }();\n\n  //---------------------------------------------------------------------\n  // qrBitBuffer\n  //---------------------------------------------------------------------\n\n  var qrBitBuffer = function() {\n\n    var _buffer = [];\n    var _length = 0;\n\n    var _this = {};\n\n    _this.getBuffer = function() {\n      return _buffer;\n    };\n\n    _this.getAt = function(index) {\n      var bufIndex = Math.floor(index / 8);\n      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;\n    };\n\n    _this.put = function(num, length) {\n      for (var i = 0; i < length; i += 1) {\n        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);\n      }\n    };\n\n    _this.getLengthInBits = function() {\n      return _length;\n    };\n\n    _this.putBit = function(bit) {\n\n      var bufIndex = Math.floor(_length / 8);\n      if (_buffer.length <= bufIndex) {\n        _buffer.push(0);\n      }\n\n      if (bit) {\n        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );\n      }\n\n      _length += 1;\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // qrNumber\n  //---------------------------------------------------------------------\n\n  var qrNumber = function(data) {\n\n    var _mode = QRMode.MODE_NUMBER;\n    var _data = data;\n\n    var _this = {};\n\n    _this.getMode = function() {\n      return _mode;\n    };\n\n    _this.getLength = function(buffer) {\n      return _data.length;\n    };\n\n    _this.write = function(buffer) {\n\n      var data = _data;\n\n      var i = 0;\n\n      while (i + 2 < data.length) {\n        buffer.put(strToNum(data.substring(i, i + 3) ), 10);\n        i += 3;\n      }\n\n      if (i < data.length) {\n        if (data.length - i == 1) {\n          buffer.put(strToNum(data.substring(i, i + 1) ), 4);\n        } else if (data.length - i == 2) {\n          buffer.put(strToNum(data.substring(i, i + 2) ), 7);\n        }\n      }\n    };\n\n    var strToNum = function(s) {\n      var num = 0;\n      for (var i = 0; i < s.length; i += 1) {\n        num = num * 10 + chatToNum(s.charAt(i) );\n      }\n      return num;\n    };\n\n    var chatToNum = function(c) {\n      if ('0' <= c && c <= '9') {\n        return c.charCodeAt(0) - '0'.charCodeAt(0);\n      }\n      throw 'illegal char :' + c;\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // qrAlphaNum\n  //---------------------------------------------------------------------\n\n  var qrAlphaNum = function(data) {\n\n    var _mode = QRMode.MODE_ALPHA_NUM;\n    var _data = data;\n\n    var _this = {};\n\n    _this.getMode = function() {\n      return _mode;\n    };\n\n    _this.getLength = function(buffer) {\n      return _data.length;\n    };\n\n    _this.write = function(buffer) {\n\n      var s = _data;\n\n      var i = 0;\n\n      while (i + 1 < s.length) {\n        buffer.put(\n          getCode(s.charAt(i) ) * 45 +\n          getCode(s.charAt(i + 1) ), 11);\n        i += 2;\n      }\n\n      if (i < s.length) {\n        buffer.put(getCode(s.charAt(i) ), 6);\n      }\n    };\n\n    var getCode = function(c) {\n\n      if ('0' <= c && c <= '9') {\n        return c.charCodeAt(0) - '0'.charCodeAt(0);\n      } else if ('A' <= c && c <= 'Z') {\n        return c.charCodeAt(0) - 'A'.charCodeAt(0) + 10;\n      } else {\n        switch (c) {\n        case ' ' : return 36;\n        case '$' : return 37;\n        case '%' : return 38;\n        case '*' : return 39;\n        case '+' : return 40;\n        case '-' : return 41;\n        case '.' : return 42;\n        case '/' : return 43;\n        case ':' : return 44;\n        default :\n          throw 'illegal char :' + c;\n        }\n      }\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // qr8BitByte\n  //---------------------------------------------------------------------\n\n  var qr8BitByte = function(data) {\n\n    var _mode = QRMode.MODE_8BIT_BYTE;\n    var _data = data;\n    var _bytes = qrcode.stringToBytes(data);\n\n    var _this = {};\n\n    _this.getMode = function() {\n      return _mode;\n    };\n\n    _this.getLength = function(buffer) {\n      return _bytes.length;\n    };\n\n    _this.write = function(buffer) {\n      for (var i = 0; i < _bytes.length; i += 1) {\n        buffer.put(_bytes[i], 8);\n      }\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // qrKanji\n  //---------------------------------------------------------------------\n\n  var qrKanji = function(data) {\n\n    var _mode = QRMode.MODE_KANJI;\n    var _data = data;\n\n    var stringToBytes = qrcode.stringToBytesFuncs['SJIS'];\n    if (!stringToBytes) {\n      throw 'sjis not supported.';\n    }\n    !function(c, code) {\n      // self test for sjis support.\n      var test = stringToBytes(c);\n      if (test.length != 2 || ( (test[0] << 8) | test[1]) != code) {\n        throw 'sjis not supported.';\n      }\n    }('\\u53cb', 0x9746);\n\n    var _bytes = stringToBytes(data);\n\n    var _this = {};\n\n    _this.getMode = function() {\n      return _mode;\n    };\n\n    _this.getLength = function(buffer) {\n      return ~~(_bytes.length / 2);\n    };\n\n    _this.write = function(buffer) {\n\n      var data = _bytes;\n\n      var i = 0;\n\n      while (i + 1 < data.length) {\n\n        var c = ( (0xff & data[i]) << 8) | (0xff & data[i + 1]);\n\n        if (0x8140 <= c && c <= 0x9FFC) {\n          c -= 0x8140;\n        } else if (0xE040 <= c && c <= 0xEBBF) {\n          c -= 0xC140;\n        } else {\n          throw 'illegal char at ' + (i + 1) + '/' + c;\n        }\n\n        c = ( (c >>> 8) & 0xff) * 0xC0 + (c & 0xff);\n\n        buffer.put(c, 13);\n\n        i += 2;\n      }\n\n      if (i < data.length) {\n        throw 'illegal char at ' + (i + 1);\n      }\n    };\n\n    return _this;\n  };\n\n  //=====================================================================\n  // GIF Support etc.\n  //\n\n  //---------------------------------------------------------------------\n  // byteArrayOutputStream\n  //---------------------------------------------------------------------\n\n  var byteArrayOutputStream = function() {\n\n    var _bytes = [];\n\n    var _this = {};\n\n    _this.writeByte = function(b) {\n      _bytes.push(b & 0xff);\n    };\n\n    _this.writeShort = function(i) {\n      _this.writeByte(i);\n      _this.writeByte(i >>> 8);\n    };\n\n    _this.writeBytes = function(b, off, len) {\n      off = off || 0;\n      len = len || b.length;\n      for (var i = 0; i < len; i += 1) {\n        _this.writeByte(b[i + off]);\n      }\n    };\n\n    _this.writeString = function(s) {\n      for (var i = 0; i < s.length; i += 1) {\n        _this.writeByte(s.charCodeAt(i) );\n      }\n    };\n\n    _this.toByteArray = function() {\n      return _bytes;\n    };\n\n    _this.toString = function() {\n      var s = '';\n      s += '[';\n      for (var i = 0; i < _bytes.length; i += 1) {\n        if (i > 0) {\n          s += ',';\n        }\n        s += _bytes[i];\n      }\n      s += ']';\n      return s;\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // base64EncodeOutputStream\n  //---------------------------------------------------------------------\n\n  var base64EncodeOutputStream = function() {\n\n    var _buffer = 0;\n    var _buflen = 0;\n    var _length = 0;\n    var _base64 = '';\n\n    var _this = {};\n\n    var writeEncoded = function(b) {\n      _base64 += String.fromCharCode(encode(b & 0x3f) );\n    };\n\n    var encode = function(n) {\n      if (n < 0) {\n        // error.\n      } else if (n < 26) {\n        return 0x41 + n;\n      } else if (n < 52) {\n        return 0x61 + (n - 26);\n      } else if (n < 62) {\n        return 0x30 + (n - 52);\n      } else if (n == 62) {\n        return 0x2b;\n      } else if (n == 63) {\n        return 0x2f;\n      }\n      throw 'n:' + n;\n    };\n\n    _this.writeByte = function(n) {\n\n      _buffer = (_buffer << 8) | (n & 0xff);\n      _buflen += 8;\n      _length += 1;\n\n      while (_buflen >= 6) {\n        writeEncoded(_buffer >>> (_buflen - 6) );\n        _buflen -= 6;\n      }\n    };\n\n    _this.flush = function() {\n\n      if (_buflen > 0) {\n        writeEncoded(_buffer << (6 - _buflen) );\n        _buffer = 0;\n        _buflen = 0;\n      }\n\n      if (_length % 3 != 0) {\n        // padding\n        var padlen = 3 - _length % 3;\n        for (var i = 0; i < padlen; i += 1) {\n          _base64 += '=';\n        }\n      }\n    };\n\n    _this.toString = function() {\n      return _base64;\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // base64DecodeInputStream\n  //---------------------------------------------------------------------\n\n  var base64DecodeInputStream = function(str) {\n\n    var _str = str;\n    var _pos = 0;\n    var _buffer = 0;\n    var _buflen = 0;\n\n    var _this = {};\n\n    _this.read = function() {\n\n      while (_buflen < 8) {\n\n        if (_pos >= _str.length) {\n          if (_buflen == 0) {\n            return -1;\n          }\n          throw 'unexpected end of file./' + _buflen;\n        }\n\n        var c = _str.charAt(_pos);\n        _pos += 1;\n\n        if (c == '=') {\n          _buflen = 0;\n          return -1;\n        } else if (c.match(/^\\s$/) ) {\n          // ignore if whitespace.\n          continue;\n        }\n\n        _buffer = (_buffer << 6) | decode(c.charCodeAt(0) );\n        _buflen += 6;\n      }\n\n      var n = (_buffer >>> (_buflen - 8) ) & 0xff;\n      _buflen -= 8;\n      return n;\n    };\n\n    var decode = function(c) {\n      if (0x41 <= c && c <= 0x5a) {\n        return c - 0x41;\n      } else if (0x61 <= c && c <= 0x7a) {\n        return c - 0x61 + 26;\n      } else if (0x30 <= c && c <= 0x39) {\n        return c - 0x30 + 52;\n      } else if (c == 0x2b) {\n        return 62;\n      } else if (c == 0x2f) {\n        return 63;\n      } else {\n        throw 'c:' + c;\n      }\n    };\n\n    return _this;\n  };\n\n  //---------------------------------------------------------------------\n  // gifImage (B/W)\n  //---------------------------------------------------------------------\n\n  var gifImage = function(width, height) {\n\n    var _width = width;\n    var _height = height;\n    var _data = new Array(width * height);\n\n    var _this = {};\n\n    _this.setPixel = function(x, y, pixel) {\n      _data[y * _width + x] = pixel;\n    };\n\n    _this.write = function(out) {\n\n      //---------------------------------\n      // GIF Signature\n\n      out.writeString('GIF87a');\n\n      //---------------------------------\n      // Screen Descriptor\n\n      out.writeShort(_width);\n      out.writeShort(_height);\n\n      out.writeByte(0x80); // 2bit\n      out.writeByte(0);\n      out.writeByte(0);\n\n      //---------------------------------\n      // Global Color Map\n\n      // black\n      out.writeByte(0x00);\n      out.writeByte(0x00);\n      out.writeByte(0x00);\n\n      // white\n      out.writeByte(0xff);\n      out.writeByte(0xff);\n      out.writeByte(0xff);\n\n      //---------------------------------\n      // Image Descriptor\n\n      out.writeString(',');\n      out.writeShort(0);\n      out.writeShort(0);\n      out.writeShort(_width);\n      out.writeShort(_height);\n      out.writeByte(0);\n\n      //---------------------------------\n      // Local Color Map\n\n      //---------------------------------\n      // Raster Data\n\n      var lzwMinCodeSize = 2;\n      var raster = getLZWRaster(lzwMinCodeSize);\n\n      out.writeByte(lzwMinCodeSize);\n\n      var offset = 0;\n\n      while (raster.length - offset > 255) {\n        out.writeByte(255);\n        out.writeBytes(raster, offset, 255);\n        offset += 255;\n      }\n\n      out.writeByte(raster.length - offset);\n      out.writeBytes(raster, offset, raster.length - offset);\n      out.writeByte(0x00);\n\n      //---------------------------------\n      // GIF Terminator\n      out.writeString(';');\n    };\n\n    var bitOutputStream = function(out) {\n\n      var _out = out;\n      var _bitLength = 0;\n      var _bitBuffer = 0;\n\n      var _this = {};\n\n      _this.write = function(data, length) {\n\n        if ( (data >>> length) != 0) {\n          throw 'length over';\n        }\n\n        while (_bitLength + length >= 8) {\n          _out.writeByte(0xff & ( (data << _bitLength) | _bitBuffer) );\n          length -= (8 - _bitLength);\n          data >>>= (8 - _bitLength);\n          _bitBuffer = 0;\n          _bitLength = 0;\n        }\n\n        _bitBuffer = (data << _bitLength) | _bitBuffer;\n        _bitLength = _bitLength + length;\n      };\n\n      _this.flush = function() {\n        if (_bitLength > 0) {\n          _out.writeByte(_bitBuffer);\n        }\n      };\n\n      return _this;\n    };\n\n    var getLZWRaster = function(lzwMinCodeSize) {\n\n      var clearCode = 1 << lzwMinCodeSize;\n      var endCode = (1 << lzwMinCodeSize) + 1;\n      var bitLength = lzwMinCodeSize + 1;\n\n      // Setup LZWTable\n      var table = lzwTable();\n\n      for (var i = 0; i < clearCode; i += 1) {\n        table.add(String.fromCharCode(i) );\n      }\n      table.add(String.fromCharCode(clearCode) );\n      table.add(String.fromCharCode(endCode) );\n\n      var byteOut = byteArrayOutputStream();\n      var bitOut = bitOutputStream(byteOut);\n\n      // clear code\n      bitOut.write(clearCode, bitLength);\n\n      var dataIndex = 0;\n\n      var s = String.fromCharCode(_data[dataIndex]);\n      dataIndex += 1;\n\n      while (dataIndex < _data.length) {\n\n        var c = String.fromCharCode(_data[dataIndex]);\n        dataIndex += 1;\n\n        if (table.contains(s + c) ) {\n\n          s = s + c;\n\n        } else {\n\n          bitOut.write(table.indexOf(s), bitLength);\n\n          if (table.size() < 0xfff) {\n\n            if (table.size() == (1 << bitLength) ) {\n              bitLength += 1;\n            }\n\n            table.add(s + c);\n          }\n\n          s = c;\n        }\n      }\n\n      bitOut.write(table.indexOf(s), bitLength);\n\n      // end code\n      bitOut.write(endCode, bitLength);\n\n      bitOut.flush();\n\n      return byteOut.toByteArray();\n    };\n\n    var lzwTable = function() {\n\n      var _map = {};\n      var _size = 0;\n\n      var _this = {};\n\n      _this.add = function(key) {\n        if (_this.contains(key) ) {\n          throw 'dup key:' + key;\n        }\n        _map[key] = _size;\n        _size += 1;\n      };\n\n      _this.size = function() {\n        return _size;\n      };\n\n      _this.indexOf = function(key) {\n        return _map[key];\n      };\n\n      _this.contains = function(key) {\n        return typeof _map[key] != 'undefined';\n      };\n\n      return _this;\n    };\n\n    return _this;\n  };\n\n  var createDataURL = function(width, height, getPixel) {\n    var gif = gifImage(width, height);\n    for (var y = 0; y < height; y += 1) {\n      for (var x = 0; x < width; x += 1) {\n        gif.setPixel(x, y, getPixel(x, y) );\n      }\n    }\n\n    var b = byteArrayOutputStream();\n    gif.write(b);\n\n    var base64 = base64EncodeOutputStream();\n    var bytes = b.toByteArray();\n    for (var i = 0; i < bytes.length; i += 1) {\n      base64.writeByte(bytes[i]);\n    }\n    base64.flush();\n\n    return 'data:image/gif;base64,' + base64;\n  };\n\n  //---------------------------------------------------------------------\n  // returns qrcode function.\n\n  return qrcode;\n}();\n\n// multibyte support\n!function() {\n\n  qrcode.stringToBytesFuncs['UTF-8'] = function(s) {\n    // http://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array\n    function toUTF8Array(str) {\n      var utf8 = [];\n      for (var i=0; i < str.length; i++) {\n        var charcode = str.charCodeAt(i);\n        if (charcode < 0x80) utf8.push(charcode);\n        else if (charcode < 0x800) {\n          utf8.push(0xc0 | (charcode >> 6),\n              0x80 | (charcode & 0x3f));\n        }\n        else if (charcode < 0xd800 || charcode >= 0xe000) {\n          utf8.push(0xe0 | (charcode >> 12),\n              0x80 | ((charcode>>6) & 0x3f),\n              0x80 | (charcode & 0x3f));\n        }\n        // surrogate pair\n        else {\n          i++;\n          // UTF-16 encodes 0x10000-0x10FFFF by\n          // subtracting 0x10000 and splitting the\n          // 20 bits of 0x0-0xFFFFF into two halves\n          charcode = 0x10000 + (((charcode & 0x3ff)<<10)\n            | (str.charCodeAt(i) & 0x3ff));\n          utf8.push(0xf0 | (charcode >>18),\n              0x80 | ((charcode>>12) & 0x3f),\n              0x80 | ((charcode>>6) & 0x3f),\n              0x80 | (charcode & 0x3f));\n        }\n      }\n      return utf8;\n    }\n    return toUTF8Array(s);\n  };\n\n}();\n\n(function (factory) {\n  if (typeof define === 'function' && define.amd) {\n      define([], factory);\n  } else if (typeof exports === 'object') {\n      module.exports = factory();\n  }\n}(function () {\n    return qrcode;\n}));\n"+";return module.exports||qrcode"))({exports:{}},{}));var t=window.__wgQrLib(0,"M");return t.addData(e),t.make(),t.createSvgTag(4)}catch(a){return""}},buildClientConfig:function(){return window.WGClientConfig.build(this,false,window.prompt,customError)},buildRouterConfig:function(){return window.WGClientConfig.build(this,true,window.prompt,customError)},refreshClientQr:function(){try{if(this.tableForm.client_config)window.WGClientConfig.validateExport(this);this.tableForm.client_qr_svg=this.tableForm.client_config?this.makeQrSvg(this.tableForm.client_config):""}catch(e){this.tableForm.client_qr_svg=""}},copyClientConfig:function(){return window.WGClientConfig.copy(this,navigator.clipboard,null,customSuccess,customError)},importClientConfig:function(){window.WGPasteImport.open(this)},submitWgImport:function(){var e=this,n=!!e.wgSitePreview;return window.WGPasteImport.submit(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)},customSuccess).then(function(t){if(t&&!n)e.openClientEndpoint();return t})},saveForm:function(){
    var view=this,form=view.tableForm,edit=view.shouHint;
    if(view.wgIfaceBusy || !view.tableRowEditing)return false;
    if(window.WGClientConfig.keyBusy(view))return customError(tr("正在生成密钥，请稍候")),false;
    if(view.wgPlanBusy)return customError(tr("正在分配地址，请稍候")),false;
    if(edit && !view._ifaceTarget)return customError(tr("设备已被删除或更改，请返回列表并重新打开。")),false;
    view.wgIfaceBusy=true;view.wgIfaceNotice="";
    function current(){return !view._isDestroyed && view.tableRowEditing && view.tableForm===form;}
    var fields={name:form.name,local_address:form.local_address,local_listenport:form.local_listenport,interface:form.interface,
        local_privatekey:form.local_privatekey,local_publickey:form.local_publickey,mtu:form.mtu};
    return view.$validator.validateAll(fields).then(function(valid){
        if(!valid || !current() || window.WGClientConfig.keyBusy(view) || view.wgPlanBusy ||
            Object.keys(fields).some(function(key){return fields[key]!==form[key];}))return false;
        var submitted=Object.assign({},form,{local_listenport:Number(form.local_listenport)});
        if(edit)submitted.expected_rows=view._ifaceTarget;
        function finish(ok,failure){
            if(view._isDestroyed)return false;
            if(view.$refs.dtable)view.$refs.dtable.reload();
            return view.getInterfaceAndServiceStatus().then(function(rows){
                if(!current())return false;
                if(ok){
                    view.tableRowEditing=false;customSuccess(view.$t("common.saveSuccess"));return true;
                }
                var match=rows && rows.some(function(row){return window.WGPasteImport.sameInterface(row,submitted);});
                var known=window.WGI18n && failure && window.WGI18n.knownText(failure.ErrMsg);
                var outcome=window.WGI18n && window.WGI18n.interfaceOutcome(failure,submitted.name,edit);
                var sameName=rows && rows.some(function(row){return row.name===submitted.name;});
                if(outcome==="rolledBack" && !sameName){
                    view.wgIfaceNotice=known;
                }else if(outcome==="saved" && (!rows || match)){
                    view.tableRowEditing=false;
                    view.wgIfaceNotice=known;
                }else if(outcome){
                    view.tableRowEditing=false;
                    view.wgIfaceNotice=tr("接口保存结果尚未确认，请刷新列表核对后再操作。");
                }else if(match){
                    view.tableRowEditing=false;
                    view.wgIfaceNotice=tr("接口配置已保存，运行状态尚未确认。请验证实际连接。")+(known?" "+known:"");
                }else if(!rows || !failure || typeof failure.Result!=="number"){
                    view.tableRowEditing=false;
                    view.wgIfaceNotice=tr("接口保存结果尚未确认，请刷新列表核对后再操作。");
                }else{
                    view.wgIfaceNotice=known || tr("路由器未确认操作成功，请刷新接口列表后重试。");
                }
                return false;
            });
        }
        return view.$http.post(p.a.apiUrl,{func_name:"wireguard",action:edit?"iface_edit":"iface_add",param:copyObj("encode",submitted)},{timeout:60000}).then(function(reply){
            var body=reply && reply.data;
            return finish(!!body && body.Result===30000,body);
        },function(error){
            return finish(false,error && (error.data || (error.response && error.response.data) || error));
        });
    }).then(function(ok){view.wgIfaceBusy=false;return ok;},function(){view.wgIfaceBusy=false;return false;});
},saveForm1:function(){window.WGClientConfig.closePhoneCopy(this);var panel=this.$refs.hyrTunnel;try{if(panel)panel.parameters();window.WGClientConfig.validate(this)}catch(e){return customError(e.message),!1;}if(this.wgPlanBusy)return customError(tr("正在分配地址，请稍候")),!1;var e=this,f=this.tableForm,g=this.wgEndpointToken,k=this.shouHint,m=this.tableForm.interface;this.$validator.validateAll({interface:this.tableForm.interface,peer_publickey:this.tableForm.peer_publickey,preSharedKey:this.tableForm.preSharedKey,heartbeatInterval:this.tableForm.keepalive,allowips:this.tableForm.allowips}).then(function(t){if(!t||e.tableForm!==f||e.tableRowEditing1===!1||e.wgEndpointToken!==g||e.tableForm.interface!==m)return!1;var transport={};try{if(panel){transport=panel.parameters()}window.WGClientConfig.validate(e)}catch(t){return customError(t.message),!1;}var a=c()({},JSON.parse(n()(e.tableForm)),{allowips:[].concat(l()(new s.a(e.tableForm.allowips.split("\n")))).join(","),endpoint_port:e.tableForm.endpoint_port?1*e.tableForm.endpoint_port:"",local_listenport:e.tableForm.local_listenport?1*e.tableForm.local_listenport:"",out_mode:"auto",out_wans:"",out_balance:"failover"});Object.assign(a,transport);if(panel){panel.saving=true;panel.closeQr()}function current(){return e.tableRowEditing1&&e.tableForm===f&&e.wgEndpointToken===g&&e.tableForm.interface===m}function close(){e.tableRowEditing1=!1;window.WGClientConfig.cancel(e)}function failure(r){if(!panel||!current())return;panel.saving=false;var msg=r&&(r.ErrMsg||(r.data&&r.data.ErrMsg));panel.error=(window.WGI18n&&window.WGI18n.knownText(msg))||tr("隧道保存失败，请检查设备和连接设置。")}e.$http.post(p.a.apiUrl,{func_name:"wireguard",action:k?"edit":"add",param:copyObj("encode",(panel&&panel.commentEdit&&panel.commentEdit(a))||a)},{timeout:transport.wg_transport&&transport.wg_transport!=="native"?300000:60000}).then(function(t){if(!t||!t.data||t.data.Result!==30000){failure(t);return}customSuccess(e.$t("common.saveSuccess"));if(!current()||!panel||!transport.wg_transport||transport.wg_transport==="native"){e.$refs.dtable1.reload();if(current())close();return}panel.saving=false;return panel.saved(a).then(function(){e.$refs.dtable1.reload();if(current())panel.$nextTick(function(){if(panel.$el&&panel.$el.scrollIntoView)panel.$el.scrollIntoView({block:"center"})})})},failure)})},allocatePeerAddress:function(){var e=this;return window.WGAddressPlan.request(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)},"peer",true)},allocateIfaceAddress:function(){var e=this;return window.WGAddressPlan.request(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)},"iface",false)},newTableRow:function(){this.wgIfaceNotice="";var e=this;return window.WGAddressPlan.openIface(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)})},targetInter:function(){this.newTableRow(),this.tableRowEditing1=!1},newTableRow1:function(){var e=this,t=window.WGAddressPlan.openPeer(this,function(t){return e.$http.post(p.a.apiUrl,t)},function(t){return copyObj("encode",t)});return this.interfaces1.length?Promise.all([t,this.openClientEndpoint()]):t},editTableRow:function(e){if(Number(e.site_client)===1){var v=this;return window.WGPasteImport.managed(this,e,true,function(t){return v.$http.post(p.a.apiUrl,t)})}this._ifaceTarget=window.WGIdentityTable.interfaceTarget(e);this.wgIfaceNotice="";window.WGAddressPlan.preserve(this);this.tableForm=c()({},JSON.parse(n()(e))),this.shouHint=!0,this.tableRowEditing=!0},editTableRow1:function(e){if(Number(e.site_client)===1 || e.native_role==='site_client'){var v=this;return window.WGPasteImport.managed(this,e,false,function(t){return v.$http.post(p.a.apiUrl,t)})}window.WGAddressPlan.preserve(this);this.wgImportNote="",this.tableForm=c()({},JSON.parse(n()(e)),{allowips:e.allowips.replace(/,/g,"\n"),out_mode:"auto",out_wans:"",out_balance:"failover",client_config:"",client_qr_svg:""}),window.WGClientConfig.fields(this),this.shouHint=!0,this.tableRowEditing1=!0,this.openClientEndpoint()}}}},"11873":function(e,t,a){t=e.exports=a(759)(),t.push([e.i,"",""])},"12040":function(e,t,a){var i=a(11873);"string"==typeof i&&(i=[[e.i,i,""]]),i.locals&&(e.exports=i.locals);a(760)("096bbe76",i,!0)},"12282":function(e,t){e.exports={render:function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("div",{staticClass:"qaq3 wg-page"},[e.xEnterprise||2==e.oemSign?a("div",[window.WGPasteImport.render(e,e.$createElement),e.wgIfaceNotice?a("p",{staticClass:"error_tip",attrs:{role:"alert"}},[e._v(e.wgIfaceNotice)]):e._e(),a("div",{directives:[{name:"show",rawName:"v-show",value:!e.tableRowEditing&&!e.tableRowEditing1&&!e.wgImportOpen&&!e.wgManagedSite,expression:"!tableRowEditing&&!tableRowEditing1"}],staticClass:"main_section"},[a("sub-title-section",{attrs:{opturl:{helpUrl:"id=1264&Itemid=1897"},opt:{helpMessage:e.$t("helpTip.wireguardTip")}}}),e._v(" "),a("div",{staticClass:"wrapper row"},[a("div",{staticClass:"box clearfix"},[a("div",{staticClass:"title_h4 clearfix"},[a("h4",[e._v(e._s(e.$t("wire_guard.interfaceList")))])]),e._v(" "),a(window.WGIdentityTable(e),{key:"dtable-"+e.wgListRevision,ref:"dtable",attrs:{opt:e.tableOptions},on:{deleteRowSuccess:e.deleteRowSuccess,batchDeleteRowSuccess:e.deleteRowSuccess,toggleRowComplete:e.deleteRowSuccess,editTableRow:e.editTableRow,newTableRow:e.newTableRow,tableLoaded:function(t){e.globalBus.$emit("loadComplete")}}}),e._v(" "),a("div",{staticClass:"title_h4 clearfix",staticStyle:{"margin-top":"100px"}},[a("h4",[e._v(e._s(e.$t("wire_guard.tunnelList")))])]),e._v(" "),a(window.WGIdentityTable(e),{key:"dtable1-"+e.wgListRevision,ref:"dtable1",attrs:{opt:e.tableOptionsTunnel},on:{editTableRow:e.editTableRow1,newTableRow:e.newTableRow1,pasteImportConfig:e.importClientConfig,tableLoaded:function(t){e.globalBus.$emit("loadComplete")}}})],1)])],1),e._v(" "),e.tableRowEditing&&!e.wgImportOpen?a("div",{staticClass:"main_section_edit"},[e.wgPlanError?a("div",{staticClass:"line_edit"},[a("p",{staticClass:"error_tip",attrs:{role:"alert"}},[e._v(e.wgPlanError)]),a("button",{staticClass:"btn",attrs:{type:"button",disabled:e.wgPlanBusy||e.wgIfaceBusy},on:{click:e.allocateIfaceAddress}},[e._v(tr("重新分配地址"))])]):e._e(),a("div",{staticClass:"title_h3"},[a("h3",[e._v(e._s(e.tableForm.id?e.$t("common.edit"):e.$t("common.add")))]),e._v(" "),a("div",{staticClass:"helpService"},[a("a",{staticClass:"close_edit close_ico",attrs:{href:"javascript:void(0)"},on:{click:function(t){e.tableRowEditing=!1,window.WGClientConfig.cancel(e)}}},[e._v("×")])])]),e._v(" "),a("div",{staticClass:"wrapper clearfix row"},[a("div",{staticClass:"box"},[a("form",{on:{submit:function(t){t.preventDefault(),e.saveForm(t)}}},[a("fieldset",{staticClass:"box_block",staticStyle:{border:"0",padding:"0",margin:"0",minWidth:"0"},attrs:{disabled:e.wgIfaceBusy}},[a("div",{staticClass:"clearfix margin_phone col-lg-11 col-lg-offset-1 "},[a("div",{staticClass:"h40"}),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.name"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.name,expression:"tableForm.name"},{name:"validate",rawName:"v-validate",value:"required|wireguardName",expression:"'required|wireguardName'"}],staticClass:"inptText",attrs:{name:"name",type:"text",placeholder:"wg","data-vv-as":e.$t("wire_guard.name")},domProps:{value:e.tableForm.name},on:{input:function(t){t.target.composing||(e.tableForm.name=t.target.value)}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("name")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("name")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.localIP"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.local_address,expression:"tableForm.local_address"},{name:"validate",rawName:"v-validate",value:"required|IPMask",expression:"'required|IPMask'"}],staticClass:"inptText",attrs:{name:"local_address",type:"text","data-vv-as":e.$t("wire_guard.localIP")},domProps:{value:e.tableForm.local_address},on:{input:function(t){t.target.composing||(e.tableForm.local_address=t.target.value)}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[a("span",{staticClass:"remark margin-l-10"},[e._v("\n                                            "+e._s(e.$t("behavior.table_header_title.reaction"))+"\n                                        ")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("local_address")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("local_address")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.localpublicKey"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.local_publickey,expression:"tableForm.local_publickey"},{name:"validate",rawName:"v-validate",value:"required|filterSpecialChar2",expression:"'required|filterSpecialChar2'"}],staticClass:"inptText",attrs:{name:"localpublicKey","data-vv-as":e.$t("wire_guard.localpublicKey"),type:"text",autocomplete:"off",readonly:""},domProps:{value:e.tableForm.local_publickey},on:{input:function(t){t.target.composing||(e.tableForm.local_publickey=t.target.value)}}}),e._v(" "),a("em",[e._v("*")]),e._v(" "),a("a",{staticClass:"btn btn_blue btn_confirm",on:{click:function(t){e.getPrivateKey()}}},[e._v(e._s(e.$t("wire_guard.generateLocalKey")))])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("local_publicKey")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("localpublicKey")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.privatekey"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.local_privatekey,expression:"tableForm.local_privatekey"},{name:"validate",rawName:"v-validate",value:"required|filterSpecialChar2",expression:"'required|filterSpecialChar2'"}],staticClass:"inptText",attrs:{name:"local_privatekey","data-vv-as":e.$t("wire_guard.privatekey"),type:"text",autocomplete:"off",readonly:""},domProps:{value:e.tableForm.local_privatekey},on:{input:function(t){t.target.composing||(e.tableForm.local_privatekey=t.target.value)}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("local_privatekey")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("local_privatekey")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.Circuit"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("div",{staticClass:"search_list"},[a("select",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.interface,expression:"tableForm.interface"}],staticClass:"selects",attrs:{name:"interface"},on:{change:function(t){var a=Array.prototype.filter.call(t.target.options,function(e){return e.selected}).map(function(e){return"_value"in e?e._value:e.value});e.tableForm.interface=t.target.multiple?a:a[0]}}},[a("option",{attrs:{value:"auto"}},[e._v(e._s(e.$t("vpn.openVpnClient.auto")))]),e._v(" "),e._l(e.interfaces,function(t){return a("option",{domProps:{value:t[0]}},[e._v("\n                                                    "+e._s(t[0]+(t.length>1?"("+t[1]+")":""))+"\n                                                ")])})],2)])])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.listeningPort"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.local_listenport,expression:"tableForm.local_listenport"},{name:"validate",rawName:"v-validate",value:"required|numeric|between:1,65535",expression:"'required|numeric|between:1,65535'"}],staticClass:"inptText",attrs:{name:"listeningPort",type:"text","data-vv-as":e.$t("wire_guard.listeningPort")},domProps:{value:e.tableForm.local_listenport},on:{input:function(t){t.target.composing||(e.tableForm.local_listenport=t.target.value)}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("listeningPort")?a("p",{staticClass:"error_tip"},[e._v("\n                                            "+e._s(e.errors.first("listeningPort")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.mtu"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.mtu,expression:"tableForm.mtu"},{name:"validate",rawName:"v-validate",value:"required|numeric|between:576,9000",expression:"'required|numeric|between:576,9000'"}],staticClass:"inptText",attrs:{name:"mtu",type:"text","data-vv-as":e.$t("wire_guard.mtu")},domProps:{value:e.tableForm.mtu},on:{input:function(t){t.target.composing||(e.tableForm.mtu=t.target.value)}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("mtu")?a("p",{staticClass:"error_tip"},[e._v("\n                                            "+e._s(e.errors.first("mtu")))]):e._e()])]),e._v(" "),a("div",{staticClass:"h20"}),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_group"},[a("button",{staticClass:"btn btn_green btn_confirm",attrs:{type:"submit",name:"button"}},[e._v("\n                                            "+e._s(e.$t("common.save"))+"\n                                        ")]),e._v(" "),a("button",{staticClass:"btn btn_cancel margin-l-10",attrs:{type:"button"},on:{click:function(t){e.tableRowEditing=!1,window.WGClientConfig.cancel(e)}}},[e._v("\n                                            "+e._s(e.$t("common.cancel"))+"\n                                        ")])])])])])])])])]):e._e(),e._v(" "),e.tableRowEditing1&&!e.wgImportOpen?a("div",{staticClass:"main_section_edit"},[a("div",{staticClass:"title_h3"},[a("h3",[e._v(e._s(e.tableForm.id?e.$t("common.edit"):e.$t("common.add")))]),e._v(" "),a("div",{staticClass:"helpService"},[a("a",{staticClass:"close_edit close_ico",attrs:{href:"javascript:void(0)"},on:{click:function(t){e.tableRowEditing1=!1,window.WGClientConfig.cancel(e)}}},[e._v("×")])])]),e._v(" "),a("div",{staticClass:"wrapper clearfix row"},[a("div",{staticClass:"box"},[a("form",{on:{submit:function(t){t.preventDefault(),e.saveForm1(t)}}},[a("div",{staticClass:"box_block"},[a("div",{staticClass:"clearfix margin_phone col-lg-11 col-lg-offset-1 "},[a("div",{staticClass:"h40"}),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.oppositeIP"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.endpoint,expression:"tableForm.endpoint"}],staticClass:"inptText",attrs:{name:"oppositeIP",type:"text",placeholder:"","data-vv-as":e.$t("wire_guard.oppositeIP")},domProps:{value:e.tableForm.endpoint},on:{input:function(t){t.target.composing||(e.tableForm.endpoint=t.target.value)}}})]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("oppositeIP")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("oppositeIP")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.oppositePort"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.endpoint_port,expression:"tableForm.endpoint_port"},{name:"validate",rawName:"v-validate",value:"numeric|between:1,65535",expression:"'numeric|between:1,65535'"}],staticClass:"inptText",attrs:{name:"endpoint_port",type:"text","data-vv-as":e.$t("wire_guard.oppositePort"),autocomplete:"off"},domProps:{value:e.tableForm.endpoint_port},on:{input:function(t){t.target.composing||(e.tableForm.endpoint_port=t.target.value)}}})]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("endpoint_port")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("endpoint_port")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.name"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("div",{staticClass:"search_list"},[a("select",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.interface,expression:"tableForm.interface"},{name:"validate",rawName:"v-validate",value:"required",expression:"'required'"}],staticClass:"selects",attrs:{name:"interface"},on:{change:function(t){var a=Array.prototype.filter.call(t.target.options,function(e){return e.selected}).map(function(e){return"_value"in e?e._value:e.value});e.tableForm.interface=t.target.multiple?a:a[0],e.syncClientDnsFromInterface()}}},e._l(e.interfaces1,function(t){return a("option",{domProps:{value:t}},[e._v("\n                                                    "+e._s(t)+"\n                                                ")])}))]),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("a",{staticClass:"btn btn_blue btn_confirm",on:{click:function(t){e.targetInter()}}},[e._v(e._s(e.$t("common.add")+e.$t("wire_guard.name")))])]),e._v(" "),a(window.WGNativeTunnel,{key:"wg-device-editor",ref:"hyrTunnel",props:{apiUrl:e.tableOptions.requests.url,makeQrSvg:e.makeQrSvg,peerForm:e.tableForm,listenPort:(e.getIfaceRow()||{}).local_listenport,serverKey:(e.getIfaceRow()||{}).local_publickey,autoEndpoint:e.wgEndpointAuto},on:{"reload-list":function(){window.WGClientConfig.cancel(e);e.tableRowEditing1=false;e.$refs.dtable1.reload()},transport:function(t,n,s,pure){e.wgPureMode=!!pure;e.wgSiteMode=!!s;if(e.wgShowNative&&!n)window.WGClientConfig.invalidate(e);if(t&&!e.wgTunnelOn){e.wgEndpointToken++;e.wgEndpointBusy=false}e.wgTunnelOn=t;e.wgShowNative=!!n},bound:function(t){e.$set(e.tableForm,"id",t);e.shouHint=true}}}),a("div",{staticClass:"line_edit",style:e.wgPureMode&&e.tableForm.peer_publickey&&e.tableForm.peer_privatekey?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.peerpublicKey"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"validate",rawName:"v-validate",value:"required",expression:"'required'"},{name:"model",rawName:"v-model",value:e.tableForm.peer_publickey,expression:"tableForm.peer_publickey"}],staticClass:"inptText",attrs:{name:"peer_publickey","data-vv-as":e.$t("wire_guard.peerpublicKey"),type:"text"},domProps:{value:e.tableForm.peer_publickey},on:{input:function(t){t.target.composing||(e.tableForm.peer_publickey=t.target.value)}}}),e._v(" "),a("em",[e._v("*")]),e._v(" "),a("a",{staticClass:"btn btn_blue btn_confirm",on:{click:function(t){e.getPeerKey()}}},[e._v(tr("生成对端密钥"))])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("peer_publickey")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("peer_publickey")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode&&e.tableForm.peer_publickey&&e.tableForm.peer_privatekey?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(tr("对端私钥："))]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.peer_privatekey,expression:"tableForm.peer_privatekey"}],staticClass:"inptText",attrs:{name:"peer_privatekey",type:"text",autocomplete:"off",placeholder:tr("自动生成，用于客户端配置/二维码")},domProps:{value:e.tableForm.peer_privatekey},on:{input:function(t){t.target.composing||(e.tableForm.peer_privatekey=t.target.value,e.tableForm.client_config="",e.tableForm.client_qr_svg="")}}})])]),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.preSharedKey"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.presharedkey,expression:"tableForm.presharedkey"},{name:"validate",rawName:"v-validate",value:"filterSpecialChar2|strLenBetween:1,64",expression:"'filterSpecialChar2|strLenBetween:1,64'"}],staticClass:"inptText",attrs:{name:"preSharedKey",type:"text","data-vv-as":e.$t("wire_guard.preSharedKey"),autocomplete:"off"},domProps:{value:e.tableForm.presharedkey},on:{input:function(t){t.target.composing||(e.tableForm.presharedkey=t.target.value,window.WGClientConfig.invalidate(e))}}})]),e._v(" "),a("a",{staticClass:"btn btn_blue btn_confirm",on:{click:function(t){e.getShareKey()}}},[e._v(e._s(e.$t("wire_guard.generateSharedKey")))]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("preSharedKey")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("preSharedKey")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.heartbeatInterval"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.keepalive,expression:"tableForm.keepalive"},{name:"validate",rawName:"v-validate",value:"required|numeric|between:0,500",expression:"'required|numeric|between:0,500'"}],staticClass:"inptText w120",attrs:{name:"heartbeatInterval",type:"text","data-vv-as":e.$t("wire_guard.heartbeatInterval")},domProps:{value:e.tableForm.keepalive},on:{input:function(t){t.target.composing||(e.tableForm.keepalive=t.target.value,window.WGClientConfig.invalidate(e))}}}),e._v("\n                                        "+e._s(e.$t("common.second"))+"\n                                        "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[a("span",{staticClass:"remark margin-l-10"},[e._v("\n                                            "+e._s(e.$t("behavior.table_header_title.head_pool"))+"\n                                        ")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("heartbeatInterval")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("heartbeatInterval")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("wire_guard.allowTargetnetworkSegments"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("textarea",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.allowips,expression:"tableForm.allowips"},{name:"validate",rawName:"v-validate",value:"required|ipOrMaskList",expression:"'required|ipOrMaskList'"}],staticClass:"inptText",attrs:{name:"allowips",rows:"","data-vv-as":e.$t("wire_guard.allowTargetnetworkSegments"),placeholder:e.$t("vpn.openVpnClient.route_format")},domProps:{value:e.tableForm.allowips},on:{input:function(t){t.target.composing||(e.tableForm.allowips=t.target.value,e.tableForm.client_config="",e.tableForm.client_qr_svg="")}}}),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("allowips")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("allowips")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("common.comment"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.comment,expression:"tableForm.comment"}],staticClass:"inptText",attrs:{name:"comment","data-vv-as":e.$t("common.comment"),type:"text"},domProps:{value:e.tableForm.comment},on:{input:function(t){t.target.composing||(e.tableForm.comment=t.target.value)}}})]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("comment")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("comment")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit",style:e.wgPureMode?{display:"none"}:null},[a("div",{staticClass:"input_tit"},[e._v(tr("客户端DNS："))]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.client_dns,expression:"tableForm.client_dns"}],staticClass:"inptText",attrs:{name:"client_dns",type:"text",placeholder:tr("例如 223.5.5.5,8.8.8.8")},domProps:{value:e.tableForm.client_dns},on:{input:function(t){t.target.composing||(e.tableForm.client_dns=t.target.value,e.tableForm.client_config="",e.tableForm.client_qr_svg="")}}})])]),e._v(" "),window.WGAddressPlan.render(e,e.$createElement),window.WGClientConfig.render(e,e.$createElement),!e.wgShowNative?e._e():a("div",{staticClass:"wg-native-exports"},[window.WGSingBox.render(e,e.$createElement,window.WGClientConfig,customError,customSuccess),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(tr("客户端配置："))]),e._v(" "),a("div",{staticClass:"input_group wg-client-actions"},[a("button",{staticClass:"btn btn_blue",attrs:{type:"button"},on:{click:function(t){e.buildClientConfig()}}},[e._v(tr("生成配置/二维码"))]),e._v(" "),a("button",{staticClass:"btn",attrs:{type:"button"},on:{click:function(t){return e.copyClientConfig()}}},[e._v(tr("复制 WG 配置"))]),e._v(" "),a("button",{staticClass:"btn",attrs:{type:"button"},on:{click:function(t){e.buildRouterConfig()}}},[e._v(tr("生成iKuai组网配置"))]),e._v(" "),a("button",{staticClass:"btn",attrs:{type:"button"},on:{click:function(t){e.importClientConfig()}}},[e._v(tr("粘贴导入配置"))])])]),e._v(" "),e.wgImportNote?a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(tr("导入结果："))]),a("div",{staticClass:"input_group"},[a("p",{staticClass:"note",attrs:{role:"status"}},[e._v(e.wgImportNote)])])]):e._e(),e._v(" "),window.WGClientConfig.renderManualCopy(e,e.$createElement,"wg")||e._e(),e.tableForm.client_config&&!(e.wgManualCopy&&e.wgManualCopy.format==="wg")?a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(tr("配置内容："))]),e._v(" "),a("div",{staticClass:"input_group"},[a("textarea",{staticClass:"inptText",attrs:{rows:"10"},domProps:{value:e.tableForm.client_config},on:{input:function(t){t.target.composing||(e.tableForm.client_config=t.target.value,e.refreshClientQr())}}})])]):e._e(),e._v(" "),e.tableForm.client_qr_svg&&window.WGClientConfig.exportMatches(e)?a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(tr("二维码："))]),e._v(" "),a("div",{staticClass:"input_group",domProps:{innerHTML:e.tableForm.client_qr_svg}})]):e._e()]),e._v(" "),a("div",{staticClass:"h20"}),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_group"},[a("button",{staticClass:"btn btn_green btn_confirm",attrs:{type:"submit",name:"button"}},[e._v("\n                                            "+e._s(e.$t("common.save"))+"\n                                        ")]),e._v(" "),a("button",{staticClass:"btn btn_cancel margin-l-10",attrs:{type:"button"},on:{click:function(t){e.tableRowEditing1=!1,window.WGClientConfig.cancel(e)}}},[e._v("\n                                            "+e._s(e.$t("common.cancel"))+"\n                                        ")])])])])])])])])]):e._e()]):a("div",{staticClass:"main_section"},[a("sub-title-section",{attrs:{opturl:{helpUrl:"id=1264&Itemid=1897"},opt:{helpMessage:e.$t("helpTip.wireguardTip")}}}),e._v(" "),a("div",{staticStyle:{width:"100%","text-align":"center","line-height":"150%","margin-top":"20%","font-size":"14px"}},[a("i",{staticClass:"ico-mark"}),e._v(e._s(e.$t("common.xEnterprise_2"))+"\n        ")])],1)])},staticRenderFns:[]}},"10134":function(t,e,n){"use strict";var r=n(163)(!0);n(10179)(String,"String",function(t){this._t=String(t),this._i=0},function(){var t,e=this._t,n=this._i;return n>=e.length?{value:void 0,done:!0}:(t=r(e,n),this._i+=t.length,{value:t,done:!1})})},"10360":function(t,e,n){t.exports={default:n(10621),__esModule:!0}},"10179":function(t,e,n){"use strict";var r=n(94),i=n(32),o=n(275),a=n(20),s=n(73),u=n(637),c=n(95),l=n(643),f=n(17)("iterator"),h=!([].keys&&"next"in[].keys()),d=function(){return this};t.exports=function(t,e,n,p,v,g,m){u(n,e,p);var y,_,x,b=function(t){if(!h&&t in k)return k[t];switch(t){case"keys":case"values":return function(){return new n(this,t)}}return function(){return new n(this,t)}},w=e+" Iterator",M="values"==v,S=!1,k=t.prototype,C=k[f]||k["@@iterator"]||v&&k[v],D=C||b(v),T=v?M?b("entries"):D:void 0,A="Array"==e?k.entries||C:C;if(A&&(x=l(A.call(new t)))!==Object.prototype&&x.next&&(c(x,w,!0),r||"function"==typeof x[f]||a(x,f,d)),M&&C&&"values"!==C.name&&(S=!0,D=function(){return C.call(this)}),r&&!m||!h&&!S&&k[f]||a(k,f,D),s[e]=D,s[w]=d,v)if(y={values:M?D:b("values"),keys:g?D:b("keys"),entries:T},m)for(_ in y)_ in k||o(k,_,y[_]);else i(i.P+i.F*(h||S),e,y);return y}},"10621":function(t,e,n){n(191),n(10134),n(10137),n(10651),n(660),n(659),n(658),t.exports=n(16).Set},"10137":function(t,e,n){n(10647);for(var r=n(3),i=n(20),o=n(73),a=n(17)("toStringTag"),s="CSSRuleList,CSSStyleDeclaration,CSSValueList,ClientRectList,DOMRectList,DOMStringList,DOMTokenList,DataTransferItemList,FileList,HTMLAllCollection,HTMLCollection,HTMLFormElement,HTMLSelectElement,MediaList,MimeTypeArray,NamedNodeMap,NodeList,PaintRequestList,Plugin,PluginArray,SVGLengthList,SVGNumberList,SVGPathSegList,SVGPointList,SVGStringList,SVGTransformList,SourceBufferList,StyleSheetList,TextTrackCueList,TextTrackList,TouchList".split(","),u=0;u<s.length;u++){var c=s[u],l=r[c],f=l&&l.prototype;f&&!f[a]&&i(f,a,c),o[c]=o.Array}},"10651":function(t,e,n){"use strict";var r=n(10630),i=n(76);t.exports=n(634)("Set",function(t){return function(){return t(this,arguments.length>0?arguments[0]:void 0)}},{add:function(t){return r.def(i(this,"Set"),t=0===t?0:t,t)}},r)},"10647":function(t,e,n){"use strict";var r=n(626),i=n(246),o=n(73),a=n(29);t.exports=n(10179)(Array,"Array",function(t,e){this._t=a(t),this._i=0,this._k=e},function(){var t=this._t,e=this._k,n=this._i++;return!t||n>=t.length?(this._t=void 0,i(1)):"keys"==e?i(0,n):"values"==e?i(0,t[n]):i(0,[n,t[n]])},"values"),o.Arguments=o.Array,r("keys"),r("values"),r("entries")},"10630":function(t,e,n){"use strict";var r=n(8).f,i=n(182),o=n(184),a=n(34),s=n(55),u=n(93),c=n(10179),l=n(246),f=n(276),h=n(7),d=n(50).fastKey,p=n(76),v=h?"_s":"size",g=function(t,e){var n,r=d(e);if("F"!==r)return t._i[r];for(n=t._f;n;n=n.n)if(n.k==e)return n};t.exports={getConstructor:function(t,e,n,c){var l=t(function(t,r){s(t,l,e,"_i"),t._t=e,t._i=i(null),t._f=void 0,t._l=void 0,t[v]=0,void 0!=r&&u(r,n,t[c],t)});return o(l.prototype,{clear:function(){for(var t=p(this,e),n=t._i,r=t._f;r;r=r.n)r.r=!0,r.p&&(r.p=r.p.n=void 0),delete n[r.i];t._f=t._l=void 0,t[v]=0},delete:function(t){var n=p(this,e),r=g(n,t);if(r){var i=r.n,o=r.p;delete n._i[r.i],r.r=!0,o&&(o.n=i),i&&(i.p=o),n._f==r&&(n._f=i),n._l==r&&(n._l=o),n[v]--}return!!r},forEach:function(t){p(this,e);for(var n,r=a(t,arguments.length>1?arguments[1]:void 0,3);n=n?n.n:this._f;)for(r(n.v,n.k,this);n&&n.r;)n=n.p},has:function(t){return!!g(p(this,e),t)}}),h&&r(l.prototype,"size",{get:function(){return p(this,e)[v]}}),l},def:function(t,e,n){var r,i,o=g(t,e);return o?o.v=n:(t._l=o={i:i=d(e,!0),k:e,v:n,p:r=t._l,n:void 0,r:!1},t._f||(t._f=o),r&&(r.n=o),t[v]++,"F"!==i&&(t._i[i]=o)),t},getEntry:g,setStrong:function(t,e,n){c(t,e,function(t,n){this._t=p(t,e),this._k=n,this._l=void 0},function(){for(var t=this,e=t._k,n=t._l;n&&n.r;)n=n.p;return t._t&&(t._l=n=n?n.n:t._t._f)?"keys"==e?l(0,n.k):"values"==e?l(0,n.v):l(0,[n.k,n.v]):(t._t=void 0,l(1))},n?"entries":"values",!n,!0),f(e)}}}});

}(typeof customError==='function'?customError:function(s){return window.customError(s);}));
