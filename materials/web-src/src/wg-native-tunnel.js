/* Device transport and role are committed with the native WG add/edit transaction. */
(function (root) {
    'use strict';
    function tr(s) { return root.WGI18n ? root.WGI18n.text(s) : s; }
    var validId = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
    var pinPattern=/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
    function isPure(method) { return method==='pure_hy2'; }
    var validName = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;
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
                resume:false,settingsOpen:false,stale:false};
        },
        computed:{
            selectedInterface:function(){return this.peerForm.interface;},
            unchanged:function () {
                var v=this;
                return v.revision>0 && fields.every(function(k,i){return v._initialFields[i]===v.peerForm[k];});
            },
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
                        member.addr_mode!==identity.addrMode || (identity.resume && member.paused) || (identity.addrMode!=='shared' && member.public_ip!==identity.publicIP))) return false;
                    v.member=member;
                    v.service={public_ip:hy.public_ip,core_storage:hy.core_storage,core_format:hy.core_format};
                    v.draft={public_ip:''};
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
                if(method==='native') this.resume=false;
                if(existing) {
                    this.mode=existing.mode;this.portMode=existing.port_mode;this.addrMode=existing.addr_mode;
                    this.draft.public_ip=existing.addr_mode==='shared'?this.service.public_ip:existing.public_ip;
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
                try {root.WGClientConfig.endpointIP(f.client_endpoint);} catch(e) {this.$set(f,'client_endpoint',address);}
                send.exit_peer=this.mode==='access'?'no':'yes';
                return send;
            },
            commentEdit:function (payload) {
                var f=this.peerForm,m=this.member;
                if(!f.id || this.selected || this.resume || (f.comment||'')===this._openedComment || editInputs(f)!==this._openedInputs) return null;
                if(m && (m.port_mode!==this.portMode || m.addr_mode!==this.addrMode ||
                    (this.addrMode!=='shared' && m.public_ip!==payload.hyr_public_ip))) return null;
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
                if(!(native?v.nativeRouterReady:v.exportReady) || (v.busy && !(copying && v.phoneKind && v.phoneKind!==qrRequested)))return false;
                if(copying && v.phoneKind===qrRequested && v.phoneText)return v.copyShownPhone();
                v.closeQr();
                if(copying)v.phoneKind=qrRequested;
                var pure=isPure(v.transport);
                var name=native?'':'HY2-'+member.name, token=++v.serial;
                v.busy=true;v._exportPending=true;v.error='';v.notice='';
                function current(){return !v._isDestroyed && !document.hidden && v.serial===token && v.peerForm===form &&
                    v.member===member && (native?v.nativeRouterReady && v.serverKey===serverKey && v.listenPort===listenPort:v.exportReady);}
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
                            (pure?matchesPureEndpoint(v,preview.server,preview.port):
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
                if(pure)body.push(h('p',{staticClass:'note'},[tr('纯 HY2 用于 IPv4 TCP／UDP 上网。访问路由器后台或两端内网请使用 WG。')]));
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
                        button(tr('复制到路由器'),function(){return v.exportMember('router');})
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
