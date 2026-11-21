/* local-only WG configuration parsing and the native multi-line import view. */
(function (root, factory) {
    var api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.WGPasteImport = api;
}(this, function () {
    'use strict';
 function tr(s){return typeof window!=='undefined'&&window.WGI18n?window.WGI18n.text(s):s;}
    function fail(message) { throw new Error(message); }
    function key(value, label, optional) {
        if (!value && optional) return '';
        if (!/^[A-Za-z0-9+/]{43}=$/.test(value || '')) fail(label + tr(' 格式不正确，请粘贴完整配置。'));
        return value;
    }
    function ipv4(value, cidr) {
        var parts = value.split('/'), octets = parts[0].split('.');
        if (parts.length > 2 || octets.length !== 4) return false;
        if (!octets.every(function (x) { return /^\d{1,3}$/.test(x) && +x <= 255; })) return false;
        return parts.length === 2 ? /^\d{1,2}$/.test(parts[1]) && +parts[1] <= 32 : !cidr;
    }
    function number(value, fallback, min, max, label) {
        if (value === undefined || value === '') return fallback;
        if (!/^\d+$/.test(value) || +value < min || +value > max) fail(label + tr(' 超出有效范围。'));
        return +value;
    }
    function clientHelper() {
        return typeof module==='object' && module.exports ? require('./wg-client-config.js') : window.WGClientConfig;
    }
    // The native Action gateway accepts the JSON bundle as lowercase hexadecimal bytes.
    function siteHex(bundle) {
        var bytes=unescape(encodeURIComponent(JSON.stringify(bundle)));
        if(bytes.length>16384)fail(tr('配置过长，请每次导入一份接口及一个隧道。'));
        var encoded='';
        for(var i=0;i<bytes.length;i++)encoded+=('0'+bytes.charCodeAt(i).toString(16)).slice(-2);
        return encoded;
    }
    function validateSite(bundle) {
        function fields(o,names){return o && typeof o==='object' && !Array.isArray(o) && Object.keys(o).every(function(k){return names.indexOf(k)>=0;});}
        function validKey(k){return typeof k==='string' && /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(k);}
        function port(n) {return Number.isInteger(n) && n>=1 && n<=65535;}
        function credential(s){return typeof s==='string' && /^[0-9a-f]{64}$/.test(s);}
        if(bundle && bundle.format==='nativerouting-pure-hy2-device'){
            var carrier=bundle.transport;
            if(bundle.purpose==='both' || bundle.purpose==='lend')
                fail(tr('纯 Hysteria 2 仅支持让这台设备连接路由器上网，请从对端重新导出'));
            if(bundle.version!==1 || bundle.purpose!=='access' ||
                !fields(bundle,['format','version','purpose','transport']) ||
                !fields(carrier,['server','server_port','certificate_public_key_sha256','password']) ||
                typeof carrier.server!=='string' || !ipv4(carrier.server,false) || carrier.server.indexOf('/')>=0 ||
                carrier.server.split('.').some(function(o){return String(+o)!==o;}) || /^(?:0\.|127\.|169\.254\.)/.test(carrier.server) || +carrier.server.split('.')[0]>=224 ||
                !port(carrier.server_port) || !validKey(carrier.certificate_public_key_sha256) || !credential(carrier.password))
                fail(tr('组网配置字段不完整或无效，请从对端重新复制。'));
            return {transport:'pure_hy2',purpose:'access',server:carrier.server,port:carrier.server_port};
        }
        if(bundle && bundle.format==='nativerouting-hy2-wg-site')
            fail(tr('此配置使用已停用的 HY2 承载 WG，请从对端重新导出原生 WG 或纯 HY2 配置。'));
        if(!bundle || bundle.format!=='nativerouting-wg-device' || bundle.version!==2)
            fail(tr('请粘贴对端 NativeRouting 路由器导出的组网配置。手机 JSON 请在 sing-box 中导入。'));
        var t=bundle.transport, w=bundle.wireguard, purpose=bundle.purpose;
        function endpoint(host){
            if(typeof host!=='string' || host.length>253 || host.indexOf('/')>=0)return false;
            if(ipv4(host,false))return true;
            return host.indexOf('.')>=0 && !/^[0-9.]+$/.test(host) && host.split('.').every(function(part){
                return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(part);
            });
        }
        if(!fields(bundle,['format','version','transport','wireguard','purpose']) ||
            ['access','lend','both'].indexOf(purpose)<0 || !fields(t,['server','server_port']) ||
            !fields(w,['address','peer_address','private_key','public_key','preshared_key','mtu','keepalive']) ||
            !endpoint(t.server) || !port(t.server_port) ||
            !validKey(w.private_key) || !validKey(w.public_key) ||
            (w.preshared_key!==undefined && !validKey(w.preshared_key)) ||
            typeof w.address!=='string' || !ipv4(w.address,true) || !/\/32$/.test(w.address) ||
            typeof w.peer_address!=='string' || !ipv4(w.peer_address,true) || !/\/32$/.test(w.peer_address) ||
            w.address.split('/')[0]===w.peer_address.split('/')[0] ||
            (w.mtu!==undefined && (!Number.isInteger(w.mtu) || w.mtu<576 || w.mtu>9000)) ||
            !(port(w.keepalive) || (w.keepalive===0 && (purpose==='access' || purpose==='both'))))
            fail(tr('组网配置字段不完整或无效，请从对端重新复制。'));
        if(t.server===w.address.split('/')[0] || t.server===w.peer_address.split('/')[0])fail(tr('WG 入口地址与隧道路由冲突'));
        return {transport:'native',purpose:purpose,server:t.server,port:t.server_port};
    }
    function parse(text) {
        if (!text || !text.trim()) fail(tr('请粘贴 WireGuard 配置。'));
        if (text.length > 65536) fail(tr('配置过长，请每次导入一份接口及一个隧道。'));
        if(text.trim().charAt(0)==='{') {
            var bundle;
            try {bundle=JSON.parse(text.trim());} catch(e){fail(tr('JSON 格式无效，请粘贴完整组网配置。'));}
            return {bundle:bundle,preview:validateSite(bundle)};
        }
        var data = {interface: {}, peer: {}}, section = '', seen = {}, notes = [], site = {};
        text.replace(/^\uFEFF/, '').split(/\r\n|\r|\n/).forEach(function (line, index) {
            var sm = /^\s*#\s*iKuai-Site-(Local|Remote)\s*=\s*(.*?)\s*$/.exec(line);
            if(sm){var sk=sm[1].toLowerCase();if(Object.prototype.hasOwnProperty.call(site,sk))fail(tr('互访网段标记重复'));site[sk]=sm[2];return;}
            line = line.replace(/[#;].*$/, '').trim();
            if (!line) return;
            var match = /^\[\s*(interface|peer)\s*\]$/i.exec(line);
            if (match) {
                section = match[1].toLowerCase();
                if (seen[section]) fail(tr('每次只支持一个 [Interface] 和一个 [Peer]，请拆分后导入。'));
                seen[section] = true; return;
            }
            match = /^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$/.exec(line);
            if (!section || !match) fail(tr('第 ') + (index + 1) + tr(' 行格式不正确，请保留配置换行。'));
            var name = match[1].toLowerCase(), value = match[2], values = data[section];
            if (Object.prototype.hasOwnProperty.call(values, name)) {
                if (name === 'address' || name === 'allowedips' || name === 'dns') values[name] += ',' + value;
                else fail(tr('第 ') + (index + 1) + tr(' 行字段重复，请检查配置。'));
            } else values[name] = value;
        });
        var hasSite=Object.keys(site).length>0;
        if(hasSite){var helper=clientHelper();if(!helper)fail(tr('页面组件尚未就绪，请刷新后重试'));var normalized=helper.siteFields(site.local,site.remote);site.local=normalized.local.join(',');site.remote=normalized.remote.join(',');}
        if (!seen.peer) fail(tr('缺少 [Peer] 段，未创建接口。'));
        var local = data.interface, peer = data.peer, result = {full: !!seen.interface, notes: notes};
        result.peer = {peer_publickey: key(peer.publickey, tr('对端 PublicKey')), presharedkey: key(peer.presharedkey, 'PresharedKey', true), endpoint: '', endpoint_port: '', keepalive: number(peer.persistentkeepalive, 0, 0, 65535, 'PersistentKeepalive'), client_dns: ''};
        if (!peer.allowedips) fail(tr('缺少 AllowedIPs，未创建接口。'));
        function v4List(value, label, requiredPrefix) {
            var out = [], skipped = false;
            value.split(',').forEach(function (item) {
                item = item.trim();
                if (item.indexOf(':') >= 0 && /^[0-9a-fA-F:.]+(?:\/\d{1,3})?$/.test(item)) { skipped = true; return; }
                if (!ipv4(item, requiredPrefix)) fail(label + tr(' 必须包含有效的 IPv4 地址或网段。'));
                if (out.indexOf(item) < 0) out.push(item);
            });
            if (!out.length) fail(label + tr(' 未包含 IPv4；当前版本不支持导入纯 IPv6 隧道。'));
            if (skipped) notes.push(label + tr(' 中的 IPv6 项不会导入，当前版本仅配置 IPv4。'));
            return out;
        }
        result.peer.site_local=site.local||'';result.peer.site_remote=site.remote||'';
        result.peer.allowips = v4List(peer.allowedips, 'AllowedIPs', false).join('\n');
        if (peer.endpoint) {
            var ep = /^([A-Za-z0-9][A-Za-z0-9.-]*):(\d+)$/.exec(peer.endpoint);
            if (!ep) fail(tr('Endpoint 请使用 IPv4 或域名:端口，当前不支持 IPv6 端点。'));
            result.peer.endpoint = ep[1];
            result.peer.endpoint_port = number(ep[2], '', 1, 65535, tr('Endpoint 端口'));
        }
        if (result.full) {
            if (!local.privatekey || !local.address) fail(tr('[Interface] 缺少 PrivateKey 或 Address，未创建接口。'));
            var addresses = v4List(local.address, 'Address', true);
            if (addresses.length !== 1) fail(tr('当前接口只支持一个 IPv4 本地地址，请调整 Address。'));
            result.local = {local_privatekey: key(local.privatekey, 'PrivateKey'), local_address: addresses[0], mtu: number(local.mtu, 1420, 576, 9000, 'MTU'), local_listenport: number(local.listenport, null, 1, 65535, 'ListenPort')};
            result.peer.client_dns = local.dns || '';
            if (local.preup || local.postup || local.predown || local.postdown || local.table || local.saveconfig) notes.push(tr('接口脚本、Table 和 SaveConfig 不会执行；路由仍由爱快分流设置管理。'));
        }
        return result;
    }
    function open(view) {
        if (view.wgImportBusy) return;
        view.wgImportText = ''; view.wgImportError = ''; view.wgImportPending = null; view.wgSitePreview=null;
        view.wgImportFromPeer = !!view.tableRowEditing1; view.wgImportOpen = true;
        view.$nextTick(function () { if (view.$refs.wgImportText) view.$refs.wgImportText.focus(); });
    }
    function close(view) {
        if (view.wgImportBusy) return;
        view.wgImportOpen = false; view.wgImportText = ''; view.wgImportError = ''; view.wgSitePreview=null;
    }
    function updatedTables(view, read) {
        var grids=['dtable1','dtable'].map(function(ref){
            var t=view.$refs[ref];
            if(!t || !t.opt || !t.paginationOptions)return null;
            var o=t.opt.requests,page=t.paginationOptions.currentPage||1,size=t.paginationOptions.rowsPerPage;
            var params=Object.assign({},o.param,{ORDER_BY:t.orderBy || o.param.ORDER_BY || '',ORDER:t.sortOrder || o.param.ORDER || ''});
            params.limit=o.param.limitSet===undefined?((page-1)*size)+','+size:o.param.limitSet;
            var alias=o.returnFieldAlias || {};
            return {ref:ref,options:o,disableLoad:o.disableLoad,page:page,size:size,orderBy:t.orderBy,sortOrder:t.sortOrder,
                params:params,data:alias.data || 'data',total:alias.total || 'total'};
        }).filter(Boolean);
        function snapshot(grid,attempt){
            return read(grid.params).then(function(response){
                var data=response.data.Data;
                if(!data || !Array.isArray(data[grid.data]) || !Number.isFinite(Number(data[grid.total])))throw Error();
                grid.rows=data[grid.data];grid.count=Number(data[grid.total]);
                grid.time=Number((response.headers || {})['x-timestamp']);
            }).catch(function(error){
                if(attempt>=2 || view._isDestroyed)throw error;
                return new Promise(function(resolve){setTimeout(resolve,250*(attempt+1));}).then(function(){return snapshot(grid,attempt+1);});
            });
        }
        // Each native grid can have different filters, sort order and page size.
        // Read sequentially; a broken connection is retried only for the read.
        return grids.reduce(function(previous,grid){
            return previous.then(function(){return snapshot(grid,0);});
        },Promise.resolve()).then(function(){
            if(view._isDestroyed)return;
            grids.forEach(function(grid){grid.options.disableLoad=true;});
            view.wgListRevision=(view.wgListRevision || 0)+1;
            if(!grids.length)return;
            return new Promise(function(resolve){
                view.$nextTick(function(){
                    grids.forEach(function(grid){
                        grid.options.disableLoad=grid.disableLoad;
                        var t=view.$refs[grid.ref];if(!t)return;
                        t.orderBy=grid.orderBy;t.sortOrder=grid.sortOrder;t.xTimestamp=grid.time;
                        var pages=t.paginationOptions;
                        pages.rowsPerPage=grid.size;pages.currentPage=grid.page;pages.totalRows=grid.count;
                        pages.totalPages=Math.ceil(grid.count/grid.size);
                        var rows=typeof copyAry==='function'?copyAry('decode',grid.rows):grid.rows;
                        t.customLoadData(rows);
                        t.$refs.dpagination.changeJumpPageNum(grid.page);
                        t.$refs.dpagination.changeCurrent((grid.page-1)*grid.size,rows.length);
                        t.$emit('tableLoaded',rows);
                    });
                    resolve();
                });
            });
        });
    }
    function sameInterface(row,expected){
        return row && row.name===expected.name && row.local_publickey===expected.local_publickey &&
            row.local_address===expected.local_address && Number(row.mtu)===Number(expected.mtu) &&
            Number(row.local_listenport)===Number(expected.local_listenport) &&
            row.enabled===expected.enabled && row.interface===expected.interface &&
            (!expected.id || String(row.id)===String(expected.id)) && Number(row.site_client)!==1;
    }
    function submit(view, post, encode, success) {
        if (view.wgImportBusy) return Promise.resolve(false);
        var parsed;
        try { parsed = parse(view.wgImportText); }
        catch (error) { view.wgImportError = error.message; return Promise.resolve(false); }
        if(parsed.bundle && !view.wgSitePreview){
            view.wgSitePreview=parsed.preview;view.wgImportError='';
            return Promise.resolve(false);
        }
        view.wgImportBusy = true; view.wgImportError = '';view.wgIfaceNotice='';view.wgListError=false;view.wgImportSavedWarning=false;
        function request(action, param, fullResponse) {
            function rejectReply(data) {
                var known=typeof window!=='undefined' && window.WGI18n && data && window.WGI18n.knownText(data.ErrMsg);
                var rejected=new Error(known || tr('路由器未确认操作成功，请刷新接口列表后重试。'));
                rejected.detail=known || '';
                if(action==='iface_add' && typeof window!=='undefined' && window.WGI18n && window.WGI18n.interfaceOutcome)
                    rejected.ifaceOutcome=window.WGI18n.interfaceOutcome(data,param.name,false);
                rejected.routerMessage=!!data && typeof data.Result==='number';
                rejected.alreadySaved=action==='site_client_import' && !!known &&
                    known===tr('组网配置已保存，请返回列表检查隧道状态后重新启用');
                throw rejected;
            }
            return post({func_name: 'wireguard', action: action, param: encode(param)}).then(function (response) {
                if (!response || !response.data || response.data.Result !== 30000) rejectReply(response && response.data);
                return fullResponse?response:(response.data.Data || {});
            },function(error){
                // The native Axios interceptor rejects logical errors with the decoded Action body.
                var body=error && (error.data || (error.response && error.response.data) || error);
                if(body && typeof body.Result==='number')rejectReply(body);
                fail(tr('请求失败，请检查连接并刷新接口列表确认结果后重试。'));
            });
        }
        function readRows(){
            return request('show',{TYPE:'iface_data,wg_iface,defaults'}).then(function(data){
                if(!Array.isArray(data.iface_data) || !Array.isArray(data.wg_iface))
                    fail(tr('接口保存结果尚未确认，请刷新列表核对后再操作。'));
                return data;
            });
        }
        function refresh(data) {
            view._ifaceRead=null;
            view.ifaceRows = data.iface_data || [];
            view.interfaces1 = data.wg_iface || [];
            view.ifaceDefaults = data.iface_defaults || {};
            if (view.$refs.dtable) view.$refs.dtable.reload();
        }
        function fill(name, data, uncertain, detail) {
            if (typeof window !== "undefined" && window.WGAddressPlan) window.WGAddressPlan.preserve(view);
            if (parsed.full || !view.wgImportFromPeer) {
                view.tableForm = {enabled: 'yes', comment: '', peer_privatekey: '', client_config: '', client_qr_svg: ''};
                view.shouHint = false;
            }
            view.$set(view.tableForm, 'client_endpoint', ''); view.$set(view.tableForm, 'exit_peer', 'no');view.$set(view.tableForm,'site_local','');view.$set(view.tableForm,'site_remote','');
            Object.keys(parsed.peer).forEach(function (field) { view.$set(view.tableForm, field, parsed.peer[field]); });
            view.$set(view.tableForm, 'interface', name);
            view.$set(view.tableForm, 'client_config', ''); view.$set(view.tableForm, 'client_qr_svg', '');
            view.tableRowEditing = false; view.tableRowEditing1 = true;
            refresh(data);
            view.wgImportNote = (parsed.full ? tr('已新建服务接口 ') + name + '。' : tr('已填入隧道配置，使用现有接口 ') + name + '。') + tr('请点击页面底部“保存”启用隧道。') + parsed.notes.join(' ');
            view.wgImportText = ''; view.wgImportOpen = false; view.wgImportPending = null;
            if(uncertain)view.wgIfaceNotice=tr('接口配置已保存，运行状态尚未确认。请验证实际连接。')+(detail?' '+detail:'');
            else success(parsed.full ? tr('已新建服务接口 ') + name + tr('，请保存隧道') : tr('已填入隧道配置，请保存'));
            return true;
        }
        if(parsed.bundle){
            function saved(warning){
                view.wgImportSavedWarning=warning;
                view.wgImportText='';view.wgImportPending=null;
                view.tableRowEditing=false;view.tableRowEditing1=false;
                function finish(){
                    view.wgImportBusy=false;close(view);
                    if(view.getInterfaceAndServiceStatus)view.getInterfaceAndServiceStatus();
                    if(!warning)success(tr('已导入对端路由器配置'));return true;
                }
                return updatedTables(view,function(param){return request('show',param,true);}).then(finish,function(){
                    view.wgListError=true;view.wgListRevision=(view.wgListRevision || 0)+1;return finish();
                });
            }
            return request('site_client_import',{config_hex:siteHex(parsed.bundle)}).then(function(){return saved(false);},function(error){
                if(error && error.alreadySaved)return saved(true);
                view.wgImportBusy=false;
                view.wgImportError=error && error.routerMessage?error.message:tr('请求失败，请检查连接并刷新接口列表确认结果后重试。');
                return false;
            });
        }
        return readRows().then(function (data) {
            var rows = data.iface_data || [];
            if (!parsed.full) {
                var name = view.wgImportFromPeer && view.tableForm.interface;
                if (!name || !rows.some(function (row) { return row.name === name; })) fail(tr('仅有 [Peer] 配置：请在已有接口的隧道编辑页导入，或提供完整 [Interface] 配置。'));
                return fill(name, data);
            }
            return request('show', {TYPE: 'gen_publickey', privatekey: parsed.local.local_privatekey}).then(function (derived) {
                if (!derived.pubkey) fail(tr('PrivateKey 无法生成公钥，未创建接口。'));
                var pending = view.wgImportPending;
                if (pending) {
                    var existing = rows.filter(function (row) { return row.name===pending.name; })[0];
                    if(pending.outcome==='rolledBack')fail(tr('接口保存结果尚未确认，请刷新列表核对后再操作。'));
                    if(!existing)fail(tr('上次接口创建结果待确认，请刷新页面检查接口列表，避免覆盖已有接口。'));
                    if(sameInterface(existing,pending) && pending.local_publickey===derived.pubkey &&
                        pending.local_address===parsed.local.local_address && pending.mtu===parsed.local.mtu &&
                        pending.requestedPort===parsed.local.local_listenport)return fill(pending.name,data,pending.uncertain,pending.detail);
                    fail(tr('上次导入的接口与当前配置不一致，请返回接口列表核对地址、MTU 和监听端口。'));
                }
                var used = {}, ports = {};
                rows.forEach(function (row) { used[row.name] = true; ports[+row.local_listenport] = true; });
                var defaults=data.iface_defaults || {},name=defaults.name;
                if(Object.prototype.hasOwnProperty.call(defaults,'name') && name!==undefined){
                    if(typeof name!=='string' || !/^wg[0-9]{1,10}$/.test(name) || used[name])fail(tr('WG 接口建议已变化，请重新导入。'));
                }else{
                    var index=1;while(used['wg'+index])index++;
                    name='wg'+index;
                }
                var port = parsed.local.local_listenport || +defaults.local_listenport || 50001;
                if (parsed.local.local_listenport && ports[port]) fail(tr('ListenPort 已被其他 WG 接口使用，请调整后再导入。'));
                while (ports[port] && port < 65535) port++;
                if (ports[port]) fail(tr('没有可用的 WG 监听端口。'));
                var param = {enabled: 'yes', name: name, interface: 'auto', local_publickey: derived.pubkey, wg_import_auto_name:'yes'};
                Object.keys(parsed.local).forEach(function (field) { param[field] = parsed.local[field]; });
                param.local_listenport = port;
                var expected={name:name,local_publickey:derived.pubkey,local_address:parsed.local.local_address,mtu:parsed.local.mtu,
                    interface:'auto',enabled:'yes',local_listenport:port,requestedPort:parsed.local.local_listenport};
                view.wgImportPending=expected;
                function confirm(failure){
                    expected.uncertain=!!failure;expected.detail=failure && failure.detail || '';expected.outcome=failure && failure.ifaceOutcome;
                    return readRows().then(function(latest){
                        var row=latest.iface_data.filter(function(item){return item.name===name;})[0];
                        if(failure && failure.ifaceOutcome==='rolledBack' && row)
                            fail(tr('接口保存结果尚未确认，请刷新列表核对后再操作。'));
                        if(sameInterface(row,expected))return fill(name,latest,expected.uncertain,expected.detail);
                        if(failure && failure.routerMessage && failure.ifaceOutcome!=='saved' && !row){
                            view.wgImportPending=null;
                            throw failure;
                        }
                        fail(tr('接口保存结果尚未确认，请刷新列表核对后再操作。'));
                    },function(readError){
                        if(failure && failure.ifaceOutcome){
                            if(failure.ifaceOutcome==='rolledBack')view.wgImportPending=null;
                            throw failure;
                        }
                        throw readError;
                    });
                }
                return request('iface_add',param).then(function(){return confirm(null);},confirm);
            });
        }).then(function (ok) { view.wgImportBusy = false; return ok; }, function (error) {
            view.wgImportBusy = false;
            view.wgImportError = error instanceof Error ? error.message : tr('请求失败，请检查连接并刷新接口列表确认结果后重试。');
            return false;
        });
    }
    function summary(h,site){
        var rows=[[tr('连接方式'),site.transport==='native'?tr('原生 WireGuard（UDP）'):tr('纯 Hysteria 2（UDP）')],
            [tr('公网入口'),site.server+':'+site.port+'/UDP']];
        var directions={access:tr('本机可经对端路由器上网'),lend:tr('对端路由器可经本机上网'),both:tr('双方可互相作为上网出口')};
        rows.push([tr('上网方向'),directions[site.purpose]],[tr('局域网互访'),tr('未设置互访网段')]);
        return h('dl',{staticClass:'wg-site-summary'},rows.reduce(function(out,r){
            return out.concat([h('dt',[r[0]]),h('dd',[r[1]])]);
        },[]));
    }
    function managed(view,row,interfaceRow,post) {
        var identity={name:interfaceRow?row.name:row.interface,peer:interfaceRow?'':String(row.id)};
        if(!interfaceRow && row.native_role==='site_client' && Number(row.site_client)!==1){
            view.wgManagedSite={name:identity.name,orphan:true};
            return;
        }
        var record=view.wgManagedSite={name:identity.name};
        post({func_name:'wireguard',action:'show',param:{TYPE:'site_client_status'}}).then(function(response){
            if(view.wgManagedSite!==record)return;
            var data=response && response.data && response.data.Data && response.data.Data.site_client_status;
            var match=data && Array.isArray(data.members) && data.members.filter(function(m){
                return m.interface===identity.name && (!identity.peer || String(m.id)===identity.peer);
            });
            if(!match || match.length!==1)throw Error();
            var m=match[0], purpose=m.purpose || 'site',transport=m.transport || 'hysteria2';
            if(transport==='hysteria2'){
                view.wgManagedSite={name:identity.name,transport:transport,retired:true};return;
            }
            var scopes=clientHelper().siteFields(m.site_local,m.site_remote);
            if(['native','pure_hy2'].indexOf(transport)<0 || ['access','lend','both'].indexOf(purpose)<0 || scopes.local.length)throw Error();
            view.wgManagedSite={name:identity.name,transport:transport,purpose:purpose,server:m.server,port:m.server_port,
                local:scopes.local,remote:scopes.remote,retired:m.retired===true,enabled:m.enabled===true || m.enabled==='yes',running:m.running===true};
        }).catch(function(){if(view.wgManagedSite===record)view.wgManagedSite={name:identity.name,error:true};});
    }
    function renderManaged(view,h){
        var site=view.wgManagedSite;
        return h('div',{staticClass:'main_section_edit'},[
            h('div',{staticClass:'title_h3'},[h('h3',[tr('已导入的路由器隧道')+' · '+site.name])]),
            h('div',{staticClass:'wrapper clearfix row'},[h('div',{staticClass:'box wg-managed-site'},[
                site.local && !site.retired?summary(h,site):view._e(),
                h('p',{attrs:{role:'status'}},[site.retired?(site.transport==='hysteria2'?tr('原 HY2 承载 WG 隧道已停用。请删除此记录并导入新的配置。'):tr('原纯 HY2 借线用途已停用，请删除此记录并从对端重新导入。')):site.orphan?tr('组网隧道缺少匹配的中继配置，请重新导入组网配置'):site.error?tr('设备已被删除或更改，请返回列表并重新打开。'):site.local?
                    (!site.enabled?tr('已停用'):site.transport==='native'?(site.running?tr('WG 接口运行中'):tr('WG 接口未运行')):site.running?tr('客户端运行中'):tr('客户端未运行')):tr('处理中…')]),
                site.retired?view._e():h('p',{staticClass:'note'},[tr('可在隧道列表启用、停用或删除此设备。')]),
                h('button',{staticClass:'btn',attrs:{type:'button'},on:{click:function(){
                    view.wgManagedSite=null;
                    view.$nextTick(function(){
                        if(view.$refs.dtable)view.$refs.dtable.reload();
                        if(view.$refs.dtable1)view.$refs.dtable1.reload();
                    });
                }}},[tr('返回并刷新列表')])
            ])])
        ]);
    }
    function render(view, h) {
        if(view.wgManagedSite) return renderManaged(view,h);
        if(!view.wgImportOpen){
            if(!view.wgListError && !view.wgImportSavedWarning)return view._e();
            var warnings=[];
            if(view.wgImportSavedWarning)warnings.push(h('span',[tr('组网配置已保存，请返回列表检查隧道状态后重新启用')]));
            if(view.wgListError)warnings.push(h('span',[tr('配置已导入，未能读取最新列表。')]),
                h('button',{staticClass:'btn',attrs:{type:'button'},on:{click:function(){
                    view.wgListError=false;view.wgListRevision++;
                }}},[tr('重新读取列表')]));
            return h('div',{staticClass:'line_edit',attrs:{role:'alert'}},warnings);
        }
        var preview=view.wgSitePreview;
        return h('div', {staticClass: 'main_section_edit'}, [
            h('div', {staticClass: 'title_h3'}, [h('h3', [tr('导入隧道配置')])]),
            h('div', {staticClass: 'wrapper clearfix row'}, [h('div', {staticClass: 'box'}, [
                h('div', {staticClass: 'line_edit'}, [h('div', {staticClass: 'input_tit'}, [tr('配置内容：')]), h('div', {staticClass: 'input_group wg-import-content'}, [
                    preview?summary(h,preview):h('textarea', {ref: 'wgImportText', staticClass: 'inptText', staticStyle: {width: '100%', maxWidth: '760px', minHeight: '280px', fontFamily: 'monospace'}, attrs: {rows: 14, spellcheck: 'false', autocomplete: 'off', disabled: view.wgImportBusy, 'aria-label': tr('隧道配置内容')}, domProps: {value: view.wgImportText}, on: {input: function (event) { view.wgImportText = event.target.value; view.wgSitePreview=null; view.wgImportError = ''; }}}),
                    h('p', {staticClass: 'note'}, [preview?(preview.transport==='pure_hy2'?tr('确认后将创建纯 HY2 设备隧道。'):tr('确认后将新建独立的 WG 接口和隧道。')):tr('粘贴从对端 NativeRouting 路由器复制的配置，或含 [Interface]、[Peer] 的原生 WG 配置。')]),
                    view.wgImportError ? h('p', {staticClass: 'error_tip', attrs: {role: 'alert'}}, [view.wgImportError]) : view._e()
                ])]),
                h('div', {staticClass: 'h20'}),
                h('div', {staticClass: 'line_edit'}, [h('div', {staticClass: 'input_group wg-import-actions'}, [
                    h('button', {staticClass: 'btn btn_green btn_confirm', attrs: {type: 'button', disabled: view.wgImportBusy}, on: {click: function () { view.submitWgImport(); }}}, [view.wgImportBusy ? tr('正在导入…') : preview?tr('确认导入'):view.wgImportText.trim().charAt(0)==='{'?tr('预览路由器配置'):tr('导入')]),
                    h('button', {staticClass: 'btn btn_cancel', attrs: {type: 'button', disabled: view.wgImportBusy}, on: {click: function () { close(view); }}}, [tr('取消')])
                ])])
            ])])
        ]);
    }
    return {sameInterface:sameInterface,validateSite:validateSite,managed:managed,parse: parse, open: open, close: close, submit: submit, render: render};
}));
