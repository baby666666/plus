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
    function parse(text) {
        if (!text || !text.trim()) fail(tr('请粘贴 WireGuard 配置。'));
        if (text.length > 65536) fail(tr('配置过长，请每次导入一份接口及一个隧道。'));
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
        if(hasSite){var helper=typeof module==='object'&&module.exports?require('./wg-client-config.js'):window.WGClientConfig;if(!helper)fail(tr('页面组件尚未就绪，请刷新后重试'));var normalized=helper.siteFields(site.local,site.remote);site.local=normalized.local.join(',');site.remote=normalized.remote.join(',');}
        if (!seen.peer) fail(tr('缺少 [Peer] 段，未创建接口。'));
        var local = data.interface, peer = data.peer, result = {full: !!seen.interface, notes: notes};
        result.peer = {peer_publickey: key(peer.publickey, tr('对端 PublicKey')), presharedkey: key(peer.presharedkey, 'PresharedKey', true), endpoint: '', endpoint_port: '', keepalive: number(peer.persistentkeepalive, 10, 0, 65535, 'PersistentKeepalive'), client_dns: ''};
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
        view.wgImportText = ''; view.wgImportError = ''; view.wgImportPending = null;
        view.wgImportFromPeer = !!view.tableRowEditing1; view.wgImportOpen = true;
        view.$nextTick(function () { if (view.$refs.wgImportText) view.$refs.wgImportText.focus(); });
    }
    function close(view) {
        if (view.wgImportBusy) return;
        view.wgImportOpen = false; view.wgImportText = ''; view.wgImportError = '';
    }
    function submit(view, post, encode, success) {
        if (view.wgImportBusy) return Promise.resolve(false);
        var parsed;
        try { parsed = parse(view.wgImportText); }
        catch (error) { view.wgImportError = error.message; return Promise.resolve(false); }
        view.wgImportBusy = true; view.wgImportError = '';
        function request(action, param) {
            return post({func_name: 'wireguard', action: action, param: encode(param)}).then(function (response) {
                if (!response || !response.data || response.data.Result !== 30000) fail(tr('路由器未确认操作成功，请刷新接口列表后重试。'));
                return response.data.Data || {};
            });
        }
        function readRows() { return request('show', {TYPE: 'iface_data,wg_iface,defaults'}); }
        function refresh(data) {
            view.ifaceRows = data.iface_data || [];
            view.interfaces1 = data.wg_iface || [];
            view.ifaceDefaults = data.iface_defaults || {};
            if (view.$refs.dtable) view.$refs.dtable.reload();
        }
        function fill(name, data) {
            if (typeof window !== "undefined" && window.WGAddressPlan) window.WGAddressPlan.preserve(view);
            if (!view.wgImportFromPeer) {
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
            success(parsed.full ? tr('已新建服务接口 ') + name + tr('，请保存隧道') : tr('已填入隧道配置，请保存'));
            return true;
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
                    var existing = rows.filter(function (row) { return row.name === pending.name; })[0];
                    if (existing && existing.local_publickey === derived.pubkey && existing.local_address === parsed.local.local_address && pending.publickey === derived.pubkey) return fill(pending.name, data);
                    if (existing) fail(tr('上次接口创建结果待确认，请刷新页面检查接口列表，避免覆盖已有接口。'));
                }
                var used = {}, ports = {};
                rows.forEach(function (row) { used[row.name] = true; ports[+row.local_listenport] = true; });
                var index = 1;
                while (used['wg' + index]) index++;
                var port = parsed.local.local_listenport || +(data.iface_defaults || {}).local_listenport || 50001;
                if (parsed.local.local_listenport && ports[port]) fail(tr('ListenPort 已被其他 WG 接口使用，请调整后再导入。'));
                while (ports[port] && port < 65535) port++;
                if (ports[port]) fail(tr('没有可用的 WG 监听端口。'));
                var name = 'wg' + index;
                var param = {enabled: 'yes', name: name, interface: 'auto', local_publickey: derived.pubkey};
                Object.keys(parsed.local).forEach(function (field) { param[field] = parsed.local[field]; });
                param.local_listenport = port;
                view.wgImportPending = {name: name, publickey: derived.pubkey};
                return request('iface_add', param).then(function () { return readRows(); }).then(function (latest) {
                    var saved = (latest.iface_data || []).filter(function (row) { return row.name === name; })[0];
                    if (!saved || saved.local_publickey !== derived.pubkey || saved.local_address !== parsed.local.local_address) fail(tr('接口创建结果尚未确认，请重试或刷新接口列表检查。'));
                    return fill(name, latest);
                });
            });
        }).then(function (ok) { view.wgImportBusy = false; return ok; }, function (error) {
            view.wgImportBusy = false;
            view.wgImportError = error instanceof Error ? error.message : tr('请求失败，请检查连接并刷新接口列表确认结果后重试。');
            return false;
        });
    }
    function render(view, h) {
        if (!view.wgImportOpen) return view._e();
        return h('div', {staticClass: 'main_section_edit'}, [
            h('div', {staticClass: 'title_h3'}, [h('h3', [tr('导入 WireGuard 配置')])]),
            h('div', {staticClass: 'wrapper clearfix row'}, [h('div', {staticClass: 'box'}, [
                h('div', {staticClass: 'line_edit'}, [h('div', {staticClass: 'input_tit'}, [tr('配置内容：')]), h('div', {staticClass: 'input_group wg-import-content'}, [
                    h('textarea', {ref: 'wgImportText', staticClass: 'inptText', staticStyle: {width: '100%', maxWidth: '760px', minHeight: '280px', fontFamily: 'monospace'}, attrs: {rows: 14, spellcheck: 'false', autocomplete: 'off', disabled: view.wgImportBusy, 'aria-label': tr('WireGuard 配置内容')}, domProps: {value: view.wgImportText}, on: {input: function (event) { view.wgImportText = event.target.value; view.wgImportError = ''; }}}),
                    h('p', {staticClass: 'note'}, [tr('粘贴完整的 [Interface] 和 [Peer] 配置。完整配置会新建服务接口，现有接口不会修改；隧道需确认后保存。')]),
                    view.wgImportError ? h('p', {staticClass: 'error_tip', attrs: {role: 'alert'}}, [view.wgImportError]) : view._e()
                ])]),
                h('div', {staticClass: 'h20'}),
                h('div', {staticClass: 'line_edit'}, [h('div', {staticClass: 'input_group wg-import-actions'}, [
                    h('button', {staticClass: 'btn btn_green btn_confirm', attrs: {type: 'button', disabled: view.wgImportBusy}, on: {click: function () { view.submitWgImport(); }}}, [view.wgImportBusy ? tr('正在导入…') : tr('导入')]),
                    h('button', {staticClass: 'btn btn_cancel', attrs: {type: 'button', disabled: view.wgImportBusy}, on: {click: function () { close(view); }}}, [tr('取消')])
                ])])
            ])])
        ]);
    }
    return {parse: parse, open: open, close: close, submit: submit, render: render};
}));
