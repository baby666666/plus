(function (root, factory) {
    if (typeof module === 'object' && module.exports) module.exports = factory();
    else root.CTPanelSourceFiles = factory();
}(this, function () {
    'use strict';
    var MAX_BYTES = 262144, MAX_ROWS = 200;
    function fail(message) { throw new Error(message); }
    function valid(row, number) {
        var prefix = '第 ' + number + ' 条：';
        var name = String(row.name || '').trim(), url = String(row.url || '').trim(), parsed;
        if (!name || name.length > 128 || /[\x00-\x1f\x7f]/.test(name)) fail(prefix + '名称不能为空，且不能超过 128 个字符或包含控制字符。');
        if (!url || url.length > 2048 || /[\s\x00-\x1f\x7f]/.test(url)) fail(prefix + 'URL 无效。');
        try { parsed = new URL(url); } catch (_) { fail(prefix + '请输入完整的 HTTP 或 HTTPS URL。'); }
        if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hash) fail(prefix + '仅支持不含账号、密码和片段的 HTTP/HTTPS URL。');
        var enabled = row.enabled === undefined || row.enabled === '' ? 'yes' : row.enabled;
        if (enabled !== 'yes' && enabled !== 'no') fail(prefix + 'enabled 仅支持 yes 或 no。');
        return {name: name, url: url, enabled: enabled};
    }
    function csv(text) {
        var rows = [], row = [], field = '', quoted = false, ended = false;
        function cell() { row.push(field); field = ''; ended = false; }
        function line() { cell(); if (row.some(function (v) { return v.trim() !== ''; })) rows.push(row); row = []; }
        for (var i = 0; i < text.length; i++) {
            var c = text[i];
            if (quoted) {
                if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else { quoted = false; ended = true; } }
                else field += c;
            } else if (c === '"') {
                if (field !== '' || ended) fail('CSV 引号格式错误。');
                quoted = true;
            } else if (c === ',') cell();
            else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; line(); }
            else { if (ended) { if (c === ' ' || c === '\t') continue; fail('CSV 引号后存在多余内容。'); } field += c; }
        }
        if (quoted) fail('CSV 引号未闭合。');
        if (field || row.length || ended) line();
        var header = rows.shift();
        if (!header || !/^name,url(,enabled)?$/.test(header.map(function (s) { return s.trim().toLowerCase(); }).join(','))) fail('CSV 表头应为 name,url 或 name,url,enabled。');
        return rows.map(function (r, i) { if (r.length !== header.length) fail('第 ' + (i + 2) + ' 行 CSV 列数不正确。'); return {name: r[0], url: r[1], enabled: r[2]}; });
    }
    function txt(text) {
        var rows = [];
        text.split(/\r\n|\r|\n/).forEach(function (line, i) {
            line = line.trim(); if (!line || line[0] === '#') return;
            var quoted = /^name=("(?:[^"\\]|\\.)*")\s+url=("(?:[^"\\]|\\.)*")(?:\s+enabled=(yes|no))?$/.exec(line);
            var old = !quoted && /^name=(.*?)\s+url=(\S+?)(?:\s+enabled=(yes|no))?$/.exec(line);
            if (!quoted && !old) fail('第 ' + (i + 1) + ' 行 TXT 格式错误，应为 name=名称 url=地址。');
            var m = quoted || old;
            try { rows.push({name: quoted ? JSON.parse(m[1]) : m[1], url: quoted ? JSON.parse(m[2]) : m[2], enabled: m[3]}); }
            catch (_) { fail('第 ' + (i + 1) + ' 行 TXT 转义格式错误。'); }
        });
        return rows;
    }
    function parse(text, filename) {
        if (typeof text !== 'string' || text.length > MAX_BYTES) fail('文件过大，最大支持 256 KiB。');
        text = text.replace(/^\uFEFF/, '');
        if (text.indexOf('\uFFFD') >= 0) fail('文件编码无法识别，请使用 UTF-8 编码。');
        var ext = /\.(csv|txt)$/i.exec(filename || '');
        if (!ext) fail('请选择 TXT 或 CSV 文件。');
        var rows = ext[1].toLowerCase() === 'csv' ? csv(text) : txt(text);
        if (!rows.length) fail('文件没有可导入的软件源。');
        if (rows.length > MAX_ROWS) fail('单次最多导入 200 条软件源。');
        return rows.map(function (r, i) { return valid(r, i + 1); });
    }
    function serialize(rows, format) {
        rows = rows.map(function (r, i) { return valid({name:r.name,url:r.url,enabled:r.enabled === false || r.enabled === 'no' ? 'no' : 'yes'}, i + 1); });
        function quote(s) { return '"' + s.replace(/"/g, '""') + '"'; }
        if (format === 'csv') return '\uFEFFname,url,enabled\r\n' + rows.map(function (r) { return [r.name,r.url,r.enabled].map(quote).join(','); }).join('\r\n');
        return rows.map(function (r) { return 'name=' + JSON.stringify(r.name) + ' url=' + JSON.stringify(r.url) + ' enabled=' + r.enabled; }).join('\n');
    }
    function encodeParams(params) {
        var out = {};
        Object.keys(params).forEach(function (name) {
            var value = params[name];
            out[name] = typeof value === 'string' ? value.replace(/[%\s"`$&;\\|'!()<>#\[\]*^]/g, function (c) { return '%' + c.charCodeAt(0).toString(16).toUpperCase(); }) : value;
        });
        out.encoding = 'url';
        return out;
    }
    function key(url) { try { return new URL(url).href.replace(/\/$/, ''); } catch (_) { return String(url).trim(); } }
    async function append(rows, request, progress) {
        // Validate the complete file before any write, then write sequentially.
        rows = rows.map(function (r,i) { return valid(r,i+1); });
        if (!rows.length || rows.length > MAX_ROWS) fail('单次导入条数应为 1 到 200 条。');
        var result = {added:0, skipped:0, total:rows.length}, existing = await request('show',{TYPE:'data'});
        if (!existing || !Array.isArray(existing.sources)) fail('无法读取现有软件源，未执行导入。');
        var seen = Object.create(null), added = [];
        existing.sources.forEach(function (r) { seen[key(r.url)] = true; });
        try {
            for (var i=0;i<rows.length;i++) {
                var row=rows[i], k=key(row.url);
                if (seen[k]) result.skipped++;
                else { await request('add', row); seen[k]=true; result.added++; added.push(row); }
                if (progress) progress(i+1,rows.length);
            }
            var saved = await request('show',{TYPE:'data'});
            if (!saved || !Array.isArray(saved.sources) || added.some(function (r) { return !saved.sources.some(function (s) { return key(s.url)===key(r.url) && s.name===r.name && s.enabled===r.enabled; }); })) fail('保存结果未确认，请刷新后检查。');
            return result;
        } catch (error) {
            var message = '已确认新增 ' + result.added + ' 条，跳过 ' + result.skipped + ' 条。导入中断：' + (error.message || '请求失败') + ' 刷新后可重试，已有 URL 将自动跳过。';
            var partial = new Error(message); partial.result=result; throw partial;
        }
    }
    return {parse:parse,serialize:serialize,append:append,encodeParams:encodeParams,MAX_BYTES:MAX_BYTES,MAX_ROWS:MAX_ROWS};
}));
