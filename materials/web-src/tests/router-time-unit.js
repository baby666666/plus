'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {execFileSync} = require('node:child_process');
const source = path.resolve(__dirname, '..');
const helper = fs.readFileSync(path.join(source, 'src/router-time.js'), 'utf8');

if (!process.argv.includes('--child')) {
  let total = 0;
  for (const zone of ['UTC', 'Asia/Shanghai', 'America/New_York', 'Asia/Kolkata', 'Asia/Kathmandu', 'Australia/Lord_Howe']) {
    const output = execFileSync(process.execPath, [__filename, '--child'], {env: {...process.env, TZ: zone}, encoding: 'utf8'});
    process.stdout.write(output);
    total += Number(/PASS (\d+)/.exec(output)[1]);
  }
  console.log(`PASS ${total} router-time cases across six browser timezone environments`);
  process.exit(0);
}

let count = 0;
function test(name, body) {
  try { body(); count++; } catch (error) { error.message = name + ': ' + error.message; throw error; }
}
function fresh() {
  const errors = [];
  let now = 1000;
  const win = {headers: {}, customError: text => errors.push(text)};
  const context = {window: win, Date: class extends Date {static now() {return now;}}};
  vm.runInNewContext(helper, context);
  return {api: win.RouterTime, win, errors, advance: ms => now += ms};
}
const epoch = 1704067200;
const zones = [['0800', '2024-01-01 08:00:00'], ['0000', '2024-01-01 00:00:00'],
  ['0545', '2024-01-01 05:45:00'], ['-0330', '2023-12-31 20:30:00'],
  ['-0930', '2023-12-31 14:30:00'], ['1245', '2024-01-01 12:45:00'],
  ['1400', '2024-01-01 14:00:00'], ['-1200', '2023-12-31 12:00:00']];
test('native entry loader initial/retry URLs preserve asset path and helper loads first', () => {
  const html = fs.readFileSync(path.join(source, '../firmware/port-3726/files/usr/ikuai/www/index.html'), 'utf8');
  const files = JSON.parse(/var files = (\[[^;]+\]);/.exec(html)[1]);
  assert(files[0].includes('/router-time.'));
  for (const file of files) for (const attempt of [0, 1, 2]) {
    const url = new URL(file + '&entry_attempt=' + attempt, 'http://router.invalid');
    assert(url.pathname.endsWith('.js'));
    assert.equal(url.searchParams.get('entry_attempt'), String(attempt));
  }
});
for (const [zone, civil] of zones) test('round trip ' + zone, () => {
  const {api} = fresh();
  assert(api.setTimezone(zone));
  assert.equal(api.format(epoch), civil);
  assert.equal(api.parse(civil), epoch);
  assert.equal(api.parse(civil.replace(' ', 'T')), epoch);
});
for (const zone of ['', '800', '8', 'UTC+8', '+08:00', '0860', '1460', '1415', '-1245', '9999', 800, null])
  test('reject invalid offset ' + zone, () => assert.equal(fresh().api.parseOffset(zone), null));
test('missing/invalid offset never falls back to browser timezone', () => {
  const {api} = fresh();
  assert.equal(api.format(epoch), '—');
  assert.equal(api.parse('2024-01-01 08:00:00'), null);
  assert.equal(api.setTimezone('invalid'), false);
  api.setTimezone('0800'); api.setTimezone('invalid');
  assert.equal(api.format(epoch), '2024-01-01 08:00:00');
});
test('explicit timezone is independent of cache and failed offsets', () => {
  const {api} = fresh(); api.setTimezone('0000');
  assert.equal(api.parse('2024-01-01 08:00:00', '0800'), epoch);
  assert.equal(api.parse('2024-01-01 08:00:00', 'bad'), null);
});
for (const civil of ['2024-03-10 02:30:17', '2024-11-03 01:30:17', '2024-10-06 02:15:17'])
  test('browser DST gap/overlap retains router civil time ' + civil, () => {
    const {api} = fresh(); api.setTimezone('0800');
    assert.equal(api.format(api.parse(civil)), civil);
    const expected = Date.parse(civil.replace(' ', 'T') + '+08:00') / 1000;
    assert.equal(api.parse(civil), expected);
  });
for (const civil of ['', 'not-a-date', '2023-02-29 12:00:00', '2024-02-30 12:00:00',
  '2024-13-01 00:00:00', '2024-00-01 00:00:00', '2024-01-00 00:00:00',
  '2024-01-01 24:00:00', '2024-01-01 12:60:00', '2024-01-01 12:00:60',
  '2024-01-01T12:00:00Z', new Date(epoch * 1000), null])
  test('reject invalid civil time ' + String(civil), () => assert.equal(fresh().api.parse(civil, '0800'), null));
test('leap day and epoch zero retained', () => {
  const {api} = fresh(); api.setTimezone('0000');
  assert.equal(api.parse('1970-01-01 00:00:00'), 0);
  assert.equal(api.format(0), '1970-01-01 00:00:00');
  assert.equal(api.format(api.parse('2024-02-29 23:59:59')), '2024-02-29 23:59:59');
  assert.equal(api.format(null), '');
});

function response(api, zone, request, data, config) {
  config = config || api.beginRequest({data: JSON.stringify(request || {})});
  api.captureResponse({config, headers: {'x-timezone': zone}, data: data || {Result: 30000}});
  return config;
}
test('response headers initialize and refresh current router timezone', () => {
  const {api, win} = fresh(); response(api, '0800'); response(api, '-0330');
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
  assert.equal(win.headers.xTimezoneHour, -3.5);
});
test('successful basic/save overrides its old header and ignores older replies', () => {
  const {api} = fresh(); response(api, '0800');
  const old = api.beginRequest({data: '{}'});
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}});
  response(api, '0800', null, null, old);
  response(api, '0800');
  assert.equal(api.format(epoch), '2024-01-01 05:45:00');
  response(api, '0545'); response(api, '-0330');
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
});
test('faster monitor or show replies cannot hide a slower successful save', () => {
  for (const newerShow of [false, true]) {
    const {api} = fresh(); response(api, '0800');
    const save = api.beginRequest({data: JSON.stringify({func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}})});
    if (newerShow) response(api, '0800', {func_name: 'basic', action: 'show'}, {Result: 30000, Data: {data: [{time_zone_full: '0800'}]}});
    else response(api, '0800', {func_name: 'sysstat', action: 'show'});
    response(api, '0800', null, null, save);
    assert.equal(api.format(epoch), '2024-01-01 05:45:00');
  }
});
test('out-of-order older save and pre-save show cannot undo the newer saved target', () => {
  const {api} = fresh(); response(api, '0800');
  const oldShow = api.beginRequest({data: JSON.stringify({func_name: 'basic', action: 'show'})});
  const oldSave = api.beginRequest({data: JSON.stringify({func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}})});
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '-0330'}});
  response(api, '0800', null, null, oldSave);
  const stale = {config: oldShow, headers: {'x-timezone': '0800'}, data: {Result: 30000, Data: {data: [{time_zone_full: '0800'}]}}};
  api.captureResponse(stale);
  assert.equal(stale.routerTimeStaleBasic, true);
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
});
test('pending header guard is bounded when another administrator changes timezone', () => {
  const {api, advance} = fresh();
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}});
  advance(5001); response(api, '-0330');
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
});
test('basic/show body wins over old header while native worker reloads', () => {
  const {api} = fresh();
  response(api, '0800', {func_name: 'basic', action: 'show'}, {Result: 30000, Data: {data: [{time_zone_full: '-0330'}]}});
  response(api, '0800');
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
});
test('a newer basic/show with old async config cannot undo a just-saved target', () => {
  const {api, advance} = fresh(); response(api, '0800');
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}});
  response(api, '0800', {func_name: 'basic', action: 'show'}, {Result: 30000, Data: {data: [{time_zone_full: '0800'}]}});
  assert.equal(api.format(epoch), '2024-01-01 05:45:00');
  advance(4000);
  response(api, '0800', {func_name: 'basic', action: 'show'}, {Result: 30000, Data: {data: [{time_zone_full: '0545'}]}});
  advance(1001);
  response(api, '-0330');
  assert.equal(api.format(epoch), '2023-12-31 20:30:00');
});
test('failed async application can recover actual config after bounded save guard', () => {
  const {api, advance} = fresh(); response(api, '0800');
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}});
  advance(5001);
  response(api, '0800', {func_name: 'basic', action: 'show'}, {Result: 30000, Data: {data: [{time_zone_full: '0800'}]}});
  assert.equal(api.format(epoch), '2024-01-01 08:00:00');
});
test('failed save does not adopt uncommitted timezone', () => {
  const {api} = fresh(); response(api, '0800');
  response(api, '0800', {func_name: 'basic', action: 'save', param: {time_zone_full: '0545'}}, {Result: 10011});
  assert.equal(api.format(epoch), '2024-01-01 08:00:00');
});
test('missing/invalid headers and malformed config cannot replace a known offset', () => {
  const {api} = fresh(); response(api, '0800');
  api.captureResponse({config: {data: '{bad'}, headers: {'x-timezone': 'invalid'}, data: {}});
  api.captureResponse({});
  assert.equal(api.format(epoch), '2024-01-01 08:00:00');
});

function h(tag, data, children) {
  if (Array.isArray(data) || typeof data === 'string') {children = data; data = {};}
  return {tag, data: data || {}, children: children || []};
}
test('native picker keeps string, seconds, DST gap, clearing and visible labels', () => {
  const {api} = fresh(); api.setTimezone('0800');
  const view = {startTime: '2024-03-10 02:30:17'};
  const label = api.renderPicker(view, h, 'startTime', '开始时间', true);
  assert.equal(label.tag, 'label');
  const input = label.children[1];
  assert.equal(input.data.attrs.type, 'datetime-local');
  assert.equal(input.data.attrs.step, '1');
  assert.equal(input.data.domProps.value, '2024-03-10T02:30:17');
  input.data.on.change({target: {value: '2024-11-03T01:30:17', validity: {valid: true}}});
  assert.equal(view.startTime, '2024-11-03 01:30:17');
  input.data.on.change({target: {value: '', validity: {valid: true}}});
  assert.equal(view.startTime, '');
});
test('invalid picker edits block old manual value and valid edits recover before blur', () => {
  const {api, errors} = fresh(); api.setTimezone('0800');
  const view = {timeset: '2024-01-01 08:00:00', tableForm: {time_zone_full: '0800'}};
  const input = api.renderPicker(view, h, 'timeset', '设置时间', false);
  input.data.on.change({target: {value: '2024-02-30T00:00:00', validity: {valid: true}}});
  assert.equal(view.timeset, '2024-01-01 08:00:00');
  assert.equal(errors.length, 1);
  assert.equal(api.validTime(view), false);
  input.data.on.input({target: {value: '2024-03-10T02:30:17', validity: {valid: true}}});
  assert.equal(view.timeset, '2024-03-10 02:30:17');
  assert.equal(api.validTime(view), true);
});
test('incomplete native input blocks old log range and full clearing restores unbounded query', () => {
  const {api} = fresh(); api.setTimezone('0800');
  const view = {startTime: '2024-01-01 08:00:00', endTime: ''};
  const input = api.renderPicker(view, h, 'startTime', '开始时间', false);
  input.data.on.input({target: {value: '', validity: {valid: false, badInput: true}}});
  assert.equal(api.range(view), null);
  input.data.on.input({target: {value: '', validity: {valid: true}}});
  assert.equal(view.startTime, '');
  assert.equal(api.range(view).start, null);
});
test('manual time matches native ten-digit epoch limits, while log parse stays unrestricted', () => {
  const {api} = fresh();
  for (const timestamp of [999999999, 1000000000, 9999999999, 10000000000]) {
    const view = {timeset: api.format(timestamp, '0800'), tableForm: {time_zone_full: '0800'}};
    assert.equal(api.validTime(view), timestamp >= 1000000000 && timestamp <= 9999999999);
  }
  assert.equal(api.parse('1970-01-01 00:00:00', '0000'), 0);
});

function modules(file, win, extra) {
  let result;
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    window: win, webpackJsonp: (ids, defs) => result = defs,
    customSuccess() {}, customError: win.customError, setTimeout(fn) { if (win.msgReceive !== undefined) fn(); }, $t: x => x, ...extra
  });
  return result;
}
function component(file, id, env) {
  const defs = modules(path.join(source, 'time', file), env.win);
  const app = modules(path.join(source, 'time/app.js'), env.win);
  const module = {exports: {}}; app[79](module, module.exports);
  const req = id => ({350: Object.assign, 80: JSON.stringify, 78: {a: {apiUrl: '/api'}},
    79: module.exports, 144: {Validator: {setLocale() {}}}, 208: {}})[id];
  req.n = x => {const get = () => x; get.a = x; return get;};
  const output = {}; defs[id]({}, output, req);
  return output.default;
}
const logPages = [['admin.js', 1652], ['notice.js', 1650], ['arp.js', 1647],
  ['pppauth.js', 1657], ['wanpppoe.js', 1656], ['apaction.js', 1655],
  ['sysevent.js', 1654], ['dhcpd.js', 1649], ['ddns.js', 1648], ['perceivable.js', 1653]];
for (const [file, id] of logPages) {
  test(file + ' actual created hook binds timezone without hiding native initialization', () => {
    const env = fresh(); let bound = 0, initialized = 0;
    env.api.bind = view => {assert.equal(view.marker, true); bound++;};
    env.win.getHeaders = () => initialized++;
    env.win.msgReceive = 1;
    const page = component(file, id, env);
    page.created.call({marker: true, getInterfaceAndServiceStatus() {initialized++;}});
    assert.equal(bound, 1);
    assert.equal(initialized, file === 'pppauth.js' || file === 'wanpppoe.js' ? 1 : 0);
  });
  test(file + ' actual component display and search use same router civil time', () => {
    const env = fresh(); env.api.setTimezone('0800');
    const page = component(file, id, env), view = {$t: x => x};
    Object.assign(view, page.data.call(view));
    let requests = 0;
    view.$refs = {dtable: {paginationOptions: {}, reload() {requests++;}, search() {requests++;}, pageConfig() {}}};
    const column = view.tableOptions.columns.find(c => c.name === 'timestamp');
    const visible = column.dataFunction(epoch).replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ');
    assert.equal(visible, '2024-01-01 08:00:00');
    view.startTime = '2024-01-01 08:00:00'; view.endTime = '2024-01-01 08:00:17';
    page.methods.search.call(view);
    assert.equal(requests, 1);
    const filters = JSON.stringify(view.tableOptions.requests.param);
    assert(filters.includes('timestamp,>=,1704067200'));
    assert(filters.includes('timestamp,<=,1704067217'));
    view.startTime = '2024-02-30 00:00:00';
    page.methods.search.call(view);
    assert.equal(requests, 1);
    assert.equal(env.errors.length, 1);
  });
  test(file + ' actual component preserves epoch-zero range', () => {
    const env = fresh(); env.api.setTimezone('0000');
    const page = component(file, id, env), view = {$t: x => x};
    Object.assign(view, page.data.call(view));
    view.$refs = {dtable: {paginationOptions: {}, reload() {}, search() {}, pageConfig() {}}};
    view.startTime = '1970-01-01 00:00:00'; view.endTime = '';
    page.methods.search.call(view);
    assert(JSON.stringify(view.tableOptions.requests.param).includes('timestamp,>=,0'));
  });
}
test('basic actual component posts selected timezone epoch, independent of header/browser', () => {
  const env = fresh(); env.api.setTimezone('-0330');
  const page = component('basic.js', 1714, env), requests = [];
  const view = {timeset: '2024-03-10 02:30:17', tableForm: {time_zone_full: '0800'}, $t: x => x,
    $http: {post(url, payload) {requests.push(payload); return {then() {}};}}};
  page.methods.setTime.call(view);
  assert.equal(requests[0].param.timestamp, Date.parse('2024-03-10T02:30:17+08:00') / 1000);
  view.timeset = '2024-02-30 00:00:00'; page.methods.setTime.call(view);
  assert.equal(requests.length, 1);
});
test('basic actual component refuses invalid manual time before saving any settings', () => {
  const env = fresh(), page = component('basic.js', 1714, env);
  const view = {timeset: 'bad', tableForm: {time_zone_full: '0800', switch_ntp: 0},
    $http: {post() {throw Error('must not save');}}, $validator: {validateAll() {throw Error('must not save');}}};
  page.methods.saveForm.call(view);
  assert.equal(env.errors.length, 1);
});
test('basic actual component never refills stale settings over submitted form', () => {
  const env = fresh(), page = component('basic.js', 1714, env);
  let completed = 0;
  const view = {tableForm: {time_zone_full: '0545', hostname: 'submitted'},
    timeset: '2024-03-10 02:30:17', timestamp: '2024-01-01 05:45:00',
    globalBus: {$emit() {completed++;}}, $http: {post() {return {then(callback) {
      callback({routerTimeStaleBasic: true, data: {Data: {timestamp: epoch, data: [{time_zone_full: '0800', hostname: 'old'}]}}});
    }};}}};
  page.methods.showData.call(view);
  assert.equal(view.tableForm.time_zone_full, '0545');
  assert.equal(view.tableForm.hostname, 'submitted');
  assert.equal(view.timestamp, '2024-01-01 05:45:00');
  assert.equal(view.timeset, '2024-03-10 02:30:17');
  assert.equal(completed, 1);
});
test('basic actual component missing timezone cannot use cached timezone to display or set clock', () => {
  const env = fresh(); env.api.setTimezone('0800');
  const page = component('basic.js', 1714, env), view = page.data();
  let requests = 0;
  view.globalBus = {$emit() {}};
  view.$http = {post() {requests++; return {then(callback) {
    callback({data: {Data: {timestamp: epoch, data: [{hostname: 'router', ntpserver_list: ''}], interface: []}}});
  }};}};
  page.methods.showData.call(view);
  assert.equal(view.tableForm.time_zone_full, '');
  assert.equal(view.timestamp, '—');
  view.timeset = '2024-01-01 08:00:00';
  for (const timezone of [undefined, '', null, 'invalid']) {
    view.tableForm.time_zone_full = timezone;
    page.methods.setTime.call(view);
  }
  assert.equal(requests, 1);
});
console.log(`PASS ${count} router-time helper and actual component cases in ${process.env.TZ}`);
