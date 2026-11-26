#!/usr/bin/env node
'use strict';
// Exercise the shipped page methods/render functions and DTable pagination without a router.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const modules = Object.create(null);
const errors = [];
const context = vm.createContext({
  webpackJsonp: (_chunks, factories) => Object.assign(modules, factories),
  window: {}, document: {querySelectorAll: () => [], activeElement: null},
  copyObj: (_direction, value) => JSON.parse(JSON.stringify(value)),
  copyAry: (_direction, value) => value,
  customError: message => errors.push(message), customSuccess: () => {},
  setTimeout, clearTimeout, console, isPhone: false, btoa: value => Buffer.from(value, "binary").toString("base64"),
});
for (const name of ['domain', 'port', 'protocol', 'updown']) {
  vm.runInContext(fs.readFileSync(path.join(root, 'materials/web-src/routing', name + '.js'), 'utf8'), context, {filename: name + '.js'});
}
const timeAssets = JSON.parse(fs.readFileSync(path.join(root, 'materials/web-src/time-assets.json'), 'utf8'));
vm.runInContext(fs.readFileSync(path.join(root, 'materials/firmware/port-3726/files/usr/ikuai/www/static/js', timeAssets.app), 'utf8'), context, {filename: 'runtime-app.js'});
const cache = Object.create(null);
function requireModule(id) {
  if (id === 80) return JSON.stringify;
  if (id === 350) return Object.assign;
  if (id === 78) return {a: {apiUrl: '/Action/call'}};
  if (id === 23) return (script, render) => ({exports: Object.assign({}, script.default, render)});
  // Component imports and transpiler helpers are not mounted in these unit tests.
  if (![1668, 1678, 1679, 1669, 2312, 2309, 2318, 2243, 320010, 320011, 320012, 846, 856, 857, 847, 400, 402, 341, 405, 729].includes(id)) return {};
  if (cache[id]) return cache[id].exports;
  const module = cache[id] = {exports: {}};
  modules[id](module, module.exports, requireModule);
  return module.exports;
}
requireModule.n = value => {
  const getter = () => value;
  getter.a = value;
  return getter;
};
const definitions = {
  domain: 846, port: 856, protocol: 857, updown: 847,
};
const tableComponent = requireModule(402).default;
const tableMethods = tableComponent.methods;
const paginationComponent = requireModule(400).default;
function createElement(tag, data, children) {
  if (Array.isArray(data) || typeof data === 'string') { children = data; data = {}; }
  const flat = (children || []).flat(Infinity).filter(child => child != null);
  return {tag, data: data || {}, children: flat.map(child => typeof child === 'string' ? {text: child, data: {}} : child)};
}
function treeNodes(node) {
  return node && typeof node === 'object' ? [node, ...(node.children || []).flatMap(treeNodes)] : [];
}
function treeText(node) {return treeNodes(node).map(item => item.text || '').join('');}
// Vue global registration caches a constructor on the original options.
// Page-local enhancements must not inherit that stale constructor.
requireModule(341)._Ctor = {0: function OriginalGlobalPicker() {}};
const components = {};
for (const [name, entry] of Object.entries(definitions)) components[name] = requireModule(entry);
function makeInstance(name) {
  const component = components[name];
  const instance = {$t: key => key};
  Object.assign(instance, component.data.call(instance));
  const requests = [], jumps = [], validations = [];
  const table = {opt: instance.tableOptions};
  Object.assign(table, tableComponent.data.call(table), {
    $http: {post: async (_url, request) => {
      requests.push(JSON.parse(JSON.stringify(request)));
      const [offset, size] = request.param.limit.split(',').map(Number);
      const rows = Array.from({length: 24}, (_, i) => ({id: 24 - i}));
      return {data: {Data: {data: rows.slice(offset, offset + size), total: rows.length}}, headers: {'x-timestamp': '1'}};
    }},
    $emit: () => {}, globalBus: {$emit: () => {}},
  });
  for (const key of ['loadData', 'reload', 'changePage']) table[key] = tableMethods[key].bind(table);
  // Start from the real state created by visiting page two, including its row offset.
  table.changePage(2);
  const pagination = {
    get opt() {return table.paginationOptions;},
    $t: key => key === 'common.dtable.records' ? '共{0}条 当前显示{1}条' : key,
    $emit: (event, value) => {
      if (event === 'changePage') {
        table.changePage(value);
        // Vue runs this real watcher after changePage replaces paginationOptions.
        tableComponent.watch.paginationOptions.call(table);
      }
    },
  };
  Object.assign(pagination, paginationComponent.data.call(pagination));
  for (const key of ['changeCurrent', 'changePage']) pagination[key] = paginationComponent.methods[key].bind(pagination);
  pagination.changeJumpPageNum = page => {
    jumps.push(page);
    paginationComponent.methods.changeJumpPageNum.call(pagination, page);
  };
  table.$refs = {dpagination: pagination};
  const saves = [];
  Object.assign(instance, {
    $refs: {dtable: table},
    $validator: {validateAll: async value => {validations.push(value); return true;}},
    $http: {post: async (_url, request) => {
      saves.push(JSON.parse(JSON.stringify(request)));
      return {data: {Result: 30000, Data: {interface: [['wan1', '主线'], ['wg2', '备用']], syn_proxy: 0}}};
    }},
    $set: (object, key, value) => {object[key] = value;},
    $createElement: createElement, _c: createElement, _v: text => ({text, data: {}}), _s: String,
    _e: () => ({isComment: true, data: {}}), _l: (items, callback) => (items || []).map(callback),
    errors: {has: () => false, first: () => ''}, globalBus: {$emit: () => {}},
    interfaces: [['wan1', '主线'], ['wg2', '备用']], showTable: true,
  });
  instance._self = instance;
  for (const [key, method] of Object.entries(component.methods)) instance[key] = method.bind(instance);
  for (const [key, compute] of Object.entries(component.computed || {})) Object.defineProperty(instance, key, {get: compute.bind(instance)});
  return {instance, component, table, pagination, saves, requests, jumps, validations};
}
function completeForm(instance, name) {
  Object.assign(instance.tableForm, {interface: 'wg2', week: '1234567', time: '00:00-23:59',
    protocol: 'tcp', app_proto: '4010374', domain: 'example.com', nr_dns: '1.1.1.1',
    upiface: 'wan1', downiface: 'wan1', src_addr: '198.18.1.2/32', dst_addr: '', comment: 'UI test'});
  if (name === 'port') instance.tableForm.type = 0;
}
async function flush() {await new Promise(resolve => setImmediate(resolve));}
async function checkSavePagination(name, operation) {
  const x = makeInstance(name);
  x.instance.newTableRow(); completeForm(x.instance, name);
  if (operation !== 'add') {
    const row = {...x.instance.tableForm, id: 17};
    if (operation === 'copy') x.instance.copyTableRow(row);
    else x.instance.editTableRow(row);
  }
  await x.instance.saveForm(); await flush();
  assert.equal(x.saves.length, 1, name + '/' + operation + ': one save');
  assert.equal(x.saves[0].action, operation === 'edit' ? 'edit' : 'add');
  assert.equal(x.requests.length, 1, name + '/' + operation + ': table refresh');
  assert.equal(x.requests[0].param.limit, operation === 'edit' ? '20,20' : '0,20', name + '/' + operation + ': page');
  assert.deepEqual(x.jumps, operation === 'edit' ? [] : [1]);
  assert.equal(x.pagination.current, operation === 'edit' ? '共24条 当前显示21-24条' : '共24条 当前显示1-20条', name + '/' + operation + ': footer range');
  assert.equal(x.pagination.jumpPage, operation === 'edit' ? 2 : 1, name + '/' + operation + ': page input');
  assert.equal(x.table.paginationOptions.currentPage, operation === 'edit' ? 2 : 1, name + '/' + operation + ': current page state');
  assert.equal(x.table.number_page, operation === 'edit' ? 20 : 0, name + '/' + operation + ': row offset state');
  assert.equal(x.requests[0].param.ORDER_BY, 'id');
  assert.equal(x.requests[0].param.ORDER, 'desc');
  assert.equal(x.instance.tableRowEditing, false);
  // The next ordinary refresh must stay on the displayed page, not silently reload page two.
  x.table.reload(); await flush();
  assert.equal(x.requests.at(-1).param.limit, operation === 'edit' ? '20,20' : '0,20', name + '/' + operation + ': subsequent refresh');
  assert.equal(x.pagination.current, operation === 'edit' ? '共24条 当前显示21-24条' : '共24条 当前显示1-20条');
  if (operation !== 'edit') {
    const count = x.requests.length;
    x.pagination.changePage(2); await flush();
    assert.equal(x.requests.length, count + 1, name + '/' + operation + ': page two remains selectable');
    assert.equal(x.requests.at(-1).param.limit, '20,20');
    assert.equal(x.pagination.jumpPage, 2);
    assert.equal(x.pagination.current, '共24条 当前显示21-24条');
  }
}
async function main() {
  for (const name of Object.keys(definitions)) {
    await checkSavePagination(name, 'add');
    await checkSavePagination(name, 'edit');
    if (name !== 'updown') await checkSavePagination(name, 'copy');
  }
  for (const name of ['port', 'protocol']) {
    const x = makeInstance(name);
    x.instance.newTableRow();
    assert.equal(x.instance.tableForm.mode, 0, name + ': native new rule load mode');
    assert.equal(x.instance.tableForm.iface_band, 0, name + ': native new rule permits failover');
    completeForm(x.instance, name);
    Object.assign(x.instance.tableForm, {id: 7, interface: 'wan1,wg2', mode: 3, iface_band: 1});
    const nodes = treeNodes(x.component.render.call(x.instance, createElement));
    const select = nodes.find(node => node.tag === 'multi-interface-select');
    assert.ok(select, name + ': native multiple exit picker is restored');
    assert.equal(select.data.model.value, 'wan1,wg2');
    assert.notEqual((select.data.attrs || {}).single, true);
    const binding = nodes.find(node => (node.data.model || {}).expression === 'tableForm.iface_band');
    assert.ok(binding, name + ': native line binding switch is restored');
    assert.equal(binding.data.attrs.opt.on, 1);
    assert.equal(binding.data.attrs.opt.off, 0);
    const mode = nodes.find(node => node.tag === 'select' && (node.data.directives || []).some(d => d.expression === 'tableForm.mode'));
    assert.ok(mode, name + ': native load modes are restored');
    assert.deepEqual(Array.from(mode.children.filter(node => node.tag === 'option'), node => node.data.attrs.value), name === 'port' ? ['0', '1', '2', '3', '4', '6'] : ['0', '1', '3']);
    assert.equal(nodes.some(node => (node.data.attrs || {}).id === 'routing-fixed-exit'), false);
    await x.instance.saveForm(); await flush();
    assert.equal(x.saves.length, 1, name + ': multiple exits may be saved');
    assert.equal(x.saves[0].param.interface, 'wan1,wg2');
    assert.equal(x.saves[0].param.mode, 3);
    assert.equal(x.saves[0].param.iface_band, 1);
    assert.equal(x.requests[0].param.limit, '20,20', 'editing preserves the current page');
    // Exercise the real native picker lifecycle and its page-local watchers.
    const picker = x.component.components.MultiInterfaceSelect;
    assert.equal(Object.hasOwn(picker, '_Ctor'), false, 'page-local picker does not reuse the globally cached constructor');
    const instance = {value: 'wan1,wg2', interfaces: [], $t: key => key, $emit: (event, value) => {
      if (event === 'input') x.instance.tableForm.interface = value;
    }};
    Object.assign(instance, picker.data.call(instance));
    for (const [key, method] of Object.entries(picker.methods)) instance[key] = method.bind(instance);
    picker.created.call(instance);
    assert.equal(instance.val, 'wan1,wg2');
    assert.deepEqual(Array.from(instance.newVal), ['wan1', 'wg2']);
    picker.watch.interfaces.call(instance, [['wan1', 'main'], ['wg2', 'backup']]);
    assert.equal(instance.newInterfaces.length, 2);
    assert.deepEqual(Array.from(instance.newVal), ['wan1', 'wg2'], 'late options retain selected exits');
    picker.watch.interfaces.call(instance, [['wan1', 'main']]);
    assert.equal(instance.val, 'wan1,wg2', 'unavailable saved exits stay visible');
    picker.watch.value.call(instance, 'wg2');
    assert.equal(instance.val, 'wg2');
    assert.deepEqual(Array.from(instance.newVal), ['wg2'], 'editing another value updates the selection');
    instance.newVal = ['wg2', 'wan1']; instance.confirmSelect();
    assert.equal(x.instance.tableForm.interface, 'wg2,wan1', 'native picker emits every selected exit');
  }
  // Port next-hop rules keep their original form and are not treated as exit selectors.
  const nextHop = makeInstance('port'); nextHop.instance.newTableRow(); completeForm(nextHop.instance, 'port');
  Object.assign(nextHop.instance.tableForm, {type: 1, nexthop: '192.0.2.1', interface: 'wan1,wg2'});
  const nextNodes = treeNodes(nextHop.component.render.call(nextHop.instance, createElement));
  assert.ok(nextNodes.some(node => (node.data.directives || []).some(d => d.expression === 'tableForm.nexthop')));
  nextHop.instance.saveForm(); await flush(); assert.equal(nextHop.saves[0].param.nexthop, '192.0.2.1');
  // initPage must work with the obsolete multi-select ref removed.
  const protocol = makeInstance('protocol'); protocol.instance.initPage(); await flush();
  assert.deepEqual(protocol.instance.interfaces, [['wan1', '主线'], ['wg2', '备用']]);
  const domain = makeInstance('domain');
  domain.instance.newTableRow(); completeForm(domain.instance, 'domain');
  assert.equal(domain.instance.tableForm.iface_band, 0, 'new domain rules permit failover');
  assert.equal(domain.instance.tableForm.mode, undefined, 'domain has no new load-mode field');
  const legacy = {...domain.instance.tableForm, id: 19, interface: 'wg2,wan1'};
  delete legacy.iface_band;
  domain.instance.editTableRow(legacy);
  assert.equal(domain.instance.tableForm.iface_band, 1, 'legacy domain rules keep their blocking policy');
  assert.equal(Object.hasOwn(legacy, 'iface_band'), false, 'editing does not mutate a stored legacy row');
  domain.instance.copyTableRow(legacy);
  assert.equal(domain.instance.tableForm.iface_band, 1, 'copy retains legacy blocking policy');
  for (const value of [0, 1, '0', '1']) {
    domain.instance.editTableRow({...legacy, iface_band: value});
    assert.equal(domain.instance.tableForm.iface_band, value, 'explicit domain policy is preserved');
    domain.instance.copyTableRow({...legacy, iface_band: value});
    assert.equal(domain.instance.tableForm.iface_band, value, 'copy preserves explicit domain policy');
  }
  domain.instance.editTableRow({...legacy, iface_band: 0});
  const bindingNodes = treeNodes(domain.component.render.call(domain.instance, createElement));
  assert.ok(bindingNodes.some(node => node.tag === 'multi-interface-select' && node.data.model.value === 'wg2,wan1'));
  assert.ok(bindingNodes.some(node => (node.data.model || {}).expression === 'tableForm.iface_band'));
  domain.instance.tableForm.nr_route = 'dns_only';
  const dnsOnlyNodes = treeNodes(domain.component.render.call(domain.instance, createElement));
  assert.equal(dnsOnlyNodes.some(node => (node.data.model || {}).expression === 'tableForm.iface_band'), false, 'DNS-only hides access failover control');
  await domain.instance.saveForm(); await flush();
  assert.equal(domain.saves[0].param.interface, 'wg2,wan1', 'domain saves every exit in its original order');
  assert.equal(domain.saves[0].param.iface_band, 0, 'hidden DNS-only policy is not changed');
  assert.equal(domain.saves[0].param.mode, undefined);
  domain.instance.initPage(); await flush();
  assert.deepEqual(domain.instance.interfaces, [['wan1', '主线'], ['wg2', '备用']], 'domain async load works without an editor ref');
  const column = domain.instance.tableOptions.columns.find(column => column.name === 'domain');
  assert.match(column.dataFunction('group.invalid', {nr_group: 'cn'}), /阶段 1 · 显式域名.*中国大陆域名组/);
  assert.match(column.dataFunction('group.invalid', {nr_group: 'fallback', nr_target: 'cn'}), /阶段 2 · 未匹配后兜底.*大陆优先，未命中阻断/);
  assert.match(column.dataFunction('example.com', {nr_group: 'manual'}), /阶段 1 · 显式域名.*example.com/);
  const domainTree = domain.component.render.call(domain.instance, createElement);
  const domainNodes = treeNodes(domainTree);
  const noticeIndex = domainNodes.findIndex(node => node.data.attrs && node.data.attrs.id === 'routing-stage-order');
  const tableIndex = domainNodes.findIndex(node => node.data.ref === 'dtable');
  assert.ok(noticeIndex >= 0 && noticeIndex < tableIndex, 'stages must be visible before the table');
  const notice = treeText(domainNodes[noticeIndex]);
  assert.match(notice, /兜底即使显示在上方，也在全部显式域名之后执行/);
  assert.match(notice, /同一阶段内从上到下/);
  assert.match(notice, /源地址只是匹配条件/);
  console.log('PASS: four real page save methods + real DTable/DPagination state and footer; add/copy/edit; native multi-exit controls and load/binding fields; async picker state and multi-exit save; domain stages and order notice.');
}
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
module.exports = {makeInstance, createElement, treeNodes, treeText};
