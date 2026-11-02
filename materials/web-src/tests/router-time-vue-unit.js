'use strict';
// Use the actual vendor bundle from the fixed firmware inputs, not a newer
// standalone Vue build: the main application uses webpack module 10 (2.4.2).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const zlib = require('node:zlib');
const vendorPath = process.argv[2];
assert(vendorPath, 'Usage: node router-time-vue-unit.js /path/to/native/vendor.9963e3172df892e7087c.js[.gz]');
let vendor = fs.readFileSync(vendorPath);
if (vendorPath.endsWith('.gz')) vendor = zlib.gunzipSync(vendor);
let definitions;
vm.runInNewContext(vendor.toString('utf8'), {
  webpackJsonp: (chunks, modules) => definitions = modules, setTimeout, clearTimeout
});
const vueExports = {};
definitions[10]({}, vueExports, id => {
  if (id === 69) return global;
  if (id === 45) return Promise;
  throw Error('Unexpected native Vue dependency ' + id);
});
const Vue = vueExports.default;
assert.equal(Vue.version, '2.4.2');
const window = {headers: {}, customError() {}};
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/router-time.js'), 'utf8'), {window});
const api = window.RouterTime;
api.install(Vue);
api.setTimezone('0800');
let count = 0;
function test(name, body) {try {body(); count++;} catch (error) {error.message = name + ': ' + error.message; throw error;}}
const view = new Vue({data: {startTime: '2024-03-10 02:30:17', endTime: ''}});
for (const [field, label] of [['startTime', '开始时间'], ['endTime', '结束时间']]) {
  test('native compiled _c renders literal ' + label, () => {
    const vnode = api.renderPicker(view, view._c, field, label, true);
    assert.equal(vnode.tag, 'label');
    assert.equal(vnode.children[0].tag, 'span');
    assert.equal(vnode.children[0].data.domProps.textContent, label + '：');
    assert.equal(vnode.children[0].data.style.display, 'inline-block');
    assert.equal(vnode.children[1].data.attrs.type, 'datetime-local');
    assert.equal(vnode.children[1].data.attrs['aria-label'], label);
  });
}
test('native compiled _c preserves manual picker and second precision', () => {
  const manual = new Vue({data: {timeset: '2024-03-10 02:30:17', tableForm: {time_zone_full: '0800'}}});
  const vnode = api.renderPicker(manual, manual._c, 'timeset', '设置时间', false);
  assert.equal(vnode.tag, 'input');
  assert.equal(vnode.data.domProps.value, '2024-03-10T02:30:17');
  assert.equal(vnode.data.attrs.step, '1');
});
(async function () {
  let changed = '', searches = 0, boundary;
  view.$watch(() => api.format(1704067200), value => {changed = value;});
  view.search = function () {searches++; boundary = api.range(view).start;};
  api.bind(view);
  api.setTimezone('0545');
  await new Promise(resolve => Vue.nextTick(resolve));
  test('native Vue tracks router timezone in current display', () => assert.equal(changed, '2024-01-01 05:45:00'));
  test('native Vue recalculates active civil filter', () => {
    assert.equal(searches, 1);
    assert.equal(boundary, Date.parse('2024-03-10T02:30:17+05:45') / 1000);
  });
  view.$destroy();
  api.setTimezone('-0330');
  await new Promise(resolve => Vue.nextTick(resolve));
  test('native Vue removes watchers on page destruction', () => assert.equal(searches, 1));
  console.log(`PASS ${count} actual Vue ${Vue.version} compiled _c and reactivity cases`);
})().catch(error => {console.error(error); process.exitCode = 1;});
