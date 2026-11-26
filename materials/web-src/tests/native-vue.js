'use strict';

// Load the actual Vue runtime embedded in the pinned firmware webpack vendor chunk.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const zlib = require('node:zlib');
module.exports = function loadNativeVue(vendorPath) {
  assert(vendorPath, 'Provide the path to the native vendor JS or JS.GZ');
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
  assert.equal(vueExports.default.version, '2.4.2');
  return vueExports.default;
};
