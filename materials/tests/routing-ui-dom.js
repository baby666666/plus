/* Browser-side isolated component checks. Open only through the local fixture server. */
(async function () {
  'use strict';
  const report = document.getElementById('result');
  const results = [], failures = [];
  const errors = [];
  window.registerFixtureModules([999], {
    78: function (module) {module.exports = {a: {apiUrl: '/fixture/call'}};},
    320999: function (_module, _exports, require) {window.fixtureRequire = require;},
  }, [320999]);
  const require = window.fixtureRequire;
  const Vue = require(10).default;
  let translations = await fetch('i18n.json').then(response => response.json());
  const localeDictionaries = {'zh-CN': translations};
  for (const locale of ['zh-TW', 'en-US']) localeDictionaries[locale] = await fetch(locale + '.json').then(response => response.json());
  Vue.config.productionTip = false;
  Vue.config.errorHandler = error => {errors.push(String(error));};
  Vue.config.warnHandler = function () {};
  const clone = value => JSON.parse(JSON.stringify(value));
  window.isPhone = false;
  window.langAry = ['zh-CN', 'en-US', 'zh-TW'];
  window.copyObj = (_direction, value) => clone(value);
  window.copyAry = (_direction, value) => clone(value);
  window.isObject = value => value && typeof value === 'object';
  window.customError = message => {errors.push(message);};
  window.customSuccess = function () {};
  window.first = {auto_refresh_rate: 1};
  window.headers = {ok: true, xArch: 'x86', xLang: 'zh-CN'};
  window.getHeaders = callback => callback(window.headers, window.first);
  Vue.prototype.$t = key => {
    let value = translations;
    for (const part of key.split('.')) value = value && value[part];
    return typeof value === 'string' ? value : key;
  };
  window.$t = Vue.prototype.$t;
  Vue.prototype.errors = {has: () => false, first: () => ''};
  Vue.prototype.$validator = {validateAll: () => Promise.resolve(true)};
  Vue.prototype.globalBus = new Vue();
  Vue.directive('validate', function () {});
  Vue.component('DTable', require(339));
  Vue.component('MultiInterfaceSelect', require(341));
  Vue.component('DSwitch', require(338));
  Vue.component('ElDialog', {props: ['value'], render: function (h) {return this.value ? h('div', {class: 'fixture-dialog'}, this.$slots.default) : h('span');}});
  const inert = {props: ['value', 'opt'], render: h => h('span')};
  for (const name of ['SubTitleSection', 'IpGroup', 'WeekdaySelect']) Vue.component(name, inert);
  const components = {domain: require(846), port: require(856), protocol: require(857), updown: require(847)};
  let mounted, host, requests, rows;
  const tick = () => new Promise(resolve => Vue.nextTick(() => setTimeout(resolve, 20)));
  function record(name, condition, details) {
    results.push((condition ? 'PASS ' : 'FAIL ') + name + (details ? ': ' + details : ''));
    if (!condition) failures.push(name);
    report.textContent = results.join('\n');
  }
  function row(id) {
    return {id, interface: 'wg2', protocol: 'tcp', type: 0, dst_type: 0, app_proto: '4010374',
      src_addr: '198.18.1.2/32', dst_addr: '', src_port: '', dst_port: '443', area_code: '',
      domain: 'example.com', nr_group: 'manual', nr_dns: '1.1.1.1', nr_route: 'fixed', nr_target: 'any',
      nr_ingress: '', week: '1234567', time: '00:00-23:59', enabled: 'yes',
      upiface: 'wan1', downiface: 'wan1', comment: 'Fixture ' + id, mode: 0, iface_band: 0};
  }
  const api = {post: async (_url, request) => {
    requests.push(clone(request));
    if (request.action === 'add') rows.unshift({...clone(request.param), id: rows.length + 1});
    if (request.action === 'edit') {
      const at = rows.findIndex(r => r.id === request.param.id);
      if (at >= 0) rows[at] = clone(request.param);
    }
    const [offset, size] = ((request.param || {}).limit || '0,20').split(',').map(Number);
    return {headers: {'x-timestamp': '1'}, data: {Result: 30000, Data: {
      data: clone(rows.slice(offset, offset + size)), total: rows.length,
      interface: [['wan1', '主线'], ['wg2', '备用']], protocol: ['any', 'tcp', 'udp'], syn_proxy: 0,
    }}};
  }, get: async () => ({data: []})};
  Vue.prototype.$http = api;
  async function mount(name, pageSize) {
    if (host) host.$destroy();
    document.getElementById('mount').innerHTML = '<div id="fixture-page"></div>';
    requests = []; rows = Array.from({length: 23}, (_, i) => row(23 - i)); errors.length = 0;
    const original = components[name];
    const component = {...original, created: undefined, mounted: undefined, beforeDestroy: undefined,
      components: {...original.components, AreaSelect: inert, ProtocolSelect: inert},
      data: function () {
        const data = original.data.call(this);
        data.tableOptions.pagination.rowsPerPage = pageSize;
        data.showTable = true;
        data.interfaces = [['wan1', '主线'], ['wg2', '备用']];
        return data;
      }};
    host = new Vue({render: h => h(component, {ref: 'page'})}).$mount('#fixture-page');
    mounted = host.$refs.page;
    await tick();
    return mounted;
  }
  function paginationText(page) {return page.$refs.dtable.$refs.dpagination.$el.textContent.replace(/\s/g, '');}
  function currentText(page) {return page.$refs.dtable.$refs.dpagination.current.replace(/\s/g, '');}
  async function scenario(name, operation, pageSize) {
    const page = await mount(name, pageSize);
    const table = page.$refs.dtable;
    table.$refs.dpagination.changePage(2); await tick();
    const oldOffset = pageSize;
    if (operation === 'add') {page.newTableRow(); Object.assign(page.tableForm, row(undefined));}
    else if (operation === 'copy') page.copyTableRow(row(2));
    else page.editTableRow(row(2));
    await tick();
    const before = requests.length;
    await page.saveForm(); await tick();
    const listCalls = requests.slice(before).filter(request => request.action === 'show' && (request.param || {}).TYPE === 'total,data');
    const add = operation !== 'edit', offset = add ? 0 : oldOffset;
    const expectedStart = offset + 1, expectedEnd = Math.min(offset + pageSize, rows.length);
    const expectedRange = expectedStart === expectedEnd ? String(expectedStart) : expectedStart + '-' + expectedEnd;
    record(name + '/' + operation + '/' + pageSize + ' rows: one Vue refresh', listCalls.length === 1, String(listCalls.length));
    record(name + '/' + operation + '/' + pageSize + ' rows: DOM footer', currentText(page).includes(expectedRange) && paginationText(page).includes(expectedRange), currentText(page));
    record(name + '/' + operation + '/' + pageSize + ' rows: state and rows', table.number_page === offset && table.paginationOptions.currentPage === (add ? 1 : 2) && table.listData[0].id === rows[offset].id);
    table.reload(); await tick();
    record(name + '/' + operation + '/' + pageSize + ' rows: subsequent refresh', currentText(page).includes(expectedRange) && table.listData[0].id === rows[offset].id);
    if (add) {
      table.$refs.dpagination.changePage(2); await tick();
      record(name + '/' + operation + '/' + pageSize + ' rows: page two clickable', table.number_page === pageSize && table.paginationOptions.currentPage === 2);
    }
    record(name + '/' + operation + '/' + pageSize + ' rows: no Vue errors', errors.length === 0, errors.join(';'));
  }
  function childNamed(page, name) {
    for (const child of page.$children) {
      if (child.$options.name === name) return child;
      const nested = childNamed(child, name); if (nested) return nested;
    }
  }
  function exitState(page) {
    const picker = childNamed(page, 'RoutingMultiInterfaceSelect');
    return {value: picker && picker.$refs.ipt.value, model: page.tableForm.interface,
      selected: picker && picker.newVal.slice(), options: picker && picker.newInterfaces.map(item => item[0])};
  }
  async function openPicker(page) {
    const picker = childNamed(page, 'RoutingMultiInterfaceSelect');
    picker.$refs.ipt.click(); await tick(); return picker;
  }
  async function loadInterfaces(page, name) {
    if (name === 'port') page.getInterfaceAndProtocol(); else page.initPage();
    await tick();
  }
  async function exitScenario(name) {
    const page = await mount(name, 20);
    page.interfaces = []; page.editTableRow(row(2)); await tick();
    record(name + ': unavailable current exit retained in DOM', exitState(page).value === 'wg2' && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    await loadInterfaces(page, name);
    let picker = await openPicker(page);
    record(name + ': async interface choices retain current exit', exitState(page).value === 'wg2' && picker.$el.querySelector('input.chk_list[value="wg2"]').checked && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    await new Promise(resolve => setTimeout(resolve, 250)); await tick();
    record(name + ': async choice remains selected after additional settling', exitState(page).value === 'wg2' && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    page.interfaces = [['wg2', '备用'], ['wan1', '主线']]; await tick();
    record(name + ': reordered interfaces preserve current choice', exitState(page).value === 'wg2' && picker.$el.querySelector('input.chk_list[value="wg2"]').checked, JSON.stringify(exitState(page)));
    page.interfaces = [['wan1', '主线']]; await tick();
    record(name + ': removed interface remains visible without model truncation', exitState(page).value === 'wg2' && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    await loadInterfaces(page, name);
    record(name + ': restored interface remains selected', picker.$el.querySelector('input.chk_list[value="wg2"]').checked && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    page.tableRowEditing = false; await tick();
    const stored = rows.find(r => r.id === 2); Object.assign(stored, {interface: 'wg2,wan1', mode: 3, iface_band: 1});
    page.editTableRow(stored); await tick(); picker = await openPicker(page);
    record(name + ': stored multiple exits retain their order', exitState(page).value === 'wg2,wan1' && page.tableForm.interface === 'wg2,wan1' && Array.from(picker.$el.querySelectorAll('input.chk_list')).every(input => input.checked), JSON.stringify(exitState(page)));
    page.tableRowEditing = false; await tick();
    record(name + ': cancel retains original multiple exit rule', stored.interface === 'wg2,wan1' && stored.mode === 3 && stored.iface_band === 1);
    page.editTableRow(stored); await tick();
    let beforeSave = requests.length;
    await page.saveForm(); await tick();
    let saves = requests.slice(beforeSave).filter(request => request.action === 'edit');
    record(name + ': untouched multiple exits save without truncation', saves.length === 1 && saves[0].param.interface === 'wg2,wan1' && saves[0].param.mode === 3 && saves[0].param.iface_band === 1);
    page.editTableRow(rows.find(r => r.id === 2)); await tick(); picker = await openPicker(page);
    picker.$el.querySelector('input.chk_list[value="wan1"]').click(); await tick();
    picker.$el.querySelector('button.btn_confirm').click(); await tick();
    record(name + ': native multiple picker confirms changed choice', exitState(page).value === 'wg2' && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    await new Promise(resolve => setTimeout(resolve, 250)); await tick();
    record(name + ': changed choice remains selected after settling', exitState(page).value === 'wg2' && page.tableForm.interface === 'wg2', JSON.stringify(exitState(page)));
    const mode = Array.from(page.$el.querySelectorAll('select')).find(select => Array.from(select.options).some(option => option.value === '3'));
    const expectedModes = name === 'port' ? ['0', '1', '2', '3', '4', '6'] : ['0', '1', '3'];
    record(name + ': native load modes remain available', JSON.stringify(Array.from(mode.options, option => option.value)) === JSON.stringify(expectedModes));
    mode.value = '1'; mode.dispatchEvent(new Event('change', {bubbles: true})); await tick();
    record(name + ': native load mode changes model', String(page.tableForm.mode) === '1');
    const binding = Array.from(page.$el.querySelectorAll('input[type="checkbox"]')).find(input => input.getAttribute('switchtitle') === translations.network.flow.line_bind);
    record(name + ': native line binding shows saved blocking choice', binding && binding.checked && page.tableForm.iface_band === 1);
    binding.click(); await tick();
    record(name + ': disabling native line binding allows failover', !binding.checked && page.tableForm.iface_band === 0);
    beforeSave = requests.length;
    await page.saveForm(); await tick();
    saves = requests.slice(beforeSave).filter(request => request.action === 'edit');
    record(name + ': selected exits mode and failure policy save together', saves.length === 1 && saves[0].param.interface === 'wg2' && String(saves[0].param.mode) === '1' && saves[0].param.iface_band === 0);
    record(name + ': edited rule closes without Vue errors', !page.tableRowEditing && errors.length === 0, errors.join(';'));
  }
  async function domainPolicyScenario() {
    const page = await mount('domain', 20);
    page.newTableRow(); await tick();
    let binding = childNamed(page, 'DSwitch');
    record('domain: new rule permits failover', page.tableForm.iface_band === 0 && binding && !binding.$el.querySelector('input').checked);
    page.tableRowEditing = false; await tick();
    const stored = rows.find(r => r.id === 2);
    stored.interface = 'wg2,wan1'; delete stored.iface_band; delete stored.mode;
    page.interfaces = []; page.editTableRow(stored); await tick();
    binding = childNamed(page, 'DSwitch');
    record('domain: legacy missing policy displays blocking', page.tableForm.iface_band === 1 && binding.$el.querySelector('input').checked && !Object.hasOwn(stored, 'iface_band'));
    record('domain: multiple exits remain visible before options arrive', exitState(page).value === 'wg2,wan1' && page.tableForm.interface === 'wg2,wan1', JSON.stringify(exitState(page)));
    await loadInterfaces(page, 'domain');
    const picker = await openPicker(page);
    record('domain: async options preserve every selected exit', exitState(page).value === 'wg2,wan1' && Array.from(picker.$el.querySelectorAll('input.chk_list')).length === 2 && Array.from(picker.$el.querySelectorAll('input.chk_list')).every(input => input.checked), JSON.stringify(exitState(page)));
    page.tableRowEditing = false; await tick();
    page.copyTableRow(stored); await tick();
    record('domain: copied legacy rule keeps blocking policy', page.tableForm.id === undefined && page.tableForm.iface_band === 1);
    page.tableRowEditing = false; await tick();
    page.editTableRow({...stored, iface_band: 0}); await tick();
    binding = childNamed(page, 'DSwitch');
    record('domain: explicit allow-failover policy stays disabled', page.tableForm.iface_band === 0 && !binding.$el.querySelector('input').checked);
    binding.$el.querySelector('input').click(); await tick();
    record('domain: line binding toggles the saved policy', page.tableForm.iface_band === 1 && binding.$el.querySelector('input').checked);
    page.tableForm.nr_route = 'dns_only'; await tick();
    record('domain: DNS-only hides binding without changing it', !childNamed(page, 'DSwitch') && page.tableForm.iface_band === 1);
    page.tableForm.nr_route = 'fixed'; await tick();
    record('domain: access routing restores the retained policy', childNamed(page, 'DSwitch').$el.querySelector('input').checked && page.tableForm.iface_band === 1);
    const before = requests.length;
    await page.saveForm(); await tick();
    const saves = requests.slice(before).filter(request => request.action === 'edit');
    record('domain: ordered exits and explicit binding save together', saves.length === 1 && saves[0].param.interface === 'wg2,wan1' && saves[0].param.iface_band === 1 && saves[0].param.mode === undefined);
    record('domain: restored controls produce no Vue errors', errors.length === 0 && !page.tableRowEditing, errors.join(';'));
  }
  const previewNames = {domain: '域名', port: '端口', protocol: '协议'};
  function busy(value) {
    document.getElementById('run').disabled = value;
    for (const name of Object.keys(previewNames)) document.getElementById('preview-' + name).disabled = value;
  }
  for (const name of Object.keys(previewNames)) {
    document.getElementById('preview-' + name).onclick = async function () {
      busy(true);
      try {
        const page = await mount(name, 20);
        const draft = {...row(2), interface: 'wg2,wan1', iface_band: 1, comment: '离线界面预览'};
        if (name === 'domain') {delete draft.mode; draft.nr_group = 'cn';}
        page.editTableRow(draft); await tick();
        document.getElementById('preview-status').textContent = previewNames[name] + '分流：真实编辑组件，本地样例数据。选择和保存仅影响本页面内存。';
        document.getElementById('results').open = false;
      } finally {busy(false);}
    };
  }
  async function runtimeStatusScenario() {
    const page = await mount('domain', 20);
    page.nrBusy = false; page.edBusy = false; page.nrRuleSaving = false;
    let calls = 0;
    page.nrApi = async () => {calls++; return {runtime_status: {
      version: 1, phase: 'running', busy: false, dns_front: 'running',
      exits: [{interface: 'wg3', health: 'failed', probe_age_seconds: 0, handshake_age_seconds: 25},
              {interface: 'wan1', health: 'reachable', probe_age_seconds: 2, handshake_age_seconds: null}],
      workers: [], quarantine: {available: true, entries: 4, remaining_seconds: 0}
    }};};
    await page.rsRefresh();
    for (const locale of ['zh-CN', 'zh-TW', 'en-US']) {
      translations = localeDictionaries[locale]; page.$forceUpdate(); await tick();
      const panel = page.$el.querySelector('#routing-runtime-status');
      const text = panel.textContent;
      const cells = Array.from(panel.querySelectorAll('tbody tr')).map(row => Array.from(row.querySelectorAll('td')).map(cell => cell.textContent));
      const unit = locale === 'en-US' ? ' seconds ago' : ' 秒前';
      record(locale + ': actual Vue DOM shows zero and nonzero ages', cells[0][2] === '0' + unit && cells[0][3] === '25' + unit && cells[1][2] === '2' + unit);
      record(locale + ': missing handshake is not zero', cells[1][3] === translations.routing_runtime.not_available);
      record(locale + ': status DOM has no unresolved placeholders', !/\{(?:seconds|count)\}/.test(text));
      record(locale + ': protection count and zero remaining time render', text.includes(translations.routing_runtime.quarantine_entries.replace('{count}', '4')) && text.includes(translations.routing_runtime.quarantine_remaining.replace('{seconds}', '0')));
    }
    record('runtime status: language switching makes no new request', calls === 1);
    record('runtime status: no Vue errors', errors.length === 0, errors.join(';'));
    translations = localeDictionaries['zh-CN']; page.$forceUpdate(); await tick();
  }
  busy(false);
  report.textContent = 'Ready. Press Run checks. Only local fixture components and data are used.';
  document.getElementById('run').onclick = async function () {
    busy(true); results.length = 0; failures.length = 0;
    document.getElementById('preview-status').textContent = '';
    document.getElementById('results').open = true;
    try {
      for (const name of Object.keys(components)) for (const pageSize of [10, 20]) {
        for (const operation of ['add', 'edit', ...(name === 'updown' ? [] : ['copy'])]) await scenario(name, operation, pageSize);
      }
      for (const name of ['port', 'protocol']) await exitScenario(name);
      await domainPolicyScenario();
      await runtimeStatusScenario();
    } catch (error) {record('fixture execution', false, error.stack || String(error));}
    report.textContent = (failures.length ? 'FAILED ' + failures.length : 'PASSED') + ' / ' + results.length + ' checks\n' + results.join('\n');
    report.className = failures.length ? 'failed' : 'passed';
    busy(false);
  };
})().catch(error => {document.getElementById('result').textContent = 'Fixture initialization failed: ' + (error.stack || error);});
