#!/usr/bin/env python3
"""Read-only screenshots and checks of two booted NativeRouting management UIs.

Run as a child of the process hosting the test VMs so their loopback forwards are
in the same network namespace. This is the real firmware page, not a component
fixture. The test-image-only default admin/admin login is used through the UI.
No configuration is saved; non-read Action calls are blocked before transmission.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[2]
FIND_PAGE = r"""function findPage() {
    var element=document.querySelector('.wg-page'), first=element && element.__vue__;
    var app=document.querySelector('#app');
    var queue=[first,app && app.__vue__],seen=[];
    while(queue.length){
        var value=queue.shift();
        if(!value || seen.indexOf(value)>=0)continue;
        seen.push(value);
        if(typeof value.editTableRow1==='function' && value.$refs && value.$refs.dtable1)return value;
        if(value.$parent)queue.push(value.$parent);
        queue=queue.concat(value.$children||[]);
    }
    return null;
}"""


def js(expression):
    return '(() => {' + FIND_PAGE + '\n' + expression + '})()'


def require(value, code):
    if not value:
        raise AssertionError(code)


def request_metadata(request):
    try:
        body = request.post_data_json
    except Exception:
        body = None
    if not isinstance(body, dict):
        return {}
    param = body.get('param') if isinstance(body.get('param'), dict) else {}
    return {'function': body.get('func_name', ''), 'action': body.get('action', ''), 'type': param.get('TYPE', '')}


def safe_status(value):
    if not isinstance(value, dict):
        return None
    result = {name: value.get(name) for name in ('connected', 'state', 'last_heartbeat')}
    result['mappings'] = [{name: row.get(name) for name in ('id', 'listening', 'active', 'rx_bytes', 'tx_bytes', 'last_success')}
                          for row in value.get('mappings', []) if isinstance(row, dict)]
    return result


class BrowserCheck:
    def __init__(self, browser, out, report):
        self.browser, self.out, self.report = browser, out, report
        self.phase = 'start'
        self.page = None
        self.role = 'page'

    def capture(self, page, name, scope):
        page.screenshot(path=str(self.out / (name + '.png')), full_page=True,
                        mask=[page.locator('input[type="password"],input[name*="privatekey"],input[name*="PrivateKey"],'
                                           'input[name*="preshared"],input[name*="preShared"],textarea[readonly]')])
        document = page.evaluate(r"""() => {
            var copy=document.documentElement.cloneNode(true);
            copy.querySelectorAll('script').forEach(function(node){node.remove();});
            copy.querySelectorAll('input,textarea').forEach(function(node){
                var key=(node.getAttribute('name')||'')+' '+(node.getAttribute('aria-label')||'');
                if(node.type==='password' || /private|preshared|password|token|client_config|sing-box JSON|HY2 URI/i.test(key)){
                    node.setAttribute('value','[REDACTED]');node.value='[REDACTED]';node.textContent='[REDACTED]';
                }
            });
            return '<!doctype html>\n'+copy.outerHTML;
        }""")
        document = re.sub(r'(?<![A-Za-z0-9])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9])', '[REDACTED-KEY]', document)
        document = re.sub(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', '[REDACTED-CREDENTIAL]', document, flags=re.I)
        (self.out / (name + '.html')).write_text(document)
        if scope and page.locator(scope).count():
            page.locator(scope).first.screenshot(path=str(self.out / (name + '-reverse.png')))

    def login(self, page, base):
        self.phase = self.role + '_login'
        page.goto(base + '/#/login', wait_until='domcontentloaded', timeout=30000)
        password = page.locator('input[type="password"]:visible').first
        password.wait_for(timeout=30000)
        username = page.locator('input[name="username"]:visible,input[name="userName"]:visible,input[type="text"]:visible').first
        username.fill('admin')
        password.fill('admin')
        candidates = page.get_by_role('button', name=re.compile(r'^\s*(登录|登錄|登入|Login|Log in)\s*$', re.I))
        with page.expect_response(lambda response: urlsplit(response.url).path == '/Action/login', timeout=20000) as pending:
            if candidates.count():
                candidates.first.click()
            elif page.locator('[type="submit"]:visible').count():
                page.locator('[type="submit"]:visible').first.click()
            else:
                password.press('Enter')
        response = pending.value.json()
        require(response.get('Result') == 10000, 'native_login_failed')
        page.wait_for_timeout(250)
        self.phase = self.role + '_wireguard_page'
        page.goto(base + '/#/vpn/wireguard-client', wait_until='domcontentloaded', timeout=30000)
        page.locator('.wg-page').wait_for(timeout=30000)
        page.wait_for_function(js('var page=findPage();return !!(page && page.$refs.dtable1 && page.$refs.dtable1.listData);'), timeout=30000)

    def open_peer(self, page, peer_id):
        self.phase = self.role + '_open_peer'
        page.wait_for_function(js('var page=findPage();return page && page.$refs.dtable1.listData.some(function(row){return String(row.id)===' + json.dumps(peer_id) + ';});'), timeout=30000)
        # Invoke the exact read-only native edit action with its current table row.
        # IDs are matched before opening; no replacement data or fixture API is used.
        page.evaluate(js('var page=findPage(),row=page.$refs.dtable1.listData.filter(function(row){return String(row.id)===' +
                         json.dumps(peer_id) + ';})[0];return page.editTableRow1(row);'))
        if self.role == 'center':
            page.wait_for_function(js("var page=findPage(),panel=page && page.$refs.hyrTunnel;return !!(panel && !panel.reading && panel.member && panel.member.reverse && panel.member.reverse.enabled);"), timeout=30000)
            require(page.evaluate(js("var panel=findPage().$refs.hyrTunnel;return panel.transport==='pure_hy2' && panel.reverseUnchanged && panel.reverseRuntime===null;")), 'editor_initial_snapshot_invalid')
        else:
            page.wait_for_function(js("var page=findPage(),site=page && page.wgManagedSite;return !!(site && site.transport==='pure_hy2' && site.reverse && site.reverse.enabled);"), timeout=30000)

    def live_snapshot(self, page, peer_id):
        self.phase = self.role + '_manual_status'
        api_type = 'hyr_status' if self.role == 'center' else 'site_client_status'
        before = page.evaluate(js("var page=findPage(),panel=page.$refs.hyrTunnel;return panel?JSON.stringify(panel.reverseDraft):null;"))
        button = page.get_by_role('button', name='读取连接状态', exact=True)
        button.wait_for(timeout=15000)
        with page.expect_response(lambda response: urlsplit(response.url).path == '/Action/call' and
                                  request_metadata(response.request).get('type') == api_type, timeout=65000) as pending:
            button.click()
        reply = pending.value.json()
        require(reply.get('Result') == 30000, 'manual_status_api_failed')
        rows = reply.get('Data', {}).get(api_type, {}).get('members', [])
        field = 'peer_id' if self.role == 'center' else 'id'
        matches = [row for row in rows if str(row.get(field)) == peer_id]
        require(len(matches) == 1, 'manual_status_identity_mismatch')
        api_status = safe_status(matches[0].get('reverse_status'))
        if self.role == 'center':
            page.wait_for_function(js("var panel=findPage().$refs.hyrTunnel;return !panel.reverseReading && panel.reverseRuntime!==null;"), timeout=15000)
            ui = page.evaluate(js("var panel=findPage().$refs.hyrTunnel;return {runtime:panel.reverseRuntime,running:panel.reverseServiceRunning,count:panel.member.reverse.mappings.length,unchanged:panel.reverseUnchanged,draft:JSON.stringify(panel.reverseDraft)};"))
            require(ui['unchanged'] and ui['draft'] == before, 'manual_status_changed_editor_draft')
            ui.pop('draft', None)
        else:
            page.wait_for_function(js("var site=findPage().wgManagedSite;return !!(site && site.reverse_status);"), timeout=15000)
            ui = page.evaluate(js("var site=findPage().wgManagedSite;return {runtime:site.reverse_status,running:site.running,count:site.reverse.mappings.length};"))
        ui_status = safe_status(ui['runtime'])
        require(api_status and ui_status, 'missing_runtime_snapshot')
        actual_running = matches[0].get('running')
        require(ui['running'] == (actual_running if isinstance(actual_running, bool) else None), 'ui_process_status_disagrees_with_api')
        require(api_status['connected'] is True and ui_status['connected'] is True, 'reverse_not_authenticated_during_ui_check')
        require(ui_status['connected'] == api_status['connected'] and ui_status['state'] == api_status['state'], 'ui_runtime_disagrees_with_api')
        require(ui['count'] == len(api_status['mappings']) == len(ui_status['mappings']), 'mapping_count_mismatch')
        for api_row, ui_row in zip(api_status['mappings'], ui_status['mappings']):
            for name in ('id', 'listening', 'active', 'rx_bytes', 'tx_bytes'):
                require(api_row[name] == ui_row[name], 'ui_mapping_disagrees_with_api')
            require((api_row['last_success'] or None) == ui_row['last_success'], 'ui_target_success_disagrees_with_api')
        require(page.locator('.wg-reverse-status').count() == 1, 'runtime_section_missing')
        text = page.locator('.wg-reverse-status').inner_text()
        for label in ('已认证连接', '服务端端口监听', '活动连接数', '接收字节', '发送字节', '最近目标连接成功'):
            require(label in text, 'runtime_label_missing')
        return {'mapping_count': ui['count'], 'process_running': ui['running'], 'api': api_status, 'ui': ui_status}

    def layout(self, page, scope):
        return page.evaluate(r"""selector => {
            var scope=document.querySelector(selector), viewport=document.documentElement.clientWidth;
            if(!scope)return {missing:true};
            var bounds=scope.getBoundingClientRect(),issues=[];
            var controls=Array.from(scope.querySelectorAll('input,select,button,fieldset,dl,.wg-reverse-preview,.wg-reverse-status-row'));
            controls.forEach(function(element){
                var r=element.getBoundingClientRect(),s=getComputedStyle(element);
                if(!r.width || !r.height || s.visibility==='hidden' || s.display==='none')return;
                if(r.left < -1 || r.right > viewport+1 || r.left < bounds.left-1 || r.right > bounds.right+1){
                    issues.push({tag:element.tagName,name:element.getAttribute('aria-label')||element.getAttribute('name')||element.className,
                        left:Math.round(r.left),right:Math.round(r.right),width:Math.round(r.width)});
                }
            });
            return {viewport:viewport,document_width:document.documentElement.scrollWidth,
                document_horizontal_overflow:document.documentElement.scrollWidth>viewport+1,
                section_left:Math.round(bounds.left),section_right:Math.round(bounds.right),
                section_scroll_width:scope.scrollWidth,section_client_width:scope.clientWidth,
                section_horizontal_overflow:scope.scrollWidth>scope.clientWidth+1,
                visible_controls:controls.filter(function(e){return !!e.getClientRects().length;}).length,issues:issues};
        }""", scope)

    def router(self, role, base, peer_id):
        self.role = role
        context = self.browser.new_context(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1,
                                           ignore_https_errors=True, locale='zh-CN')
        context.add_init_script("try{localStorage.setItem('language','zh-CN');sessionStorage.setItem('uiLocalePreference','zh-CN');}catch(e){}")
        blocked, status_requests, errors = [], [], []

        def guard(route):
            request = route.request
            path = urlsplit(request.url).path
            if path.startswith('/Action/') and request.method not in ('GET', 'HEAD'):
                metadata = request_metadata(request)
                allowed = path == '/Action/login' or path == '/Action/call' and metadata.get('action') == 'show'
                if not allowed:
                    blocked.append({'path': path, **metadata})
                    route.abort('blockedbyclient')
                    return
            route.continue_()

        context.route('**/Action/**', guard)
        page = context.new_page()
        self.page = page
        page.on('pageerror', lambda error: errors.append(type(error).__name__))
        page.on('request', lambda request: status_requests.append(request_metadata(request))
                if request_metadata(request).get('type') in ('hyr_status', 'site_client_status') else None)
        record = {'role': role, 'viewports': [], 'configuration_writes_sent': 0}
        self.report['routers'].append(record)
        scope = '.wg-reverse-editor' if role == 'center' else '.wg-managed-site'
        try:
            self.login(page, base)
            self.open_peer(page, peer_id)
            for name, width, height in (('desktop', 1440, 1000), ('mobile', 390, 844)):
                self.phase = role + '_' + name
                page.set_viewport_size({'width': width, 'height': height})
                page.evaluate('window.scrollTo(0,0)')
                page.wait_for_timeout(200)
                previous = len(status_requests)
                snapshot = self.live_snapshot(page, peer_id)
                require(len(status_requests) == previous + 1, 'manual_read_did_not_issue_exactly_one_status_request')
                page.wait_for_timeout(1200)
                require(len(status_requests) == previous + 1, 'unexpected_reverse_status_polling')
                self.phase = role + '_' + name + '_capture'
                layout = self.layout(page, scope)
                self.capture(page, role + '-' + name, scope)
                record['viewports'].append({'name': name, 'snapshot': snapshot, 'layout': layout})
            record['blocked_non_read_requests'] = blocked
            record['page_error_count'] = len(errors)
            record['passed'] = not blocked and not errors and all(not row['layout'].get('missing') and
                not row['layout']['section_horizontal_overflow'] and not row['layout']['issues'] for row in record['viewports'])
            print(json.dumps({'router': role, 'passed': record['passed'], 'viewports': len(record['viewports']),
                              'blocked_non_read_requests': len(blocked), 'page_errors': len(errors)}), flush=True)
        except Exception as error:
            record['passed'] = False
            record['failure'] = str(error) if isinstance(error, AssertionError) else type(error).__name__
            record['phase'] = self.phase
            record['blocked_non_read_requests'] = blocked
            record['page_error_count'] = len(errors)
            try:
                self.capture(page, role + '-failure', scope)
            except Exception:
                record['failure_capture_failed'] = True
        finally:
            context.close()
            self.page = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--center-url', required=True)
    parser.add_argument('--client-url', required=True)
    parser.add_argument('--center-peer-id', required=True)
    parser.add_argument('--client-peer-id', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--chromium', type=Path, default=Path(os.environ.get('NR_TEST_CHROMIUM', '/usr/bin/chromium')),
                        help='Chromium executable or a dependency wrapper; defaults to NR_TEST_CHROMIUM or /usr/bin/chromium')
    args = parser.parse_args()
    out = args.out.resolve()
    if ROOT in out.parents or out == ROOT or out.exists() and any(out.iterdir()):
        parser.error('--out must be a new or empty directory outside the checkout')
    for value in (args.center_url, args.client_url):
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.query or url.fragment:
            parser.error('Management URLs must be plain HTTP(S) origins without credentials')
    for value in (args.center_peer_id, args.client_peer_id):
        if not re.fullmatch(r'[1-9][0-9]*', value):
            parser.error('Peer IDs must be positive decimal integers')
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    report = {'test': 'native_reverse_browser', 'scope': {'real_firmware_page': True, 'fixture': False,
              'read_only_configuration': True, 'mobile_viewport_only': True, 'browser': 'Chromium'}, 'routers': []}
    started = time.monotonic()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(args.chromium.resolve()), headless=True,
                                                  args=['--no-sandbox', '--disable-dev-shm-usage'])
            try:
                check = BrowserCheck(browser, out, report)
                check.router('center', args.center_url.rstrip('/'), args.center_peer_id)
                check.router('client', args.client_url.rstrip('/'), args.client_peer_id)
            finally:
                browser.close()
    except Exception as error:
        report['failure'] = type(error).__name__
        if 'process_singleton_posix' in str(error) and 'Operation not permitted' in str(error):
            report['failure'] = 'environment_denied_browser_ipc'
            report['failure_detail'] = 'The execution environment denied Chromium its process-singleton socket before a page could open.'
        elif '/usr/lib/chromium/chromium: not found' in str(error):
            report['failure'] = 'browser_executable_missing'
            report['failure_detail'] = 'The installed Chromium launcher has no corresponding browser executable.'
    report['passed'] = len(report['routers']) == 2 and all(row.get('passed') for row in report['routers']) and not report.get('failure')
    report['duration_seconds'] = round(time.monotonic() - started, 3)
    (out / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'routers': len(report['routers']),
                      'duration_seconds': report['duration_seconds']}, ensure_ascii=False), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
