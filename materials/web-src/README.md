# NativeRouting 1.0 网页维护源

src/wg-page.js 为当前编译 WG 页面快照，wg-address-plan.js 为地址表单逻辑，wg-paste-import.js 为粘贴导入，wg-actions.css 为原生按钮样式。wg-assets.json 记录当前哈希运行资源。修改这些源后执行 python3 tools/sync_wg.py --write，再更新材料摘要；不带 --write 只校验。

控制面板仍编辑 src/ctpanel.js 并执行 tools/sync_ctpanel.py --write。实际装包目录是 materials/firmware/port-3726/files，不能只修改源而不更新运行文件。

执行 python3 tools/run_wg_tests.py --lua /path/to/lua；另运行 node materials/web-src/tests/source-files-unit.js、node materials/web-src/tests/export-unit.js 和 python3 materials/web-src/tests/export-backend-unit.py。单测不替代新固件启动与网络测试。

路由器时区逻辑维护在 src/router-time.js；time/ 保存对应的 app、基础设置和九个日志页面编译快照，详见 time/README.md。修改后运行 python3 tools/sync_router_time.py --write，同步哈希资源、活动 manifest/index 及 gzip；默认模式只校验。执行 node materials/web-src/tests/router-time-unit.js 验证多浏览器时区、日志筛选和手工设置时间。此工具与 sync_wg.py / sync_routing.py 共用活动 manifest，运行后仍须通过三者的默认校验。

分流状态秒数与数量在 routing/domain.js 的 rsRender 中显式插值；原生翻译器不处理命名参数。统一测试入口为 tools/run_host_tests.py，运行命令和真实浏览器夹具见 docs/BUILD.md。
