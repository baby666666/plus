# 路由器时区页面维护

`../src/router-time.js` 是可读的公共时间逻辑。`app.js` 及本目录的页面编译快照组成当前管理界面源，可直接生成运行资源。

| 源文件 | Webpack chunk / component | 原生功能 |
| --- | --- | --- |
| basic.js | 89 / 1714 | basic |
| admin.js | 122 / 1652 | syslog-webadmin |
| notice.js | 123 / 1650 | syslog-notice |
| arp.js | 124 / 1647 | syslog-arp |
| pppauth.js | 160 / 1657 | syslog-pppauth |
| wanpppoe.js | 161 / 1656 | syslog-wanpppoe |
| apaction.js | 162 / 1655 | syslog-apaction |
| sysevent.js | 163 / 1654 | syslog-sysevent |
| dhcpd.js | 164 / 1649 | syslog-dhcpd |
| ddns.js | 165 / 1648 | syslog-ddns |

原生日志 API 储存并返回 Unix 秒；时间错误来自页面的浏览器本地 Date/Moment 格式化和筛选转换。app 的现有 Axios 请求/响应拦截器仅增加请求序号及 RouterTime 回调，复用每次响应的 X-Timezone，不新增定时器、轮询或后端 API。不要全局改变 Date、Moment 或通用 stamp_date，否则会波及不属于本次范围的页面。

X-Timezone / time_zone_full 是固定偏移 HHMM 字符串（如 0800、0545、-0330），不是 IANA 夏令时地区。basic/save 的返回头可能仍是原时区；配置写入、配置读取与普通请求分别排序，后发先到的监控响应不能挤掉成功保存结果。成功保存后的旧 basic/show 不回填表单或手工时间。新时区等待对应响应头最多 5 秒，期间读取旧配置也不回退目标、读取同一目标不延长窗口；之后正常采用后续配置/响应头，避免屏蔽另一位管理员的更改。Vue 响应状态更新当前日志显示，已有时间条件会同步重查；没有条件时只重绘，不额外查询。缺少或非法时区时显示占位符，带时间条件的查询会阻止提交，不退回浏览器时区。

九个日志页面同时修改显示和筛选，包含合法的 Unix 0 边界。基础设置手工设置时间按当前选中的 time_zone_full 转成 Unix 秒，保存前及 set_time 前均校验，限制在原生后台实际支持的十位秒值范围；日志与筛选仍允许更早时间。日期输入改用原生 datetime-local，保留秒及选择器，模型始终是日期时间字符串；不能使用 valueAsDate/valueAsNumber 或旧 Element Date 模型，否则浏览器夏令时空缺会把路由器 02:30 自动改为 03:30。非法或未完成的输入会阻止使用旧模型查询/保存，合法编辑与清空即时同步。筛选输入保留可见开始/结束标签。

更新流程：

1. 编辑上述源文件，执行 `python3 tools/sync_router_time.py --write`。
2. 执行 `node materials/web-src/tests/router-time-unit.js`；其子进程覆盖 UTC、上海、纽约、印度、尼泊尔和 Lord Howe，检查 DST 空缺/重叠与正负半小时/四分之一小时时区。
   另运行 `node materials/web-src/tests/router-time-vue-unit.js /path/to/native/vendor.9963e3172df892e7087c.js.gz`，使用固定基础输入中的原生 vendor，验证实际主应用 Vue 2.4.2 编译 `_c` 下的标签文字与响应更新；不要用独立 vue.js 的其它版本冒充主应用。
3. 运行 `tools/sync_router_time.py`、`tools/sync_wg.py`、`tools/sync_routing.py`、`tools/sync_ctpanel.py` 默认校验，更新材料摘要及权限清单。
4. 真实浏览器验证原生日历、清空、秒精度及筛选请求，并在新固件核对活动资源。宿主组件测试不能替代此步骤。

`../time-assets.json` 记录哈希运行资源。`sync_router_time.py` 以源生成 app/helper/chunks，修改 `wg-assets.json` 指向的共享 manifest 和 index 顺序加载器，并生成 gzip 副本；它不修改 WG 或分流源。helper URL 必须保留 `?v=1.0`，因为原生顺序加载器在首次加载和重试时直接追加 `&entry_attempt`。测试使用实际 index 的 URL 数组检查该路径。先后运行其他同步工具不能丢弃本表中的 chunk 哈希。
