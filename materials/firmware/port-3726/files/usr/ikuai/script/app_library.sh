#!/bin/bash /etc/ikcommon
# Compatibility endpoint: application catalogue support is disabled.
status(){ echo '{"apps":[],"removed":true,"revision":"disabled","job":{"state":"idle"}}'; }
job_status(){ echo '{"state":"idle","removed":true}'; }
migrate(){ return 0; }
removed(){ echo '应用规则库已移除，请使用原生协议分流';return 1; }
save(){ removed; }
request(){ removed; }
update(){ removed; }
detail(){ removed; }
work(){ removed; }
