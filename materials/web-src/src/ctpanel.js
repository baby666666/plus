
var app = new Vue({
    el: '#app',
    data: {
        loading: false,
        loading_text: '',
        rcTurnoffStatus: false,
        sources: [],
        editIndex: -1,
        isAdding: false,
        selectAll: false,
        exportMenu: false,
        exportBusy: false,
        importOpen: false,
        importBusy: false,
        importFileName: '',
        importRows: [],
        importMessage: '',
        importError: '',
        editForm: {
            id: '',
            name: '',
            url: ''
        }
    },
    created() {
        this.loadInitData();
    },
    methods: {
        loadInitData() {
            var payload = {
                func_name: 'plugin_ctpanel',
                action: 'show',
                param: {TYPE: 'data'}
            };
            AjaxPost('/Action/call', payload, (response) => {
                if (response.Result % 10000 == 0 && response.Data) {
                    this.rcTurnoffStatus = response.Data.rcstatus === 'off';
                    if (response.Data.sources && Array.isArray(response.Data.sources)) {
                        this.sources = response.Data.sources.map((item) => ({
                            id: item.id,
                            name: item.name,
                            url: item.url,
                            enabled: item.enabled == 'yes',
                            selected: false
                        }));
                    }
                }
            });
        },
        switchRC() {
            var payload = {
                func_name: 'plugin_ctpanel',
                action: 'set_rc_trunoff',
                param: {status: this.rcTurnoffStatus}
            };
            AjaxPost('/Action/call', payload, (response) => {
                if (response.Result % 10000 == 0) {
                    this.$message({
                        message: '云端远控已' + (this.rcTurnoffStatus ? '设为禁用' : '恢复启用') + '，重启系统后生效！',
                        type: 'success'
                    });
                } else {
                    this.rcTurnoffStatus = !this.rcTurnoffStatus;
                    this.$message.error('操作失败！' + response.ErrMsg);
                }
            });
        },
        addRow() {
            if (this.isAdding || this.editIndex !== -1) {
                this.$message.warning('请先完成当前的编辑操作！');
                return;
            }
            this.isAdding = true;
            this.editForm = { id: '', name: '', url: '' };
        },
        editRow(index) {
            if (this.isAdding || this.editIndex !== -1) {
                this.$message.warning('请先完成当前的编辑操作！');
                return;
            }
            this.editIndex = index;
            this.editForm = {
                id: this.sources[index].id,
                name: this.sources[index].name,
                url: this.sources[index].url
            };
        },
        cancelEdit() {
            this.isAdding = false;
            this.editIndex = -1;
            this.editForm = { id: '', name: '', url: '' };
        },
        confirmSave() {
            if (!this.editForm.name.trim()) {
                this.$message.warning('请输入软件源名称！');
                return;
            }
            if (!this.editForm.url.trim()) {
                this.$message.warning('请输入软件源URL！');
                return;
            }
            this.loading = true;
            this.loading_text = this.isAdding ? '正在添加...' : '正在更新...';
            var payload = {
                func_name: 'plugin_ctpanel',
                action: this.isAdding ? 'add' : 'edit',
                param: this.isAdding
                    ? { name: this.editForm.name.trim(), url: this.editForm.url.trim() }
                    : { id: this.editForm.id, name: this.editForm.name.trim(), url: this.editForm.url.trim() }
            };
            payload.param = CTPanelSourceFiles.encodeParams(payload.param);
            AjaxPost('/Action/call', payload, (response) => {
                this.loading = false;
                if (response.Result % 10000 == 0) {
                    this.$message({ message: this.isAdding ? '添加成功！' : '更新成功！', type: 'success' });
                    this.cancelEdit();
                    this.loadInitData();
                } else {
                    this.$message.error('操作失败！' + response.ErrMsg);
                }
            });
        },
        deleteRow(id) {
            if (this.isAdding || this.editIndex !== -1) {
                this.$message.warning('请先完成当前的编辑操作！');
                return;
            }
            this.$confirm('确定要删除这个软件源吗？', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.callSourceAction('del', id, '删除成功！');
            }).catch(() => {});
        },
        enableRow(id) {
            this.callSourceAction('enable', id, '启用成功！');
        },
        disableRow(id) {
            this.callSourceAction('disable', id, '停用成功！');
        },
        callSourceAction(action, id, message) {
            this.loading = true;
            this.loading_text = '正在处理...';
            AjaxPost('/Action/call', {
                func_name: 'plugin_ctpanel',
                action: action,
                param: { id: id }
            }, (response) => {
                this.loading = false;
                if (response.Result % 10000 == 0) {
                    this.$message({ message: message, type: 'success' });
                    this.loadInitData();
                } else {
                    this.$message.error('操作失败！' + response.ErrMsg);
                }
            });
        },
        toggleSelectAll() {
            this.sources.forEach((source) => {
                source.selected = this.selectAll;
            });
        },
        batchEnableRows() {
            this.batchSourceAction('enable', '请选择要启用的软件源！', '批量启用完成！');
        },
        batchDisableRows() {
            this.batchSourceAction('disable', '请选择要停用的软件源！', '批量停用完成！');
        },
        batchDeleteRows() {
            const selected = this.sources.filter((s) => s.selected);
            if (selected.length === 0) {
                this.$message.warning('请选择要删除的软件源！');
                return;
            }
            this.$confirm('确定要删除选中的 ' + selected.length + ' 个软件源吗？', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.batchSourceAction('del', '', '批量删除完成！', selected);
            }).catch(() => {});
        },
        batchSourceAction(action, emptyMessage, doneMessage, selectedRows) {
            const selected = selectedRows || this.sources.filter((s) => s.selected);
            if (selected.length === 0) {
                this.$message.warning(emptyMessage);
                return;
            }
            this.loading = true;
            this.loading_text = '正在批量处理...';
            let completed = 0;
            selected.forEach((source) => {
                AjaxPost('/Action/call', {
                    func_name: 'plugin_ctpanel',
                    action: action,
                    param: { id: source.id }
                }, () => {
                    completed++;
                    if (completed === selected.length) {
                        this.loading = false;
                        this.$message({ message: doneMessage, type: 'success' });
                        this.selectAll = false;
                        this.loadInitData();
                    }
                });
            });
        },
        openImport() {
            if (this.isAdding || this.editIndex !== -1) { this.$message.warning('请先完成当前的编辑操作！'); return; }
            this.importOpen = true; this.importBusy = false; this.importFileName = '';
            this.importRows = []; this.importMessage = ''; this.importError = '';
        },
        closeImport() { if (!this.importBusy) this.importOpen = false; },
        selectImportFile(event) {
            const file = event.target.files[0]; this.importRows = []; this.importMessage = ''; this.importError = '';
            if (!file) return;
            this.importFileName = file.name;
            if (file.size > CTPanelSourceFiles.MAX_BYTES) { this.importError = '文件过大，最大支持 256 KiB。'; return; }
            const reader = new FileReader(); this.importBusy = true;
            reader.onload = () => {
                this.importBusy = false;
                try { this.importRows = CTPanelSourceFiles.parse(reader.result, file.name); this.importMessage = '已读取 ' + this.importRows.length + ' 条软件源。'; }
                catch (error) { this.importError = error.message; }
            };
            reader.onerror = () => { this.importBusy = false; this.importError = '文件读取失败，请重新选择。'; };
            reader.readAsText(file, 'UTF-8');
        },
        sourceRequest(action, param) {
            return new Promise((resolve, reject) => {
                AjaxPost('/Action/call', {func_name:'plugin_ctpanel',action:action,param:CTPanelSourceFiles.encodeParams(param)},
                    (response) => { if (response && response.Result === 30000) resolve(response.Data || {}); else reject(new Error(response.ErrMsg || '服务器未确认操作成功')); },
                    (error) => reject(new Error(error.ErrMsg || '网络请求失败')));
            });
        },
        importSources() {
            if (this.importBusy) return;
            if (!this.importRows.length) { this.importError = '请先选择有效的 TXT 或 CSV 文件。'; return; }
            this.importBusy = true; this.importError = '';
            CTPanelSourceFiles.append(this.importRows, (action,param) => this.sourceRequest(action,param),
                (done,total) => { this.importMessage = '正在导入 ' + done + '/' + total + '…'; })
            .then((result) => {
                this.importBusy = false; this.importRows = [];
                this.importMessage = '导入完成：新增 ' + result.added + ' 条，跳过已有 URL ' + result.skipped + ' 条。';
                this.loadInitData();
            }).catch((error) => { this.importBusy = false; this.importError = error.message; this.importMessage = ''; this.loadInitData(); });
        },
        exportFile(format) {
            if (this.exportBusy) return;
            if (format !== 'csv' && format !== 'txt') { this.$message.error('不支持的导出格式。'); return; }
            if (this.sources.length === 0) { this.$message.warning('暂无软件源数据可导出！'); return; }
            this.exportMenu = false;
            this.exportBusy = true;
            // Use the same authenticated export/download contract as native tables.
            // Blob URLs can lose their filename or expire before a download starts.
            AjaxPost('/Action/call', {func_name:'plugin_ctpanel',action:'EXPORT',param:{format:format}},
                (response) => {
                    this.exportBusy = false;
                    const expected = 'software_sources.' + format;
                    if (!response || response.Result !== 30000 || response.Filename !== expected) {
                        this.$message.error(response && response.ErrMsg || '服务器未生成有效的导出文件，请重试。');
                        return;
                    }
                    window.location.href = '/Action/download?filename=' + encodeURIComponent(expected);
                },
                () => { this.exportBusy = false; this.$message.error('导出请求失败，请检查连接后重试。'); });
        }
    }
});
