/* Shared plugin requests: report HTTP/transport/JSON errors without throwing. */
function PluginRequest(method, url, data, success, error, async, progress, jsonBody) {
    var xhr = new XMLHttpRequest();
    success = typeof success === 'function' ? success : function () {};
    error = typeof error === 'function' ? error : function () {};
    async = async === undefined ? true : async;
    function fail(message) {
        var result;
        try { result = JSON.parse(xhr.responseText); } catch (_) {}
        error(result && typeof result === 'object' ? result : {Result: xhr.status || 0, ErrMsg: message});
    }
    xhr.open(method, url, async);
    xhr.onload = function () {
        if ((xhr.status >= 200 && xhr.status < 300) || xhr.status === 304) {
            var result;
            try { result = JSON.parse(xhr.responseText); }
            catch (_) { fail('服务器返回了无效的数据，请刷新后重试'); return; }
            success(result);
        } else { fail('请求失败（HTTP ' + xhr.status + '）'); }
    };
    xhr.onerror = function () { fail('网络连接失败，请重试'); };
    xhr.ontimeout = function () { fail('请求超时，请重试'); };
    if (async) xhr.timeout = 30000;
    if (progress && xhr.upload) xhr.upload.onprogress = progress;
    if (jsonBody) xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(jsonBody ? JSON.stringify(data || {}) : data);
    return xhr;
}
var AjaxPost = function (url, data, success, error, async) {
    return PluginRequest('POST', url, data, success, error, async, null, true);
};
var AjaxGet = function (url, success, error) {
    return PluginRequest('GET', url, null, success, error, true, null, false);
};
var AjaxuploadFile = function (url, data, success, error, async) {
    var that = this;
    return PluginRequest('POST', url, data, success, error, async, function (event) {
        if (event.lengthComputable && that.uploadConf) {
            that.uploadConf.Percentage = Math.round(100 * event.loaded / event.total) + '%';
        }
    }, false);
};
var MessageTip = function (message, color) {
    this.messageNotice = true;
    this.Message = message;
    this.msgcolor = color;
    var that = this;
    setTimeout(function () { that.messageNotice = false; }, 1500);
};
