/* Router civil time is independent of the administrator's browser timezone.
 * Native X-Timezone and basic.time_zone_full are fixed signed HHMM offsets.
 * Do not change Date/Moment globally: other components may display client time.
 */
(function (root, factory) {
  var api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.RouterTime = api;
}(typeof window === 'object' ? window : null, function (root) {
  'use strict';
  var offset = null, sequence = 0, observedSequence = 0, saveSequence = 0, showSequence = 0;
  var pendingOffset = null, pendingUntil = 0, reactiveState = null;

  function install(Vue) {
    if (!reactiveState) reactiveState = new Vue({data: {minutes: offset}});
  }

  function bind(view) {
    if (!reactiveState || typeof view.$watch !== 'function') return;
    // Vue disposes this component-owned watcher on route/component destruction.
    view.$watch(function () {return reactiveState.minutes;}, function (current, previous) {
      if (current !== null && current !== previous && (view.startTime || view.endTime)) view.search();
    });
  }

  function parseOffset(value) {
    if (typeof value !== 'string' || !/^[+-]?\d{4}$/.test(value)) return null;
    var negative = value.charAt(0) === '-', digits = value.replace(/^[+-]/, '');
    var hours = +digits.slice(0, 2), minutes = +digits.slice(2);
    if (minutes > 59 || hours * 60 + minutes > (negative ? 720 : 840)) return null;
    return (negative ? -1 : 1) * (hours * 60 + minutes);
  }

  function setTimezone(value) {
    var minutes = parseOffset(value);
    if (minutes === null) return false;
    offset = minutes;
    if (reactiveState) reactiveState.minutes = minutes;
    // Keep the existing native header consumers coherent after a settings save.
    if (root && root.headers) {
      root.headers.xTimezone = value;
      root.headers.xTimezoneHour = minutes / 60;
    }
    return true;
  }

  function beginRequest(config) {
    config.routerTimeSequence = ++sequence;
    return config;
  }

  function captureResponse(response) {
    var config = response.config || {}, order = config.routerTimeSequence || 0;
    var headers = response.headers || {}, value = headers['x-timezone'];
    var request = config.data, data = response.data || {}, authoritative = false;
    if (typeof request === 'string') {
      try { request = JSON.parse(request); } catch (ignore) { request = null; }
    }
    if (request && request.func_name === 'basic' && data.Result === 30000) {
      if (request.action === 'save' && request.param) {
        // A periodic status response must not hide an earlier, slower save.
        // Configuration writes have their own ordering, separate from headers.
        if (order < saveSequence) return;
        value = request.param.time_zone_full;
        if (parseOffset(value) !== null) {
          saveSequence = order;
          pendingOffset = parseOffset(value);
          pendingUntil = Date.now() + 5000;
        }
        authoritative = true;
      } else if (request.action === 'show' && data.Data && data.Data.data && data.Data.data[0]) {
        if (order < saveSequence || order < showSequence) {
          response.routerTimeStaleBasic = true;
          return;
        }
        value = data.Data.data[0].time_zone_full;
        var shownOffset = parseOffset(value);
        // basic/save applies asynchronously: even a newer show request can
        // still see the previous config. Keep the saved target during the same
        // bounded confirmation window, without extending it on every show.
        if (pendingOffset !== null && shownOffset !== pendingOffset && Date.now() < pendingUntil) {
          response.routerTimeStaleBasic = true;
          return;
        }
        authoritative = true;
        if (shownOffset !== null) showSequence = order;
        if (shownOffset === parseOffset(headers['x-timezone'])) pendingOffset = null;
        else if (pendingOffset !== shownOffset) {
          pendingOffset = shownOffset;
          pendingUntil = Date.now() + 5000;
        }
      }
    }
    if (!authoritative && (order < observedSequence || order < saveSequence || order < showSequence)) return;
    var minutes = parseOffset(value);
    if (minutes === null) return;
    // basic/save returns before the native web worker reload. Its old header,
    // and requests issued before the save, must not undo the confirmed setting.
    if (!authoritative && Date.now() >= pendingUntil) pendingOffset = null;
    if (!authoritative && pendingOffset !== null && minutes !== pendingOffset) return;
    if (!authoritative && minutes === pendingOffset) pendingOffset = null;
    observedSequence = Math.max(observedSequence, order);
    setTimezone(value);
  }

  function selectedOffset(value) {
    return value === undefined ? (reactiveState ? reactiveState.minutes : offset) : parseOffset(value);
  }
  function pad(value, width) {
    var text = String(value);
    while (text.length < (width || 2)) text = '0' + text;
    return text;
  }
  function blank(value) { return value === '' || value === null || value === undefined; }

  function format(timestamp, timezone) {
    var minutes = selectedOffset(timezone);
    if (blank(timestamp)) return '';
    if (minutes === null || (typeof timestamp !== 'number' &&
        (typeof timestamp !== 'string' || !/^-?\d+(?:\.\d+)?$/.test(timestamp))) ||
        !isFinite(Number(timestamp))) return '—';
    var date = new Date((Number(timestamp) + minutes * 60) * 1000);
    if (!isFinite(date.getTime())) return '—';
    return pad(date.getUTCFullYear(), 4) + '-' + pad(date.getUTCMonth() + 1) + '-' +
      pad(date.getUTCDate()) + ' ' + pad(date.getUTCHours()) + ':' +
      pad(date.getUTCMinutes()) + ':' + pad(date.getUTCSeconds());
  }

  function parse(value, timezone) {
    var minutes = selectedOffset(timezone);
    if (minutes === null || typeof value !== 'string') return null;
    // A string, including native datetime-local's value, preserves wall-clock
    // fields even when they fall inside the browser's daylight-saving gap.
    var match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(value);
    if (!match) return null;
    var year = +match[1], month = +match[2], day = +match[3], hour = +match[4];
    var minute = +match[5], second = +(match[6] || 0);
    if (year < 1900 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59) return null;
    var date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
    if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
        date.getUTCDate() !== day) return null;
    return date.getTime() / 1000 - minutes * 60;
  }

  function warn(view, rangeError) {
    var language = view && view.$i18n && view.$i18n.locale;
    var text = rangeError ? (language === 'en-US' ?
      'This date is outside the firmware-supported range. Choose a more recent date.' :
      '该日期超出固件支持范围，请选择较近的日期。') : language === 'en-US' ?
      'Check the router timezone and enter a valid date and time.' :
      '请确认路由器时区已加载，并输入有效的日期和时间。';
    if (root && typeof root.customError === 'function') root.customError(text);
    return false;
  }

  function range(view) {
    if (view.routerTimeInvalid && (view.routerTimeInvalid.startTime || view.routerTimeInvalid.endTime)) {
      warn(view);
      return null;
    }
    var start = blank(view.startTime) ? null : parse(view.startTime);
    var end = blank(view.endTime) ? null : parse(view.endTime);
    if ((!blank(view.startTime) && start === null) || (!blank(view.endTime) && end === null) ||
        (start !== null && end !== null && start > end)) {
      warn(view);
      return null;
    }
    return {start: start, end: end};
  }

  function validTime(view) {
    if (view.routerTimeInvalid && view.routerTimeInvalid.timeset) return warn(view);
    if (parseOffset(view.tableForm.time_zone_full) === null) return warn(view);
    var timestamp = parse(view.timeset, view.tableForm.time_zone_full);
    if (timestamp === null) return warn(view);
    // Native basic.sh accepts exactly ten unsigned digits; API acknowledgement
    // precedes that async validation. Reject unsupported dates before the save.
    return (timestamp >= 1000000000 && timestamp <= 9999999999) || warn(view, true);
  }

  function renderPicker(view, createElement, field, label, showLabel) {
    var value = typeof view[field] === 'string' ? view[field].replace(' ', 'T') : '';
    // datetime-local uses civil strings without a browser timezone. Keeping a
    // native picker also avoids the old Element widget's Date/DST normalization.
    function update(event, report) {
      var target = event.target, next = target.value.replace('T', ' ');
      var invalid = (target.validity && !target.validity.valid) ||
        (next && parse(next, field === 'timeset' ? view.tableForm.time_zone_full : undefined) === null);
      if (!view.routerTimeInvalid) view.routerTimeInvalid = {};
      view.routerTimeInvalid[field] = !!invalid;
      if (invalid) return report ? warn(view) : false;
      // Commit all valid edits (including clear) so a keyboard submit cannot
      // use an earlier value while the native control shows something else.
      view[field] = next;
    }
    var input = createElement('input', {
      staticClass: 'inptText',
      style: {width: '210px'},
      attrs: {type: 'datetime-local', step: '1', min: '1900-01-01T00:00:00',
        max: '9999-12-31T23:59:59', 'aria-label': label, title: label},
      domProps: {value: value},
      on: {input: function (event) {update(event, false);}, change: function (event) {update(event, true);}}
    });
    return showLabel ? createElement('label', [createElement('span', {
      style: {display: 'inline-block', marginRight: '4px'},
      // Compiled pages pass Vue's _c, which does not normalize a raw string
      // child like $createElement does. Set the native text property directly.
      domProps: {textContent: label + '：'}
    }), input]) : input;
  }

  return {parseOffset: parseOffset, setTimezone: setTimezone, beginRequest: beginRequest,
    captureResponse: captureResponse, format: format, parse: parse, range: range,
    validTime: validTime, renderPicker: renderPicker, install: install, bind: bind};
}));
