/* Run via page.evaluate in a real, authenticated WG add/edit form on a test VM. */
(async function verifyDeviceEditorIdentity() {
    'use strict';
    const parent=document.querySelector('.wg-page').__vue__;
    const editor=parent.$refs.hyrTunnel, draft=parent.tableForm, initial=editor.transport;
    if (!editor.service || editor.reading || editor.saving || editor.busy || initial!=='native') {
        throw new Error('Open a ready native device draft before running this test');
    }
    const options=Array.from(editor.$el.querySelectorAll('input[name="wg_transport"]'),input=>input.value);
    if(options.join(',')!=='native,pure_hy2')throw new Error('Unexpected transport choices');
    for (const transport of ['pure_hy2','native','pure_hy2']) {
        const selector='input[name="wg_transport"][value="'+transport+'"]';
        const radio=editor.$el.querySelector(selector);
        if (!radio || radio.disabled) throw new Error('Transport control unavailable');
        radio.click();
        await editor.$nextTick();
        await parent.$nextTick();
        if (parent.$refs.hyrTunnel!==editor || editor._isDestroyed || parent.tableForm!==draft ||
            editor.transport!==transport || !editor.$el.querySelector(selector).checked ||
            parent.wgPureMode!==(transport==='pure_hy2')) {
            throw new Error('Native form recreated its device editor or lost the transport selection');
        }
    }
    return {passed:true, switches:3};
}())
