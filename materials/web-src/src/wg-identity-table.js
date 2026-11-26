/* Add identity checks to mutations from the two WireGuard lists. The native table supplies their rendering, filtering and pagination. */
(function(root){
    'use strict';
    var base, guarded;
    function tr(s){return root.WGI18n?root.WGI18n.text(s):s;}
    function stale(){return tr('设备已被删除或更改，请返回列表并重新打开。');}
    function identity(row,iface){
        var r={id:String(row.id),interface:iface?row.name:row.interface,public_key:iface?row.local_publickey:row.peer_publickey};
        var key=/^[A-Za-z0-9+/]{43}=$/;
        if(!/^[1-9]\d{0,9}$/.test(r.id) || !/^wg\d{1,10}$/.test(r.interface) || !key.test(r.public_key))return null;
        if(!iface){
            r.iface_id=String(row.iface_id);r.server_key=row.server_key;
            if(!(r.iface_id==='0' && r.server_key==='') && !(/^[1-9]\d{0,9}$/.test(r.iface_id) && key.test(r.server_key)))return null;
        }
        return r;
    }
    function snapshot(table,row){
        return identity(row,table.opt.requests.delRowAction==='iface_del');
    }
    function hex(rows){
        var text=JSON.stringify(rows),out='';
        for(var i=0;i<text.length;i++)out+=('0'+text.charCodeAt(i).toString(16)).slice(-2);
        return out;
    }
    function valid(table,rows){
        if(!rows.length){root.customError(table.$t('firewall.arp.checkTip'));return false;}
        if(rows.some(function(r){return !r;})){root.customError(stale());return false;}
        return true;
    }
    function selected(table){
        return table.rowChecking.map(function(id){return table._wgChecked[id] || null;});
    }
    function mutate(table,action,rows,event,state){
        if(table._isDestroyed || !valid(table,rows))return false;
        var req=table.opt.requests,ids=rows.map(function(r){return r.id;}).join(',');
        return table.$http.post(req.url,{func_name:'wireguard',action:action,param:{id:ids,expected_rows:hex(rows)}}).then(function(reply){
            if(!reply || !reply.data || reply.data.Result!==30000)throw (reply && reply.data || {});
            if(table._isDestroyed)return true;
            var affected={};rows.forEach(function(r){affected[r.id]=JSON.stringify(r);});
            // A newer list can arrive before the response. Never update a replacement row in its place.
            table.listData=table.listData.filter(function(row){
                if(affected[row.id]!==JSON.stringify(snapshot(table,row)))return true;
                if(state){row.enabled=state;return true;}
                return false;
            });
            table.toggleCheckAll(true);
            if(state)table.$emit(event,state==='yes');else table.$emit(event);
            if(!state)table.paginationOptions.currentPage=1;
            table.reload(!state);
            return true;
        }).catch(function(error){
            if(!table._isDestroyed){
                var body=error && (error.data || error),known=root.WGI18n && root.WGI18n.knownText(body && body.ErrMsg);
                root.customError(known || tr('请求失败，请检查连接并刷新接口列表确认结果后重试。'));
                table.toggleCheckAll(true);table.reload();
            }
            return false;
        });
    }
    function toggle(table,state,rows){
        return mutate(table,state==='yes'?table.opt.requests.enableRowAction:table.opt.requests.disableRowAction,
            rows,'toggleRowComplete',state);
    }
    function remove(table,rows,message,batch){
        if(!valid(table,rows))return false;
        table.editingRow=null;
        return root.customConfirm(message||table.$t(batch?'firewall.arp.delAllConfirm':'firewall.arp.delRowConfirm')).then(function(){
            return mutate(table,table.opt.requests.delRowAction,rows,batch?'batchDeleteRowSuccess':'deleteRowSuccess');
        },function(){return false;});
    }
    root.WGIdentityTable=function(view){
        var parent=view.$options.components.DTable;
        if(!parent || typeof parent.extend!=='function')return 'wg-table-unavailable';
        if(base===parent)return guarded;
        base=parent;
        var native=parent.options.methods;
        guarded=parent.extend({
            name:'WGIdentityTable',
            created:function(){this._wgChecked={};},
            methods:{
                toggleCheckRow:function(row,event){
                    native.toggleCheckRow.call(this,row,event);
                    if(event.target.checked)this._wgChecked[row.id]=snapshot(this,row);else delete this._wgChecked[row.id];
                },
                toggleCheckAll:function(clear){
                    native.toggleCheckAll.call(this,clear);
                    var t=this;t._wgChecked={};
                    t.listData.forEach(function(row){if(t.rowChecking.indexOf(row.id)>=0)t._wgChecked[row.id]=snapshot(t,row);});
                },
                toggleRowsState:function(state,row){return toggle(this,state,[snapshot(this,row)]);},
                batchEnableRows:function(){return toggle(this,'yes',selected(this));},
                batchDisableRows:function(){return toggle(this,'no',selected(this));},
                deleteRow:function(row,message){return remove(this,[snapshot(this,row)],message,false);},
                batchDeleteRows:function(message){return remove(this,selected(this),message,true);}
            }
        });
        return guarded;
    };
    root.WGIdentityTable.interfaceTarget=function(row){
        var original=identity(row,true);
        return original?hex([original]):'';
    };
}(this));
