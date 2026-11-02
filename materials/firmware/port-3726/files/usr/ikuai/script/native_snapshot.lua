#!/usr/bin/lua
-- One read transaction and one interpreter instead of five independent readers.
-- Publish only after every table was read and encoded successfully.
local sqlite=require('lsqlite3');local json=require('cjson')
local path,out=assert(arg[1]),assert(arg[2])
local exists=assert(io.open(path,'rb'));exists:close()
local db=assert(sqlite.open(path));db:busy_timeout(10000)
local tmp=out..'.new'
local ok,err=pcall(function()
 assert(db:exec('BEGIN')==sqlite.OK,db:errmsg())
 local result={}
 -- New rules appear at the top of every routing page and match first.
 -- Keep all routing stages in descending ID order; groups have no priority.
 for _,spec in ipairs{{'port','stream_ipport','id desc'},{'domain','stream_domain','id desc'},{'ipgroup','ipgroup','id'},{'macgroup','macgroup','id'},{'protocol','stream_layer7','id desc'}}do
  local rows={};for row in db:nrows('select * from '..spec[2]..' order by '..spec[3]..';')do rows[#rows+1]=row end
  result[#result+1]='"'..spec[1]..'":'..(#rows==0 and '[]'or json.encode(rows))
 end
 assert(db:exec('COMMIT')==sqlite.OK,db:errmsg())
 local f=assert(io.open(tmp,'w'));local written,why=f:write('{',table.concat(result,','),'}\n');local closed,whyclose=f:close();assert(written,why);assert(closed,whyclose)
 assert(os.rename(tmp,out))
end)
if not ok then db:exec('ROLLBACK')end
db:close();if not ok then os.remove(tmp);io.stderr:write(tostring(err),'\n');os.exit(1)end
