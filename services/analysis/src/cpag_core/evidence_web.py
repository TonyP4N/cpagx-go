"""Explicit localhost-only packet evidence viewer. No default route is changed."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .packet_job import verify_artifacts, query_evidence

PAGE='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>合成抓包证据查看</title>
<style>body{font:16px system-ui;max-width:1100px;margin:36px auto;padding:0 24px;background:#f6f8fa;color:#182335}h1{font-size:26px}button,select{font:inherit;padding:8px;margin:4px;border:1px solid #b5c4d4;border-radius:5px;background:white}button:hover{background:#e6eef8}section{background:white;padding:20px;margin:16px 0;border:1px solid #d7e0e8;border-radius:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}#error{color:#b42318}small{color:#526478}</style>
<h1>合成抓包 · 观测图与原始证据</h1><p>仅限软件行为验证。请求响应关联不表示攻击、因果关系或物理动作成功。</p>
<p id="error" role="alert"></p><section><h2>观测节点</h2><div id="nodes"></div><h3>协议关联</h3><div id="edges"></div></section>
<section><h2>事件 → 字段 → 原始帧</h2><p id="selected">请选择观测节点或关联端点</p><label>字段 <select id="fields" aria-label="字段"></select></label><p id="summary"></p><pre id="evidence"></pre></section>
<small>每次查询均核对原抓包、产物、图引用与字段片段；缺失或篡改会拒绝展示。抓包时间未进行跨源对齐。</small>
<script>
let chosen=null,requestRevision=0;const el=id=>document.getElementById(id);
async function get(path){el('error').textContent='';const r=await fetch(path,{cache:'no-store'});const v=await r.json();if(!r.ok)throw Error(v.error);return v;}
function button(label,click){const b=document.createElement('button');b.textContent=label;b.onclick=()=>click().catch(fail);return b;}
function fail(e){el('error').textContent='证据核验失败：'+e.message;el('evidence').textContent='';el('summary').textContent='';}
async function selectEvent(id){const revision=++requestRevision;chosen=id;el('selected').textContent=id;el('evidence').textContent='';el('summary').textContent='核验中';el('fields').replaceChildren();const q=await get('/api/evidence?event='+encodeURIComponent(id));if(revision!==requestRevision)return;el('fields').replaceChildren();Object.keys(q.observation.fields).forEach(name=>{const o=document.createElement('option');o.value=name;o.textContent=name;el('fields').append(o);});await showField();}
async function showField(){if(!chosen)return;const revision=++requestRevision;el('evidence').textContent='';el('summary').textContent='核验中';const q=await get('/api/evidence?event='+encodeURIComponent(chosen)+'&field='+encodeURIComponent(el('fields').value));if(revision!==requestRevision)return;const pieces=Object.values(q.verified_fields).flat();el('summary').textContent='核验通过 · 原始帧 '+[...new Set(pieces.map(p=>p.frame_number))].join(', ')+' · '+q.observation.association_status;el('evidence').textContent=JSON.stringify({event_id:q.event.event_id,field:el('fields').value,evidence:pieces.map(p=>({frame:p.frame_number,file_sha256:p.file_sha256,frame_sha256:p.frame_sha256,raw_hex:p.raw_hex,field_hex:p.field.hex,field_sha256:p.field.sha256,absolute_byte_offset:p.field.absolute_byte_offset}))},null,2);}
el('fields').onchange=()=>showField().catch(fail);
get('/api/graph').then(r=>{r.events.forEach((e,i)=>el('nodes').append(button('节点 '+(i+1)+' · '+e.operation,()=>selectEvent(e.event_id))));r.graph.edges.forEach((e,i)=>{const row=document.createElement('div');row.append('关联 '+(i+1)+'：',button('请求证据',()=>selectEvent(e.source)),' → ',button('响应证据',()=>selectEvent(e.target)));el('edges').append(row);});if(!r.graph.edges.length)el('edges').textContent='无可确认的协议关联（请查看缺失或歧义状态）';}).catch(fail);
</script></html>'''


def handler(output,network):
    # Both paths are operator-selected once at startup, never supplied by HTTP.
    output,network=Path(output),Path(network)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if len(self.path)>4096:self.send_error(414);return
            route=urlsplit(self.path)
            try:
                if route.path=='/' and not route.query:
                    body=PAGE.encode();content='text/html; charset=utf-8'
                elif route.path=='/api/graph' and not route.query:
                    result=verify_artifacts(output,network)
                    body=json.dumps({'events':result['events'],'graph':result['graph']}).encode();content='application/json'
                elif route.path=='/api/evidence':
                    query=parse_qs(route.query,keep_blank_values=True)
                    if set(query)-{'event','field'} or len(query.get('event',[]))!=1 or len(query.get('field',[]))>1:
                        raise ValueError('one event and optional field required')
                    body=json.dumps(query_evidence(output,network,query['event'][0],query.get('field',[None])[0])).encode();content='application/json'
                else:self.send_error(404);return
                self.send_response(200)
            except (OSError,ValueError,KeyError) as error:
                self.send_response(409);body=json.dumps({'error':str(error)}).encode();content='application/json'
            self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers();self.wfile.write(body)
    return Handler


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--enable-evidence-viewer',action='store_true',required=True)
    p.add_argument('--output',required=True);p.add_argument('--network',required=True);p.add_argument('--port',type=int,default=18100)
    a=p.parse_args();verify_artifacts(a.output,a.network)
    server=ThreadingHTTPServer(('127.0.0.1',a.port),handler(a.output,a.network))
    print('Synthetic evidence viewer http://127.0.0.1:'+str(server.server_port),flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()

if __name__=='__main__':main()
