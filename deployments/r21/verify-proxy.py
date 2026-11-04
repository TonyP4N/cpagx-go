#!/usr/bin/env python3
"""Real HTTPS client verification using only the explicitly supplied test CA."""
import argparse
import hashlib
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import ssl
import subprocess
from urllib.parse import urlsplit


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();state=json.loads(a.state.read_text());url=urlsplit(state['url']);http_url=urlsplit(state.get('httpUrl','http://'+url.hostname));ctx=ssl.create_default_context(cafile=state['caFile']);result={'scope':'actual TLS client with explicit temporary test CA; no OS/browser trust installation','checks':{}}
 def request(method,path,body=None,headers=None,tls=True):
  connection=http.client.HTTPSConnection(url.hostname,url.port,context=ctx,timeout=15) if tls else http.client.HTTPConnection(http_url.hostname,http_url.port or 80,timeout=15)
  if isinstance(body,dict):body=json.dumps(body).encode();headers={'Content-Type':'application/json',**(headers or {})}
  connection.request(method,path,body,headers or {});response=connection.getresponse();payload=response.read();meta={'status':response.status,'headers':dict(response.getheaders())};connection.close()
  try:value=json.loads(payload)
  except ValueError:value=payload.decode(errors='replace')
  return meta,value
 ready,_=request('GET','/health/ready');assert ready['status']==200;result['checks']['explicit_CA_chain_and_hostname_verified']={'status':200,'verify_mode':str(ctx.verify_mode),'check_hostname':ctx.check_hostname}
 credentials={key:state[key] for key in ['username','password']};login,_=request('POST','/api/v3/session',credentials,{'Origin':state['url']});assert login['status']==200
 cookies=SimpleCookie();cookies.load(login['headers']['Set-Cookie']);session=cookies['cpag_session'];assert session['secure'] and session['httponly'] and session['samesite'].lower()=='strict';result['checks']['secure_cookie']={'Secure':bool(session['secure']),'HttpOnly':bool(session['httponly']),'SameSite':session['samesite'],'Path':session['path']}
 bad,value=request('POST','/api/v3/session',credentials,{'Origin':'https://evil.invalid','Forwarded':'proto=https;host='+url.netloc,'X-Forwarded-Host':url.netloc,'X-Forwarded-Proto':'https'});assert bad['status']==403;result['checks']['bad_origin_with_forwarding_spoof_rejected']={'status':403,'code':value['error']['code']}
 bad_host,value=request('GET','/health/live',headers={'Host':'evil.invalid'});assert bad_host['status']==421 and isinstance(value,dict);result['checks']['https_bad_host_rejected']={'status':421,'code':value['error']['code']}
 bad_http,value=request('GET','/health/live',headers={'Host':'evil.invalid'},tls=False);assert bad_http['status']==421;result['checks']['http_bad_host_rejected']={'status':421}
 redirect,_=request('GET','/workbench/?r21-probe=1',tls=False);assert redirect['status']==308 and redirect['headers']['Location']==state['url']+'/workbench/?r21-probe=1';result['checks']['fixed_https_redirect']={'status':308,'location':redirect['headers']['Location']}
 token=b'r21-acme-owned-probe\n';subprocess.run(['docker','exec','-i',state['outer'],'sh','-c','cat > /var/lib/cpag-acme/.well-known/acme-challenge/r21-owned-probe'],input=token,check=True)
 acme,value=request('GET','/.well-known/acme-challenge/r21-owned-probe',tls=False);assert acme['status']==200 and value==token.decode();result['checks']['acme_webroot_local_readback']={'status':200,'sha256':hashlib.sha256(token).hexdigest(),'external_ACME_issuance_tested':False}
 active=subprocess.check_output(['docker','exec',state['outer'],'cat','/etc/cpag/proxy-location.conf'],text=True)
 assert all('proxy_set_header '+name+' "";' in active for name in ['Forwarded','X-Forwarded-Host','X-Forwarded-Proto','X-Forwarded-For']);assert 'proxy_pass http://127.0.0.1:8095;' in active
 result['checks']['proxy_only_public_loopback_and_strips_forwarding_claims']=True
 request('DELETE','/api/v3/session',headers={'Origin':state['url'],'Cookie':'cpag_session='+session.value})
 result['status']='passed';a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
