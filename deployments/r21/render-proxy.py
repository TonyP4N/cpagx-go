#!/usr/bin/env python3
"""Render an explicit hostname/origin; redirects never reflect request Host."""
import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--origin',required=True);p.add_argument('--http-authority');p.add_argument('--nginx-user',default='nginx');p.add_argument('--output-root',type=Path,default=Path('/etc/cpag'));a=p.parse_args();origin=urlsplit(a.origin)
 try:port=origin.port
 except ValueError:p.error('invalid origin port')
 if origin.scheme!='https' or not origin.hostname or origin.path or origin.query or origin.fragment or origin.username or a.origin!='https://'+origin.netloc:p.error('exact HTTPS origin without path/userinfo required')
 if not re.fullmatch(r'[A-Za-z0-9.:-]+',origin.hostname) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',a.nginx_user):p.error('ASCII hostname and installed nginx username required')
 def authority(value):
  if not re.fullmatch(r'[A-Za-z0-9.\[\]:-]+',value):p.error('invalid explicit authority')
  return value
 host=origin.hostname if ':' not in origin.hostname else '['+origin.hostname+']'
 https=[authority(origin.netloc)]
 if port in (None,443):https=list(dict.fromkeys([host,host+':443']))
 http=[authority(a.http_authority)] if a.http_authority else [host,host+':80']
 replacements={'@ORIGIN@':a.origin,'@SERVER_NAME@':host,'@HTTPS_HOSTS@':' '.join('"'+x+'" 1;' for x in https),'@HTTP_HOSTS@':' '.join('"'+x+'" 1;' for x in http),'@NGINX_USER@':a.nginx_user}
 text=(Path(__file__).parent/'nginx.conf').read_text()
 for key,value in replacements.items():text=text.replace(key,value)
 a.output_root.mkdir(parents=True,exist_ok=True)
 for name,content in [('nginx.conf',text),('proxy-location.conf',(Path(__file__).parent/'proxy-location.conf').read_text())]:
  with (a.output_root/name).open('x') as stream:stream.write(content)
 print(json.dumps({'status':'rendered','origin':a.origin,'http_authority':http,'output':str(a.output_root/'nginx.conf')}))
if __name__=='__main__':main()
