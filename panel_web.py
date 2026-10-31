"""Admin mount boundary. Public subscriptions/static/preferences stay at their old paths."""
import re
from urllib.parse import urlsplit, urlunsplit
from flask import has_request_context, request, url_for as flask_url_for

PUBLIC = {'subscription','subscription_profile','static','preferences'}


def admin_path(value):
    if value in ('','/'): return ''
    if type(value) is not str or not re.fullmatch(r'/[A-Za-z0-9_-]{1,64}',value):
        raise ValueError('Use one ASCII path segment, for example /my-admin')
    if value[1:].lower() in ('s','static','preferences','api','login','logout','users','settings','backups'):
        raise ValueError('Reserved public or application path')
    return value


def public_port(value):
    if type(value) is bool: raise ValueError('Invalid port')
    if type(value) not in (str,int) or not str(value).isascii() or not str(value).isdigit(): raise ValueError('Invalid port')
    value=int(value)
    if value != 443 and not 1024 <= value <= 65535 or value in (8000,2019):
        raise ValueError('Use 443 or 1024-65535, excluding internal ports 8000/2019')
    return value


class AdminMount:
    def __init__(self, app, prefix): self.app,self.prefix=app,admin_path(prefix)
    def __call__(self,environ,start_response):
        path=environ.get('PATH_INFO','/')
        public=path.startswith(('/s/','/static/')) or path in ('/preferences','/s')
        if self.prefix and not public:
            if path==self.prefix or path.startswith(self.prefix+'/'):
                environ=environ.copy()
                environ['SCRIPT_NAME']=environ.get('SCRIPT_NAME','')+self.prefix
                environ['PATH_INFO']=path[len(self.prefix):] or '/'
            else:
                start_response('404 Not Found',[('Content-Type','text/plain; charset=utf-8'),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff')])
                return [b'Not Found']
        return self.app(environ,start_response)


def url_for(endpoint,**values):
    url=flask_url_for(endpoint,**values)
    if endpoint in PUBLIC and has_request_context() and request.script_root:
        parts=urlsplit(url)
        prefix=request.script_root
        path=parts.path
        if path==prefix or path.startswith(prefix+'/'): path=path[len(prefix):] or '/'
        url=urlunsplit((parts.scheme,parts.netloc,path,parts.query,parts.fragment))
    return url
