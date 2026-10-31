"""Unprivileged web UI. VPN control is confined to root-owned broker/services."""
import hmac
import os
import re
import secrets
import sqlite3
import logging
import time
from datetime import timedelta, datetime, timezone
from functools import wraps
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, Response, send_file, abort, redirect, render_template as flask_render_template, request, session
from werkzeug.security import check_password_hash
from quota import Quotas, TokenStorageError
from vpn.client import request_profile, maintenance_request
from vpn.maintenance import FILENAME
from metrics import host_metrics, online_users, summaries
from panel_web import AdminMount, admin_path, public_port, url_for
from flask import g
from i18n import LocalizedLoader, translate, format_date, parse_date, date_input


def create_app(config=None):
    app = Flask(__name__)
    app.logger.setLevel(logging.INFO)
    app.jinja_env.globals['url_for']=url_for
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('PANEL_SECRET'),
        ADMIN_PASSWORD_HASH=os.environ.get('PANEL_PASSWORD_HASH'),
        DATABASE=os.environ.get('PANEL_DATABASE', 'instance/quota.sqlite'),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=True, PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        ADMIN_PATH=admin_path(os.environ.get('PANEL_ADMIN_PATH','')),
        DEFAULT_CALENDAR=os.environ.get('PANEL_CALENDAR','gregorian'),
        VPN_CONFIGURED=os.environ.get('PANEL_VPN_CONFIGURED') == '1',
        BACKUP_DIRECTORY='/var/lib/openvpn-panel-backups',
        ONLINE_SNAPSHOT='/var/lib/openvpn-panel-status/online.json',
        MAX_CONTENT_LENGTH=32768, TRUSTED_HOSTS=['localhost', '127.0.0.1'],
    )
    if os.environ.get('PANEL_HOST'):
        app.config['TRUSTED_HOSTS'] = [os.environ['PANEL_HOST']]
        for host in os.environ.get('PANEL_EXTRA_HOSTS','').split(','):
            if host and re.fullmatch(r'[A-Za-z0-9.-]{1,253}',host):
                app.config['TRUSTED_HOSTS'].append(host)
    if os.environ.get('PANEL_LOCAL_HTTP') == '1':
        app.config['SESSION_COOKIE_SECURE'] = False
    if config:
        app.config.update(config)
    if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
        raise RuntimeError('Set PANEL_SECRET to a random secret of at least 32 characters')
    if not app.config['ADMIN_PASSWORD_HASH']:
        raise RuntimeError('Set PANEL_PASSWORD_HASH using python manage.py password-hash')
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    quotas = Quotas(app.config['DATABASE'])
    app.extensions['quotas'] = quotas
    # Global (not client-IP based) throttle also works behind a reverse proxy.
    # Single worker deployment is required; use shared storage before scaling.
    attempts = []
    profile_attempts = []
    lock = Lock()

    # The loader chooses source by browser language; never reuse a compiled
    # template from another language. User content is still Jinja-autoescaped.
    app.jinja_loader = LocalizedLoader(app.jinja_loader)
    app.jinja_env.cache = None
    app.jinja_env.globals.update(t=translate, date_input=date_input)

    def render_template(template_name,**context):
        for key in ('error',):
            if key in context: context[key] = translate(context[key])
        return flask_render_template(template_name,**context)

    @app.before_request
    def preferences_context():
        g.language = request.cookies.get('panel-language', 'fa')
        if g.language not in ('fa', 'en'): g.language = 'fa'
        g.calendar = request.cookies.get('panel-calendar', app.config['DEFAULT_CALENDAR'])
        if g.calendar not in ('gregorian','jalali'): g.calendar = 'gregorian'

    @app.post('/preferences')
    def preferences():
        language = request.form.get('language', g.language)
        calendar = request.form.get('calendar', 'gregorian')
        if language not in ('fa','en') or calendar not in ('gregorian','jalali'): abort(400)
        target = request.form.get('next', url_for('login'))
        # Only root-relative, non-ambiguous same-origin redirects.
        if not target.startswith('/') or target.startswith('//') or '\\' in target or any(ord(c) < 32 or ord(c) == 127 for c in target):
            abort(400)
        response = redirect(target)
        for name, value in (('panel-language',language),('panel-calendar',calendar)):
            response.set_cookie(name, value, max_age=31536000, secure=app.config['SESSION_COOKIE_SECURE'], httponly=True, samesite='Lax', path='/')
        return response

    @app.before_request
    def csrf_check():
        if request.method == 'POST':
            supplied = request.form.get('csrf', '')
            expected = session.get('csrf')
            if not expected or not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
                abort(400)

    @app.after_request
    def headers(response):
        response.headers['Content-Language'] = g.get('language','fa')
        if response.is_json and g.get('language') == 'en':
            # Translate only explicitly human-readable error/message fields.
            data = response.get_json()
            if isinstance(data,dict):
                for key in ('error','message'):
                    if isinstance(data.get(key),str): data[key] = translate(data[key])
                response.set_data(app.json.dumps(data))
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.context_processor
    def context():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return dict(csrf=session['csrf'], vpn_configured=app.config['VPN_CONFIGURED'], language=g.language, calendar=g.calendar)

    def admin(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get('admin'):
                return redirect(url_for('login'))
            return view(*args, **kwargs)
        return wrapped

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            with lock:
                now = time.monotonic()
                attempts[:] = [t for t in attempts if now - t < 300]
                if len(attempts) >= 10:
                    abort(429)
                attempts.append(now)
            if check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form.get('password', '')):
                session.clear()
                session['admin'] = True
                session.permanent = True
                return redirect(url_for('dashboard'))
            error = 'رمز عبور نادرست است.'
        return render_template('login.html', error=error)

    @app.post('/logout')
    @admin
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @admin
    def dashboard():
        all_users = quotas.list_users()
        search = request.args.get('q', '').strip()[:64]
        online = online_users(app.config['ONLINE_SNAPSHOT'])
        status_filter = request.args.get('status', 'all')
        valid_filters = ('all', 'active', 'disabled', 'expired', 'limited', 'online', 'near_limit', 'near_expiry')
        if status_filter not in valid_filters:
            status_filter = 'all'
        per_page = request.args.get('per_page', str(session.get('users_per_page',20)))
        per_page = int(per_page) if per_page in ('20','50','100') else 20
        session['users_per_page'] = per_page
        try:
            page = max(1, int(request.args.get('page','1')[:12]))
        except ValueError:
            page = 1
        checks = {
            'all': lambda u: True, 'active': lambda u: u.allowed,
            'disabled': lambda u: not u.enabled,
            'expired': lambda u: u.remaining_seconds is not None and u.remaining_seconds <= 0,
            'limited': lambda u: u.remaining_bytes == 0,
            'online': lambda u: online is not None and u.name in online,
            'near_limit': lambda u: u.allowed and u.remaining_bytes <= u.limit_bytes * 0.1,
            'near_expiry': lambda u: u.allowed and u.remaining_seconds is not None and u.remaining_seconds <= 3 * 86400,
        }
        filtered = [u for u in all_users if search.casefold() in u.name.casefold() and checks[status_filter](u)]
        total = len(filtered)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        start = (page - 1) * per_page
        users = filtered[start:start+per_page]
        return render_template('dashboard.html', users=users, search=search,
                               status_filter=status_filter, per_page=per_page, page=page, pages=pages,
                               filtered_total=total, range_start=start+1 if total else 0,
                               range_end=min(start+per_page,total),
                               stats={**summaries(all_users, online), 'traffic': quotas.total_traffic()}, metrics=host_metrics(), online=online)

    @app.get('/api/metrics')
    @admin
    def live_metrics():
        return jsonify(host_metrics())

    @app.post('/users')
    @admin
    def create_user():
        wants_json = request.accept_mimetypes['application/json'] > request.accept_mimetypes['text/html']
        name = request.form.get('name', '')
        gib_text = request.form.get('gib', '50')
        days_text = request.form.get('days', '30')
        error = None
        try:
            gib, days = int(gib_text), int(days_text)
            if not 1 <= gib <= 100000 or not 1 <= days <= 3650:
                raise ValueError()
            token = quotas.create_user(name, gib * 1024**3, days, remember=True)
        except ValueError:
            error = 'نام باید ۱ تا ۶۴ حرف انگلیسی، عدد، خط تیره یا زیرخط باشد؛ حجم و روزها نیز باید در بازهٔ مجاز باشند.'
        except TokenStorageError:
            if wants_json: return jsonify(error='ذخیرهٔ امن لینک در دسترس نیست؛ وضعیت فایل کلید را بررسی کنید.'),503
            return render_template('message.html',error='ذخیرهٔ امن لینک در دسترس نیست؛ با پشتیبانی بررسی کنید.'),503
        except sqlite3.IntegrityError:
            error = 'این نام قبلاً ثبت شده است؛ نام دیگری انتخاب کنید.'
        if error:
            if wants_json:
                return jsonify(error=error), 400
            return render_template('message.html', error=error, create_another=True,
                                   form_name=name, form_gib=gib_text, form_days=days_text), 400
        app.logger.info('Admin created user=%s', name)
        if wants_json:
            return jsonify(name=name, subscription_url=url_for('subscription', token=token, _external=True),
                           profile_url=url_for('download_profile', name=name) if app.config['VPN_CONFIGURED'] else None)
        return render_template('message.html', token=token, name=name, create_another=True,
                               form_gib=gib, form_days=days)

    def return_to_user_list():
        # Only fixed local route + bounded query fields; never accept a redirect URL.
        return redirect(url_for('dashboard', q=request.form.get('q','')[:64],
            status=request.form.get('status','all')[:20], per_page=request.form.get('per_page','20')[:3],
            page=request.form.get('page','1')[:12], _anchor='users'))

    @app.post('/users/<name>/toggle')
    @admin
    def toggle(name):
        value = request.form.get('enabled')
        if value not in ('0', '1'):
            abort(400)
        try:
            quotas.set_enabled(name, value == '1')
            app.logger.info('Admin set enabled=%s user=%s', value, name)
        except KeyError:
            abort(404)
        return return_to_user_list()

    @app.post('/users/<name>/token')
    @admin
    def rotate(name):
        try:
            token = quotas.rotate_token(name, remember=True)
            app.logger.info('Admin rotated status link user=%s', name)
        except TokenStorageError:
            if request.accept_mimetypes['application/json'] > request.accept_mimetypes['text/html']:
                return jsonify(error='ذخیرهٔ امن لینک در دسترس نیست؛ لینک قبلی تغییر نکرده است.'),503
            return render_template('message.html',error='ذخیرهٔ امن لینک در دسترس نیست؛ لینک قبلی تغییر نکرده است.'),503
        except KeyError:
            abort(404)
        if request.accept_mimetypes['application/json'] > request.accept_mimetypes['text/html']:
            return jsonify(subscription_url=url_for('subscription',token=token,_external=True))
        return render_template('message.html', token=token, name=name)

    @app.post('/users/<name>/limits')
    @admin
    def limits(name):
        try:
            days = int(request.form.get('days',''))
            if request.form.get('set_expiry_date') == '1':
                state = quotas.status(name)
                if state.first_connected is None: raise ValueError('Not activated')
                # Whole-day validity preserves first-connect time-of-day and
                # never changes consumption or activation in the database.
                selected = parse_date(request.form.get('expiry_date',''), request.form.get('date_calendar',g.calendar))
                first = datetime.fromtimestamp(state.first_connected, timezone.utc).date()
                days = (selected-first).days
            quotas.update_limits(name, int(request.form.get('gib', '')) * 1024**3, days)
            app.logger.info('Admin changed allowance user=%s', name)
        except ValueError:
            abort(400)
        except KeyError:
            abort(404)
        return return_to_user_list()

    def list_context():
        return dict(search=request.args.get('q','')[:64], status_filter=request.args.get('status','all')[:20],
                    per_page=request.args.get('per_page','20')[:3], page=request.args.get('page','1')[:12])

    @app.get('/users/<name>/edit')
    @admin
    def edit_user(name):
        try: state=quotas.status(name)
        except KeyError: abort(404)
        return render_template('user_edit.html',user=state,**list_context())

    @app.route('/users/<name>/delete',methods=['GET','POST'])
    @admin
    def delete_user(name):
        try: state=quotas.status(name)
        except KeyError: abort(404)
        if request.method=='POST':
            if request.form.get('confirm')!='1' or request.form.get('confirm_name')!=name:
                abort(400,description='برای حذف، نام کاربر و تأیید را وارد کنید.')
            quotas.delete_user(name)
            app.logger.info('Admin deleted user=%s',name)
            return return_to_user_list()
        return render_template('user_delete.html',user=state,**list_context())

    @app.post('/users/<name>/link')
    @admin
    def copy_user_link(name):
        wants_json=request.accept_mimetypes['application/json'] > request.accept_mimetypes['text/html']
        try: token=quotas.remembered_token(name)
        except KeyError: abort(404)
        except TokenStorageError:
            if wants_json: return jsonify(error='کلید ذخیرهٔ لینک در دسترس نیست؛ لینک قبلی تغییر نکرده است.'),503
            return render_template('message.html',error='کلید ذخیرهٔ لینک در دسترس نیست؛ لینک قبلی تغییر نکرده است.'),503
        if token is None:
            if wants_json: return jsonify(needs_rotation=True,error='این لینک قدیمی فقط به‌صورت هش ذخیره شده؛ برای صدور لینک قابل کپی، تأیید ابطال لینک قبلی لازم است.'),409
            return render_template('legacy_link.html',name=name)
        if wants_json: return jsonify(subscription_url=url_for('subscription',token=token,_external=True))
        return render_template('message.html',token=token,name=name)

    @app.post('/users/<name>/profile')
    @admin
    def download_profile(name):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name, re.ASCII):
            abort(400)
        if not app.config['VPN_CONFIGURED']:
            abort(503)
        try:
            quotas.status(name)
        except KeyError:
            abort(404)
        action = request.form.get('action', 'download')
        if action not in ('download', 'rotate'):
            abort(400)
        try:
            profile = request_profile(name, action)
        except (ValueError, OSError):
            app.logger.error('VPN profile helper failed')
            return render_template('message.html', error='ساخت فایل اتصال ناموفق بود؛ وضعیت سرویس و PKI را بررسی کنید.'), 503
        app.logger.info('Admin profile operation=%s user=%s', action, name)
        return Response(profile, mimetype='application/x-openvpn-profile', headers={
            'Content-Disposition': f'attachment; filename="{name}.ovpn"'})

    def privileged(message):
        if not app.config['VPN_CONFIGURED']:
            abort(503)
        try:
            return maintenance_request(message)
        except (OSError, ValueError):
            abort(503, description='سرویس نگهداری در دسترس نیست یا تنظیمات معتبر نیست.')

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('message.html', error=error.description), 403

    def confirm_password():
        if not check_password_hash(app.config['ADMIN_PASSWORD_HASH'], request.form.get('password', '')):
            abort(403, description='رمز تأیید صحیح نیست. رمز فعلی ورود مدیر پنل را وارد کنید؛ نه رمز SSH/root، رمز Cloudflare یا رمز بکاپ. درخواست تغییر تنظیمات اجرا نشده است.')

    @app.get('/settings/network')
    @admin
    def network_page():
        return render_template('network.html', settings=privileged(dict(operation='network-settings-get')))

    @app.post('/settings/panel')
    @admin
    def panel_settings():
        confirm_password()
        if request.form.get('confirm')!='1': abort(400)
        try:
            port=public_port(request.form.get('public_port',''))
            prefix=admin_path(request.form.get('admin_path','')) if request.form.get('custom_path')=='1' else ''
        except ValueError as error: abort(400,description=str(error))
        privileged(dict(operation='panel-save',public_port=port,admin_path=prefix))
        return render_template('network_pending.html',target=None,panel_change=True,new_path=prefix,new_port=port)

    @app.post('/settings/ssl')
    @admin
    def ssl_settings():
        from vpn.network_settings import domain
        confirm_password()
        if request.form.get('confirm') != '1':
            abort(400)
        try:
            host = domain(request.form.get('domain',''))
        except ValueError:
            abort(400, description='دامنهٔ معتبر بدون https، مسیر یا پورت وارد کنید.')
        queued=privileged(dict(operation='ssl-save',domain=host,use_for_vpn=request.form.get('use_for_vpn')=='1'))
        app.logger.info('Admin queued SSL settings change')
        port=public_port(queued.get('public_port',443))
        target='https://'+host+(':'+str(port) if port!=443 else '')+app.config['ADMIN_PATH']
        return render_template('network_pending.html', target=target)

    @app.post('/settings/vpn')
    @admin
    def vpn_settings():
        from vpn.network_settings import protocol, endpoint
        confirm_password()
        if request.form.get('confirm') != '1':
            abort(400)
        try:
            chosen = protocol(request.form.get('protocol',''))
            remote = endpoint(request.form.get('endpoint',''))
        except ValueError:
            abort(400, description='پروتکل یا آدرس VPN معتبر نیست.')
        privileged(dict(operation='vpn-save',protocol=chosen,endpoint=remote))
        app.logger.info('Admin queued VPN settings change')
        return render_template('network_pending.html', target=None)

    @app.get('/backups')
    @admin
    def backup_page():
        return render_template('backups.html', settings=privileged(dict(operation='backup-settings-get')))

    @app.post('/backups/settings')
    @admin
    def backup_settings():
        confirm_password()
        try:
            interval = int(request.form.get('interval', ''))
        except ValueError:
            abort(400)
        if not 5 <= interval <= 10080:
            abort(400)
        token = request.form.get('token', '').strip()
        chat_id = request.form.get('chat_id', '').strip()
        phrase = request.form.get('passphrase', '')
        if phrase and phrase != request.form.get('passphrase_repeat', ''):
            abort(400, description='تکرار رمز بکاپ یکسان نیست.')
        if ((token and not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}', token)) or
                (chat_id and not re.fullmatch(r'-?[0-9]{1,20}|@[A-Za-z0-9_]{5,64}', chat_id)) or
                (phrase and not 16 <= len(phrase) <= 1024)):
            abort(400, description='توکن، Chat ID یا طول رمز بکاپ معتبر نیست.')
        privileged(dict(operation='backup-settings-save', interval=interval,
            enabled=request.form.get('enabled') == '1', token=request.form.get('token', '').strip(),
            chat_id=request.form.get('chat_id', '').strip(), passphrase=request.form.get('passphrase', '')))
        app.logger.info('Admin changed encrypted backup settings')
        return redirect(url_for('backup_page'))

    @app.post('/backups/create')
    @admin
    def backup_create():
        privileged(dict(operation='backup-create'))
        return redirect(url_for('backup_page'))

    @app.get('/backups/download/<name>')
    @admin
    def backup_download(name):
        if not FILENAME.fullmatch(name):
            abort(404)
        path = Path(app.config['BACKUP_DIRECTORY']) / name
        if path.is_symlink() or not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=name, mimetype='application/octet-stream')

    @app.post('/system/web')
    @admin
    def web_control():
        confirm_password()
        action = request.form.get('action')
        if action not in ('stop', 'restart') or request.form.get('confirm') != '1':
            abort(400)
        privileged(dict(operation='web-control', action=action))
        app.logger.info('Admin scheduled web service action=%s', action)
        return render_template('control.html', action=action)

    @app.get('/s/<token>')
    def subscription(token):
        if len(token) != 43:
            abort(404)
        state = quotas.status_by_token(token)
        if state is None:
            abort(404)
        return render_template('status.html', user=state, token=token, public_page=True)

    @app.post('/s/<token>/profile')
    def subscription_profile(token):
        # Bearer link authorizes only its own identity and a non-rotating download.
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token, re.ASCII):
            abort(404)
        state = quotas.status_by_token(token)
        if state is None:
            abort(404)
        if not state.allowed:
            return render_template('message.html', public_page=True,
                                   error='اشتراک شما فعال نیست؛ برای تمدید با پشتیبانی تماس بگیرید.'), 403
        if not app.config['VPN_CONFIGURED']:
            abort(503)
        with lock:
            now = time.monotonic()
            profile_attempts[:] = [(t, name) for t, name in profile_attempts if now - t < 60]
            if len(profile_attempts) >= 60 or sum(name == state.name for _, name in profile_attempts) >= 6:
                abort(429, description='برای دانلود مجدد یک دقیقه صبر کنید.')
            profile_attempts.append((now, state.name))
        try:
            profile = request_profile(state.name, 'download')
        except (ValueError, OSError):
            return render_template('message.html', public_page=True,
                                   error='فایل اتصال فعلاً آماده نیست؛ کمی بعد تلاش کنید یا به پشتیبانی اطلاع دهید.'), 503
        return Response(profile, mimetype='application/x-openvpn-profile', headers={
            'Content-Disposition': f'attachment; filename="{state.name}.ovpn"',
            'X-Robots-Tag': 'noindex, nofollow, noarchive'})

    @app.template_filter('utc')
    def utc(value):
        return format_date(value)

    @app.template_filter('gib')
    def gib(value):
        return f'{value / 1024**3:.2f}'

    app.wsgi_app=AdminMount(app.wsgi_app,app.config['ADMIN_PATH'])
    return app
