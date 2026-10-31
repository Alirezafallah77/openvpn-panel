"""Unprivileged web UI. VPN control is confined to root-owned broker/services."""
import hmac
import os
import re
import secrets
import sqlite3
import logging
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from threading import Lock

from flask import Flask, Response, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from quota import Quotas
from vpn.client import request_profile


def create_app(config=None):
    app = Flask(__name__)
    app.logger.setLevel(logging.INFO)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('PANEL_SECRET'),
        ADMIN_PASSWORD_HASH=os.environ.get('PANEL_PASSWORD_HASH'),
        DATABASE=os.environ.get('PANEL_DATABASE', 'instance/quota.sqlite'),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_SECURE=True, PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        VPN_CONFIGURED=os.environ.get('PANEL_VPN_CONFIGURED') == '1',
        MAX_CONTENT_LENGTH=8192, TRUSTED_HOSTS=['localhost', '127.0.0.1'],
    )
    if os.environ.get('PANEL_HOST'):
        app.config['TRUSTED_HOSTS'] = [os.environ['PANEL_HOST']]
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
    lock = Lock()

    @app.before_request
    def csrf_check():
        if request.method == 'POST':
            supplied = request.form.get('csrf', '')
            expected = session.get('csrf')
            if not expected or not hmac.compare_digest(supplied.encode('utf-8'), expected.encode('utf-8')):
                abort(400)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.context_processor
    def context():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return dict(csrf=session['csrf'], vpn_configured=app.config['VPN_CONFIGURED'])

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
        return render_template('dashboard.html', users=quotas.list_users())

    @app.post('/users')
    @admin
    def create_user():
        try:
            gib = int(request.form.get('gib', ''))
            days = int(request.form.get('days', ''))
            if not 1 <= gib <= 100000 or not 1 <= days <= 3650:
                raise ValueError()
            name = request.form.get('name', '')
            token = quotas.create_user(name, gib * 1024**3, days)
        except (ValueError, sqlite3.IntegrityError):
            return render_template('message.html', error='نام تکراری یا مقادیر نامعتبر است.'), 400
        app.logger.info('Admin created user=%s', name)
        return render_template('message.html', token=token, name=name)

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
        return redirect(url_for('dashboard'))

    @app.post('/users/<name>/token')
    @admin
    def rotate(name):
        try:
            token = quotas.rotate_token(name)
            app.logger.info('Admin rotated status link user=%s', name)
        except KeyError:
            abort(404)
        return render_template('message.html', token=token, name=name)

    @app.post('/users/<name>/limits')
    @admin
    def limits(name):
        try:
            quotas.update_limits(name, int(request.form.get('gib', '')) * 1024**3,
                                 int(request.form.get('days', '')))
            app.logger.info('Admin changed allowance user=%s', name)
        except ValueError:
            abort(400)
        except KeyError:
            abort(404)
        return redirect(url_for('dashboard'))

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

    @app.get('/s/<token>')
    def subscription(token):
        if len(token) != 43:
            abort(404)
        state = quotas.status_by_token(token)
        if state is None:
            abort(404)
        return render_template('status.html', user=state)

    @app.template_filter('gib')
    def gib(value):
        return f'{value / 1024**3:.2f}'

    return app
