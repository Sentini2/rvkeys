#!/usr/bin/env python
# RV Solutions • Servidor de licenças + painel + auto‑update  v4.0

import os, json, time, random, string, hashlib, functools
from datetime import datetime
from flask import (
    Flask, request, jsonify, abort, render_template_string,
    redirect, url_for, session, flash, send_from_directory
)
from flask_cors import CORS
from passlib.hash import pbkdf2_sha256

# ─── Config ───
DATA_FILE   = 'keys.json'
UPD_FILE    = 'update.json'
FILES_DIR   = 'files'
ADMIN_USER  = 'rvadmin'
ADMIN_PASSHASH = pbkdf2_sha256.hash('mudar123')
HOST, PORT  = '0.0.0.0', 5001

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)
os.makedirs(FILES_DIR, exist_ok=True)

# ─── Helpers ───
def _load(path=DATA_FILE):
    if not os.path.exists(path): json.dump({}, open(path, 'w'))
    with open(path) as f: return json.load(f)

def _save(d, path=DATA_FILE): json.dump(d, open(path, 'w'), indent=2)

def _sha(s): return hashlib.sha256(s.encode()).hexdigest()

def rnd(n=16):
    s = ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))
    return '-'.join([s[i:i+4] for i in range(0, n, 4)])

def _login_required(fn):
    @functools.wraps(fn)
    def w(*a, **kw):
        if not session.get('logged'):
            return redirect(url_for('login'))
        return fn(*a, **kw)
    return w

# ─── API de validação ───
@app.post('/validate')
def validate():
    j    = request.get_json() or {}
    key  = j.get('key', '').upper()
    hwid = j.get('hwid')
    rec  = _load().get(key)

    if not rec or rec['status'] == 'banned':
        return jsonify(ok=False, reason='INVALID'), 403
    if rec['expires'] and time.time() > rec['expires']:
        return jsonify(ok=False, reason='EXPIRED'), 403

    if rec.get('type', 'single') == 'admin':
        token = _sha(key + str(rec['expires']))
        return jsonify(ok=True, token=token, expires=rec['expires'])

    if rec['hwid'] and rec['hwid'] != hwid:
        return jsonify(ok=False, reason='HWID_MISMATCH'), 403
    if not rec['hwid']:
        rec['hwid'] = hwid
        _save(_load())

    token = _sha(key + hwid + str(rec['expires']))
    return jsonify(ok=True, token=token, expires=rec['expires'])

@app.get('/exists/<key>')
def exists(key):
    rec = _load().get(key.upper())
    if rec and rec.get('status', 'active') != 'banned':
        return jsonify(exists=True)
    return jsonify(exists=False), 404

@app.get('/latest')
def latest():
    return jsonify(_load(UPD_FILE) or {})

@app.post('/set_update')
@_login_required
def set_update():
    ver = request.form['ver'].strip()
    url = request.form['url'].strip()
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        fname = f"{int(time.time())}_{f.filename}"
        path = os.path.join(FILES_DIR, fname)
        f.save(path)
        url = request.url_root.rstrip('/') + url_for('download', fname=fname).lstrip('/')
    _save({'version': ver, 'url': url}, UPD_FILE)
    flash('Atualização publicada.', 'success')
    return redirect('/')

@app.get('/download/<path:fname>')
def download(fname):
    return send_from_directory(FILES_DIR, fname, as_attachment=True)

# ─── Login ───
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('user', '').strip()
        pw   = request.form.get('pw', '').strip()

        if user == ADMIN_USER and pbkdf2_sha256.verify(pw, ADMIN_PASSHASH):
            session['logged'] = True
            return redirect('/')

        data = _load()
        key_data = data.get(user.upper())
        if key_data and key_data.get('type') == 'admin' and key_data.get('status') == 'active':
            session['logged'] = True
            return redirect('/')

        flash('Credenciais inválidas.', 'danger')
    return render_template_string(TPL_LOGIN)

@app.get('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ─── Painel ───
@app.get('/')
@_login_required
def panel():
    q = request.args.get('q', '').upper()
    keys = {k: v for k, v in _load().items() if q in k.upper()}
    upd = _load(UPD_FILE)
    return render_template_string(TPL_PANEL, keys=keys, q=q, upd=upd, time=time)

# ─── Criação e edição de chaves ───
@app.post('/new')
@_login_required
def new():
    qty = int(request.form.get('qty', 1))
    days = int(request.form.get('days', 0))
    data = _load()
    exp = int(time.time() + days * 86400) if days else 0
    out = []
    for _ in range(qty):
        k = rnd()
        data[k] = dict(expires=exp, hwid=None, status='active', type='single')
        out.append(k)
    _save(data)
    flash(f'{qty} chave(s) criada(s).', 'success')
    session['last_keys'] = out
    return redirect('/')

@app.post('/new_admin')
@_login_required
def new_admin():
    qty = int(request.form.get('qty', 1))
    data = _load()
    out = []
    for _ in range(qty):
        k = rnd()
        data[k] = dict(expires=0, hwid=None, status='active', type='admin')
        out.append(k)
    _save(data)
    flash(f'{qty} chave(s) ADMIN criadas.', 'warning')
    session['last_keys'] = out
    return redirect('/')

@app.post('/edit/<key>')
@_login_required
def edit(key):
    d = _load()
    exp = request.form.get('expires')
    d[key]['expires'] = int(time.mktime(datetime.strptime(exp, '%Y-%m-%d').timetuple())) if exp else 0
    _save(d)
    flash('Chave atualizada.', 'success')
    return redirect(f'/?q={key}')

@app.get('/toggle/<key>')
@_login_required
def toggle(key):
    d = _load()
    d[key]['status'] = 'banned' if d[key]['status'] == 'active' else 'active'
    _save(d)
    flash('Status alterado.', 'warning')
    return redirect(f'/?q={key}')

@app.get('/del/<key>')
@_login_required
def delete(key):
    d = _load()
    d.pop(key, None)
    _save(d)
    flash('Chave removida.', 'danger')
    return redirect('/')

# ─── HTML Templates ───
TPL_LOGIN = """<!doctype html><title>Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<div class=container style="max-width:420px">
  <h3 class="text-center my-4">Painel RV</h3>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% for c,t in m %}<div class="alert alert-{{c}}">{{t}}</div>{% endfor %}{% endwith %}
  <form method=post class="border rounded p-4 shadow">
   <input name=user class=form-control placeholder="Usuário ou Chave ADMIN" autofocus><br>
   <input name=pw type=password class=form-control placeholder="Senha (deixe em branco se for chave ADMIN)"><br>
   <button class="btn btn-primary w-100">Entrar</button>
  </form></div>"""

TPL_PANEL = """<!doctype html><title>Painel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<div class=container py-4>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4>Painel de Licenças</h4>
    <a href=/logout class="btn btn-outline-dark btn-sm">Sair</a>
  </div>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% for c,t in m %}<div class="alert alert-{{c}}">{{t}}</div>{% endfor %}{% endwith %}

  <!-- [restante do painel já incluso no seu código original] -->

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
"""

# ─── Main ───
if __name__ == '__main__':
    print(f'» Painel em http://{HOST}:{PORT}  (login: {ADMIN_USER})')
    app.run(host=HOST, port=PORT)
