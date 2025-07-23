#!/usr/bin/env python
# Servidor de licenças + painel de administração
# © RV Solutions • Flask 3.x

import os, json, time, random, string, hashlib, functools
from datetime import datetime
from flask import (
    Flask, request, jsonify, abort, render_template_string,
    redirect, url_for, session, flash
)
from passlib.hash import pbkdf2_sha256

### ‑‑‑ CONFIGURAÇÕES GERAIS ‑‑‑ ###
DATA_FILE      = 'keys.json'
ADMIN_USER     = 'rvadmin'
ADMIN_PASSHASH = pbkdf2_sha256.hash('mudar123')         # troque a senha!
HOST, PORT     = '0.0.0.0', 5001
SECRET_KEY     = os.urandom(24)                         # sessão Flask

### ‑‑‑ HELPERS ‑‑‑ ###
from flask_cors import CORS
app  = Flask(__name__)
CORS(app)  
app.secret_key = SECRET_KEY



def _load() -> dict:
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f: json.dump({}, f)
    with open(DATA_FILE) as f: return json.load(f)

def _save(data: dict):
    with open(DATA_FILE, 'w') as f: json.dump(data, f, indent=2)

def _login_required(f):
    @functools.wraps(f)
    def wrap(*a, **kw):
        if not session.get('logged'):
            return redirect(url_for('login', next=request.path))
        return f(*a, **kw)
    return wrap

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def random_key(n=16) -> str:
    s = ''.join(random.choices(string.ascii_uppercase+string.digits, k=n))
    return '-'.join([s[i:i+4] for i in range(0, n, 4)])

### ‑‑‑ API PÚBLICA (/validate) ‑‑‑ ###
@app.post('/validate')
def validate():
    data  = _load()
    body  = request.get_json(force=True) or {}
    key   = body.get('key', '').upper()
    hwid  = body.get('hwid')
    rec   = data.get(key)

    if not rec or rec.get('status') == 'banned':
        return jsonify(ok=False, reason='INVALID'), 403
    if rec['expires'] and time.time() > rec['expires']:
        return jsonify(ok=False, reason='EXPIRED'), 403
    if rec['hwid'] and rec['hwid'] != hwid:
        return jsonify(ok=False, reason='HWID_MISMATCH'), 403

    if not rec['hwid']:
        rec['hwid'] = hwid
        _save(data)

    token = _sha(key + hwid + str(rec['expires']))
    return jsonify(ok=True, token=token, expires=rec['expires'])

### ‑‑‑ AUTENTICAÇÃO ADMIN ‑‑‑ ###
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['user']; p = request.form['pw']
        if u == ADMIN_USER and pbkdf2_sha256.verify(p, ADMIN_PASSHASH):
            session['logged'] = True
            return redirect(request.args.get('next', url_for('panel')))
        flash('Credenciais inválidas.', 'danger')
    return render_template_string(TPL_LOGIN)

@app.get('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

### ‑‑‑ PAINEL ADMIN ‑‑‑ ###
@app.get('/')
@_login_required
def panel():
    q   = request.args.get('q', '').upper()
    dat = _load()
    keys = {k: v for k, v in dat.items() if q in k.upper()}
    return render_template_string(TPL_PANEL, keys=keys, q=q, time=time)

@app.post('/new')
@_login_required
def new():
    qtd   = int(request.form.get('qty', 1))
    days  = int(request.form.get('days', 0))
    data  = _load()
    out   = []
    exp   = int(time.time()+days*86400) if days else 0
    for _ in range(qtd):
        k = random_key()
        data[k] = dict(expires=exp, hwid=None, status='active')
        out.append(k)
    _save(data)
    flash(f'{qtd} chave(s) criada(s).', 'success')
    session['last_keys'] = out
    return redirect(url_for('panel'))

@app.post('/edit/<key>')
@_login_required
def edit(key):
    data = _load()
    if key not in data: abort(404)
    exp = request.form.get('expires')
    data[key]['expires'] = int(time.mktime(
        datetime.strptime(exp, '%Y-%m-%d').timetuple())) if exp else 0
    _save(data)
    flash('Chave atualizada.', 'success')
    return redirect(url_for('panel', q=key))

@app.get('/toggle/<key>')
@_login_required
def toggle(key):
    data = _load()
    if key not in data: abort(404)
    data[key]['status'] = 'banned' if data[key]['status']=='active' else 'active'
    _save(data)
    flash('Status alterado.', 'warning')
    return redirect(url_for('panel', q=key))

@app.get('/del/<key>')
@_login_required
def delete(key):
    data = _load()
    if data.pop(key, None):
        _save(data)
        flash('Chave removida.', 'danger')
    return redirect(url_for('panel'))



### ‑‑‑ TEMPLATES EMBUTIDOS (Jinja2) ‑‑‑ ###
TPL_LOGIN = """
<!doctype html><title>Login • Painel RV</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<div class="container py-5" style="max-width:400px">
  <h3 class="mb-4 text-center">Painel de Licenças</h3>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% if m %}{% for cat,txt in m %}
      <div class="alert alert-{{cat}}">{{txt}}</div>{% endfor %}
    {% endif %}{% endwith %}
  <form method="post">
    <div class="mb-3"><input name="user" class="form-control" placeholder="Usuário" required></div>
    <div class="mb-3"><input name="pw" type="password" class="form-control" placeholder="Senha" required></div>
    <button class="btn btn-primary w-100">Entrar</button>
  </form>
</div>
"""

TPL_PANEL = """
<!doctype html><title>Painel • RV Solutions</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4>Painel de Licenças</h4>
    <a href="{{url_for('logout')}}" class="btn btn-outline-dark btn-sm">Sair</a>
  </div>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% if m %}{% for cat,txt in m %}
      <div class="alert alert-{{cat}}">{{txt}}</div>{% endfor %}
    {% endif %}{% endwith %}
  <form class="row g-2 mb-4" method="get">
    <div class="col"><input name="q" value="{{q}}" class="form-control" placeholder="Buscar chave"></div>
    <div class="col-auto"><button class="btn btn-outline-secondary">Buscar</button></div>
  </form>
  <details class="mb-4">
    <summary class="h6">Criar novas chaves</summary>
    <form class="row g-2 mt-2" method="post" action="{{url_for('new')}}">
      <div class="col"><input type="number" name="qty" min="1" value="1" class="form-control" placeholder="Qtde"></div>
      <div class="col"><input type="number" name="days" min="0" value="30" class="form-control" placeholder="Dias de validade (0=vitalícia)"></div>
      <div class="col-auto"><button class="btn btn-success">Gerar</button></div>
    </form>
    {% if session.get('last_keys') %}
      <div class="mt-2"><small>Últimas: {{ session.pop('last_keys')|join(', ') }}</small></div>
    {% endif %}
  </details>
  <table class="table table-sm table-bordered align-middle">
    <thead class="table-light"><tr>
      <th>Chave</th><th>Expira</th><th>HWID</th><th>Status</th><th style="width:120px">Ações</th></tr></thead>
    <tbody>
    {% for k,v in keys.items() %}
      <tr class="{% if v.status=='banned' %}table-danger{% endif %}">
        <td class="font-monospace">{{k}}</td>
        <td>
          {% if v.expires %}{{time.strftime('%d/%m/%Y', time.localtime(v.expires))}}
          {% else %}<span class="text-success">Vitalícia</span>{% endif %}
        </td>
        <td class="font-monospace">{{v.hwid or '-'}}</td>
        <td>{{v.status}}</td>
        <td>
          <a class="btn btn-sm btn-outline-primary" data-bs-toggle="modal"
             href="#edit{{loop.index}}">Editar</a>
          <a href="{{url_for('toggle',key=k)}}" class="btn btn-sm btn-outline-warning">Ban</a>
          <a href="{{url_for('delete',key=k)}}" class="btn btn-sm btn-outline-danger"
             onclick="return confirm('Excluir {{k}}?')">Del</a>
          <!-- Modal editar -->
          <div class="modal fade" id="edit{{loop.index}}">
           <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content p-3">
             <form method="post" action="{{url_for('edit',key=k)}}">
               <h6 class="mb-3">Alterar expiração de {{k}}</h6>
               <input type="date" name="expires" class="form-control mb-3"
                value="{{'' if not v.expires else time.strftime('%Y-%m-%d', time.localtime(v.expires))}}">
               <button class="btn btn-primary">Salvar</button>
             </form>
            </div></div></div>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="5" class="text-center">Nenhuma chave encontrada.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
"""
@app.get('/exists/<key>')
def exists(key):
    rec = _load().get(key.upper())
    # usa .get('status') para não estourar KeyError
    if rec and rec.get('status', 'active') != 'banned':
        return jsonify(exists=True)
    return jsonify(exists=False), 404

if __name__ == '__main__':
    print(f'» Painel em http://{HOST}:{PORT}  (login: {ADMIN_USER})')
    app.run(host=HOST, port=PORT, debug=False)
