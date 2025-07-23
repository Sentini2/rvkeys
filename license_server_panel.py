#!/usr/bin/env python
# RV Solutions • Servidor de licenças + painel + auto‑update  v4.2
# - Conta quantas vezes cada chave foi usada (campo "uses")
# - Não bloqueia por HWID

import os, json, time, random, string, hashlib, functools
from datetime import datetime
from flask import (
    Flask, request, jsonify, render_template_string,
    redirect, url_for, session, flash, send_from_directory
)
from flask_cors import CORS
from passlib.hash import pbkdf2_sha256

# ── Config ──────────────────────────────────────────────
DATA_FILE   = 'keys.json'          # banco de licenças
UPD_FILE    = 'update.json'        # versão mais recente do Loader
FILES_DIR   = 'files'              # pasta de uploads (.exe)
ADMIN_USER  = 'rvadmin'
ADMIN_PASSHASH = pbkdf2_sha256.hash('mudar123')   # troque!
HOST, PORT  = '0.0.0.0', 5001

app = Flask(__name__)
CORS(app)                          # libera chamadas /exists do admin.html
app.secret_key = os.urandom(24)
os.makedirs(FILES_DIR, exist_ok=True)

# ── Helpers ─────────────────────────────────────────────
def _load(path=DATA_FILE):
    if not os.path.exists(path):
        json.dump({}, open(path,'w'))
    with open(path) as f: return json.load(f)

def _save(data, path=DATA_FILE):
    json.dump(data, open(path,'w'), indent=2)

_sha = lambda s: hashlib.sha256(s.encode()).hexdigest()

def rnd_key():
    return '-'.join(''.join(random.choices(
        string.ascii_uppercase+string.digits, k=4)) for _ in range(4))

def login_required(fn):
    @functools.wraps(fn)
    def wrap(*a,**k):
        if not session.get('logged'):
            return redirect(url_for('login'))
        return fn(*a,**k)
    return wrap

# ╔════════════════════════════════════════════════════╗
# ║                    API CLIENTE                     ║
# ╚════════════════════════════════════════════════════╝
@app.post('/validate')
def validate():
    body = request.get_json(force=True) or {}
    key  = body.get('key','').upper()
    data = _load(); rec = data.get(key)

    if not rec or rec.get('status') == 'banned':
        return jsonify(ok=False, reason='INVALID'), 403
    if rec['expires'] and time.time() > rec['expires']:
        return jsonify(ok=False, reason='EXPIRED'), 403

    # conta usos
    rec['uses'] = rec.get('uses', 0) + 1
    _save(data)

    return jsonify(ok=True,
                   token=_sha(key + str(rec['expires'])),
                   expires=rec['expires'])

@app.get('/exists/<key>')
def exists(key):
    rec = _load().get(key.upper())
    return jsonify(exists=bool(rec and rec.get('status')!='banned'))

# ╔════════════════════════════════════════════════════╗
# ║                 API DE ATUALIZAÇÃO                 ║
# ╚════════════════════════════════════════════════════╝
@app.get('/latest')
def latest(): return jsonify(_load(UPD_FILE) or {})

@app.post('/set_update'); @login_required
def set_update():
    ver = request.form['ver'].strip()
    url = request.form['url'].strip()

    # upload opcional
    if 'file' in request.files and request.files['file'].filename:
        f     = request.files['file']
        fname = f"{int(time.time())}_{f.filename}"
        f.save(os.path.join(FILES_DIR, fname))
        url = (request.url_root.rstrip('/') +
               url_for('download', fname=fname).lstrip('/'))

    _save({'version': ver, 'url': url}, UPD_FILE)
    flash('Atualização publicada.', 'success')
    return redirect('/')

@app.get('/download/<path:fname>')
def download(fname):
    return send_from_directory(FILES_DIR, fname, as_attachment=True)

# ╔════════════════════════════════════════════════════╗
# ║           Autenticação painel (rvadmin)            ║
# ╚════════════════════════════════════════════════════╝
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        if (request.form['user']==ADMIN_USER and
            pbkdf2_sha256.verify(request.form['pw'], ADMIN_PASSHASH)):
            session['logged']=True; return redirect('/')
        flash('Credenciais inválidas.', 'danger')
    return render_template_string(TPL_LOGIN)

@app.get('/logout')
def logout():
    session.clear(); return redirect('/login')

# ╔════════════════════════════════════════════════════╗
# ║                     Painel web                     ║
# ╚════════════════════════════════════════════════════╝
@app.get('/'); @login_required
def panel():
    q=request.args.get('q','').upper()
    all=_load(); keys={k:v for k,v in all.items() if q in k.upper()}
    upd=_load(UPD_FILE)
    return render_template_string(TPL_PANEL, keys=keys, q=q, upd=upd, time=time)

# ── CRUD de chaves ────────────────────────────────────
@app.post('/new'); @login_required
def new():
    qty=int(request.form['qty']); days=int(request.form['days'])
    data=_load(); exp=int(time.time()+days*86400) if days else 0
    for _ in range(qty):
        data[rnd_key()] = dict(expires=exp, status='active', uses=0)
    _save(data)
    flash('Chaves criadas.', 'success'); return redirect('/')

@app.post('/edit/<key>'); @login_required
def edit(key):
    d=_load(); exp=request.form.get('expires')
    d[key]['expires'] = int(time.mktime(
        datetime.strptime(exp,'%Y-%m-%d').timetuple())) if exp else 0
    _save(d); flash('Chave atualizada.','success')
    return redirect(f'/?q={key}')

@app.get('/toggle/<key>'); @login_required
def toggle(key):
    d=_load(); d[key]['status']='banned' if d[key]['status']=='active' else 'active'
    _save(d); flash('Status alterado.','warning')
    return redirect(f'/?q={key}')

@app.get('/del/<key>'); @login_required
def delete(key):
    d=_load(); d.pop(key,None); _save(d); flash('Chave removida.','danger')
    return redirect('/')

# ╔════════════════════════════════════════════════════╗
# ║                 Templates Jinja2                   ║
# ╚════════════════════════════════════════════════════╝
TPL_LOGIN = """
<!doctype html><title>Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<div class="container" style="max-width:420px">
  <h3 class="text-center my-4">Painel RV</h3>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% for cat,msg in m %}<div class="alert alert-{{cat}}">{{msg}}</div>{% endfor %}
  {% endwith %}
  <form method="post" class="border rounded p-4 shadow">
    <input name="user" class="form-control mb-3" placeholder="Usuário" autofocus>
    <input name="pw" type="password" class="form-control mb-3" placeholder="Senha">
    <button class="btn btn-primary w-100">Entrar</button>
  </form>
</div>
"""

TPL_PANEL = """
<!doctype html><title>Painel</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h4>Painel de Licenças</h4><a href="/logout" class="btn btn-outline-dark btn-sm">Sair</a>
  </div>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% for cat,msg in m %}<div class="alert alert-{{cat}}">{{msg}}</div>{% endfor %}
  {% endwith %}

  <form class="row g-2 mb-4">
    <div class="col"><input name="q" value="{{q}}" class="form-control" placeholder="Buscar chave"></div>
    <div class="col-auto"><button class="btn btn-outline-secondary">Buscar</button></div>
  </form>

  <details class="mb-4"><summary class="h6">Criar novas chaves</summary>
    <form class="row g-2 mt-2" method="post" action="/new">
      <div class="col"><input type="number" name="qty" min="1" value="1" class="form-control" placeholder="Qtde" required></div>
      <div class="col"><input type="number" name="days" min="0" value="30" class="form-control" placeholder="Dias (0=vitalícia)"></div>
      <div class="col-auto"><button class="btn btn-success">Gerar</button></div>
    </form>
  </details>

  <details class="mb-4" open><summary class="h6">Nova atualização (versão atual: {{upd.version if upd else 'nenhuma'}})</summary>
    <form class="row g-2 mt-2" method="post" action="/set_update" enctype="multipart/form-data">
      <div class="col"><input name="ver" class="form-control" placeholder="Versão ex: 1.2" required></div>
      <div class="col"><input name="url" class="form-control" placeholder="URL direta (.exe) – opcional"></div>
      <div class="col"><input type="file" name="file" class="form-control"></div>
      <div class="col-auto"><button class="btn btn-primary">Publicar</button></div>
    </form>
  </details>

  <table class="table table-sm table-bordered align-middle">
    <thead class="table-light"><tr>
      <th>Chave</th><th>Usos</th><th>Expira</th><th>Status</th><th style="width:120px">Ações</th>
    </tr></thead>
    <tbody>
    {% for k,v in keys.items() %}
      <tr class="{% if v.status=='banned' %}table-danger{% endif %}">
        <td class="font-monospace">{{k}}</td>
        <td>{{v.uses}}</td>
        <td>{% if v.expires %}{{time.strftime('%d/%m/%Y'
              ,time.localtime(v.expires))}}{% else %}<span class="text-success">Vitalícia</span>{% endif %}</td>
        <td>{{v.status}}</td>
        <td>
          <a class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" href="#m{{loop.index}}">Editar</a>
          <a href="/toggle/{{k}}" class="btn btn-sm btn-outline-warning">Ban</a>
          <a href="/del/{{k}}" class="btn btn-sm btn-outline-danger" onclick="return confirm('Excluir {{k}}?')">Del</a>

          <div class="modal fade" id="m{{loop.index}}">
            <div class="modal-dialog modal-dialog-centered">
              <div class="modal-content p-3">
                <form method="post" action="/edit/{{k}}">
                  <h6 class="mb-3">Expiração de {{k}}</h6>
                  <input type="date" name="expires"
                    value="{{'' if not v.expires else time.strftime('%Y-%m-%d',time.localtime(v.expires))}}"
                    class="form-control mb-3">
                  <button class="btn btn-primary">Salvar</button>
                </form>
              </div>
            </div>
          </div>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="5" class="text-center">Nenhuma chave.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
"""

# ── main ──────────────────────────────────────────────
if __name__ == '__main__':
    print(f'» Painel em http://{HOST}:{PORT}  (login: {ADMIN_USER})')
    app.run(host=HOST, port=PORT)
