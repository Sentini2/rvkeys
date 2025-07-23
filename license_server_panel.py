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
DATA_FILE   = 'keys.json'          # banco de licenças
UPD_FILE    = 'update.json'        # versão mais recente do Loader
FILES_DIR   = 'files'              # onde ficam uploads
ADMIN_USER  = 'rvadmin'
ADMIN_PASSHASH = pbkdf2_sha256.hash('mudar123')
HOST, PORT  = '0.0.0.0', 5001

app = Flask(__name__)
CORS(app)                          # libera /exists para o painel
app.secret_key = os.urandom(24)
os.makedirs(FILES_DIR, exist_ok=True)

# ─── Helpers ───
def _load(path=DATA_FILE):
    if not os.path.exists(path): json.dump({}, open(path, 'w'))
    with open(path) as f: return json.load(f)

def _save(d, path=DATA_FILE): json.dump(d, open(path, 'w'), indent=2)

def _sha(s): return hashlib.sha256(s.encode()).hexdigest()

def rnd(n=16):
    s=''.join(random.choices(string.ascii_uppercase+string.digits,k=n))
    return '-'.join([s[i:i+4] for i in range(0,n,4)])

def _login_required(fn):
    @functools.wraps(fn)
    def w(*a,**kw):
        if not session.get('logged'): return redirect(url_for('login'))
        return fn(*a,**kw)
    return w

# ─── API licenças ───
@app.post('/validate')
def validate():
    data = _load()
    body = request.get_json(force=True) or {}
    key  = body.get('key', '').upper()
    rec  = data.get(key)

    # ── validações básicas ──────────────────────────
    if not rec or rec.get('status') == 'banned':
        return jsonify(ok=False, reason='INVALID'), 403
    if rec['expires'] and time.time() > rec['expires']:
        return jsonify(ok=False, reason='EXPIRED'), 403

    # ── GERA TOKEN (sem HWID) ───────────────────────
    token = _sha(key + str(rec['expires']))

    return jsonify(ok=True, token=token, expires=rec['expires'])


# usado pelo painel HTML para checar existência
@app.get('/exists/<key>')
def exists(key):
    rec=_load().get(key.upper())
    if rec and rec.get('status','active')!='banned':
        return jsonify(exists=True)
    return jsonify(exists=False), 404

# ─── API atualização ───
@app.get('/latest')
def latest(): return jsonify(_load(UPD_FILE) or {})

@app.post('/set_update'); @_login_required
def set_update():
    ver=request.form['ver'].strip()
    url=request.form['url'].strip()
    if 'file' in request.files and request.files['file'].filename:
        f=request.files['file']
        fname=f"{int(time.time())}_{f.filename}"
        path=os.path.join(FILES_DIR,fname)
        f.save(path)
        url=request.url_root.rstrip('/')+url_for('download',fname=fname).lstrip('/')
    _save({'version':ver,'url':url}, UPD_FILE)
    flash('Atualização publicada.','success')
    return redirect('/')

@app.get('/download/<path:fname>')
def download(fname): return send_from_directory(FILES_DIR,fname,as_attachment=True)

# ─── Login ───
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        if (request.form['user']==ADMIN_USER
            and pbkdf2_sha256.verify(request.form['pw'],ADMIN_PASSHASH)):
            session['logged']=True; return redirect('/')
        flash('Credenciais inválidas.','danger')
    return render_template_string(TPL_LOGIN)

@app.get('/logout'); def logout(): session.clear(); return redirect('/login')

# ─── Painel principal ───
@app.get('/'); @_login_required
def panel():
    q=request.args.get('q','').upper()
    keys={k:v for k,v in _load().items() if q in k.upper()}
    upd=_load(UPD_FILE)
    return render_template_string(TPL_PANEL, keys=keys, q=q, upd=upd, time=time)

# =================== rotas chaves ===================
@app.post('/new'); @_login_required
def new():
    qty=int(request.form.get('qty',1))
    days=int(request.form.get('days',0))
    data=_load(); exp=int(time.time()+days*86400) if days else 0
    out=[]
    for _ in range(qty):
        k=rnd(); data[k]=dict(expires=exp,hwid=None,status='active',type='single')
        out.append(k)
    _save(data); flash(f'{qty} chave(s) criada(s).','success')
    session['last_keys']=out; return redirect('/')

@app.post('/new_admin'); @_login_required
def new_admin():
    qty=int(request.form.get('qty',1))
    data=_load(); out=[]
    for _ in range(qty):
        k=rnd(); data[k]=dict(expires=0,hwid=None,status='active',type='admin')
        out.append(k)
    _save(data); flash(f'{qty} chave(s) ADMIN criadas.','warning')
    session['last_keys']=out; return redirect('/')

@app.post('/edit/<key>'); @_login_required
def edit(key):
    d=_load(); exp=request.form.get('expires')
    d[key]['expires']=int(time.mktime(datetime.strptime(exp,'%Y-%m-%d').timetuple())) if exp else 0
    _save(d); flash('Chave atualizada.','success'); return redirect(f'/?q={key}')

@app.get('/toggle/<key>'); @_login_required
def toggle(key):
    d=_load(); d[key]['status']='banned' if d[key]['status']=='active' else 'active'
    _save(d); flash('Status alterado.','warning'); return redirect(f'/?q={key}')

@app.get('/del/<key>'); @_login_required
def delete(key):
    d=_load(); d.pop(key,None); _save(d); flash('Chave removida.','danger'); return redirect('/')

# ─── HTML (Jinja2) ───
TPL_LOGIN = """<!doctype html><title>Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<div class=container style="max-width:420px">
  <h3 class="text-center my-4">Painel RV</h3>
  {% with m=get_flashed_messages(with_categories=1) %}
    {% for c,t in m %}<div class="alert alert-{{c}}">{{t}}</div>{% endfor %}{% endwith %}
  <form method=post class="border rounded p-4 shadow">
    <input name=user class=form-control placeholder=Usuário autofocus><br>
    <input name=pw type=password class=form-control placeholder=Senha><br>
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

  <!-- Busca -->
  <form class="row g-2 mb-4">
    <div class=col><input name=q value="{{q}}" class=form-control placeholder="Buscar chave"></div>
    <div class=col-auto><button class="btn btn-outline-secondary">Buscar</button></div>
  </form>

  <!-- Novas chaves single -->
  <details class=mb-4><summary class=h6>Criar chaves SINGLE</summary>
    <form class="row g-2 mt-2" method=post action=/new>
      <div class=col><input type=number name=qty min=1 value=1 class=form-control placeholder=Qtde></div>
      <div class=col><input type=number name=days min=0 value=30 class=form-control placeholder="Dias (0=vitalícia)"></div>
      <div class=col-auto><button class="btn btn-success">Gerar</button></div>
    </form>
  </details>

  <!-- Novas chaves admin -->
  <details class=mb-4><summary class=h6>Criar chaves ADMIN (multi‑PC)</summary>
    <form class="row g-2 mt-2" method=post action=/new_admin>
      <div class=col><input type=number name=qty min=1 value=1 class=form-control placeholder=Qtde></div>
      <div class=col-auto><button class="btn btn-warning">Gerar ADMIN</button></div>
    </form>
  </details>

  <!-- Atualização -->
  <details class=mb-4 open><summary class=h6>Nova atualização (versão atual: {{upd.version if upd else 'nenhuma'}})</summary>
    <form class="row g-2 mt-2" method=post action=/set_update enctype=multipart/form-data>
      <div class=col><input name=ver class=form-control placeholder="Versão ex: 1.2" required></div>
      <div class=col><input name=url class=form-control placeholder="URL direta (.exe) – opcional"></div>
      <div class=col><input type=file name=file class=form-control></div>
      <div class=col-auto><button class="btn btn-primary">Publicar</button></div>
    </form>
  </details>

  <!-- Tabela -->
  <table class="table table-sm table-bordered align-middle">
    <thead class=table-light><tr>
      <th>Chave</th><th>Tipo</th><th>Expira</th><th>HWID</th><th>Status</th><th style=width:120px>Ações</th></tr></thead>
    <tbody>{% for k,v in keys.items() %}
      <tr class="{% if v.status=='banned' %}table-danger{% endif %}">
        <td class=font-monospace>{{k}}</td>
        <td>{{v.type}}</td>
        <td>{% if v.expires %}{{time.strftime('%d/%m/%Y',time.localtime(v.expires))}}{% else %}<span class=text-success>Vitalícia</span>{% endif %}</td>
        <td class=font-monospace>{{v.hwid or '-'}}</td>
        <td>{{v.status}}</td>
        <td>
          <a class="btn btn-sm btn-outline-primary" data-bs-toggle=modal href="#e{{loop.index}}">Editar</a>
          <a href="/toggle/{{k}}" class="btn btn-sm btn-outline-warning">Ban</a>
          <a href="/del/{{k}}" class="btn btn-sm btn-outline-danger" onclick="return confirm('Excluir {{k}}?')">Del</a>
          <!-- modal editar -->
          <div class="modal fade" id="e{{loop.index}}">
            <div class="modal-dialog modal-dialog-centered"><div class="modal-content p-3">
              <form method=post action="/edit/{{k}}">
                <h6>Expiração de {{k}}</h6>
                <input type=date name=expires value="{{'' if not v.expires else time.strftime('%Y-%m-%d',time.localtime(v.expires))}}" class=form-control mb-3>
                <button class="btn btn-primary">Salvar</button>
              </form></div></div></div>
        </td></tr>{% else %}
      <tr><td colspan=6 class=text-center>Nenhuma chave.</td></tr>{% endfor %}
    </tbody></table>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
"""

# ─── main ───
if __name__ == '__main__':
    print(f'» Painel em http://{HOST}:{PORT}  (login: {ADMIN_USER})')
    app.run(host=HOST, port=PORT)
