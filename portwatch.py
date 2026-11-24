#!/usr/bin/env python3
"""portwatch v2 : supervision légère des ports ouverts (Python 3 standard, ~10 Mo de RAM).

Web  : sudo python3 portwatch.py      puis http://127.0.0.1:9999
Shell: sudo python3 portwatch.py --cli
"""
import hmac, json, os, pwd, re, signal, subprocess, sys, time
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ----------------------------- CONFIGURATION -----------------------------
HOST, PORT = "127.0.0.1", 9999   # "0.0.0.0" pour accès depuis un autre PC (définir alors TOKEN)
TOKEN = ""                       # si défini : accès via http://ip:9999/?token=MONTOKEN
ENABLE_ACTIONS = True            # boutons Démarrer / Redémarrer / Arrêter
REFRESH = 3                      # secondes entre deux rafraîchissements

# port, name, desc : obligatoires
# expect : mot attendu dans le processus (sinon pastille orange "occupé par autre chose")
# web    : True -> bouton "Ouvrir" ; check : chemin HTTP testé (code + temps de réponse)
# start / restart : commande (liste) lancée par les boutons. À ADAPTER à votre installation.
WATCH = [
    {"port": 8081, "name": "Tomcat", "desc": "Serveur d'applications", "expect": "java",
     "web": True, "check": "/",
     "start": ["systemctl", "start", "tomcat8"],
     "restart": ["systemctl", "restart", "tomcat8"]},
    {"port": 4200, "name": "Angular", "desc": "ng serve", "expect": "node", "web": True},
    {"port": 6321, "name": "SFTP", "desc": "Accès SFTP", "expect": "sshd"},
]
# --------------------------------------------------------------------------

HZ = os.sysconf("SC_CLK_TCK")
PUBLIC = {"0.0.0.0", "*", "[::]", "::"}
ACTIONS_OK = ENABLE_ACTIONS and (HOST in ("127.0.0.1", "localhost", "::1") or bool(TOKEN))


def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def proc_info(pid):
    d = {}
    try: d["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError: pass
    try: d["cwd"] = os.readlink(f"/proc/{pid}/cwd")
    except OSError: pass
    try: d["cmd"] = read(f"/proc/{pid}/cmdline", "rb").replace(b"\0", b" ").decode(errors="replace").strip()[:600]
    except OSError: pass
    try:
        st = read(f"/proc/{pid}/status")
        m = re.search(r"VmRSS:\s+(\d+) kB", st)
        if m: d["rss_mb"] = round(int(m.group(1)) / 1024, 1)
        m = re.search(r"Uid:\s+(\d+)", st)
        if m:
            try: d["user"] = pwd.getpwuid(int(m.group(1))).pw_name
            except KeyError: d["user"] = m.group(1)
        fields = read(f"/proc/{pid}/stat").rsplit(")", 1)[1].split()
        d["uptime"] = int(float(read("/proc/uptime").split()[0]) - int(fields[19]) / HZ)
    except (OSError, IndexError, ValueError):
        pass
    return d


_cache = (0, {})


def listening():
    global _cache
    if time.time() - _cache[0] < 1:
        return _cache[1]
    res = {}
    out = subprocess.run(["ss", "-H", "-ltnp"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        addr, port = p[3].rsplit(":", 1)
        port = int(port)
        e = res.get(port)
        if e is None:
            e = res[port] = {"binds": [], "process": None, "pid": None}
            m = re.search(r'\("([^"]+)",pid=(\d+)', line)
            if m:
                e["process"], e["pid"] = m.group(1), int(m.group(2))
                e.update(proc_info(e["pid"]))
        e["binds"].append(addr)
    for e in res.values():
        e["binds"] = sorted(set(e["binds"]))
        e["public"] = any(b in PUBLIC for b in e["binds"])
    _cache = (time.time(), res)
    return res


def health(port, path):
    t = time.time()
    try:
        code = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=1).status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        return {"code": None, "ms": None}
    return {"code": code, "ms": int((time.time() - t) * 1000)}


def status():
    ports = listening()
    rows, seen = [], set()
    for w in WATCH:
        seen.add(w["port"])
        i = ports.get(w["port"])
        r = {"port": w["port"], "name": w["name"], "desc": w.get("desc", ""), "watched": True,
             "web": w.get("web", False),
             "actions": {k: bool(w.get(k)) for k in ("start", "restart")}}
        if i is None:
            r["state"] = "down"
        else:
            r.update(i)
            r["state"] = "up"
            exp = w.get("expect")
            if exp and i.get("process"):
                hay = " ".join(str(i.get(k) or "") for k in ("process", "cmd", "exe")).lower()
                if exp.lower() not in hay:
                    r["state"] = "warn"
                    r["msg"] = f"Port occupé par « {i['process']} » (attendu : {exp})"
            if w.get("check"):
                h = r["http"] = health(w["port"], w["check"])
                if h["code"] is None or h["code"] >= 500:
                    r["state"] = "warn"
                    r["msg"] = r.get("msg") or "Le port est ouvert mais l'application ne répond pas correctement"
        rows.append(r)
    for port in sorted(set(ports) - seen):
        i = ports[port]
        rows.append({"port": port, "name": i["process"] or "?", "desc": "", "watched": False,
                     "state": "up", "web": False, "actions": {}, **i})
    return {"rows": rows, "root": os.geteuid() == 0, "actions": ACTIONS_OK}


def do_action(port, act):
    if act in ("term", "kill"):
        pid = (listening().get(port) or {}).get("pid")
        if not pid or pid in (1, os.getpid()):
            return 400, "Aucun processus ciblable (droits root nécessaires ?)"
        os.kill(pid, signal.SIGTERM if act == "term" else signal.SIGKILL)
        return 200, f"Signal envoyé au PID {pid}"
    w = next((x for x in WATCH if x["port"] == port), None)
    if act in ("start", "restart") and w and w.get(act):
        r = subprocess.run(w[act], capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr).strip()[-400:]
        return (200 if r.returncode == 0 else 500), out or f"Terminé (code {r.returncode})"
    return 400, "Action inconnue"


PAGE = r"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Ports</title>
<style>
:root{--bg:#fafafa;--fg:#222;--mu:#777;--bd:#ddd;--card:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#1b1b1b;--fg:#eee;--mu:#999;--bd:#333;--card:#242424}}
body{font:15px system-ui,sans-serif;margin:0;padding:1.2rem 1.5rem;background:var(--bg);color:var(--fg)}
header{display:flex;flex-wrap:wrap;gap:.8rem;align-items:center;margin-bottom:1rem}
h1{font-size:1.1rem;margin:0}#sum{color:var(--mu);font-size:.85rem;flex:1}
input[type=search]{font:inherit;padding:.25rem .5rem;border:1px solid var(--bd);border-radius:.4rem;background:var(--card);color:var(--fg)}
label{font-size:.85rem;color:var(--mu)}
.r{border-bottom:1px solid var(--bd)}
.m{display:flex;align-items:center;gap:.7rem;padding:.4rem 0;cursor:pointer;flex-wrap:wrap}
.d{width:.9rem;height:.9rem;border-radius:50%;flex:none}
.up{background:#2ecc71}.down{background:#e74c3c}.warn{background:#f39c12}
.p{width:4rem;font-variant-numeric:tabular-nums}.n{width:8rem;font-weight:600}
.x{flex:1;min-width:10rem;color:var(--mu);font-size:.8rem;overflow-wrap:anywhere}
.b{font-size:.7rem;padding:.1rem .45rem;border-radius:.7rem;border:1px solid var(--bd);color:var(--mu)}
.ok{color:#2ecc71;border-color:#2ecc71}.ko{color:#e74c3c;border-color:#e74c3c}.pub{color:#f39c12;border-color:#f39c12}
button,a.btn{font:inherit;font-size:.8rem;padding:.15rem .6rem;border:1px solid var(--bd);border-radius:.4rem;background:var(--card);color:var(--fg);cursor:pointer;text-decoration:none}
dl.dt{display:grid;grid-template-columns:8rem 1fr;gap:.2rem .8rem;margin:0;padding:.2rem 0 .8rem 1.6rem;font-size:.8rem}
.dt dt{color:var(--mu)}.dt dd{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,monospace}
.acts{grid-column:1/-1;display:flex;gap:.5rem;flex-wrap:wrap}
.bn{background:#f39c1233;border:1px solid #f39c12;padding:.4rem .8rem;border-radius:.4rem;margin-bottom:.8rem;font-size:.85rem}
#lg{font:.8rem ui-monospace,monospace;color:var(--mu);padding:.4rem 0;max-height:12rem;overflow:auto}
details{margin-top:1.2rem}summary{cursor:pointer;color:var(--mu);font-size:.85rem}
#t{position:fixed;bottom:1rem;right:1rem;background:#333;color:#fff;padding:.5rem .9rem;border-radius:.4rem;display:none;max-width:80vw;white-space:pre-wrap}
</style>
<header><h1>Ports</h1><span id=sum></span>
<input id=q type=search placeholder="Filtrer (port, nom, chemin...)">
<label><input id=ow type=checkbox> Surveillés seulement</label>
<button id=pz>Pause</button></header>
<div id=bn class=bn hidden></div>
<div id=l></div>
<details><summary>Journal des changements</summary><div id=lg></div></details>
<div id=t></div>
<script>
const $=s=>document.querySelector(s),Q=location.search,REFRESH=__R__;
const open=new Set();let prev=null,paused=false,last=null,tt;
const LBL={up:'actif',down:'inactif',warn:'à vérifier'};
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function toast(m){const t=$('#t');t.textContent=m;t.style.display='block';clearTimeout(tt);tt=setTimeout(()=>t.style.display='none',5000)}
function copy(v){navigator.clipboard?navigator.clipboard.writeText(v).then(()=>toast('Copié')):prompt('Copier :',v)}
function fmtUp(s){if(s==null)return'';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
 return d?d+' j '+h+' h':h?h+' h '+m+' min':m?m+' min':s+' s'}
function log(txt){const d=el('div','',new Date().toLocaleTimeString()+'  '+txt);$('#lg').prepend(d);
 while($('#lg').children.length>50)$('#lg').lastChild.remove()}
async function act(port,a,label){
 if(!confirm(label+' - port '+port+' ?'))return;
 try{const r=await fetch('/act'+Q,{method:'POST',headers:{'X-Portwatch':'1','Content-Type':'application/json'},body:JSON.stringify({port,act:a})});
  toast((await r.json()).msg)}catch(e){toast('Erreur réseau')}
 setTimeout(tick,800)}
function btn(txt,fn){const b=el('button','',txt);b.onclick=e=>{e.stopPropagation();fn()};return b}
function render(d){
 const f=$('#q').value.toLowerCase(),ow=$('#ow').checked,l=$('#l');l.textContent='';
 const cur={};let bad=0,w=0,okw=0;
 for(const s of d.rows){cur[s.port]=s.state;if(s.watched){w++;s.state==='up'?okw++:bad++}}
 if(prev){for(const p in cur)if(prev[p]!==cur[p]){const s=d.rows.find(x=>x.port==p);
   log(p+' '+s.name+' : '+(prev[p]?LBL[prev[p]]+' -> ':'ouvert -> ')+LBL[cur[p]])}
  for(const p in prev)if(!(p in cur))log(p+' : fermé')}
 prev=cur;
 $('#sum').textContent=okw+'/'+w+' surveillés actifs · '+d.rows.filter(s=>s.state!=='down').length+' ports ouverts · '+new Date().toLocaleTimeString();
 document.title=(bad?'🔴 '+bad:'🟢')+' · Ports';
 const bn=$('#bn'),notes=[];
 if(!d.root)notes.push('Non lancé en root : noms de processus et actions indisponibles pour certains ports.');
 if(!d.actions)notes.push('Actions désactivées (accès non local sans TOKEN, ou ENABLE_ACTIONS=False).');
 bn.hidden=!notes.length;bn.textContent=notes.join(' ');
 for(const s of d.rows){
  if(ow&&!s.watched)continue;
  if(f&&!(s.port+' '+s.name+' '+(s.process||'')+' '+(s.cmd||'')+' '+(s.exe||'')).toLowerCase().includes(f))continue;
  const r=el('div','r'),m=el('div','m');
  r.title=[s.desc,s.exe,s.cmd,s.pid?'PID '+s.pid:''].filter(Boolean).join('\n');
  m.onclick=()=>{open.has(s.port)?open.delete(s.port):open.add(s.port);render(last)};
  m.append(el('span','d '+s.state),el('span','p',s.port),el('span','n',s.name),
   el('span','x',s.state==='down'?(s.desc||'inactif'):(s.exe||s.process||s.desc)));
  if(s.state!=='down')m.append(el('span','b '+(s.public?'pub':''),s.public?'exposé':'local'));
  if(s.http)m.append(el('span','b '+(s.http.code&&s.http.code<500?'ok':'ko'),s.http.code?'HTTP '+s.http.code+' · '+s.http.ms+' ms':'HTTP KO'));
  if(s.msg)m.append(el('span','b ko','⚠ '+s.msg));
  if(s.web&&s.state!=='down'){const u='http://'+location.hostname+':'+s.port;
   const a=el('a','btn','Ouvrir');a.href=u;a.target='_blank';a.onclick=e=>e.stopPropagation();m.append(a,btn('Copier l\'URL',()=>copy(u)))}
  r.append(m);
  if(open.has(s.port)){
   const dl=el('dl','dt'),add=(k,v)=>{if(v!=null&&v!=='')dl.append(el('dt','',k),el('dd','',v))};
   add('Description',s.desc);add('PID',s.pid);add('Utilisateur',s.user);
   add('Mémoire',s.rss_mb!=null?s.rss_mb+' Mo':null);add('Actif depuis',fmtUp(s.uptime));
   add('Écoute sur',(s.binds||[]).join(', '));add('Exécutable',s.exe);add('Dossier',s.cwd);add('Commande',s.cmd);
   const ac=el('div','acts');
   if(d.actions){
    if(s.state==='down'&&s.actions.start)ac.append(btn('Démarrer',()=>act(s.port,'start','Démarrer '+s.name)));
    if(s.state!=='down'&&s.actions.restart)ac.append(btn('Redémarrer',()=>act(s.port,'restart','Redémarrer '+s.name)));
    if(s.state!=='down'&&s.pid){ac.append(btn('Arrêter (SIGTERM)',()=>act(s.port,'term','Arrêter '+s.name)));
     ac.append(btn('Forcer (SIGKILL)',()=>act(s.port,'kill','FORCER l\'arrêt de '+s.name)))}}
   if(s.cmd)ac.append(btn('Copier la commande',()=>copy(s.cmd)));
   dl.append(ac);r.append(dl)}
  l.append(r)}}
async function tick(){
 if(document.hidden||paused)return;
 try{last=await(await fetch('/api'+Q)).json();render(last)}
 catch(e){$('#bn').hidden=false;$('#bn').textContent='Serveur portwatch injoignable...'}}
$('#q').oninput=$('#ow').onchange=()=>last&&render(last);
$('#pz').onclick=()=>{paused=!paused;$('#pz').textContent=paused?'Reprendre':'Pause';tick()};
tick();setInterval(tick,REFRESH*1000);
</script>""".replace("__R__", str(REFRESH))


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        if not TOKEN:
            return True
        t = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return hmac.compare_digest(t, TOKEN)

    def do_GET(self):
        if not self._auth():
            return self._send(403, "Accès refusé", "text/plain; charset=utf-8")
        if urlparse(self.path).path == "/api":
            return self._send(200, status())
        self._send(200, PAGE, "text/html; charset=utf-8")

    def do_POST(self):
        origin = self.headers.get("Origin")
        if (not ACTIONS_OK or not self._auth() or self.headers.get("X-Portwatch") != "1"
                or (origin and urlparse(origin).netloc != self.headers.get("Host"))):
            return self._send(403, {"msg": "Refusé"})
        try:
            n = min(int(self.headers.get("Content-Length", 0) or 0), 4096)
            data = json.loads(self.rfile.read(n))
            code, msg = do_action(int(data["port"]), data["act"])
        except PermissionError:
            code, msg = 403, "Permission refusée (lancez portwatch avec sudo)"
        except subprocess.TimeoutExpired:
            code, msg = 500, "Commande trop longue (60 s)"
        except Exception as e:
            code, msg = 500, f"Erreur : {e}"
        self._send(code, {"msg": msg})

    def log_message(self, *a):
        pass


def cli():
    for r in status()["rows"]:
        c = {"up": "32", "warn": "33", "down": "31"}[r["state"]]
        print(f"\033[{c}m●\033[0m {r['port']:<6}{r['name']:<14}{r.get('exe') or r['desc']}"
              + (f"  ⚠ {r['msg']}" if r.get("msg") else ""))


if __name__ == "__main__":
    if "--cli" in sys.argv:
        cli()
        sys.exit()
    print(f"portwatch sur http://{HOST}:{PORT}" + (f"/?token={TOKEN}" if TOKEN else ""), file=sys.stderr)
    if not ACTIONS_OK and ENABLE_ACTIONS:
        print("Actions désactivées : accès non local sans TOKEN.", file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
