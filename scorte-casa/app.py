"""Scorte di casa: server web + API JSON + SQLite + login. Solo libreria standard di Python 3.8+."""
import hashlib, hmac, io, json, mimetypes, os, re, secrets, sqlite3, time
from email.message import Message
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "scorte.db"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
STATIC = os.path.join(BASE, "static")
REG_APERTA = os.environ.get("REGISTRAZIONE_APERTA") == "1"  # chiunque può creare un account
INVITO = os.environ.get("CODICE_INVITO", "")  # oppure serve questo codice per creare un account
COOKIE_SECURE = os.environ.get("COOKIE_SECURE") == "1"
DURATA = 30 * 86400

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS utenti (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, pw TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS sessioni (
      token TEXT PRIMARY KEY, utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE, scade REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS articoli (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      utente_id INTEGER NOT NULL REFERENCES utenti(id) ON DELETE CASCADE,
      nome TEXT NOT NULL, categoria TEXT NOT NULL DEFAULT '', unita TEXT NOT NULL DEFAULT 'pz',
      scorta_minima REAL NOT NULL DEFAULT 0 CHECK (scorta_minima >= 0), UNIQUE (utente_id, nome))""",
    """CREATE TABLE IF NOT EXISTS movimenti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      articolo_id INTEGER NOT NULL REFERENCES articoli(id) ON DELETE CASCADE,
      tipo TEXT NOT NULL CHECK (tipo IN ('carico','consumo','inventario')),
      delta REAL NOT NULL, nota TEXT NOT NULL DEFAULT '',
      data TEXT NOT NULL DEFAULT (datetime('now','localtime')))""",
]
# La giacenza non è salvata: è la somma dei movimenti, così lo storico è sempre coerente.
SEL = ("SELECT a.*, ROUND(COALESCE(SUM(m.delta),0),3) AS giacenza FROM articoli a "
       "LEFT JOIN movimenti m ON m.articolo_id = a.id ")
FALLITI = {}


def run(sql, args=()):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        cur = c.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()]
        c.commit()
        return rows, cur.lastrowid
    finally:
        c.close()


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def verifica_pw(pw, salvata):
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(salvata.split(":")[0])), salvata)


DUMMY = hash_pw("password-finta")
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()


def numero(v, nome, minimo=0, stretto=False):
    try:
        n = float(str(v).replace(",", "."))
    except (TypeError, ValueError):
        raise ValueError(f"{nome} non è un numero valido")
    if n < minimo or (stretto and n == minimo):
        raise ValueError(f"{nome} deve essere {'maggiore di' if stretto else 'almeno'} {minimo:g}")
    return n


def campi(d):
    nome = str(d.get("nome", "")).strip()
    if not nome:
        raise ValueError("Il nome è obbligatorio")
    return (nome, str(d.get("categoria", "")).strip(), str(d.get("unita") or "pz").strip(),
            numero(d.get("scorta_minima") or 0, "La scorta minima"))


def articolo(aid, uid):
    rows, _ = run(SEL + "WHERE a.id = ? AND a.utente_id = ? GROUP BY a.id", (aid, uid))
    return rows[0] if rows else None


class Handler(BaseHTTPRequestHandler):
    nuovo_cookie = None

    def invia(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self.nuovo_cookie:
            self.send_header("Set-Cookie", self.nuovo_cookie)
        self.end_headers()
        self.wfile.write(data)

    def cookie(self, valore, durata):
        sicuro = COOKIE_SECURE or self.headers.get("X-Forwarded-Proto") == "https"
        return f"sessione={valore}; Path=/; HttpOnly; SameSite=Lax; Max-Age={durata}" + ("; Secure" if sicuro else "")

    def corpo(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ValueError("Richiesta non valida")

    def token(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["sessione"].value if "sessione" in c else None

    def utente(self):
        t = self.token()
        if not t:
            return None
        r, _ = run("SELECT u.id, u.username FROM sessioni s JOIN utenti u ON u.id = s.utente_id "
                   "WHERE s.token = ? AND s.scade > ?", (sha(t), time.time()))
        return r[0] if r else None

    def accesso(self, azione):
        d = self.corpo()
        nome, pw = str(d.get("username", "")).strip().lower(), str(d.get("password", ""))
        chiave, ora = (self.client_address[0], nome), time.time()
        if azione == "registrati":
            if not (REG_APERTA or run("SELECT COUNT(*) AS n FROM utenti")[0][0]["n"] == 0):
                if not INVITO:
                    return 403, {"errore": "Le registrazioni sono chiuse"}
                ck = ("invito", self.client_address[0])
                FALLITI[ck] = [t for t in FALLITI.get(ck, []) if ora - t < 600]
                if len(FALLITI[ck]) >= 5:
                    return 429, {"errore": "Troppi tentativi: riprova tra qualche minuto"}
                if not hmac.compare_digest(str(d.get("invito", "")).encode(), INVITO.encode()):
                    FALLITI[ck].append(ora)
                    return 403, {"errore": "Codice di invito errato"}
            if not re.fullmatch(r"[a-z0-9_.-]{3,32}", nome):
                return 400, {"errore": "Il nome utente deve avere 3-32 caratteri: lettere, numeri, punto, trattino"}
            if not 8 <= len(pw) <= 200:
                return 400, {"errore": "La password deve avere almeno 8 caratteri"}
            try:
                uid = run("INSERT INTO utenti (username, pw) VALUES (?,?)", (nome, hash_pw(pw)))[1]
            except sqlite3.IntegrityError:
                return 409, {"errore": "Nome utente già in uso"}
        else:
            FALLITI[chiave] = [t for t in FALLITI.get(chiave, []) if ora - t < 600]
            if len(FALLITI[chiave]) >= 5:
                return 429, {"errore": "Troppi tentativi: riprova tra qualche minuto"}
            r = run("SELECT id, pw FROM utenti WHERE username = ?", (nome,))[0]
            valida = verifica_pw(pw[:200], r[0]["pw"] if r else DUMMY)  # tempo simile anche se l'utente non esiste
            if not r or not valida:
                FALLITI[chiave].append(ora)
                return 401, {"errore": "Nome utente o password errati"}
            uid = r[0]["id"]
        t = secrets.token_urlsafe(32)
        run("DELETE FROM sessioni WHERE scade < ?", (ora,))
        run("INSERT INTO sessioni (token, utente_id, scade) VALUES (?,?,?)", (sha(t), uid, ora + DURATA))
        self.nuovo_cookie = self.cookie(t, DURATA)
        return 200, {"utente": nome}

    def api(self, metodo, parti, query):
        if parti == ["stato"] and metodo == "GET":
            u = self.utente()
            primo = run("SELECT COUNT(*) AS n FROM utenti")[0][0]["n"] == 0
            return 200, {"utente": u["username"] if u else None, "registrazione": REG_APERTA or primo or bool(INVITO),
                         "invito": bool(INVITO) and not REG_APERTA and not primo}
        if metodo != "GET" and not self.headers.get("Content-Type", "").startswith("application/json"):
            return 415, {"errore": "Richiesta non valida"}  # blocca i form inviati da altri siti (CSRF)
        if parti in (["registrati"], ["accedi"]) and metodo == "POST":
            return self.accesso(parti[0])
        if parti == ["esci"] and metodo == "POST":
            if self.token():
                run("DELETE FROM sessioni WHERE token = ?", (sha(self.token()),))
            self.nuovo_cookie = self.cookie("", 0)
            return 200, {"ok": True}
        u = self.utente()
        if not u:
            return 401, {"errore": "Accedi per continuare"}
        uid = u["id"]
        if parti == ["articoli"] and metodo == "GET":
            return 200, run(SEL + "WHERE a.utente_id = ? GROUP BY a.id ORDER BY a.categoria, a.nome", (uid,))[0]
        if parti == ["articoli"] and metodo == "POST":
            nuovo = run("INSERT INTO articoli (nome, categoria, unita, scorta_minima, utente_id) VALUES (?,?,?,?,?)",
                        campi(self.corpo()) + (uid,))[1]
            return 201, articolo(nuovo, uid)
        if len(parti) == 2 and parti[0] == "articoli" and parti[1].isdigit():
            aid = int(parti[1])
            if not articolo(aid, uid):
                return 404, {"errore": "Articolo non trovato"}
            if metodo == "PUT":
                run("UPDATE articoli SET nome=?, categoria=?, unita=?, scorta_minima=? WHERE id=? AND utente_id=?",
                    campi(self.corpo()) + (aid, uid))
                return 200, articolo(aid, uid)
            if metodo == "DELETE":
                run("DELETE FROM articoli WHERE id = ? AND utente_id = ?", (aid, uid))
                return 200, {"ok": True}
        if parti == ["movimenti"] and metodo == "GET":
            limite = min(max(int((query.get("limite") or ["100"])[0]), 1), 500)
            return 200, run("SELECT m.*, a.nome, a.unita FROM movimenti m JOIN articoli a ON a.id = m.articolo_id "
                            "WHERE a.utente_id = ? ORDER BY m.id DESC LIMIT ?", (uid, limite))[0]
        if parti == ["movimenti"] and metodo == "POST":
            d = self.corpo()
            art = articolo(int(str(d.get("articolo_id") or 0)) if str(d.get("articolo_id") or 0).isdigit() else 0, uid)
            if not art:
                return 404, {"errore": "Articolo non trovato"}
            tipo, giacenza = d.get("tipo"), art["giacenza"]
            if tipo == "carico":
                delta = numero(d.get("quantita"), "La quantità", 0, True)
            elif tipo == "consumo":
                q = numero(d.get("quantita"), "La quantità", 0, True)
                if q > giacenza + 1e-9:
                    return 400, {"errore": f"Giacenza insufficiente: in casa ci sono {giacenza:g} {art['unita']}"}
                delta = -q
            elif tipo == "inventario":
                delta = numero(d.get("quantita"), "La quantità contata") - giacenza
            else:
                return 400, {"errore": "Tipo di movimento non valido"}
            run("INSERT INTO movimenti (articolo_id, tipo, delta, nota) VALUES (?,?,?,?)",
                (art["id"], tipo, round(delta, 3), str(d.get("nota", "")).strip()))
            return 201, articolo(art["id"], uid)
        if parti == ["spesa"] and metodo == "GET":
            righe = run(SEL + "WHERE a.utente_id = ? GROUP BY a.id HAVING giacenza < a.scorta_minima "
                        "ORDER BY a.categoria, a.nome", (uid,))[0]
            for r in righe:
                r["da_comprare"] = round(r["scorta_minima"] - r["giacenza"], 3)
            return 200, righe
        return 404, {"errore": "Percorso non trovato"}

    def gestisci(self, metodo):
        url = urlparse(self.path)
        try:
            if url.path.startswith("/api/"):
                code, obj = self.api(metodo, [p for p in url.path.split("/") if p][1:], parse_qs(url.query))
                return self.invia(code, obj)
            if metodo != "GET":
                return self.invia(405, {"errore": "Metodo non consentito"})
            nome = "index.html" if url.path == "/" else url.path.lstrip("/")
            percorso = os.path.realpath(os.path.join(STATIC, nome))
            if not percorso.startswith(STATIC + os.sep) or not os.path.isfile(percorso):
                return self.invia(404, {"errore": "Pagina non trovata"})
            with open(percorso, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", (mimetypes.guess_type(percorso)[0] or "text/plain") + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
        except ValueError as e:
            self.invia(400, {"errore": str(e)})
        except sqlite3.IntegrityError:
            self.invia(409, {"errore": "Esiste già un articolo con questo nome"})

    def do_GET(self): self.gestisci("GET")
    def do_POST(self): self.gestisci("POST")
    def do_PUT(self): self.gestisci("PUT")
    def do_DELETE(self): self.gestisci("DELETE")

    def log_message(self, fmt, *args):
        pass


class HandlerWsgi(Handler):
    """Adatta il Handler a WSGI, per hosting come PythonAnywhere che non lanciano app.py direttamente."""

    def __init__(self, environ):
        self.headers = Message()
        for nome, chiave in (("Cookie", "HTTP_COOKIE"), ("Content-Type", "CONTENT_TYPE"),
                             ("Content-Length", "CONTENT_LENGTH"), ("X-Forwarded-Proto", "HTTP_X_FORWARDED_PROTO")):
            if environ.get(chiave):
                self.headers[nome] = environ[chiave]
        q = environ.get("QUERY_STRING")
        self.path = environ.get("PATH_INFO", "/") + ("?" + q if q else "")
        self.client_address = (environ.get("REMOTE_ADDR", ""), 0)
        self.rfile, self.wfile = environ["wsgi.input"], io.BytesIO()
        self.stato, self.intestazioni = 500, []

    def send_response(self, code, message=None): self.stato = code
    def send_header(self, k, v): self.intestazioni.append((k, v))
    def end_headers(self): pass


_pronto = False


def application(environ, start_response):
    global _pronto
    if not _pronto:
        for s in SCHEMA:
            run(s)
        _pronto = True
    h = HandlerWsgi(environ)
    h.gestisci(environ["REQUEST_METHOD"])
    start_response(f"{h.stato} {HTTPStatus(h.stato).phrase}", h.intestazioni)
    return [h.wfile.getvalue()]


if __name__ == "__main__":
    for s in SCHEMA:
        run(s)
    print(f"Scorte di casa attivo su http://localhost:{PORT} (database: {DB})")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
