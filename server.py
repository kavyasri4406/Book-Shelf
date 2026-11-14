#!/usr/bin/env python3
"""Book Shelf server: serves the app and stores each account's library.

Run:  python3 server.py [port]      (default: $PORT, else 8765)
Accounts and libraries live in bookshelf.db (SQLite) inside $DATA_DIR (default: ./data),
or, when DATABASE_URL is set to a Neon Postgres connection string, in that database instead.
On a host, use DATABASE_URL or point DATA_DIR at a persistent disk, or every restart loses all accounts.
Set TRUST_PROXY=1 when running behind the host's HTTPS proxy, so login limits see real visitor addresses.
Needs only the Python standard library.
"""
import functools, hashlib, hmac, json, os, re, secrets, socket, sqlite3, sys, time, urllib.error, urllib.parse, urllib.request
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

ROOT = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(os.environ.get('DATA_DIR') or os.path.join(ROOT, 'data'), 'bookshelf.db')
TRUST_PROXY = os.environ.get('TRUST_PROXY') == '1'
MAX_BODY = 12 * 1024 * 1024          # a library with a few custom pictures fits well inside this
SESSION_DAYS = 30
PBKDF2_ROUNDS = 200_000
USERNAME = re.compile(r'^[a-z0-9_.+@-]{3,80}$')   # a plain name or an email address
SPINE_KEY = re.compile(r'^[^,\s]{2,160}\|[^,\s]{0,60}$')   # normalised title|author, as the app builds it
FAILS = {}                           # (ip, username) -> recent failed login times


def load_env_file(path=os.path.join(ROOT, '.env')):
    """Read KEY=value lines from a .env file without overriding real environment variables."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip().removeprefix('export ').strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


load_env_file(os.path.join(ROOT, '.env.local'))   # `neon init` writes here
load_env_file()
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()


class Duplicate(Exception):
    """A row with that unique value already exists."""


class NeonResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class NeonConn:
    """Neon Postgres over its HTTPS SQL endpoint, so the server still needs no database driver.
    Mirrors the few sqlite3 calls the handler makes: execute(...).fetchone(), `with con:` and close()."""
    endpoint = None                    # found on first use, then shared

    def __init__(self, url):
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass

    def _post(self, endpoint, body):
        req = urllib.request.Request(endpoint, data=body, method='POST', headers={
            'Content-Type': 'application/json', 'Neon-Connection-String': self.url,
            'Neon-Raw-Text-Output': 'true', 'Neon-Array-Mode': 'true'})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read() or b'{}')
            except ValueError:
                err = {}
            if err.get('code') == '23505':
                raise Duplicate(err.get('message', 'duplicate'))
            raise RuntimeError(f"database error {e.code}: {err.get('message', e.reason)}")

    def execute(self, sql, params=()):
        n = iter(range(1, 1000))
        query = re.sub(r'\?', lambda m: f'${next(n)}', sql)
        enc = lambda v: None if v is None else ('\\x' + bytes(v).hex()) if isinstance(v, (bytes, bytearray, memoryview)) else str(v)
        body = json.dumps({'query': query, 'params': [enc(v) for v in params]}).encode()
        host = urllib.parse.urlparse(self.url).hostname or ''
        tries = [NeonConn.endpoint] if NeonConn.endpoint else [
            os.environ.get('NEON_HTTP_ENDPOINT') or 'https://' + re.sub(r'^[^.]+\.', 'api.', host) + '/sql',
            'https://' + host + '/sql']
        last = None
        for ep in tries:
            try:
                res = self._post(ep, body)
                NeonConn.endpoint = ep
                return NeonResult(res.get('rows') or [])
            except (Duplicate, RuntimeError):
                raise
            except OSError as e:          # could not reach that address: try the next form
                last = e
        raise RuntimeError(f'could not reach the database: {last}')


def blob(v):
    """Bytes from either backend (Neon sends bytea as \\x-prefixed hex text)."""
    if isinstance(v, str):
        return bytes.fromhex(v[2:]) if v.startswith('\\x') else v.encode()
    return bytes(v)


def db():
    if DATABASE_URL:
        return NeonConn(DATABASE_URL)
    con = sqlite3.connect(DB, timeout=10)
    con.execute('PRAGMA foreign_keys=ON')
    return con


def init():
    if DATABASE_URL:
        con = NeonConn(DATABASE_URL)
        for stmt in ('CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, '
                     'salt BYTEA NOT NULL, hash BYTEA NOT NULL, created DOUBLE PRECISION NOT NULL)',
                     'CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, '
                     'user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires DOUBLE PRECISION NOT NULL)',
                     'CREATE TABLE IF NOT EXISTS libraries(user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, '
                     'data TEXT NOT NULL, updated DOUBLE PRECISION NOT NULL)',
                     'CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY, '
                     'user_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE, created DOUBLE PRECISION NOT NULL)',
                     'CREATE TABLE IF NOT EXISTS spines(key TEXT PRIMARY KEY, img TEXT NOT NULL, '
                     'user_id BIGINT REFERENCES users(id) ON DELETE SET NULL, created DOUBLE PRECISION NOT NULL)'):
            con.execute(stmt)
        return
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with db() as con:
        con.executescript('''
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL, hash BLOB NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS libraries(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                data TEXT NOT NULL, updated REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY,
                user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS spines(key TEXT PRIMARY KEY, img TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created REAL NOT NULL);
        ''')


def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ROUNDS)


def lan_ip():
    """This computer's address on the local network, for share links (a UDP connect sends nothing)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('10.255.255.255', 1))
            return s.getsockname()[0]
    except OSError:
        return None


BOOK_FIELDS = ('id', 'title', 'author', 'cover', 'pages', 'face', 'flip', 'mirror', 'row', 'rgb', 'status', 'rating', 'isbn')


def public_shelf(data):
    """Only what a shared shelf needs: no notes, sessions, reviews or reading history."""
    books = [{k: b[k] for k in BOOK_FIELDS if k in b} for b in data.get('books', []) if isinstance(b, dict)]
    shelf = dict(data.get('shelf') or {})
    if shelf.get('wall') != 'custom':
        shelf.pop('customWall', None)
    used = {str(o.get('k', ''))[2:] for o in shelf.get('objects', []) if isinstance(o, dict) and str(o.get('k', '')).startswith('c:')}
    custom = [c for c in data.get('custom', []) if isinstance(c, dict) and c.get('id') in used]
    return {'books': books, 'shelf': shelf, 'custom': custom}


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Handler(SimpleHTTPRequestHandler):
    server_version = 'Bookshelf/1.0'
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, '.webmanifest': 'application/manifest+json', '.js': 'text/javascript'}

    def end_headers(self):
        # the page, its scripts and the manifest are checked for updates on every load
        if self.path.split('?')[0].endswith(('.html', '.js', '.webmanifest', '/')):
            self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    # ---- helpers ----
    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            raise ValueError('too large')
        obj = json.loads(self.rfile.read(n) or b'{}')
        if not isinstance(obj, dict):
            raise ValueError('bad body')
        return obj

    def user_id(self, con):
        auth = self.headers.get('Authorization') or ''
        if not auth.startswith('Bearer '):
            return None
        row = con.execute('SELECT user_id FROM sessions WHERE token_hash=? AND expires>?',
                          (token_hash(auth[7:]), time.time())).fetchone()
        return int(row[0]) if row else None

    def new_session(self, con, uid):
        token = secrets.token_urlsafe(32)
        con.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
        con.execute('INSERT INTO sessions VALUES(?,?,?)', (token_hash(token), uid, time.time() + SESSION_DAYS * 86400))
        return token

    # ---- routing ----
    def do_GET(self):
        path = self.path.split('?')[0]
        if path.startswith('/api/'):
            return self.api('GET', path[5:])
        # never serve the database, this script, or hidden files
        if path.startswith('/data') or path.endswith(('.py', '.yaml', '.md')) or '/.' in path or path.startswith(('/Dockerfile', '/__pycache__')):
            return self.send_error(404)
        super().do_GET()

    def do_POST(self):
        self.route_write('POST')

    def do_PUT(self):
        self.route_write('PUT')

    def route_write(self, method):
        path = self.path.split('?')[0]
        if not path.startswith('/api/'):
            return self.send_error(404)
        self.api(method, path[5:])

    def api(self, method, name):
        try:
            body = self.read_json() if method != 'GET' else {}
        except ValueError as e:
            return self.send_json(413 if str(e) == 'too large' else 400, {'error': 'That request could not be read'})
        con = db()
        try:
            with con:
                if (method, name) in (('POST', 'signup'), ('POST', 'login')):
                    return self.sign(con, name, body)
                if method == 'GET' and name.startswith('shared/'):
                    row = con.execute('SELECT u.username, l.data FROM shares s JOIN users u ON u.id=s.user_id '
                                      'LEFT JOIN libraries l ON l.user_id=s.user_id WHERE s.id=?', (name[7:],)).fetchone()
                    if not row:
                        return self.send_json(404, {'error': 'This shelf is not shared any more'})
                    return self.send_json(200, {'name': row[0].split('@')[0],      # never show the owner's email
                                                'data': public_shelf(json.loads(row[1]) if row[1] else {})})
                if (method, name) == ('GET', 'spines'):
                    q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                    keys = [k for k in (q.get('keys', [''])[0]).split(',') if SPINE_KEY.match(k)][:80]
                    found = {}
                    for k in keys:
                        row = con.execute('SELECT img FROM spines WHERE key=?', (k,)).fetchone()
                        if row:
                            found[k] = row[0]
                    return self.send_json(200, {'spines': found})
                uid = self.user_id(con)
                if uid is None:
                    return self.send_json(401, {'error': 'Please log in again'})
                if (method, name) == ('GET', 'data'):
                    row = con.execute('SELECT data FROM libraries WHERE user_id=?', (uid,)).fetchone()
                    return self.send_json(200, {'data': json.loads(row[0]) if row else None})
                if (method, name) == ('PUT', 'data'):
                    if not isinstance(body.get('data'), dict):
                        return self.send_json(400, {'error': 'No library in that request'})
                    con.execute('INSERT INTO libraries VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated=excluded.updated',
                                (uid, json.dumps(body['data']), time.time()))
                    return self.send_json(200, {'ok': True})
                if (method, name) == ('POST', 'share'):
                    row = con.execute('SELECT id FROM shares WHERE user_id=?', (uid,)).fetchone()
                    sid = row[0] if row else secrets.token_urlsafe(9)
                    if not row:
                        con.execute('INSERT INTO shares VALUES(?,?,?)', (sid, uid, time.time()))
                    return self.send_json(200, {'id': sid, 'lan': lan_ip()})
                if (method, name) == ('POST', 'spine'):
                    key, img = str(body.get('key') or ''), str(body.get('img') or '')
                    if not SPINE_KEY.match(key) or not img.startswith('data:image/jpeg;base64,') or len(img) > 300_000:
                        return self.send_json(400, {'error': 'That spine photo could not be shared'})
                    con.execute('INSERT INTO spines(key,img,user_id,created) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE '
                                'SET img=excluded.img, created=excluded.created WHERE spines.user_id=excluded.user_id',
                                (key, img, uid, time.time()))
                    return self.send_json(200, {'ok': True})
                if (method, name) == ('POST', 'unshare'):
                    con.execute('DELETE FROM shares WHERE user_id=?', (uid,))
                    return self.send_json(200, {'ok': True})
                if (method, name) == ('POST', 'logout'):
                    con.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(self.headers['Authorization'][7:]),))
                    return self.send_json(200, {'ok': True})
                return self.send_json(404, {'error': 'Unknown request'})
        finally:
            con.close()

    def sign(self, con, mode, body):
        username = str(body.get('username') or '').strip().lower()
        password = str(body.get('password') or '')
        if not USERNAME.match(username):
            return self.send_json(400, {'error': 'Use an email address, or a username of 3 or more letters and digits (no spaces)'})
        if not 6 <= len(password) <= 200:
            return self.send_json(400, {'error': 'Password must be at least 6 characters'})
        if mode == 'signup':
            salt = secrets.token_bytes(16)
            try:
                uid = int(con.execute('INSERT INTO users(username,salt,hash,created) VALUES(?,?,?,?) RETURNING id',
                                      (username, salt, pw_hash(password, salt), time.time())).fetchone()[0])
            except (sqlite3.IntegrityError, Duplicate):
                return self.send_json(409, {'error': 'That username is taken'})
            return self.send_json(200, {'token': self.new_session(con, uid), 'username': username, 'data': None})
        # login: at most 8 wrong passwords per address and username in 5 minutes
        ip = (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip() if TRUST_PROXY else ''
        key = (ip or self.client_address[0], username)
        recent = [t for t in FAILS.get(key, []) if t > time.time() - 300]
        if len(recent) >= 8:
            return self.send_json(429, {'error': 'Too many attempts. Try again in a few minutes'})
        row = con.execute('SELECT id,salt,hash FROM users WHERE username=?', (username,)).fetchone()
        uid, salt, stored = (int(row[0]), blob(row[1]), blob(row[2])) if row else (None, b'\0' * 16, b'')
        if not hmac.compare_digest(pw_hash(password, salt), stored) or uid is None:
            FAILS[key] = recent + [time.time()]
            return self.send_json(401, {'error': 'Wrong username or password'})
        FAILS.pop(key, None)
        lib = con.execute('SELECT data FROM libraries WHERE user_id=?', (uid,)).fetchone()
        self.send_json(200, {'token': self.new_session(con, uid), 'username': username,
                             'data': json.loads(lib[0]) if lib else None})

    def log_message(self, fmt, *args):
        pass


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get('PORT') or 8765)
    try:
        init()
    except Exception as e:                 # stop here, loudly, rather than run without the accounts database
        print(f'Book Shelf could not open its database: {e}', file=sys.stderr, flush=True)
        sys.exit(1)
    where = 'Neon Postgres (DATABASE_URL)' if DATABASE_URL else os.path.dirname(DB)
    print(f'Book Shelf running on port {port} (accounts in {where})', flush=True)
    ThreadingHTTPServer(('0.0.0.0', port), functools.partial(Handler, directory=ROOT)).serve_forever()
