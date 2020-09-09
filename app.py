import os
from flask import Flask, request, redirect, render_template, abort
import mysql.connector
from dotenv import load_dotenv
import secrets
import hashlib
load_dotenv()

app = Flask(__name__)

db = mysql.connector.connect(
    host = os.getenv("HOST"),
    user = os.getenv("USER"),
    password = os.getenv("PASSWORD"),
    database = os.getenv("DATABASE")
)

c = db.cursor()

# login
@app.route("/login", methods = ["GET", "POST"])
def page_login():
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
        except KeyError:
            abort(400)
        result = login(username, password)
        if result is None:
            return render_template("edit.html",
                            message = "Wrong")
        response = redirect("edit")
        response.set_cookie(key = "session", value = result[0],
                            max_age = result[1], httponly = True)
        return response
    else:
        session = get_session(request)
        if session:
            return redirect("edit")
        return render_template("login.html")

@app.route("/edit", methods = ["GET", "POST"])
def page_edit():
    session = get_session(request)
    if not session:
        return redirect("login")
    return render_template("edit.html",
                            message = session[2])

@app.after_request
def update_session_cookie(response):
    session = get_session(request)

    if not session is None:
        response.set_cookie(key = "session", value = session[0], max_age = session[1], httponly = True)

    return response

def get_session(request):
    session_cookie = request.cookies.get("session")
    if session_cookie is None:
        return None
    c.execute("UPDATE sessions SET expires_after = DATE_ADD(NOW(), INTERVAL 1 HOUR) \
              WHERE session_id = %(sid)s;", {"sid": session_cookie})
    db.commit()

    # max_age = 3600 seconds = 1 hour
    c.execute("SELECT session_id, 3600 as max_age, user_id FROM sessions \
              WHERE session_id = %(sid)s;",
              {"sid": session_cookie})
    return c.fetchone()

def login(username, password):
    c.execute("SELECT id FROM users WHERE username = %(username)s;", {"username": username})
    user_id = c.fetchone()
    if user_id is None:
        return None
    if auth(user_id[0], password):
        return create_authenticated_session(user_id[0])
    return None

def auth(user_id, password):
    c.execute("SELECT salt, hash FROM users WHERE id = %(user_id)s;", {"user_id": user_id})
    r = c.fetchone()
    if r is None:
        return False
    salt = r[0]
    hash_db = r[1]

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password))
    hash_user = h.hexdigest()
    return secrets.compare_digest(hash_db, hash_user)

def create_authenticated_session(user_id):
    sid = secrets.token_hex(32)
    c.execute("INSERT INTO sessions VALUES (null, %(sid)s, DATE_ADD(NOW(), INTERVAL 1 HOUR), %(user_id)s);",
                {"sid": sid, "user_id": user_id})
    db.commit()
    return sid, 3600 # 1 hour

def init_db():
    try:
        c.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL UNIQUE, username VARCHAR(254) NOT NULL UNIQUE, \
            salt TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(username))")
        c.execute("CREATE TABLE IF NOT EXISTS sessions (id SERIAL, session_id VARCHAR(254) NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            user_id INTEGER REFERENCES users(id), PRIMARY KEY(session_id));")
        db.commit()
    except Exception as error:
        print(f"{bcolors.FAIL}{error}{bcolors.ENDC}")
    finally:
        print(f"{bcolors.OKGREEN}Database connected.{bcolors.ENDC}")

class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

init_db()

def create_user(username, password):
    salt = secrets.token_hex(32)

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(password))
    user_hash = h.hexdigest()
    print(f"{bcolors.OKBLUE}{username}{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}{salt}{bcolors.ENDC}")
    print(f"{bcolors.OKBLUE}{user_hash}{bcolors.ENDC}")

# create_user("katalam", "abc")