import os
from flask import Flask, request, redirect, render_template, abort, url_for
import mysql.connector
from dotenv import load_dotenv
import secrets
import hashlib
import requests
load_dotenv()

app = Flask(__name__)

db = mysql.connector.connect(
    host = os.getenv("HOST"),
    user = os.getenv("USER"),
    password = os.getenv("PASSWORD"),
    database = os.getenv("DATABASE")
)

c = db.cursor()

@app.route("/")
def page():
    return render_template("base.html", login = True)

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
            return render_template("base.html",
                            h = "Falsch", message = "Dein Passwort oder dein Benutzername ist falsch.")
        response = redirect("edit")
        response.set_cookie(key = "session", value = result[0],
                            max_age = result[1], httponly = True)
        return response
    else:
        session = get_session(request)
        if session:
            return redirect("edit")
        return render_template("login.html", login = True)

@app.route("/edit", methods = ["GET", "POST"])
def page_edit():
    session = get_session(request)
    if not session:
        return redirect(url_for("page_login"))
    c.execute("SELECT * FROM characters;")

    return render_template("edit.html",
                            rows = c.fetchall())

@app.route("/logout", methods = ["GET", "POST"])
def page_logout():
    session = get_session(request)
    if session is None:
        return redirect(url_for("page_login"))
    result = remove_session(session[0])
    response = redirect("login")
    response.set_cookie(key = "session", value = result[0], max_age = result[1], httponly = True)
    return response

@app.route("/character/<charId>", methods = ["GET", "POST"])
def page_edit_char(charId):
    session = get_session(request)
    if session is None:
        return redirect(url_for("page_login"))
    c.execute("SELECT first_name, last_name, a, b FROM characters WHERE id = %(charid)s;", {"charid": charId})
    data = c.fetchone()
    if data is None:
        return redirect(url_for("page_login"))
    return render_template("edit_char.html",
                        a = data[2], b = data[3],
                        id = charId, h = data[0] + " " + data[1],
                        disable_a = allowed_to_change(data[2], session[2]),
                        disable_b = allowed_to_change(data[3], session[2]))

@app.route("/character/<charId>/save", methods = ["GET", "POST"])
def page_edit_char_save(charId):
    session = get_session(request)
    if session is None:
        return redirect(url_for("page_login"))
    a = request.form.get("a")
    b = request.form.get("b")

    c.execute("SELECT * FROM characters WHERE id = %(id)s;", {"id": charId})
    data = c.fetchone()
    name = data[1] + " " + data[2]
    old_a = data[4]
    old_b = data[5]
    if not a == old_a:
        message_discord(session[2], "A", name, get_name_type(old_a), get_name_type(a))
    if not b == old_b:
        message_discord(session[2], "B", name, get_name_type(old_b), get_name_type(b))

    if not a is None:
        c.execute("UPDATE `characters` SET `a`= %(a)s WHERE id = %(id)s;", {"a": a, "id": charId})
    if not b is None:
        c.execute("UPDATE `characters` SET `b`= %(b)s WHERE id = %(id)s;", {"b": b, "id": charId})
    return redirect(url_for("page_edit_char", charId = charId))

@app.route("/character/new", methods = ["GET", "POST"])
def page_new_char():
    message_discord(1, "A", "Markus Ritter", "Ja", "Sperre")
    return render_template("base.html")

def message_discord(user, type, name, old_value, new_value):
    requests.post("https://discordapp.com/api/webhooks/754321362343952475/IAzRcNh-UZdzp65qMhzgbxmdqPBSLXDVeEDTtddfp9m46tBrmUgiiuBHPB8Ndtxv54DI", json={
        "embeds": [
            {
            "title": "Änderung",
            "description": str(user) + " hat Waffenschein " + type + " von " + name + " von " + old_value + " in " + new_value + " geändert.",
            "color": 16711680
            }
        ],
        "username": "Waffenscheinregister",
        "avatar_url": "https://i.imgur.com/f7yTuA5.jpeg"
        })

def get_name_type(value):
    switcher = {
        0: "Nicht Erworben",
        1: "Entzogen",
        2: "Sperre",
        3: "Beantragt",
        4: "Aktiv"
    }
    return switcher.get(value, "Nicht Erworben")

"""
Return allowed to changed a or b value based on userId
if returned value is 0 you are not allowed to change it
"""
def allowed_to_change(value, userId):
    c.execute("SELECT police, store FROM users WHERE id = %(userId)s;", {"userId": userId})
    data = c.fetchone()
    if data is None:
        return False
    switcher = {
        0: data[0] or data[1], # nicht erworben
        1: data[1], # Entzogen
        2: data[0], # Sperre
        3: data[0] or data[1], # Beantragt, not available for class b
        4: data[0] # aktiv
    }
    return switcher.get(value, 0)
        

"""
Removes session from db and returns empty session cookie values.
"""
def remove_session(session_id):
    c.execute("DELETE FROM sessions WHERE session_id = %(sid)s;", {"sid": session_id})
    db.commit()
    return "", 0

"""
After each request from client the session cookie gets updated.
"""
@app.after_request
def update_session_cookie(response):
    session = get_session(request)

    if not session is None:
        response.set_cookie(key = "session", value = session[0], max_age = session[1], httponly = True)

    return response


"""
Removes expired sessions before the request handling.
"""
@app.before_request
def remove_expired_sessions():
    c.execute("DELETE FROM sessions WHERE expires_after < NOW();")
    db.commit()

"""
If session cookie is set return this session and update expire date inside db else return none.
"""
def get_session(request):
    session_cookie = request.cookies.get("session")
    if session_cookie is None:
        return None
    c.execute("UPDATE sessions SET expires_after = DATE_ADD(NOW(), INTERVAL 1 HOUR) \
              WHERE session_id = %(sid)s;", {"sid": session_cookie})
    db.commit()

    c.execute("SELECT session_id, 3600 as max_age, user_id FROM sessions \
              WHERE session_id = %(sid)s;",
              {"sid": session_cookie})
    return c.fetchone()

"""
Handles login process for given username and password.
"""
def login(username, password):
    c.execute("SELECT id FROM users WHERE username = %(username)s;", {"username": username})
    user_id = c.fetchone()
    if user_id is None:
        return None
    if auth(user_id[0], password):
        return create_authenticated_session(user_id[0])
    return None


"""
Compares given plain password with saved hash in db.
"""
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

"""
Generate and save new session in database and return session id.
"""
def create_authenticated_session(user_id):
    sid = secrets.token_hex(32)
    c.execute("INSERT INTO sessions VALUES (null, %(sid)s, DATE_ADD(NOW(), INTERVAL 1 HOUR), %(user_id)s);",
                {"sid": sid, "user_id": user_id})
    db.commit()
    return sid, 3600


"""
Init database for first usage.
"""
def init_db():
    try:
        c.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL UNIQUE, username VARCHAR(254) NOT NULL UNIQUE, \
            salt TEXT NOT NULL, hash TEXT NOT NULL, police BOOLEAN, store BOOLEAN, PRIMARY KEY(username))")
        c.execute("CREATE TABLE IF NOT EXISTS sessions (id SERIAL, session_id VARCHAR(254) NOT NULL UNIQUE, expires_after TIMESTAMP NOT NULL, \
            user_id INTEGER REFERENCES users(id), PRIMARY KEY(session_id));")
        c.execute("CREATE TABLE IF NOT EXISTS characters (id SERIAL, first_name VARCHAR(254) NOT NULL, last_name VARCHAR(254) NOT NULL, \
            birthday VARCHAR(254) NOT NULL, a INT(1), b INT(1), PRIMARY KEY(id));")
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