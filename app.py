import os, secrets, hashlib, requests, mysql.connector
from flask import Flask, request, redirect, render_template, abort, url_for, session
from dotenv import load_dotenv
from datetime import date
load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')
app.session_cookie_name = os.getenv('SESSION_NAME')

db = mysql.connector.connect(
    host = os.getenv('DB_HOST'),
    user = os.getenv('DB_USER'),
    password = os.getenv('DB_PASSWORD'),
    database = os.getenv('DB_DATABASE')
)

c = db.cursor()

@app.route('/')
def index():
    return render_template('base.html', sid='sid' in session)

# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'sid' in session:
        return redirect('edit')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        result = user_login(username, password)
        if result is None:
            return render_template('base.html',
                h='Falsch',
                m='Benutername oder Passwort ist falsch.')
        session['sid'] = result[0]
        session['user_id'] = result[1]
        return redirect('edit')
    return render_template('login.html')

@app.route('/edit')
def edit():
    if 'sid' not in session:
        return redirect('login')
    c.execute('SELECT * FROM characters;')
    data = c.fetchall()
    return render_template('edit.html',
        rows=data, new=True, sid=True)

@app.route('/logout')
def logout():
    session.pop('sid', None)
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/character/<cid>', methods=['GET', 'POST'])
def edit_char(cid):
    if 'sid' not in session:
        return redirect('login')
    if request.method == 'GET':
        c.execute('SELECT first_name, last_name, a, b, \
                          comment, last_edited, \
                          last_edited_from, birthday, id_card \
                   FROM characters WHERE id=%(c)s;', { 'c': cid })
        data = c.fetchone()
        if data is None:
            return redirect(url_for('edit'))
        f_name, l_name, a, b, comment, l_edited, l_e_from, birthday, id_c = data
        l_e_name = None
        if l_edited is not None:
                c.execute('SELECT username FROM users \
                           WHERE id = %(uid)s;', { "uid": l_e_from })
                r = c.fetchone()
                if r is not None:
                    l_e_name = r[0]
        return render_template("edit_char.html",
                            a=a, b=b, id=cid, h=f_name + ' ' + l_name,
                            disable_a=allowed_to_change(a, session['user_id']),
                            disable_b=allowed_to_change(b, session['user_id']),
                            Name=l_e_name, Date=l_edited, Comment=comment,
                            MedicName='MEDIC!', MedicDate='01.01.1190',
                            Birthday=birthday, Idcardid=id_c, sid=True)
    # POST
    a = int(request.form.get('a'))
    b = int(request.form.get('b'))
    comment = request.form.get('comment')
    birthday = request.form.get('birthday')
    idcard = request.form.get('id')

    c.execute('SELECT * FROM characters WHERE id=%(cid)s;', { 'cid': cid })
    data = c.fetchone()
    _id, f_name, l_name, birthdaydb, id_card, old_a, old_b, commentdb, l_edited, l_e_from = data
    name = f_name + ' ' + l_name
    if a is not old_a:
        message_discord(session['user_id'], 'A', name,
            get_name_type(old_a), get_name_type(a))
    if b is not old_b:
        message_discord(session['user_id'], 'B', name,
            get_name_type(old_b), get_name_type(b))

    c.execute('UPDATE characters SET a=%(a)s, b=%(b)s \
               WHERE id=%(cid)s;', { 'a': a, 'b': b, 'cid': cid })
    if comment is not None and comment is not commentdb:
        c.execute('UPDATE `characters` \
                   SET comment=%(c)s, last_edited=%(d)s, last_edited_from=%(uid)s \
                   WHERE id = %(cid)s;',
            { 'c': comment,
              'd': date.today().strftime('%d.%m.%Y'),
              'uid': session['user_id'], 'cid': cid })
    if birthday is not None and birthday is not birthdaydb:
        c.execute('UPDATE characters SET birthday=%(b)s \
                   WHERE id=%(id)s;', { 'b': birthday, 'id': cid })
    if idcard is not None and idcard is not id_card:
        c.execute('UPDATE characters SET id_card=%(idcard)s \
                   WHERE id=%(id)s;', { "idcard": idcard, "id": cid })
    db.commit()
    return redirect(url_for('edit_char', cid=cid))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        code = request.form.get('invite_code')

        c.execute('SELECT id FROM invite_codes \
                   WHERE code=%(c)s', { 'c': code })
        data = c.fetchone()
        if data is None:
            return render_template('base.html', sid='sid' in session,
                                    h='Falscher EInladungscode',
                                    m='Einladungscode falsch.')
        c.execute('DELETE FROM invite_codes WHERE id=%(i)s', { 'i': data[0] })
        db.commit()

        salt = secrets.token_hex(32)

        h = hashlib.sha512()
        h.update(str.encode(salt))
        h.update(str.encode(password))
        user_hash = h.hexdigest()

        c.execute('INSERT INTO users (username, salt, hash) \
                   VALUES (%(u)s, %(s)s, %(h)s);', {
                       'u': username,
                       's': salt,
                       'h': user_hash })
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/new', methods=['GET', 'POST'])
def new():
    if 'sid' not in session:
        return redirect('login')
    if request.method == 'POST':
        name = request.form.get('name')
        surname = request.form.get('surname')
        birthday = request.form.get('birthday')
        cardId = request.form.get('id')
        if name != '' and surname != '' and birthday != '':
            c.execute('INSERT INTO characters \
                       (first_name, last_name, birthday, id_card) \
                       VALUES (%(n)s, %(s)s, %(b)s, %(c)s);',
                       { 'n': name, 's': surname, 'b': birthday, 'c': cardId })
            cid = c.lastrowid
            return redirect(url_for('edit_char', cid=cid))
        return redirect('new')
    return render_template("new.html")

def message_discord(user, type, name, old_value, new_value):
    if os.getenv('DISCORD_WEBHOOK') is not None:
        requests.post(os.getenv('DISCORD_WEBHOOK'), json={
            'embeds': [
                {
                    'title': 'Änderung',
                    'description': str(user) + ' hat Waffenschein ' + type + ' von ' + name + ' von ' + old_value + ' in ' + new_value + ' geändert.',
                    'color': 16711680
                }
            ],
                'username': 'Waffenscheinregister',
                'avatar_url': os.getenv('DISCORD_AVATAR_URL')
            })

def get_name_type(value):
    switcher = {
        0: 'Nicht Erworben',
        1: 'Entzogen',
        2: 'Sperre',
        3: 'Beantragt',
        4: 'Aktiv'
    }
    return switcher.get(value, 'Nicht Erworben')

'''
Return allowed to changed a or b value based on userId
if returned value is 0 you are not allowed to change it
'''
def allowed_to_change(value, userId):
    c.execute('SELECT police, store FROM users WHERE id = %(userId)s;', { 'userId': userId })
    data = c.fetchone()
    police, store = data
    if data is None:
        return False
    switcher = {
        0: police or store, # nicht erworben
        1: store, # Entzogen
        2: police, # Sperre
        3: police or store, # Beantragt, not available for class b
        4: police # aktiv
    }
    return switcher.get(value, 0)

@app.errorhandler(404)
def not_found(error):
    return render_template('base.html',
                h='404', m='Site not found.', sid='sid' in session), 404

@app.errorhandler(Exception)
def error(e):
    return e

@app.before_request
def remove_expired_sessions():
    sql = 'DELETE FROM sessions \
           WHERE expires_after < NOW();'
    c.execute(sql)
    db.commit()
    if 'sid' in session:
        sql = "SELECT session_id, user_id \
               FROM sessions WHERE session_id='{}';".format(session['sid'])
        c.execute(sql)
        data = c.fetchone()
        if data is None:
            session.pop('sid', None)
            session.pop('user_id', None)
            return
        session['sid'] = data[0]
        session['user_id'] = data[1]

@app.after_request
def update_sessions(response):
    if 'sid' in session:
        sql = "UPDATE sessions \
               SET expires_after = DATE_ADD(NOW(), INTERVAL 1 HOUR) \
               WHERE session_id='{}';".format(session['sid'])
        c.execute(sql)
        db.commit()
    return response

'''
Return authenticated session if username in database
and given plain passwords hash is equal database saved one.
'''
def user_login(username, password):
    c.execute('SELECT id FROM users WHERE username=%(u)s;', { 'u': username })
    user_id = c.fetchone()
    if user_id is None:
        return None
    if auth(user_id[0], password):
        return create_authenticated_session(user_id[0])
    return None

'''
Compares given plain password with saved hash and return the result.
'''
def auth(user_id, password):
    c.execute('SELECT salt, hash \
               FROM users WHERE id=%(u)s;', { 'u': user_id })
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

'''
Creates authenticated session.
'''
def create_authenticated_session(user_id):
    sid = secrets.token_hex(32)
    sql = "INSERT INTO sessions (session_id, expires_after, user_id) \
           VALUES ('{}', DATE_ADD(NOW(), INTERVAL 1 HOUR), '{}');".format(sid, user_id)
    c.execute(sql)
    db.commit()
    return sid, user_id

if __name__ == "__main__":
    app.run()
