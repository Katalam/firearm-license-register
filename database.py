import os, mysql.connector, sys, secrets, hashlib
from dotenv import load_dotenv
load_dotenv()

db = mysql.connector.connect(
    host = os.getenv('DB_HOST'),
    user = os.getenv('DB_USER'),
    password = os.getenv('DB_PASSWORD'),
    database = os.getenv('DB_DATABASE')
)

c = db.cursor()

user_sql = '''CREATE TABLE IF NOT EXISTS users (
    id SERIAL,
    username VARCHAR(254) NOT NULL DEFAULT '',
    salt VARCHAR(254) NOT NULL DEFAULT '',
    hash VARCHAR(254) NOT NULL DEFAULT '',
    create_code BOOLEAN NOT NULL DEFAULT FALSE,
    store BOOLEAN NOT NULL DEFAULT FALSE,
    police BOOLEAN NOT NULL DEFAULT FALSE,
    medic BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id));
    '''

session_sql = '''CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL,
    session_id VARCHAR(254) NOT NULL UNIQUE DEFAULT '',
    expires_after TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    PRIMARY KEY (session_id));
    '''

invite_codes_sql = '''CREATE TABLE IF NOT EXISTS invite_codes (
    id SERIAL,
    code VARCHAR(254) NOT NULL DEFAULT '',
    created_from VARCHAR(254) NOT NULL DEFAULT 0,
    PRIMARY KEY (id));'''

characters_sql = '''CREATE TABLE IF NOT EXISTS characters (
    id SERIAL,
    first_name VARCHAR(254) NOT NULL DEFAULT '',
    last_name VARCHAR(254) NOT NULL DEFAULT '',
    birthday VARCHAR(254) NOT NULL DEFAULT '',
    id_card VARCHAR(254) NOT NULL DEFAULT '',
    a BOOLEAN NOT NULL DEFAULT FALSE,
    b BOOLEAN NOT NULL DEFAULT FALSE,
    comment VARCHAR(254) NOT NULL DEFAULT '',
    last_edited VARCHAR(254) NOT NULL DEFAULT '',
    last_edited_from INT(11) NOT NULL DEFAULT 0,
    PRIMARY KEY (id));'''

c.execute(user_sql)
c.execute(session_sql)
c.execute(invite_codes_sql)
c.execute(characters_sql)
db.commit()


'''
Save new user is username and password is given.
'''
if len(sys.argv) > 1:
    salt = secrets.token_hex(32)

    h = hashlib.sha512()
    h.update(str.encode(salt))
    h.update(str.encode(sys.argv[2]))
    user_hash = h.hexdigest()
    sql = "INSERT INTO users (username, salt, hash) \
        VALUES ('{}', '{}', '{}');".format(sys.argv[1], salt, user_hash)
    c.execute(sql)
    db.commit()