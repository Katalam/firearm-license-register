from flask import Flask
import mysql.connector
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

db = mysql.connector.connect(
	host = 'localhost',
	user = 'root',
	password = '',
	database = 'auth'
)

dbcursor = db.cursor()

@app.route('/')
def hello_world():
	dbcursor.execute('SELECT Name FROM test')
	result = dbcursor.fetchall()
	text = ''
	for x in result:
		text += (x[0] + '\n')
	print(text)
	return text


def init_db():
	try:
		dbcursor.execute('CREATE TABLE IF NOT EXISTS users (id SERIAL UNIQUE, username VARCHAR(254) NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL, PRIMARY KEY(username))')
		db.commit()
	except Exception as error:
		print(error)
	finally:
		print('Database connected.')

init_db()
